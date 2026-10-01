"""Real HTTP regressions for the scanner's canceled semantic reviews."""

from __future__ import annotations

import copy
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from oss_pr_radar.llm import DeepSeekEvaluator, DeepSeekRequestError


@contextmanager
def review_server(*, keepalive_lines: int, interval: float, status: int = 200):
    requests = []
    body = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "decision": "REJECT",
                                "semanticSignal": "FILTER",
                                "score": 1,
                                "confidence": 0.9,
                                "evidence_ids": ["issue_data.issue_body"],
                            }
                        )
                    }
                }
            ]
        }
    ).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(status)
            self.send_header("Content-Length", str(keepalive_lines + len(body)))
            self.end_headers()
            try:
                for _ in range(keepalive_lines):
                    self.wfile.write(b"\n")
                    self.wfile.flush()
                    time.sleep(interval)
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_keepalive_response_cannot_extend_request_deadline(tmp_path):
    with review_server(keepalive_lines=24, interval=0.025) as (url, requests):
        evaluator = DeepSeekEvaluator("test-only", "test", url, tmp_path / "cache.json", 0.15)
        started = time.monotonic()
        with pytest.raises(DeepSeekRequestError) as failure:
            evaluator._request_once({}, 0)
        elapsed = time.monotonic() - started
        assert failure.value.category == "timeout"
        assert elapsed < 0.45
        assert len(requests) == 1


def test_completed_keepalive_review_is_cached_and_remains_usable_after_scan_deadline(tmp_path):
    candidate = {
        "repo": "example/project",
        "num": 1,
        "auto_spawn": True,
        "_llm_context": {"issue_body": "A public issue to review"},
    }
    with review_server(keepalive_lines=2, interval=0.01) as (url, requests):
        evaluator = DeepSeekEvaluator("test-only", "test", url, tmp_path / "cache.json", 1)
        assert evaluator.evaluate_candidates([copy.deepcopy(candidate)]) == []
        assert "example/project#1" in evaluator.rejected_candidates
        assert (tmp_path / "cache.json").is_file()
        evaluator.remaining_seconds = lambda: 0
        assert evaluator.evaluate_candidates([copy.deepcopy(candidate)]) == []
        assert "example/project#1" in evaluator.rejected_candidates
        assert len(requests) == 1
        pending = {**candidate, "num": 2}
        result = evaluator.evaluate_candidates([copy.deepcopy(pending)])
        assert result[0]["auto_spawn"] is False
        assert result[0]["notify"] is False
        assert result[0]["gate_decision"] == "RETRY_REQUIRED"
        assert result[0]["llm_review"]["error_category"] == "scan_deadline"
        assert len(requests) == 1


def test_http_error_does_not_wait_for_unused_keepalive_body(tmp_path):
    with review_server(keepalive_lines=24, interval=0.025, status=503) as (url, requests):
        evaluator = DeepSeekEvaluator("test-only", "test", url, tmp_path / "cache.json", 1)
        started = time.monotonic()
        with pytest.raises(DeepSeekRequestError) as failure:
            evaluator._request_once({}, 0)
        assert time.monotonic() - started < 0.45
        assert failure.value.category == "http_error"
        assert failure.value.status_code == 503
        assert failure.value.retryable is True
        assert len(requests) == 1


def test_retry_wait_cannot_overrun_remaining_scan_budget(tmp_path, monkeypatch):
    evaluator = DeepSeekEvaluator("test-only", "test", "https://example.invalid", tmp_path / "c")
    evaluator.remaining_seconds = lambda: 0.5
    calls = []

    def failed_request(_payload, attempt):
        calls.append(attempt)
        raise DeepSeekRequestError("timeout", retryable=True)

    monkeypatch.setattr(evaluator, "_request_once", failed_request)
    monkeypatch.setattr(time, "sleep", lambda _delay: pytest.fail("retry exceeds scan budget"))
    with pytest.raises(DeepSeekRequestError) as failure:
        evaluator._request({})
    assert failure.value.category == "scan_deadline"
    assert calls == [0]
