from __future__ import annotations

import json
import os
import selectors
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
import test_local_dispatch_bridge as native_fixture

from scripts import local_dispatch_bridge as bridge


@contextmanager
def _response_pipe():
    read_fd, write_fd = os.pipe()
    output = os.fdopen(read_fd, "rb", buffering=0)
    selector = selectors.DefaultSelector()
    selector.register(output, selectors.EVENT_READ)
    try:
        yield SimpleNamespace(stdout=output), selector, write_fd
    finally:
        selector.close()
        output.close()
        os.close(write_fd)


def _frame(value):
    return (json.dumps(value) + "\n").encode()


def test_app_server_response_consumes_coalesced_resume_without_new_io():
    with _response_pipe() as (process, selector, write_fd):
        os.write(
            write_fd,
            _frame({"id": 1, "result": {}})
            + _frame({"id": 2, "result": {"thread": {"id": "central"}}}),
        )
        buffer, initialized = bridge._read_app_server_response(
            process, selector, b"", response_id=1, timeout=0.2, action="initialize"
        )
        assert initialized["id"] == 1 and buffer.endswith(b"\n")
        # The writer remains open; there is no new IO or EOF to wake select.
        buffer, resumed = bridge._read_app_server_response(
            process, selector, buffer, response_id=2, timeout=0.05, action="resume"
        )
        assert resumed["result"]["thread"]["id"] == "central" and buffer == b""


def test_app_server_response_consumes_buffered_error_without_new_io():
    with _response_pipe() as (process, selector, _write_fd):
        with pytest.raises(
            RuntimeError, match="DESKTOP_ACTIVE_WRITER:already has an active writer"
        ):
            bridge._read_app_server_response(
                process,
                selector,
                _frame({"id": 2, "error": {"message": "already has an active writer"}}),
                response_id=2,
                timeout=0.05,
                action="resume",
            )


def test_app_server_response_joins_partial_buffer_and_ignores_unrelated_frames():
    with _response_pipe() as (process, selector, write_fd):
        frame = _frame({"id": 2, "result": {"thread": {"id": "central"}}})
        prefix = b"not-json\n" + _frame({"method": "notification"}) + _frame({"id": 9})
        timer = threading.Timer(0.01, os.write, args=(write_fd, frame[12:]))
        timer.start()
        try:
            remaining, resumed = bridge._read_app_server_response(
                process,
                selector,
                prefix + frame[:12],
                response_id=2,
                timeout=0.2,
                action="resume",
            )
            assert resumed["id"] == 2 and remaining == b""
        finally:
            timer.join()


@pytest.mark.parametrize("buffer", [b"", b'{"id":2,"result":'])
def test_app_server_response_keeps_original_timeout_for_incomplete_reply(buffer):
    with _response_pipe() as (process, selector, _write_fd):
        with pytest.raises(RuntimeError, match="app server did not complete resume request"):
            bridge._read_app_server_response(
                process, selector, buffer, response_id=2, timeout=0.02, action="resume"
            )


def test_app_server_response_keeps_eof_failure_without_complete_reply():
    read_fd, write_fd = os.pipe()
    output = os.fdopen(read_fd, "rb", buffering=0)
    with selectors.DefaultSelector() as selector:
        selector.register(output, selectors.EVENT_READ)
        os.close(write_fd)
        try:
            with pytest.raises(RuntimeError, match="app server did not complete resume request"):
                bridge._read_app_server_response(
                    SimpleNamespace(stdout=output),
                    selector,
                    b'{"id":2',
                    response_id=2,
                    timeout=0.2,
                    action="resume",
                )
        finally:
            output.close()


class StrictAppServer:
    """A pipe-backed boundary that rejects RPC before the initialized handshake."""

    def __init__(self, thread_id, *, failure=None):
        self.thread_id = thread_id
        self.failure = failure
        read_fd, self.write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)
        self.stdin = self
        self.frames = []
        self.pending = b""
        self.initialized = False
        self.initialize_replied = False

    def write(self, value):
        self.pending += value
        return len(value)

    def flush(self):
        while b"\n" in self.pending:
            raw, self.pending = self.pending.split(b"\n", 1)
            frame = json.loads(raw)
            self.frames.append(frame)
            method = frame["method"]
            if method == "initialize":
                assert len(self.frames) == 1
                response = {"id": frame["id"], "result": {}}
                if self.failure == "initialize":
                    response = {"id": frame["id"], "error": {"message": "init denied"}}
                self.initialize_replied = self.failure != "initialize"
            elif method == "initialized":
                assert self.initialize_replied and "id" not in frame
                self.initialized = True
                continue
            elif method == "thread/resume":
                if not self.initialized:
                    response = {
                        "id": frame["id"],
                        "error": {"message": "resume before initialized"},
                    }
                elif self.failure == "resume":
                    response = {"id": frame["id"], "error": {"message": "resume denied"}}
                else:
                    assert frame["params"]["excludeTurns"] is True
                    response = {
                        "id": frame["id"],
                        "result": {
                            "thread": {
                                "id": "foreign" if self.failure == "foreign" else self.thread_id,
                                "turns": [],
                            }
                        },
                    }
            elif method == "turn/start":
                assert self.initialized and self.failure is None
                assert frame["params"]["threadId"] == self.thread_id
                response = {"id": frame["id"], "result": {"turn": {"id": "strict-turn"}}}
            else:
                raise AssertionError(f"unexpected RPC: {method}")
            os.write(self.write_fd, _frame(response))

    def poll(self):
        return 0

    def close(self):
        self.stdout.close()
        os.close(self.write_fd)


@pytest.mark.parametrize("failure", [None, "initialize", "resume", "foreign"])
def test_task_worker_uses_ordered_metadata_resume_and_preserves_bound_validation(
    monkeypatch, tmp_path, failure
):
    module = native_fixture.MODULE
    store, candidate, worktree, result_path, original, binding, args = (
        native_fixture._bound_validation_worker_fixture(monkeypatch, tmp_path)
    )
    process = StrictAppServer(candidate["threadId"], failure=failure)

    @contextmanager
    def session(*_args, **_kwargs):
        yield process

    monkeypatch.setattr(module, "_app_server_action_session", session)
    monkeypatch.setattr(module.shutil, "which", lambda _: "/test/codex")
    monkeypatch.setattr(module, "_finalize_terminal_turn_resources", lambda **_kwargs: None)
    monkeypatch.setattr(
        module,
        "_wait_for_app_server_terminal_turn",
        lambda *_args, **_kwargs: {"status": "completed", "turnId": "strict-turn"},
    )
    original_read = module._read_app_server_response

    def read_response(*args, response_id, **kwargs):
        if response_id == 0:
            assert [item["method"] for item in process.frames] == ["initialize"]
        return original_read(*args, response_id=response_id, **kwargs)

    monkeypatch.setattr(module, "_read_app_server_response", read_response)
    try:
        if failure:
            detail = {
                "initialize": "APP_SERVER_INITIALIZE_FAILED:init denied",
                "resume": "APP_SERVER_RESUME_FAILED:resume denied",
                "foreign": "app server resumed the wrong task",
            }[failure]
            with pytest.raises(RuntimeError, match=detail):
                module._app_server_task_turn_worker(args)
            assert all(item["method"] != "turn/start" for item in process.frames)
            negative = json.loads(native_fixture.Path(args.receipt).read_bytes())
            assert negative["ok"] is False and negative["turnStarted"] is False
            assert store.unresolved_validation_followups()
        else:
            result = module._app_server_task_turn_worker(args)
            assert result["turnStatus"] == "completed"
            assert [item["method"] for item in process.frames] == [
                "initialize",
                "initialized",
                "thread/resume",
                "turn/start",
            ]
            resume = process.frames[2]["params"]
            assert resume["threadId"] == candidate["threadId"] and resume["excludeTurns"] is True
            assert resume["cwd"] == str(worktree)
            turn = process.frames[3]["params"]
            assert binding["worktreeInputPath"] in turn["input"][0]["text"]
            assert binding["reservationDigest"] in turn["clientUserMessageId"]
            assert store.unresolved_validation_followups() == []
        assert result_path.read_bytes() == original
        assert (worktree / binding["worktreeInputPath"]).read_bytes() == original
        assert json.loads(original)["quality"]["relevant_tests_green"] is False
        with store.connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM publication_effects").fetchone()[0] == 0
    finally:
        process.close()
