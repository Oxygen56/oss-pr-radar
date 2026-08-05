from pathlib import Path

from oss_pr_radar.local_publication import advance_once, launch_agent_spec


def test_fast_publication_runs_ingestion_and_publication_in_order(tmp_path):
    calls = []
    responses = {
        "ingest-results": {
            "ok": True,
            "ingested": [{"key": "a/b#1", "stage": "FIX_READY"}],
            "publicationRequests": [{"requestId": "request-1", "status": "PENDING"}],
            "errors": [],
        },
        "publication-run": {
            "ok": True,
            "published": [{"key": "a/b#1", "prUrl": "https://github.com/a/b/pull/2"}],
            "pending": [],
            "blocked": [],
            "errors": [],
        },
    }

    def runner(root: Path, operation: str):
        calls.append((root, operation))
        return responses[operation]

    result = advance_once(tmp_path, runner=runner)

    assert [operation for _, operation in calls] == ["ingest-results", "publication-run"]
    assert result["ok"] is True
    assert result["activity"] is True
    assert result["published"][0]["prUrl"] == "https://github.com/a/b/pull/2"


def test_fast_publication_is_quiet_when_no_result_or_request_exists(tmp_path):
    def runner(_root: Path, operation: str):
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["activity"] is False


def test_launch_agent_uses_local_venv_and_contains_no_credentials(tmp_path):
    root = tmp_path / "radar"
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    home = tmp_path / "home"

    spec = launch_agent_spec(root, interval_seconds=5, home=home)

    assert spec["StartInterval"] == 15
    assert spec["ProgramArguments"][0:2] == ["/usr/bin/env", "-i"]
    assert str(python) in spec["ProgramArguments"]
    assert spec["WorkingDirectory"] == str(root.resolve())
    assert "FEISHU" not in str(spec)
    assert "DEEPSEEK" not in str(spec)
