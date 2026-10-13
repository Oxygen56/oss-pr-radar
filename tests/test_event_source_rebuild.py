from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_pr_radar import agentscope_events, local_publication, nanobot_events, release_binding
from scripts import local_dispatch_bridge as bridge

LANES = [
    ("agentscope", "agentscope-ai/agentscope", agentscope_events),
    ("nanobot", "HKUDS/nanobot", nanobot_events),
]


def _worker(namespace):
    path = Path(__file__).parents[1] / "scripts" / f"{namespace}_event_worker.py"
    spec = importlib.util.spec_from_file_location(f"{namespace}_rebuild_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _event(repo, number=1, event_id="event"):
    return {
        "eventId": event_id,
        "repo": repo,
        "number": number,
        "kind": "issue_update",
        "eventKey": f"{repo}#{number}",
        "issue": {"state": "open", "html_url": f"https://github.com/{repo}/issues/{number}"},
    }


def _manifest(root, repo, cwd, thread="central"):
    value = {
        "schemaVersion": "oss-pr-radar-event-lane-v1",
        "repositories": {repo: {"activeThreadId": thread, "cwd": str(cwd)}},
    }
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    (root / "event-lane-manifest.json").write_bytes(data)
    (root / "event-lane-manifest.sha256").write_text(hashlib.sha256(data).hexdigest() + "\n")


@pytest.mark.parametrize("namespace,repo,module", LANES)
def test_lane_dispatch_is_scoped_exact_once_and_current_model(
    tmp_path, monkeypatch, namespace, repo, module
):
    worker = _worker(namespace)
    cwd = tmp_path / repo.rsplit("/", 1)[1]
    cwd.mkdir()
    monkeypatch.setattr(worker, "ROOT", tmp_path)
    monkeypatch.setattr(worker, "CENTRAL_CWD", cwd)
    _manifest(tmp_path, repo, cwd)
    calls = []
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda root, op, **kwargs: (
            calls.append((op, kwargs))
            or {"ok": True, "threadId": "central", "turnId": "turn", "turnStarted": True}
        ),
    )
    lane = module.EventLane(tmp_path / "state" / "events.db")
    lane.append(_event(repo))
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(tmp_path, lane, claimed)
    worker.issue_handler_delivery(tmp_path, lane, claimed)
    assert len(calls) == 1
    assert calls[0][0] == f"{namespace}-event-create"
    argv = calls[0][1]["extra_args"]
    assert argv[argv.index("--model") + 1] == "gpt-6.1-sol"
    assert f"schemaVersion={namespace}_event_outcome_v1" in argv[argv.index("--prompt") + 1]
    assert "deepseek-flash" in argv[argv.index("--prompt") + 1]
    assert calls[0][1]["inactive_release"] is True
    assert calls[0][1]["code_root"] == tmp_path
    assert lane.ack("event", lease_token=claimed["leaseToken"])
    assert not lane.ack("event", lease_token=claimed["leaseToken"])
    assert lane.handler_turn("event")["thread_id"] == "central"


@pytest.mark.parametrize("namespace,repo,module", LANES)
@pytest.mark.parametrize(
    "foreign", ["other-repo", "conflicting-key", "nonnumeric", "different-number"]
)
def test_cross_lane_or_ambiguous_key_never_dispatches(
    tmp_path, monkeypatch, namespace, repo, module, foreign
):
    worker = _worker(namespace)
    monkeypatch.setattr(
        worker, "run_bridge", lambda *_a, **_k: pytest.fail("foreign event must not dispatch")
    )
    lane = module.EventLane(tmp_path / "events.db")
    event = _event(repo)
    if foreign == "other-repo":
        event["repo"] = "HKUDS/nanobot" if namespace == "agentscope" else "agentscope-ai/agentscope"
    elif foreign == "conflicting-key":
        event["eventKey"] = (
            "agentscope-ai/agentscope#1" if namespace == "nanobot" else "HKUDS/nanobot#1"
        )
    elif foreign == "nonnumeric":
        event["eventKey"] = f"{repo}#1/foreign"
    else:
        event["eventKey"] = f"{repo}#2"
    lane.append(event)
    worker.issue_handler_delivery(tmp_path, lane, lane.claim(limit=1)[0])
    with lane.connect() as db:
        row = db.execute("SELECT status,payload_json FROM event_lane_events").fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["payload_json"])["terminalReason"] == "foreign_repository_event"


@pytest.mark.parametrize("namespace,repo,module", LANES)
def test_capacity_is_atomic_and_busy_does_not_spend_retry(tmp_path, namespace, repo, module):
    lane = module.EventLane(tmp_path / "events.db")
    for number in (1, 2, 3):
        lane.register_public_work(f"{repo}#{number}")
    lane.append(_event(repo, 4, "fourth"))
    claim = lane.claim(limit=1)[0]
    busy = lane.try_reserve_handler_turn_if_idle(
        f"{repo}#4", "fourth", "client", lease_token=claim["leaseToken"], max_active_work=3
    )
    assert busy == {"status": "busy", "reason": "active_work_limit", "activeCount": 3}
    assert lane.handler_turn("fourth") is None
    lane.clear_public_work(f"{repo}#3")
    claim = lane.claim(limit=1)[0]
    assert claim["attempts"] == 1
    assert (
        lane.try_reserve_handler_turn_if_idle(
            f"{repo}#4", "fourth", "client", lease_token=claim["leaseToken"], max_active_work=3
        )["status"]
        == "reserved"
    )


@pytest.mark.parametrize("namespace,repo,module", LANES)
def test_same_schema_completed_exact_outcome_and_bounded_wait(tmp_path, namespace, repo, module):
    lane = module.EventLane(tmp_path / "events.db")
    outcome = {
        "schemaVersion": f"{namespace}_event_outcome_v1",
        "eventId": "event",
        "publicKey": f"{repo}#1",
        "state": "no_action",
    }
    receipt = {"turnStatus": "completed", "outcome": outcome}
    assert lane._valid_outcome_receipt(receipt, "event", f"{repo}#1")
    for changed in [
        dict(outcome, extra=True),
        dict(outcome, publicKey="other/repo#1"),
        dict(
            outcome,
            schemaVersion="nanobot_event_outcome_v1"
            if namespace == "agentscope"
            else "agentscope_event_outcome_v1",
        ),
    ]:
        assert not lane._valid_outcome_receipt(
            {"turnStatus": "completed", "outcome": changed}, "event", f"{repo}#1"
        )
    assert not lane._valid_outcome_receipt(
        dict(receipt, turnStatus="interrupted"), "event", f"{repo}#1"
    )
    start = datetime(2026, 10, 13, tzinfo=UTC)
    waiting = dict(
        outcome,
        state="design_wait",
        waitStartedAt=start.isoformat(),
        waitUntil=(start + timedelta(hours=24)).isoformat(),
    )
    assert lane._valid_outcome_receipt(
        {"turnStatus": "completed", "outcome": waiting}, "event", f"{repo}#1"
    )
    waiting["waitUntil"] = (start + timedelta(hours=24, seconds=1)).isoformat()
    assert not lane._valid_outcome_receipt(
        {"turnStatus": "completed", "outcome": waiting}, "event", f"{repo}#1"
    )


def _bridge_request(tmp_path, monkeypatch, namespace="nanobot", bootstrap=False):
    repo = dict((ns, repo) for ns, repo, _module in LANES)[namespace]
    cwd = tmp_path / repo.rsplit("/", 1)[1]
    cwd.mkdir()
    code = tmp_path / "code"
    code.mkdir()
    state = tmp_path / "state"
    _manifest(code, repo, cwd)
    monkeypatch.setattr(bridge, "ROOT", code)
    monkeypatch.setattr(bridge, "STATE", state)
    monkeypatch.setattr(bridge, "GITHUB_ROOT", tmp_path)
    artifact_root = state / f"{namespace}_event_bootstrap" if bootstrap else state
    receipt = artifact_root / f"{namespace}_event_receipts" / ("a" * 64 + ".json")
    outcome = artifact_root / f"{namespace}_event_outcomes" / receipt.name
    outcome.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    event_id = f"{namespace}-bootstrap-new" if bootstrap else "event"
    key = f"{repo}#bootstrap-new" if bootstrap else f"{repo}#1"
    value = {
        "eventId": event_id,
        "eventKey": key,
        "model": "gpt-6.1-sol",
        "threadId": "central",
        "cwd": str(cwd),
        "prompt": "caller prompt",
        "outcomePath": str(outcome),
        "bootstrap": bootstrap,
    }
    request = receipt.with_suffix(".request.json")
    request.write_text(json.dumps(value))
    args = argparse.Namespace(
        operation=f"{namespace}-event-worker",
        request=request,
        receipt=receipt,
        ledger=tmp_path / "fake.db",
    )
    return args, value, outcome


@pytest.mark.parametrize("namespace,repo,module", LANES)
@pytest.mark.parametrize("bootstrap", [False, True])
def test_real_event_turn_request_uses_exact_model_medium_and_same_thread(
    tmp_path, monkeypatch, namespace, repo, module, bootstrap
):
    args, request, outcome = _bridge_request(tmp_path, monkeypatch, namespace, bootstrap)
    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), poll=lambda: 0)

    class Selector:
        def register(self, *_a):
            pass

        def close(self):
            pass

    monkeypatch.setattr(bridge.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(bridge.shutil, "which", lambda _: "codex-test-boundary")
    monkeypatch.setattr(bridge, "ledger", lambda _: object())

    @contextmanager
    def session(*_args, **_kwargs):
        yield process

    monkeypatch.setattr(bridge, "_app_server_action_session", session)

    def response(*_a, response_id, **_kw):
        return b"", {
            "result": {"thread": {"id": "central"}}
            if response_id == 2
            else {"turn": {"id": "actual-turn"}}
        }

    monkeypatch.setattr(bridge, "_read_app_server_response", response)

    def terminal(*_a, **_kw):
        outcome.write_text(
            json.dumps(
                {
                    "schemaVersion": f"{namespace}_event_outcome_v1",
                    "eventId": request["eventId"],
                    "publicKey": request["eventKey"],
                    "state": "no_action",
                }
            )
        )
        return {"status": "completed"}

    monkeypatch.setattr(bridge, "_wait_for_app_server_terminal_turn", terminal)
    result = bridge._event_worker(args)
    frames = [json.loads(line) for line in process.stdin.getvalue().decode().splitlines()]
    assert [frame["method"] for frame in frames] == [
        "initialize",
        "initialized",
        "thread/resume",
        "turn/start",
    ]
    params = frames[-1]["params"]
    assert params["model"] == "gpt-6.1-sol" and params["effort"] == "medium"
    assert params["threadId"] == "central"
    assert result["turnStatus"] == "completed" and result["outcome"]["state"] == "no_action"
    if bootstrap:
        prompt = params["input"][0]["text"]
        assert "Do not read repositories, run commands, access GitHub" in prompt
        assert "caller prompt" not in prompt
        assert not (bridge.STATE / f"{namespace}_event_outcomes").exists()


@pytest.mark.parametrize("mutation", ["repo", "thread", "model", "path", "cwd"])
def test_request_binding_rejects_before_sender(tmp_path, monkeypatch, mutation):
    args, request, outcome = _bridge_request(tmp_path, monkeypatch)
    if mutation == "repo":
        request["eventKey"] = "agentscope-ai/agentscope#1"
    elif mutation == "thread":
        request["threadId"] = "other"
    elif mutation == "model":
        request["model"] = "gpt-6-astra"
    elif mutation == "path":
        request["outcomePath"] = str(
            outcome.parent.parent / "agentscope_event_outcomes" / outcome.name
        )
    else:
        request["cwd"] = str(tmp_path)
    args.request.write_text(json.dumps(request))
    monkeypatch.setattr(
        bridge.shutil, "which", lambda _: pytest.fail("invalid binding must not reach sender")
    )
    with pytest.raises(RuntimeError):
        bridge._event_worker(args)


@pytest.mark.parametrize("namespace,repo,module", LANES)
@pytest.mark.parametrize("failure", [None, "initialize", "resume", "foreign"])
def test_event_worker_waits_for_initialize_then_resumes_metadata_before_turn(
    tmp_path, monkeypatch, namespace, repo, module, failure
):
    from test_app_server_response_buffer import StrictAppServer

    args, request, outcome = _bridge_request(tmp_path, monkeypatch, namespace, bootstrap=True)
    process = StrictAppServer("central", failure=failure)

    @contextmanager
    def session(*_args, **_kwargs):
        yield process

    monkeypatch.setattr(bridge, "_app_server_action_session", session)
    monkeypatch.setattr(bridge.shutil, "which", lambda _: "/test/codex")
    monkeypatch.setattr(bridge, "ledger", lambda _: object())
    monkeypatch.setattr(bridge, "_terminate_app_server_process", lambda *_args: None)
    original_read = bridge._read_app_server_response

    def read_response(*args, response_id, **kwargs):
        if response_id == 1:
            assert [item["method"] for item in process.frames] == ["initialize"]
        return original_read(*args, response_id=response_id, **kwargs)

    monkeypatch.setattr(bridge, "_read_app_server_response", read_response)

    def terminal(*_args, **_kwargs):
        outcome.write_text(
            json.dumps(
                {
                    "schemaVersion": f"{namespace}_event_outcome_v1",
                    "eventId": request["eventId"],
                    "publicKey": request["eventKey"],
                    "state": "no_action",
                }
            )
        )
        return {"status": "completed"}

    monkeypatch.setattr(bridge, "_wait_for_app_server_terminal_turn", terminal)
    try:
        if failure:
            detail = {
                "initialize": "APP_SERVER_INITIALIZE_FAILED:init denied",
                "resume": "APP_SERVER_THREAD/RESUME_FAILED:resume denied",
                "foreign": "event app-server resumed a foreign thread",
            }[failure]
            with pytest.raises(RuntimeError, match=detail):
                bridge._event_worker(args)
            assert all(item["method"] != "turn/start" for item in process.frames)
            negative = json.loads(args.receipt.read_bytes())
            assert negative["ok"] is False and negative["turnStarted"] is False
            assert negative["turnId"] is None and not outcome.exists()
        else:
            result = bridge._event_worker(args)
            assert result["turnStatus"] == "completed"
            assert [item["method"] for item in process.frames] == [
                "initialize",
                "initialized",
                "thread/resume",
                "turn/start",
            ]
            assert process.frames[2]["params"] == {"threadId": "central", "excludeTurns": True}
            params = process.frames[3]["params"]
            assert params["model"] == "gpt-6.1-sol" and params["effort"] == "medium"
            assert params["threadId"] == "central"
            assert (
                params["clientUserMessageId"]
                == f"oss-pr-radar:{namespace}-event:{request['eventId']}"
            )
            assert result["outcome"]["state"] == "no_action"
    finally:
        process.close()


@pytest.mark.parametrize("operation", ["drain-once", "publish-ready", "sync", "root-task-create"])
def test_inactive_bridge_cannot_authorize_main_operations(tmp_path, monkeypatch, operation):
    monkeypatch.setattr(
        local_publication, "bind_verified_release", lambda *_a: pytest.fail("reject before binder")
    )
    with pytest.raises(RuntimeError, match="not allowed"):
        local_publication.run_bridge(
            tmp_path, operation, code_root=tmp_path / "releases" / "event", inactive_release=True
        )


def test_independent_binder_rejects_external_release_and_symlink(tmp_path, monkeypatch):
    (tmp_path / "releases").mkdir(mode=0o700)
    (tmp_path / "state").mkdir(mode=0o700)
    external = tmp_path / "other"
    external.mkdir(mode=0o700)
    monkeypatch.setattr(
        release_binding, "verify_release", lambda _: pytest.fail("external must not verify")
    )
    with pytest.raises(RuntimeError, match="escapes"):
        release_binding.bind_verified_release(tmp_path, external)
    alias = tmp_path / "releases" / "alias"
    alias.symlink_to(external, target_is_directory=True)
    with pytest.raises(RuntimeError, match="real directory"):
        release_binding.bind_verified_release(tmp_path, alias)


def test_main_event_operation_requires_current_core_authorization(tmp_path, monkeypatch, capsys):
    args, request, outcome = _bridge_request(tmp_path, monkeypatch)
    monkeypatch.setattr(bridge, "bind_runtime", lambda *_a: None)
    monkeypatch.setattr(
        bridge,
        "require_operational_authorization",
        lambda *_a: (_ for _ in ()).throw(RuntimeError("missing current core authorization")),
    )
    monkeypatch.setattr(
        bridge, "_event_worker", lambda *_a: pytest.fail("unauthorized must not create turn")
    )
    monkeypatch.setattr(
        bridge.sys,
        "argv",
        [
            "bridge",
            "--runtime-root",
            str(tmp_path),
            "nanobot-event-worker",
            "--request",
            str(args.request),
            "--receipt",
            str(args.receipt),
        ],
    )
    assert bridge.main() == 2
    assert "missing current core authorization" in capsys.readouterr().out


def test_event_main_cannot_use_a_foreign_ledger_under_current_authorization(
    tmp_path, monkeypatch, capsys
):
    args, _request, _outcome = _bridge_request(tmp_path, monkeypatch)
    monkeypatch.setattr(bridge, "bind_runtime", lambda *_a: None)
    monkeypatch.setattr(bridge, "bind_verified_release", lambda *_a: None)
    monkeypatch.setattr(
        bridge, "require_operational_authorization", lambda *_a: {"state": "ACTIVE"}
    )
    monkeypatch.setattr(bridge, "runtime_ledger_path", lambda *_a: tmp_path / "current.db")
    monkeypatch.setattr(
        bridge, "_event_worker", lambda *_a: pytest.fail("foreign ledger must not reach sender")
    )
    monkeypatch.setattr(
        bridge.sys,
        "argv",
        [
            "bridge",
            "--runtime-root",
            str(tmp_path),
            "--ledger",
            str(tmp_path / "foreign.db"),
            "nanobot-event-worker",
            "--request",
            str(args.request),
            "--receipt",
            str(args.receipt),
        ],
    )
    assert bridge.main() == 2
    assert "ledger must be the runtime ledger" in capsys.readouterr().out


def test_event_sender_rejects_a_foreign_resumed_thread(tmp_path, monkeypatch):
    args, _request, _outcome = _bridge_request(tmp_path, monkeypatch)
    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), poll=lambda: 0)

    class Selector:
        def register(self, *_a):
            pass

        def close(self):
            pass

    monkeypatch.setattr(bridge.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(bridge.shutil, "which", lambda _: "codex-test-boundary")
    monkeypatch.setattr(bridge, "ledger", lambda _: object())

    @contextmanager
    def session(*_a, **_kw):
        yield process

    monkeypatch.setattr(bridge, "_app_server_action_session", session)
    monkeypatch.setattr(
        bridge,
        "_read_app_server_response",
        lambda *_a, **_kw: (b"", {"result": {"thread": {"id": "foreign"}}}),
    )
    with pytest.raises(RuntimeError, match="foreign thread"):
        bridge._event_worker(args)
    assert b'"method": "turn/start"' not in process.stdin.getvalue()


@pytest.mark.parametrize("namespace", ["agentscope", "nanobot"])
def test_installer_needs_verified_release_and_current_auth_before_loading(
    tmp_path, monkeypatch, namespace
):
    path = Path(__file__).parents[1] / "scripts" / f"install_{namespace}_event_worker.py"
    spec = importlib.util.spec_from_file_location(f"install_{namespace}_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module,
        "require_operational_authorization",
        lambda *_a: (_ for _ in ()).throw(RuntimeError("no main authorization")),
    )
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_a, **_kw: pytest.fail("authorization must precede launchctl"),
    )
    with pytest.raises(RuntimeError, match="no main authorization"):
        module.install(tmp_path / "runtime", code_root=tmp_path / "release", home=tmp_path / "home")
    assert not (tmp_path / "home").exists()
    python = tmp_path / "runtime" / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("runtime boundary")
    monkeypatch.setattr(
        module,
        "bind_verified_release",
        lambda *_a: (_ for _ in ()).throw(RuntimeError("invalid event release")),
    )
    with pytest.raises(RuntimeError, match="invalid event release"):
        module.spec(tmp_path / "runtime", code_root=tmp_path / "release", home=tmp_path / "home")


def test_nanobot_bootstrap_watermark_is_isolated_and_post_boundary_dispatches_once(
    tmp_path, monkeypatch
):
    worker = _worker("nanobot")
    lane = nanobot_events.EventLane(tmp_path / "state" / "nanobot-events.sqlite3")
    seed = tmp_path / "state" / "nanobot-public-work.json"
    seed.write_text(json.dumps({"baselineThrough": "2026-10-13T10:00:00Z", "items": []}))
    delivered = []
    events = [
        dict(
            _event("HKUDS/nanobot", event_id="github:HKUDS/nanobot:1:issue_update:old"),
            updatedAt="2026-10-13T09:59:59Z",
        ),
        dict(
            _event("HKUDS/nanobot", 2, "github:HKUDS/nanobot:2:issue_update:new"),
            updatedAt="2026-10-13T10:00:01Z",
        ),
    ]
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self, **_kw: worker.PollResult("ok", events=tuple(events)),
    )
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "full_reconcile",
        lambda *_a, **_kw: worker.PollResult("not_modified"),
    )
    first = worker.run_once(
        tmp_path, deliver=delivered.append, now=datetime(2026, 10, 13, 10, 1, tzinfo=UTC)
    )
    second = worker.run_once(
        tmp_path, deliver=delivered.append, now=datetime(2026, 10, 13, 10, 2, tzinfo=UTC)
    )
    assert first["bootstrapTerminalized"] == 1
    assert [event["eventId"] for event in delivered] == [events[1]["eventId"]]
    assert second["codexWake"] is False
    assert not (tmp_path / "state" / "agentscope-events.sqlite3").exists()
    assert (
        lane.state_value(worker.BOOTSTRAP_BOUNDARY_STATE_KEY)["baselineThrough"]
        == "2026-10-13T10:00:00Z"
    )
    seed.write_text(json.dumps({"baselineThrough": "2026-10-13T10:00:02Z", "items": []}))
    with pytest.raises(RuntimeError, match="baselineThrough changed after bootstrap"):
        worker.run_once(tmp_path, deliver=delivered.append)


@pytest.mark.parametrize("namespace,repo,module", LANES)
def test_seed_record_conflicting_repo_key_or_url_never_enters_lane(
    tmp_path, namespace, repo, module
):
    worker = _worker(namespace)
    reader = getattr(worker, f"_is_{namespace}_record")
    assert reader({"repo": repo, "key": f"{repo}#1"})
    assert not reader({"repo": "foreign/repo", "key": f"{repo}#1"})
    assert not reader({"repo": repo, "key": "foreign/repo#1"})
    assert not reader({"repo": repo, "issueUrl": "https://github.com/foreign/repo/issues/1"})


@pytest.mark.parametrize("namespace,repo,module", LANES)
@pytest.mark.parametrize("invalid", ["future-start", "naive-start", "naive-until"])
def test_design_wait_is_timezone_bound_and_cannot_defer_into_the_future(
    tmp_path, monkeypatch, namespace, repo, module, invalid
):
    now = datetime.now(UTC)
    started, until = now - timedelta(seconds=1), now + timedelta(hours=23)
    path = tmp_path / "outcome.json"
    base = {
        "schemaVersion": f"{namespace}_event_outcome_v1",
        "eventId": "event",
        "publicKey": f"{repo}#1",
        "state": "design_wait",
        "waitStartedAt": started.isoformat(),
        "waitUntil": until.isoformat(),
    }
    lane = module.EventLane(tmp_path / "events.db")
    worker = _worker(namespace)
    assert worker._valid_machine_outcome("event", f"{repo}#1", base)
    assert lane._valid_outcome_receipt(
        {"turnStatus": "completed", "outcome": base}, "event", f"{repo}#1"
    )
    path.write_text(json.dumps(base))
    assert (
        bridge._validated_event_outcome(
            path,
            allowed_dir=tmp_path,
            event_id="event",
            public_key=f"{repo}#1",
            namespace=namespace,
        )
        == base
    )
    changed = dict(base)
    if invalid == "future-start":
        changed.update(
            waitStartedAt=(now + timedelta(days=2)).isoformat(),
            waitUntil=(now + timedelta(days=2, hours=23)).isoformat(),
        )
    elif invalid == "naive-start":
        changed["waitStartedAt"] = started.replace(tzinfo=None).isoformat()
    else:
        changed["waitUntil"] = until.replace(tzinfo=None).isoformat()
    path.write_text(json.dumps(changed))
    assert not worker._valid_machine_outcome("event", f"{repo}#1", changed)
    assert not lane._valid_outcome_receipt(
        {"turnStatus": "completed", "outcome": changed}, "event", f"{repo}#1"
    )
    assert bridge._validated_event_outcome(
        path, allowed_dir=tmp_path, event_id="event", public_key=f"{repo}#1", namespace=namespace
    ) == {"error": "OUTCOME_WAIT_INVALID"}
