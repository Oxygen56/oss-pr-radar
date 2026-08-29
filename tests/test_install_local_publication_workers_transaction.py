from __future__ import annotations

import importlib.util
import json
import os
import plistlib
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from oss_pr_radar.local_publication import slow_advance_once

SCRIPT = Path(__file__).parents[1] / "scripts" / "install_local_publication_workers.py"
sys.path.insert(0, str(SCRIPT.parent))
module_spec = importlib.util.spec_from_file_location("install_workers_transaction", SCRIPT)
assert module_spec and module_spec.loader
INSTALL = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = INSTALL
module_spec.loader.exec_module(INSTALL)


class FakeLaunchctl:
    def __init__(
        self,
        domain: str,
        loaded: set[str],
        failure: str | None = None,
        failure_at: int = 2,
        bootout_failures: set[str] | None = None,
        print_outputs: dict[str, str] | None = None,
    ) -> None:
        self.domain = domain
        self.loaded = set(loaded)
        self.failure = failure
        self.failure_at = failure_at
        self.bootout_failures = bootout_failures or set()
        self.print_outputs = print_outputs or {}
        self.counts = {"bootstrap": 0, "kickstart": 0}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        self.calls.append(arguments)
        command = arguments[0]
        if command == "print":
            return subprocess.CompletedProcess(
                ["launchctl", *arguments],
                0 if arguments[1] in self.loaded else 113,
                self.print_outputs.get(arguments[1], ""),
                "",
            )
        if command == "bootout":
            if arguments[1] in self.bootout_failures:
                return subprocess.CompletedProcess(["launchctl", *arguments], 1, "", "failed")
            self.loaded.discard(arguments[1])
            return subprocess.CompletedProcess(["launchctl", *arguments], 0, "", "")
        if command == "bootstrap":
            self.counts[command] += 1
            if self.failure == command and self.counts[command] == self.failure_at:
                return subprocess.CompletedProcess(["launchctl", *arguments], 1, "", "failed")
            path = Path(arguments[2])
            self.loaded.add(f"{arguments[1]}/{path.stem}")
            return subprocess.CompletedProcess(["launchctl", *arguments], 0, "", "")
        if command == "kickstart":
            self.counts[command] += 1
            if self.failure == command and self.counts[command] == self.failure_at:
                return subprocess.CompletedProcess(["launchctl", *arguments], 1, "", "failed")
            self.loaded.add(arguments[2])
            return subprocess.CompletedProcess(["launchctl", *arguments], 0, "", "")
        raise AssertionError(f"unexpected launchctl command: {arguments}")


def specs(tmp_path: Path) -> list[dict[str, object]]:
    labels = (
        "com.oss-pr-radar.local-publication",
        "com.oss-pr-radar.local-publication-slow",
        "com.oss-pr-radar.queue-importer",
    )
    return [
        {
            "Label": label,
            "ProgramArguments": ["/usr/bin/env", label],
            "WorkingDirectory": str(tmp_path),
            "RunAtLoad": True,
            "StartInterval": 60,
            "StandardOutPath": str(tmp_path / "logs" / f"{index}.out"),
            "StandardErrorPath": str(tmp_path / "logs" / f"{index}.err"),
        }
        for index, label in enumerate(labels)
    ]


def plist_path(home: Path, label: str) -> Path:
    return home / "Library" / "LaunchAgents" / f"{label}.plist"


@pytest.mark.parametrize("failure", ["bootstrap", "kickstart"])
def test_second_worker_failure_restores_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    fast = plist_path(home, str(worker_specs[0]["Label"]))
    slow = plist_path(home, str(worker_specs[1]["Label"]))
    fast_before = plistlib.dumps({"old": "fast"}, fmt=plistlib.FMT_XML)
    slow_before = plistlib.dumps({"old": "slow"}, fmt=plistlib.FMT_XML)
    fast.write_bytes(fast_before)
    slow.write_bytes(slow_before)
    os.chmod(fast, 0o640)
    os.chmod(slow, 0o604)

    domain = "gui/4242"
    fast_service = f"{domain}/{worker_specs[0]['Label']}"
    fake = FakeLaunchctl(domain, {fast_service}, failure=failure)
    monkeypatch.setattr(INSTALL, "launchctl", fake)

    with pytest.raises(RuntimeError, match="rolled back"):
        INSTALL.install_workers(worker_specs, home=home, domain=domain)

    assert fast.read_bytes() == fast_before
    assert slow.read_bytes() == slow_before
    assert fast.stat().st_mode & 0o777 == 0o640
    assert slow.stat().st_mode & 0o777 == 0o604
    assert not plist_path(home, str(worker_specs[2]["Label"])).exists()
    assert fake.loaded == {fast_service}
    assert not list(launch_dir.glob(".*.tmp"))


def test_success_installs_and_loads_all_three_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    existing = plist_path(home, str(worker_specs[0]["Label"]))
    existing.write_bytes(plistlib.dumps({"old": True}, fmt=plistlib.FMT_XML))
    os.chmod(existing, 0o640)

    domain = "gui/4242"
    fake = FakeLaunchctl(domain, set())
    monkeypatch.setattr(INSTALL, "launchctl", fake)

    result = INSTALL.install_workers(worker_specs, home=home, domain=domain)

    assert result["ok"] is True
    assert len(result["workers"]) == 3
    assert fake.loaded == {f"{domain}/{spec['Label']}" for spec in worker_specs}
    for spec in worker_specs:
        path = plist_path(home, str(spec["Label"]))
        assert plistlib.loads(path.read_bytes()) == spec
    assert existing.stat().st_mode & 0o777 == 0o640
    assert not list(launch_dir.glob(".*.tmp"))


def _write_staged_plists(home: Path, worker_specs: list[dict[str, object]]) -> None:
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True, exist_ok=True)
    for spec in worker_specs:
        path = plist_path(home, str(spec["Label"]))
        path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML))
        path.chmod(0o600)


@pytest.mark.parametrize("failure", [None, "kickstart"])
def test_first_activation_promotes_auth_before_bootstrap_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot",
        lambda _root: {
            "level": "ok",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.5,
        },
    )
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    home = tmp_path / "home"
    worker_specs = specs(tmp_path)
    _write_staged_plists(home, worker_specs)
    domain = "gui/4242"
    fake = FakeLaunchctl(domain, set(), failure=failure, failure_at=1)
    authorization = {
        "state": "STAGED",
        "workerConfigDigest": INSTALL.worker_spec_digest(worker_specs),
    }
    events: list[str] = []

    def slow_runner(_root: Path, operation: str) -> dict[str, object]:
        assert authorization["state"] == "ACTIVE"
        return {
            "ok": True,
            "errors": [],
            "updated": [],
            "ingested": [],
            "publicationRequests": [],
            "validationDeferred": [],
            "published": [],
            "pending": [],
            "blocked": [],
            "renamed": [],
            "archived": [],
            "candidates": [],
            "unresolved": [],
            "reconciled": [],
            "recoverable": [],
            "action": "none",
            "operation": operation,
        }

    def observed_launchctl(*arguments: str, check: bool = True):
        if arguments[0] in {"bootstrap", "kickstart"}:
            assert authorization["state"] == "ACTIVE"
            events.append(arguments[0])
        if arguments[0] == "kickstart" and arguments[2].endswith(
            "com.oss-pr-radar.local-publication-slow"
        ):
            # The first slow-worker action is reproduction-probe.  It must
            # observe ACTIVE auth, never the consumed STAGED proof.
            events.append("reproduction-probe")
            assert authorization["state"] == "ACTIVE"
            if failure is None:
                assert slow_advance_once(runtime, runner=slow_runner)["ok"] is True
        return fake(*arguments, check=check)

    def finalize(_runtime: Path):
        events.append("finalize")
        authorization["state"] = "ACTIVE"
        return authorization

    monkeypatch.setattr(INSTALL, "launchctl", observed_launchctl)
    monkeypatch.setattr(INSTALL, "_launchctl_config_matches", lambda *_args: True)
    monkeypatch.setattr(
        INSTALL,
        "require_operational_authorization",
        lambda *_args, **_kwargs: authorization,
    )
    monkeypatch.setattr(INSTALL, "finalize_operational_authorization", finalize)
    revoked: list[Path] = []
    monkeypatch.setattr(INSTALL, "revoke_operational_authorization", revoked.append)

    if failure is None:
        result = INSTALL.activate_staged_workers(
            worker_specs,
            home=home,
            domain=domain,
            runtime_root=runtime,
            require_stage_receipt=True,
        )
        assert result["ok"] is True
        assert events[0] == "finalize"
        assert events.index("finalize") < events.index("reproduction-probe")
        assert revoked == []
    else:
        with pytest.raises(RuntimeError, match="rolled back"):
            INSTALL.activate_staged_workers(
                worker_specs,
                home=home,
                domain=domain,
                runtime_root=runtime,
                require_stage_receipt=True,
            )
        assert events[0] == "finalize"
        assert revoked == [runtime]
        assert fake.loaded == set()


def test_first_worker_failure_does_not_touch_later_loaded_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    before: dict[Path, bytes] = {}
    for index, spec in enumerate(worker_specs):
        path = plist_path(home, str(spec["Label"]))
        before[path] = plistlib.dumps({"old": index}, fmt=plistlib.FMT_XML)
        path.write_bytes(before[path])
        os.chmod(path, 0o640 + index)

    domain = "gui/4242"
    services = [f"{domain}/{spec['Label']}" for spec in worker_specs]
    fake = FakeLaunchctl(domain, set(services[1:]), failure="bootstrap", failure_at=1)
    monkeypatch.setattr(INSTALL, "launchctl", fake)

    with pytest.raises(RuntimeError, match="rolled back"):
        INSTALL.install_workers(worker_specs, home=home, domain=domain)

    assert {path: path.read_bytes() for path in before} == before
    assert {path: path.stat().st_mode & 0o777 for path in before} == {
        path: 0o640 + index for index, path in enumerate(before)
    }
    assert fake.loaded == set(services[1:])
    assert [call[0] for call in fake.calls] == [
        "print",
        "print",
        "print",
        "bootstrap",
        "bootout",
        "print",
    ]
    assert not any(
        call[0] in {"bootout", "kickstart"} and call[1] in set(services[1:]) for call in fake.calls
    )
    assert not any(
        call[0] == "bootstrap" and str(plist_path(home, str(spec["Label"]))) in call
        for spec in worker_specs[1:]
        for call in fake.calls
    )
    assert not list(launch_dir.glob(".*.tmp"))


def test_uninstall_keeps_plist_when_bootout_leaves_service_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    for spec in worker_specs:
        plist_path(home, str(spec["Label"])).write_bytes(b"keep-or-remove")

    domain = "gui/4242"
    services = [f"{domain}/{spec['Label']}" for spec in worker_specs]
    fake = FakeLaunchctl(domain, set(services), bootout_failures={services[0]})
    monkeypatch.setattr(INSTALL, "launchctl", fake)

    result = INSTALL.uninstall_workers(worker_specs, home=home, domain=domain)

    assert result["ok"] is False
    assert plist_path(home, str(worker_specs[0]["Label"])).exists()
    assert not plist_path(home, str(worker_specs[1]["Label"])).exists()
    assert not plist_path(home, str(worker_specs[2]["Label"])).exists()
    assert fake.loaded == {services[0]}
    assert not list(launch_dir.glob(".*.tmp"))


def test_uninstall_requires_runtime_binding_and_authorization_before_launchctl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    labels = tuple(spec["Label"] for spec in specs(tmp_path))
    for label in labels:
        plist_path(home, str(label)).write_bytes(b"remove-me")

    domain = f"gui/{os.getuid()}"
    services = {f"{domain}/{label}" for label in labels}
    fake = FakeLaunchctl(domain, services)
    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_local_publication_workers.py", "--uninstall"],
    )

    assert INSTALL.main() == 1
    assert all(plist_path(home, str(label)).read_bytes() == b"remove-me" for label in labels)
    assert fake.loaded == services


@pytest.mark.parametrize("mode", ["--stage", "--uninstall"])
def test_worker_write_modes_require_authorization_before_any_launchctl_or_plist_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    fake = FakeLaunchctl(f"gui/{os.getuid()}", set())
    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r1"},
    )
    if mode == "--stage":
        monkeypatch.setattr(
            INSTALL,
            "require_worker_staging_authorization",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("missing staging authorization")
            ),
        )
    else:
        monkeypatch.setattr(
            INSTALL,
            "require_operational_authorization",
            lambda _root: (_ for _ in ()).throw(RuntimeError("missing authorization")),
        )
    monkeypatch.setattr(
        INSTALL,
        "worker_specs",
        lambda *_args, **_kwargs: specs(tmp_path),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_local_publication_workers.py", "--runtime-root", str(tmp_path), mode],
    )

    assert INSTALL.main() == 1
    assert fake.calls == []
    assert not list((home / "Library" / "LaunchAgents").glob("*.plist"))


def test_authorized_stage_uses_only_the_three_current_worker_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, list[str]]] = []
    worker_specs_value = specs(tmp_path)
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r1"},
    )
    monkeypatch.setattr(
        INSTALL, "require_worker_staging_authorization", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        INSTALL,
        "consume_worker_staging_authorization",
        lambda *_args, **_kwargs: {
            "schema": "receipt",
            "state": "CONSUMED",
            "workerSpecDigest": "test",
        },
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: worker_specs_value)
    monkeypatch.setattr(
        INSTALL,
        "launchctl",
        lambda *arguments, check=True: subprocess.CompletedProcess(
            ["launchctl", *arguments],
            113 if arguments and arguments[0] == "print" else 0,
            "",
            "",
        ),
    )
    monkeypatch.setattr(
        INSTALL,
        "stage_workers",
        lambda worker_specs, **_kwargs: (
            calls.append(("stage", [str(spec["Label"]) for spec in worker_specs]))
            or {"ok": True, "staged": True}
        ),
    )
    monkeypatch.setattr(INSTALL, "_staging_records", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_local_publication_workers.py", "--runtime-root", str(tmp_path), "--stage"],
    )

    assert INSTALL.main() == 0
    assert calls == [
        (
            "stage",
            [
                "com.oss-pr-radar.local-publication",
                "com.oss-pr-radar.local-publication-slow",
                "com.oss-pr-radar.queue-importer",
            ],
        )
    ]


def test_worker_installer_rejects_tampered_or_missing_release_before_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": False, "error": "release manifest tampered"},
    )
    monkeypatch.setattr(
        INSTALL,
        "require_operational_authorization",
        lambda _root: pytest.fail("authorization must not run for a bad release"),
    )
    monkeypatch.setattr(
        INSTALL, "launchctl", lambda *_args, **_kwargs: pytest.fail("must fail closed")
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_local_publication_workers.py", "--runtime-root", str(tmp_path), "--stage"],
    )

    assert INSTALL.main() == 1


def test_worker_status_is_read_only_and_requires_only_runtime_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = specs(tmp_path)[0]
    monkeypatch.setattr(
        INSTALL,
        "launchctl",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 113, "", "not loaded"),
    )
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "releaseId": "r1", "policyDigest": "p1"},
    )
    monkeypatch.setattr(
        INSTALL,
        "disk_snapshot",
        lambda _root: {
            "level": "ok",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.5,
        },
    )
    monkeypatch.setattr(INSTALL, "pending_publication_effects", lambda _path: 0)
    monkeypatch.setattr(
        INSTALL,
        "pid_probe",
        lambda *_args, **_kwargs: {"alive": False, "versionMatched": True},
    )

    result = INSTALL.service_status(
        f"gui/{os.getuid()}/{expected['Label']}",
        plist_path(tmp_path / "home", str(expected["Label"])),
        expected,
    )

    assert result["installed"] is False
    assert not (tmp_path / "state").exists()


def test_worker_status_uses_complete_runtime_state_without_cross_worker_false_alarms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    worker_specs = specs(tmp_path)
    _write_staged_plists(home, worker_specs)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    now = time.time()
    (state_dir / "runtime-health.json").write_text(
        json.dumps(
            {
                "workers": {
                    "fast": {
                        "lastSuccessAt": now - 10,
                        "lastExitCode": 0,
                        "consecutiveFailures": 0,
                    },
                    "slow": {
                        "lastSuccessAt": now - 10,
                        "lastExitCode": 0,
                        "consecutiveFailures": 0,
                    },
                    "queue-importer": {
                        "queueImportSuccessAt": now - 10,
                        "queueLastExitCode": 0,
                        "queueConsecutiveFailures": 0,
                    },
                },
                "deployment": {
                    "manifestVerified": True,
                    "deploymentDirty": False,
                    "releaseVersion": "r1",
                    "policyDigest": "p1",
                    "pendingPublicationEffects": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "slow-worker-backoff.json").write_text(
        json.dumps(
            {
                "failureCount": 1,
                "nextAttemptAt": now + 60,
                "inFlight": False,
            }
        ),
        encoding="utf-8",
    )
    domain = "gui/4242"
    services = {f"{domain}/{spec['Label']}" for spec in worker_specs}
    outputs = {service: "runs = 1\nlast exit code = 0\n" for service in services}
    monkeypatch.setattr(
        INSTALL, "launchctl", FakeLaunchctl(domain, services, print_outputs=outputs)
    )
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "releaseId": "r1", "policyDigest": "p1"},
    )
    monkeypatch.setattr(
        INSTALL,
        "disk_snapshot",
        lambda _root: {
            "level": "ok",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.5,
        },
    )
    monkeypatch.setattr(INSTALL, "pending_publication_effects", lambda _path: 0)
    monkeypatch.setattr(
        INSTALL,
        "pid_probe",
        lambda *_args, **_kwargs: {"alive": False, "versionMatched": True},
    )

    statuses = [
        INSTALL.service_status(
            f"{domain}/{spec['Label']}",
            plist_path(home, str(spec["Label"])),
            spec,
        )
        for spec in worker_specs
    ]

    assert [status["ok"] for status in statuses] == [True, False, True]
    assert statuses[0]["runtimeHealth"]["healthy"] is False
    assert statuses[0]["workerRuntimeHealth"]["healthy"] is True
    assert statuses[1]["workerRuntimeHealth"]["lastExitCode"] == 1


def test_worker_status_reports_disk_warning_without_failing_loaded_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    worker_specs = specs(tmp_path)
    _write_staged_plists(home, worker_specs)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    now = time.time()
    (state_dir / "runtime-health.json").write_text(
        json.dumps(
            {
                "workers": {
                    "fast": {
                        "lastSuccessAt": now - 10,
                        "lastExitCode": 0,
                        "consecutiveFailures": 0,
                    },
                    "slow": {
                        "lastSuccessAt": now - 10,
                        "lastExitCode": 0,
                        "consecutiveFailures": 0,
                    },
                    "queue-importer": {
                        "queueImportSuccessAt": now - 10,
                        "queueLastExitCode": 0,
                        "queueConsecutiveFailures": 0,
                    },
                },
                "deployment": {
                    "manifestVerified": True,
                    "deploymentDirty": False,
                    "releaseVersion": "r1",
                    "policyDigest": "p1",
                    "pendingPublicationEffects": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    (state_dir / "slow-worker-backoff.json").write_text("{}\n", encoding="utf-8")
    domain = "gui/4242"
    services = {f"{domain}/{spec['Label']}" for spec in worker_specs}
    outputs = {service: "runs = 1\nlast exit code = 0\n" for service in services}
    monkeypatch.setattr(
        INSTALL, "launchctl", FakeLaunchctl(domain, services, print_outputs=outputs)
    )
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "releaseId": "r1", "policyDigest": "p1"},
    )
    monkeypatch.setattr(
        INSTALL,
        "disk_snapshot",
        lambda _root: {
            "level": "warning",
            "freeBytes": 50 * 1024 * 1024 * 1024,
            "usedFraction": 0.93,
        },
    )
    monkeypatch.setattr(INSTALL, "pending_publication_effects", lambda _path: 0)
    monkeypatch.setattr(
        INSTALL,
        "pid_probe",
        lambda *_args, **_kwargs: {"alive": False, "versionMatched": True},
    )

    statuses = [
        INSTALL.service_status(
            f"{domain}/{spec['Label']}",
            plist_path(home, str(spec["Label"])),
            spec,
        )
        for spec in worker_specs
    ]

    assert [status["ok"] for status in statuses] == [True, True, True]
    assert statuses[0]["runtimeHealth"]["healthy"] is True
    assert statuses[0]["runtimeHealth"]["issues"] == []
    assert statuses[0]["runtimeHealth"]["warnings"] == ["DISK_WARNING_THRESHOLD"]


def test_status_top_level_ok_aggregates_worker_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    worker_specs = specs(tmp_path)
    worker_health = {
        str(worker_specs[0]["Label"]): True,
        str(worker_specs[1]["Label"]): False,
        str(worker_specs[2]["Label"]): True,
    }
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {
            "valid": True,
            "path": str(tmp_path / "release"),
            "releaseId": "r1",
        },
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: worker_specs)
    gate_reads = 0
    gate_health = {
        "ok": False,
        "blocked": True,
        "reason": "DISK_STOP_THRESHOLD",
        "active": True,
        "gateActive": True,
        "restartSafe": True,
        "snapshot": {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
        },
    }

    def read_gate_once(*_args, **_kwargs):
        nonlocal gate_reads
        gate_reads += 1
        return dict(gate_health)

    monkeypatch.setattr(INSTALL, "read_disk_pressure_gate_health", read_gate_once)
    monkeypatch.setattr(
        INSTALL,
        "service_status",
        lambda _service, _plist_path, expected, **_kwargs: {
            "ok": worker_health[str(expected["Label"])],
            "installed": True,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "install_local_publication_workers.py",
            "--runtime-root",
            str(tmp_path),
            "--status",
        ],
    )

    assert INSTALL.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["diskPressureGate"] == gate_health
    assert gate_reads == 1
    assert [worker["ok"] for worker in result["workers"]] == [True, False, True]


def test_legacy_installer_is_only_a_compatibility_forwarder():
    legacy = SCRIPT.parent / "install_local_publication_agent.py"
    text = legacy.read_text(encoding="utf-8")
    assert "launchctl" not in text
    assert "com.oss-pr-radar.local-publication" not in text
    assert "install_local_publication_workers" in text


def test_legacy_installer_help_has_no_bypass_option():
    legacy = SCRIPT.parent / "install_local_publication_agent.py"
    completed = subprocess.run(
        [sys.executable, str(legacy), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "skip-auth" not in completed.stdout
    assert "allow-unreleased-code" not in completed.stdout


def test_legacy_installer_without_runtime_cannot_start_any_service():
    legacy = SCRIPT.parent / "install_local_publication_agent.py"
    completed = subprocess.run(
        [sys.executable, str(legacy), "--uninstall"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "runtime-root" in completed.stdout


def test_stage_rejects_loaded_worker_before_writing_any_plist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    domain = "gui/4242"
    worker_specs = specs(tmp_path)
    loaded = {f"{domain}/{worker_specs[0]['Label']}"}
    monkeypatch.setattr(INSTALL, "launchctl", FakeLaunchctl(domain, loaded))

    with pytest.raises(RuntimeError, match="refuses to unload"):
        INSTALL.stage_workers(worker_specs, home=home, domain=domain)
    assert not list((home / "Library" / "LaunchAgents").glob("*.plist"))


def _previous_release_specs(tmp_path: Path) -> list[dict[str, object]]:
    previous = []
    for spec in specs(tmp_path):
        old = dict(spec)
        old["ProgramArguments"] = ["/old/immutable-release/worker", str(spec["Label"])]
        previous.append(old)
    return previous


def test_stage_workers_default_rejects_complete_unloaded_previous_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    current = specs(tmp_path)
    previous = _previous_release_specs(tmp_path)
    _write_staged_plists(home, previous)
    before = {
        str(spec["Label"]): plist_path(home, str(spec["Label"])).read_bytes() for spec in previous
    }
    domain = "gui/4242"
    monkeypatch.setattr(INSTALL, "launchctl", FakeLaunchctl(domain, set()))

    with pytest.raises(RuntimeError, match="conflicting staged worker configuration"):
        INSTALL.stage_workers(current, home=home, domain=domain)

    assert all(plist_path(home, label).read_bytes() == raw for label, raw in before.items())


def test_authorized_stage_replaces_complete_unloaded_previous_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    home = tmp_path / "home"
    current = specs(tmp_path)
    _write_staged_plists(home, _previous_release_specs(tmp_path))
    domain = f"gui/{os.getuid()}"
    fake = FakeLaunchctl(domain, set())
    authorization_checks: list[bool] = []

    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r2"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: current)
    monkeypatch.setattr(
        INSTALL,
        "require_worker_staging_authorization",
        lambda *_args, **_kwargs: authorization_checks.append(True),
    )

    def consume(*_args, worker_records, **_kwargs):
        assert len(worker_records) == 3
        assert all(
            plistlib.loads(plist_path(home, str(spec["Label"])).read_bytes()) == spec
            for spec in current
        )
        return {
            "schema": "receipt",
            "state": "CONSUMED",
            "workerSpecDigest": INSTALL.worker_spec_digest(current),
        }

    monkeypatch.setattr(INSTALL, "consume_worker_staging_authorization", consume)
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    assert INSTALL.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["changed"] is True
    assert authorization_checks == [True]
    assert all(
        plistlib.loads(plist_path(home, str(spec["Label"])).read_bytes()) == spec
        for spec in current
    )


@pytest.mark.parametrize("existing", ["loaded", "partial", "unsafe-mode"])
def test_authorized_stage_does_not_expand_recovery_beyond_complete_unloaded_configs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    existing: str,
) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    home = tmp_path / "home"
    current = specs(tmp_path)
    previous = _previous_release_specs(tmp_path)
    if existing == "partial":
        _write_staged_plists(home, previous[:2])
    else:
        _write_staged_plists(home, previous)
    if existing == "unsafe-mode":
        plist_path(home, str(previous[0]["Label"])).chmod(0o644)
    before = {
        path.name: (path.read_bytes(), path.stat().st_mode & 0o777)
        for path in (home / "Library" / "LaunchAgents").glob("*.plist")
    }
    domain = f"gui/{os.getuid()}"
    loaded = {f"{domain}/{current[0]['Label']}"} if existing == "loaded" else set()
    fake = FakeLaunchctl(domain, loaded)
    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r2"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: current)
    monkeypatch.setattr(
        INSTALL, "require_worker_staging_authorization", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        INSTALL,
        "consume_worker_staging_authorization",
        lambda *_args, **_kwargs: pytest.fail("invalid recovery must not consume authorization"),
    )
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    assert INSTALL.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert "refuse" in result["error"]
    after = {
        path.name: (path.read_bytes(), path.stat().st_mode & 0o777)
        for path in (home / "Library" / "LaunchAgents").glob("*.plist")
    }
    assert after == before


def test_existing_receipt_never_allows_conflicting_worker_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    receipt = INSTALL.staged_worker_receipt_path(runtime)
    receipt.write_text("existing durable receipt\n", encoding="utf-8")
    home = tmp_path / "home"
    current = specs(tmp_path)
    previous = _previous_release_specs(tmp_path)
    _write_staged_plists(home, previous)
    before = {
        str(spec["Label"]): plist_path(home, str(spec["Label"])).read_bytes() for spec in previous
    }
    domain = f"gui/{os.getuid()}"
    monkeypatch.setattr(INSTALL, "launchctl", FakeLaunchctl(domain, set()))
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r2"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: current)
    monkeypatch.setattr(
        INSTALL,
        "require_worker_staging_authorization",
        lambda *_args, **_kwargs: pytest.fail("receipt recovery must not issue a new permit"),
    )
    monkeypatch.setattr(
        INSTALL,
        "consume_worker_staging_authorization",
        lambda *_args, **_kwargs: pytest.fail("conflicting files must fail before receipt read"),
    )
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    assert INSTALL.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert "conflicting staged worker configuration" in result["error"]
    assert all(plist_path(home, label).read_bytes() == raw for label, raw in before.items())


def test_authorized_previous_release_replacement_rolls_back_if_receipt_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    home = tmp_path / "home"
    current = specs(tmp_path)
    previous = _previous_release_specs(tmp_path)
    _write_staged_plists(home, previous)
    before = {
        str(spec["Label"]): plist_path(home, str(spec["Label"])).read_bytes() for spec in previous
    }
    domain = f"gui/{os.getuid()}"
    monkeypatch.setattr(INSTALL, "launchctl", FakeLaunchctl(domain, set()))
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r2"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: current)
    monkeypatch.setattr(
        INSTALL, "require_worker_staging_authorization", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        INSTALL,
        "consume_worker_staging_authorization",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected receipt failure")),
    )
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    assert INSTALL.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert "injected receipt failure" in result["error"]
    assert all(plist_path(home, label).read_bytes() == raw for label, raw in before.items())


def test_stage_receipt_uses_fresh_launchctl_observation_not_hardcoded_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    for spec in worker_specs:
        path = plist_path(home, str(spec["Label"]))
        path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML))
        path.chmod(0o600)
    domain = "gui/4242"
    fake = FakeLaunchctl(domain, set())
    monkeypatch.setattr(INSTALL, "launchctl", fake)

    records = INSTALL._staging_records(worker_specs, home=home, domain=domain)
    assert len(records) == 3
    assert all(item["loaded"] is False and item["pid"] is None for item in records)
    assert all(item["observedAt"].endswith("Z") for item in records)
    assert all(call[0] == "print" for call in fake.calls)


def test_stage_does_not_rewrite_when_full_authorization_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    state = runtime / "state"
    state.mkdir(parents=True)
    authorization = state / "operational-authorization.json"
    authorization.write_bytes(b"signed-full-auth")
    before = authorization.read_bytes()
    home = tmp_path / "home"
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r1"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: specs(tmp_path))
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    assert INSTALL.main() == 1
    assert authorization.read_bytes() == before


def test_stage_transaction_lock_serializes_two_stagers(tmp_path: Path) -> None:
    acquired: list[bool] = []
    release = threading.Event()

    with INSTALL.worker_staging_transaction_lock(tmp_path):

        def contender() -> None:
            with INSTALL.worker_staging_transaction_lock(tmp_path):
                acquired.append(True)
                release.wait(timeout=2)

        thread = threading.Thread(target=contender)
        thread.start()
        time.sleep(0.05)
        assert acquired == []
    thread.join(timeout=2)
    assert acquired == [True]


@pytest.mark.parametrize(
    "loaded_labels,stale_label",
    [
        (("com.oss-pr-radar.local-publication",), None),
        (
            (
                "com.oss-pr-radar.local-publication",
                "com.oss-pr-radar.local-publication-slow",
                "com.oss-pr-radar.queue-importer",
            ),
            None,
        ),
        (
            (
                "com.oss-pr-radar.local-publication",
                "com.oss-pr-radar.local-publication-slow",
                "com.oss-pr-radar.queue-importer",
            ),
            "com.oss-pr-radar.local-publication",
        ),
    ],
)
def test_first_activation_rejects_loaded_launchd_cache_before_finalize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loaded_labels: tuple[str, ...],
    stale_label: str | None,
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    for spec in worker_specs:
        path = plist_path(home, str(spec["Label"]))
        plist = dict(spec)
        if str(spec["Label"]) == stale_label:
            plist["ProgramArguments"] = ["/old/runtime/worker"]
            plist["WorkingDirectory"] = "/old/runtime"
        path.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML))
        path.chmod(0o600)
    domain = f"gui/{os.getuid()}"
    loaded = {f"{domain}/{label}" for label in loaded_labels}
    fake = FakeLaunchctl(domain, loaded)
    auth = {"state": "STAGED", "workerConfigDigest": INSTALL.worker_spec_digest(worker_specs)}
    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(
        INSTALL, "require_operational_authorization", lambda *_args, **_kwargs: auth
    )
    monkeypatch.setattr(
        INSTALL,
        "finalize_operational_authorization",
        lambda *_args, **_kwargs: pytest.fail("a loaded stage must never finalize"),
    )

    with pytest.raises(RuntimeError, match="explicitly unloaded"):
        INSTALL.activate_staged_workers(
            worker_specs,
            home=home,
            domain=domain,
            runtime_root=tmp_path / "runtime",
            require_stage_receipt=True,
        )
    assert auth["state"] == "STAGED"
    assert all(call[0] == "print" for call in fake.calls)


@pytest.mark.parametrize("case", ["correct", "old-command", "old-workdir", "partial-old-cache"])
def test_ensure_requires_exact_loaded_launchd_command_and_workdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    home = tmp_path / "home"
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True)
    worker_specs = specs(tmp_path)
    domain = f"gui/{os.getuid()}"
    services = {f"{domain}/{spec['Label']}" for spec in worker_specs}

    def launch_output(
        spec: dict[str, object], *, command: list[str] | None = None, workdir: str | None = None
    ) -> str:
        arguments = command or [str(value) for value in spec["ProgramArguments"]]
        cwd = workdir or str(spec["WorkingDirectory"])
        lines = ["state = waiting", f"program = {arguments[0]}", "arguments = {"]
        lines.extend(f'  "{value}"' for value in arguments)
        lines.extend(["}", f"working directory = {cwd}", "last exit code = 0"])
        return "\n".join(lines) + "\n"

    outputs = {f"{domain}/{spec['Label']}": launch_output(spec) for spec in worker_specs}
    loaded = services
    if case == "old-command":
        first = worker_specs[0]
        outputs[f"{domain}/{first['Label']}"] = launch_output(
            first, command=["/old/runtime/worker"]
        )
    elif case == "old-workdir":
        first = worker_specs[0]
        outputs[f"{domain}/{first['Label']}"] = launch_output(first, workdir="/old/runtime")
    elif case == "partial-old-cache":
        loaded = {f"{domain}/{worker_specs[0]['Label']}"}
        outputs = {
            f"{domain}/{worker_specs[0]['Label']}": launch_output(
                worker_specs[0], command=["/old/runtime/worker"]
            )
        }
    fake = FakeLaunchctl(domain, loaded, print_outputs=outputs)
    auth = {"state": "ACTIVE", "workerConfigDigest": INSTALL.worker_spec_digest(worker_specs)}
    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(
        INSTALL, "require_operational_authorization", lambda *_args, **_kwargs: auth
    )
    for spec in worker_specs:
        path = plist_path(home, str(spec["Label"]))
        path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML))
        path.chmod(0o600)

    if case == "correct":
        result = INSTALL.ensure_workers(
            worker_specs, home=home, domain=domain, runtime_root=tmp_path / "runtime"
        )
        assert result["changed"] is False
        assert fake.counts == {"bootstrap": 0, "kickstart": 0}
    else:
        with pytest.raises(RuntimeError, match="staged and unloaded"):
            INSTALL.ensure_workers(
                worker_specs, home=home, domain=domain, runtime_root=tmp_path / "runtime"
            )
        assert fake.counts == {"bootstrap": 0, "kickstart": 0}


def test_two_complete_stage_transactions_have_one_receipt_and_one_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    home = tmp_path / "home"
    worker_specs = specs(tmp_path)
    domain = f"gui/{os.getuid()}"
    fake = FakeLaunchctl(domain, set())
    write_calls: list[str] = []
    consume_calls: list[int] = []
    receipt_path = INSTALL.staged_worker_receipt_path(runtime)
    original_write = INSTALL._write_plist_atomically

    def write_plist(path, spec, mode):
        write_calls.append(str(path))
        return original_write(path, spec, mode)

    def consume(*_args, **_kwargs):
        if not receipt_path.exists():
            consume_calls.append(1)
            receipt_path.write_text(
                json.dumps(
                    {
                        "schema": "receipt",
                        "state": "CONSUMED",
                        "workerSpecDigest": INSTALL.worker_spec_digest(worker_specs),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)
        return json.loads(receipt_path.read_text(encoding="utf-8"))

    monkeypatch.setattr(INSTALL, "launchctl", fake)
    monkeypatch.setattr(INSTALL, "_write_plist_atomically", write_plist)
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r1"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: worker_specs)
    monkeypatch.setattr(
        INSTALL, "require_worker_staging_authorization", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(INSTALL, "consume_worker_staging_authorization", consume)
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    results: list[int] = []
    barrier = threading.Barrier(2)

    def run_stage() -> None:
        barrier.wait()
        results.append(INSTALL.main())

    threads = [threading.Thread(target=run_stage) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert results == [0, 0]
    assert len(write_calls) == 3
    assert consume_calls == [1]
    assert receipt_path.exists()
    assert all(
        plist_path(home, str(spec["Label"])).stat().st_mode & 0o777 == 0o600
        for spec in worker_specs
    )


def test_stage_failure_after_plist_writes_removes_only_new_plists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "state").mkdir(parents=True)
    home = tmp_path / "home"
    worker_specs = specs(tmp_path)
    domain = f"gui/{os.getuid()}"
    monkeypatch.setattr(INSTALL.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(
        INSTALL,
        "active_release_evidence",
        lambda _root: {"valid": True, "path": str(tmp_path / "release"), "releaseId": "r1"},
    )
    monkeypatch.setattr(INSTALL, "worker_specs", lambda *_args, **_kwargs: worker_specs)
    monkeypatch.setattr(
        INSTALL, "require_worker_staging_authorization", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        INSTALL,
        "_staging_records",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("injected crash")),
    )
    monkeypatch.setattr(INSTALL, "launchctl", FakeLaunchctl(domain, set()))
    monkeypatch.setattr(sys, "argv", ["installer", "--runtime-root", str(runtime), "--stage"])

    assert INSTALL.main() == 1
    assert not list((home / "Library" / "LaunchAgents").glob("*.plist"))
