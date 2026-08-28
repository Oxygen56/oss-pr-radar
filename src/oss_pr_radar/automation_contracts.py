"""Machine-readable contracts for the two deployed Codex automations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .local_publication import worker_specs
from .release_binding import bind_runtime, runtime_python

HEARTBEAT_AUTOMATION_ID = "oss-pr-radar"
DAILY_WAR_ROOM_AUTOMATION_ID = "daily-github-open-pr-status-review"
HEARTBEAT_KIND = "heartbeat"
DAILY_WAR_ROOM_KIND = "heartbeat"
AUTOMATION_STATUS = "ACTIVE"
HEARTBEAT_RRULE = "FREQ=HOURLY;BYMINUTE=30"
DAILY_WAR_ROOM_RRULE = "FREQ=DAILY;BYHOUR=9;BYMINUTE=0;BYSECOND=0"
HEARTBEAT_TARGET_THREAD_ID = "019f71c3-4f26-7030-b126-25f8cfbac4c4"
DAILY_WAR_ROOM_TARGET_THREAD_ID = "01a03bf2-e310-7f63-8db6-a9ec0a39f4aa"
HEARTBEAT_NAME = "OSS PR Radar 控制器（单会话）"
DAILY_WAR_ROOM_NAME = "Daily GitHub open PR status review"
AUTOMATION_PROMPT_POLICY = "oss-pr-radar.prompt-bound.v1"
CUTOVER_ORDER = (
    "deploy",
    "stopEvidence",
    "bootstrap",
    "liveSnapshot",
    "stage6Verification",
    "stage6Rehearsal",
    "prepare",
    "restoreRehearse",
    "activate",
    "managedCountsEvidence",
    "issueWorkerStagingAuthorization",
    "stageWorkerConfigs",
    "automationActivation",
    "automationSnapshot",
    "strictPreflight",
    "issueOperationalAuthorization",
    "activateWorkers",
    "strictFinalAcceptance",
)


def build_contracts(runtime_root: Path, *, home: Path | None = None) -> dict[str, Any]:
    binding = bind_runtime(runtime_root)
    root = runtime_root.resolve()
    python = str(runtime_python(root))
    code = str(binding.code_root)
    workers = {
        spec["Label"]: {
            "command": spec["ProgramArguments"],
            "workdir": spec["WorkingDirectory"],
            "status": "configured",
        }
        for spec in worker_specs(binding.code_root, home=home or Path.home(), runtime_root=root)
    }
    cutover = code + "/scripts/stage7_cutover.py"
    acceptance = code + "/scripts/stage7_acceptance.py"
    evidence = code + "/scripts/stage7_evidence.py"
    live_states = code + "/scripts/snapshot_managed_pr_states.py"
    rehearsal = code + "/scripts/stage6_compact_rehearsal.py"
    worker_install = code + "/scripts/install_local_publication_workers.py"
    contracts = {
        "schema": "oss-pr-radar.automation-command-contracts.v2",
        "release": {
            "runtimeRoot": str(root),
            "codeRoot": code,
            "releaseId": binding.release_id,
            "manifestSha256": binding.release.get("manifestSha256"),
        },
        "heartbeat": {
            "version": 1,
            "name": HEARTBEAT_NAME,
            "id": HEARTBEAT_AUTOMATION_ID,
            "kind": HEARTBEAT_KIND,
            "status": AUTOMATION_STATUS,
            "rrule": HEARTBEAT_RRULE,
            "targetThreadId": HEARTBEAT_TARGET_THREAD_ID,
            "releaseCommand": [
                python,
                code + "/scripts/controller_cycle.py",
                "--root",
                str(root),
                "--code-root",
                code,
            ],
            "externalActionsOwnedBy": "controller",
            "promptPolicy": AUTOMATION_PROMPT_POLICY,
            "workerEnsureCommand": [
                python,
                worker_install,
                "--runtime-root",
                str(root),
                "--ensure",
            ],
        },
        "dailyWarRoom": {
            "version": 1,
            "name": DAILY_WAR_ROOM_NAME,
            "id": DAILY_WAR_ROOM_AUTOMATION_ID,
            "kind": DAILY_WAR_ROOM_KIND,
            "status": AUTOMATION_STATUS,
            "rrule": DAILY_WAR_ROOM_RRULE,
            "targetThreadId": DAILY_WAR_ROOM_TARGET_THREAD_ID,
            "releaseCommand": [
                python,
                code + "/scripts/daily_war_room_cycle.py",
                "--runtime-root",
                str(root),
                "--send",
            ],
            "sendFlag": "--send",
            "artifactRoot": str(root / "reports" / "war-room" / "daily"),
            "promptPolicy": AUTOMATION_PROMPT_POLICY,
        },
        "workers": workers,
        "cutoverOrder": list(CUTOVER_ORDER),
        "cutoverRequires": {
            step: list(CUTOVER_ORDER[:index]) for index, step in enumerate(CUTOVER_ORDER)
        },
        "stage6": {
            "stage6Verification": {
                "command": [
                    python,
                    code + "/scripts/stage6_manifest.py",
                    "--artifact-root",
                    "<stage6-report-root>",
                    "--verification-out",
                    "<verification-root>/verification-manifest.json",
                    "--run",
                ],
                "workdir": str(root),
                "requires": ["bootstrap"],
                "inputs": ["stage6-report", "stage6-envelope", "verification-manifest"],
            },
            "liveSnapshot": {
                "command": [
                    python,
                    live_states,
                    "--source",
                    "<legacy-ledger-source>",
                    "--legacy-db",
                    "<legacy-war-room-db>",
                    "--legacy-reports",
                    "<legacy-reports-dir>",
                    "--followup",
                    "<followup-snapshot>",
                    "--quiesce-token",
                    "<quiesce-token>",
                    "--out",
                    "<live-states>",
                    "--workers",
                    "<workers>",
                    "--max-attempts",
                    "<max-attempts>",
                ],
                "workdir": str(root),
                "readOnlyExternal": True,
                "outputMode": "atomic_0600",
                "requires": ["bootstrap"],
            },
            "stage6Rehearsal": {
                "command": [
                    python,
                    rehearsal,
                    "--artifact-root",
                    "<stage6-rehearsal-root>",
                    "--verification-manifest",
                    "<verification-root>/verification-manifest.json",
                    "--source",
                    "<managed-ledger-source>",
                    "--legacy-db",
                    "<legacy-war-room-db>",
                    "--legacy-reports",
                    "<legacy-reports-dir>",
                    "--followup",
                    "<followup-snapshot>",
                    "--live-states",
                    "<live-states>",
                    "--code-head",
                    str(binding.release.get("commit")),
                    "--observed-at",
                    "<snapshot-observed-at>",
                ],
                "workdir": str(root),
                "requires": ["stage6Verification", "liveSnapshot"],
            },
        },
        "stage7": {
            "stopEvidence": {
                "command": [
                    python,
                    cutover,
                    "stop-evidence",
                    "--runtime-root",
                    str(root),
                    "--out",
                    "<service-stopped-evidence>",
                ],
                "workdir": str(root),
                "requires": ["deploy"],
            },
            "bootstrap": {
                "command": [
                    python,
                    cutover,
                    "bootstrap",
                    "--runtime-root",
                    str(root),
                    "--legacy-source",
                    "<legacy-ledger-source>",
                    "--service-stopped-evidence",
                    "<service-stopped-evidence>",
                    "--quiesce-token",
                    "<quiesce-token>",
                ],
                "workdir": str(root),
                "requires": ["stopEvidence"],
            },
            "prepare": {
                "command": [
                    python,
                    cutover,
                    "prepare",
                    "--runtime-root",
                    str(root),
                    "--source",
                    "<managed-ledger-source>",
                    "--quiesce-token",
                    "<quiesce-token>",
                    "--observed-at",
                    "<observed-at>",
                ],
                "workdir": str(root),
                "requires": ["bootstrap"],
            },
            "activate": {
                "command": [
                    python,
                    cutover,
                    "activate",
                    "--runtime-root",
                    str(root),
                    "--manifest",
                    "<prepared-manifest>",
                ],
                "workdir": str(root),
                "requires": ["restoreRehearse"],
            },
            "rollback": {
                "command": [
                    python,
                    cutover,
                    "rollback",
                    "--runtime-root",
                    str(root),
                    "--manifest",
                    "<activated-manifest>",
                ],
                "workdir": str(root),
            },
            "status": {
                "command": [python, cutover, "status", "--runtime-root", str(root)],
                "workdir": str(root),
            },
            "stageWorkerConfigs": {
                "command": [
                    python,
                    worker_install,
                    "--runtime-root",
                    str(root),
                    "--stage",
                ],
                "workdir": str(root),
                "binds": ["activeRelease", "runtimeRoot", "workerSpecs", "unloaded"],
                "requires": ["issueWorkerStagingAuthorization"],
            },
            "automationActivation": {
                "action": "automation_update",
                "targets": [HEARTBEAT_AUTOMATION_ID, DAILY_WAR_ROOM_AUTOMATION_ID],
                "requires": ["stageWorkerConfigs"],
            },
            "strictPreflight": {
                "command": [
                    python,
                    acceptance,
                    "--runtime-root",
                    str(root),
                    "--managed-counts-evidence",
                    "<managed-counts-evidence>",
                    "--automation-snapshot",
                    "<automation-snapshot>",
                    "--preflight",
                ],
                "workdir": str(root),
                "allowsWorkersLoaded": False,
                "requires": ["stageWorkerConfigs", "managedCountsEvidence", "automationSnapshot"],
            },
            "issueWorkerStagingAuthorization": {
                "command": [
                    python,
                    evidence,
                    "worker-staging-authorization",
                    "--runtime-root",
                    str(root),
                    "--managed-counts-evidence",
                    "<managed-counts-evidence>",
                ],
                "workdir": str(root),
                "outputMode": "private_0600_fixed_path",
                "requires": ["managedCountsEvidence"],
            },
            "issueOperationalAuthorization": {
                "command": [
                    python,
                    evidence,
                    "operational-authorization",
                    "--runtime-root",
                    str(root),
                    "--managed-counts-evidence",
                    "<managed-counts-evidence>",
                    "--automation-snapshot",
                    "<automation-snapshot>",
                ],
                "workdir": str(root),
                "outputMode": "private_0600_fixed_path",
                "requires": ["strictPreflight"],
            },
            "activateWorkers": {
                "command": [python, worker_install, "--runtime-root", str(root), "--activate"],
                "workdir": str(root),
                "requires": ["issueOperationalAuthorization"],
            },
            "strictFinalAcceptance": {
                "command": [
                    python,
                    acceptance,
                    "--runtime-root",
                    str(root),
                    "--managed-counts-evidence",
                    "<managed-counts-evidence>",
                    "--automation-snapshot",
                    "<automation-snapshot>",
                ],
                "workdir": str(root),
                "requires": ["activateWorkers"],
            },
            "automationSnapshot": {
                "command": [
                    python,
                    evidence,
                    "automation-snapshot",
                    "--runtime-root",
                    str(root),
                    "--heartbeat-toml",
                    "<heartbeat-automation-toml>",
                    "--daily-toml",
                    "<daily-automation-toml>",
                    "--out",
                    "<automation-snapshot>",
                ],
                "workdir": str(root),
                "requires": ["automationActivation", "stageWorkerConfigs"],
            },
            "managedCountsEvidence": {
                "command": [
                    python,
                    evidence,
                    "managed-counts",
                    "--runtime-root",
                    str(root),
                    "--report",
                    "<stage6-report>",
                    "--envelope",
                    "<stage6-envelope>",
                    "--code-head",
                    str(binding.release.get("commit")),
                    "--out",
                    "<managed-counts-evidence>",
                ],
                "workdir": str(root),
                "requires": ["stage6Verification"],
            },
            "restoreRehearse": {
                "command": [
                    python,
                    cutover,
                    "restore",
                    "--manifest",
                    "<prepared-manifest>",
                    "--repo",
                    "<source-repo>",
                    "--mode",
                    "rehearse",
                ],
                "workdir": str(root),
                "requires": ["prepare"],
            },
            "restoreApply": {
                "command": [
                    python,
                    cutover,
                    "restore",
                    "--manifest",
                    "<prepared-manifest>",
                    "--repo",
                    "<exact-clean-repo>",
                    "--mode",
                    "apply",
                ],
                "workdir": str(root),
            },
        },
    }
    contract_refs = {
        "deploy": "deployment",
        "stopEvidence": "stage7.stopEvidence",
        "bootstrap": "stage7.bootstrap",
        "liveSnapshot": "stage6.liveSnapshot",
        "stage6Verification": "stage6.stage6Verification",
        "stage6Rehearsal": "stage6.stage6Rehearsal",
        "prepare": "stage7.prepare",
        "restoreRehearse": "stage7.restoreRehearse",
        "activate": "stage7.activate",
        "automationActivation": "stage7.automationActivation",
        "automationSnapshot": "stage7.automationSnapshot",
        "managedCountsEvidence": "stage7.managedCountsEvidence",
        "issueWorkerStagingAuthorization": "stage7.issueWorkerStagingAuthorization",
        "stageWorkerConfigs": "stage7.stageWorkerConfigs",
        "strictPreflight": "stage7.strictPreflight",
        "issueOperationalAuthorization": "stage7.issueOperationalAuthorization",
        "activateWorkers": "stage7.activateWorkers",
        "strictFinalAcceptance": "stage7.strictFinalAcceptance",
    }
    deployment = {
        "command": [
            python,
            code + "/scripts/deploy_local_runtime.py",
            "--source",
            "<accepted-clean-source>",
            "--target",
            str(root),
        ],
        "workdir": str(root),
    }
    contracts["deployment"] = deployment
    cutover_plan: list[dict[str, Any]] = []
    for index, step in enumerate(CUTOVER_ORDER):
        reference = contract_refs[step]
        section_name, contract_name = (
            reference.split(".", 1) if "." in reference else (None, reference)
        )
        target = deployment if reference == "deployment" else contracts[section_name][contract_name]
        entry: dict[str, Any] = {
            "id": step,
            "requires": list(CUTOVER_ORDER[:index]),
            "contractRef": reference,
        }
        if "command" in target:
            entry["command"] = list(target["command"])
        elif "action" in target:
            entry["action"] = target["action"]
        else:
            raise RuntimeError(f"cutover contract has no executable action: {reference}")
        cutover_plan.append(entry)
    contracts["cutoverPlan"] = cutover_plan
    return contracts
