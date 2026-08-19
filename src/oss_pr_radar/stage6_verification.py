"""Versioned definitions and binding checks for Stage 6 evidence."""

from __future__ import annotations

import json
import re
from typing import Any

from .util import canonical_json, sha256_json

STAGE6_VERIFICATION_SCHEMA = "oss-pr-radar.stage6.verification.v1"
_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")

VERSIONED_DEFINITIONS: dict[str, Any] = {
    "commands": [
        {"id": "full-pytest", "command": "python -m pytest -q"},
        {
            "id": "focused-stage6",
            "command": "python -m pytest -q tests/test_legacy_migration.py tests/test_stage6_rehearsal.py tests/test_managed_round8_key_rotation.py",
        },
        {"id": "ruff", "command": "ruff check ."},
        {
            "id": "yaml",
            "command": (
                "ruby -ryaml -e 'ARGV.each { |path| YAML.load_file(path); puts path }' -- "
                ".github/workflows/ci.yml .github/workflows/health.yml .github/workflows/radar.yml"
            ),
        },
        {"id": "code-integrity", "command": "python scripts/verify_code_identity.py"},
    ],
    "faultTests": [
        "concurrent_source_change_abort_without_replace",
        "legacy_forged_terminal_state_non_authorizing",
        "previous_key_online_restore_rejected",
        "public_safe_scan_excludes_restricted_recovery",
    ],
    "testIds": [
        "tests/test_legacy_migration.py::test_authoritative_reconciliation_closes_only_with_exact_evidence",
        "tests/test_legacy_migration.py::test_legacy_terminal_labels_cannot_authorize_projection",
        "tests/test_stage6_rehearsal.py::test_stable_copy_requires_proof_and_preserves_target_on_source_change",
        "tests/test_stage6_rehearsal.py::test_public_manifest_excludes_restricted_recovery_from_safety_claim",
        "tests/test_stage6_rehearsal.py::test_free_space_guard_fails_before_reserve_is_crossed",
        "tests/test_stage6_rehearsal.py::test_sqlite_restore_target_is_private_at_creation",
        "tests/test_managed_round7_security.py::test_root_signature_required_unknown_key_and_previous_key_rotation",
        "tests/test_managed_round8_key_rotation.py::test_snapshot_certificate_and_attestation_sign_current_with_previous_verify",
    ],
}


def _copy_definitions() -> dict[str, Any]:
    return json.loads(canonical_json(VERSIONED_DEFINITIONS))


def build_verification_manifest(code_head: str, *, results: dict[str, Any] | None = None) -> dict[str, Any]:
    if not _HEAD_RE.fullmatch(code_head):
        raise ValueError("verification manifest requires a full 40-character commit SHA")
    definitions = _copy_definitions()
    binding = {
        "schema": STAGE6_VERIFICATION_SCHEMA,
        "codeHead": code_head,
        "definitions": definitions,
    }
    manifest = {
        **binding,
        "definitionDigest": sha256_json(binding),
        "results": results or {},
    }
    manifest["manifestDigest"] = sha256_json(manifest)
    return manifest


def validate_verification_manifest(manifest: object, code_head: str) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("verification manifest must be an object")
    expected = build_verification_manifest(code_head)
    if manifest.get("schema") != expected["schema"]:
        raise ValueError("verification manifest schema is unsupported")
    if manifest.get("codeHead") != code_head:
        raise ValueError("verification manifest is bound to a different commit")
    if manifest.get("definitions") != expected["definitions"]:
        raise ValueError("verification manifest definitions do not match the versioned checks")
    if manifest.get("definitionDigest") != expected["definitionDigest"]:
        raise ValueError("verification manifest definition digest is invalid")
    if set(manifest) != set(expected):
        raise ValueError("verification manifest contains unexpected fields")
    results = manifest.get("results", {})
    if not isinstance(results, dict):
        raise ValueError("verification manifest results must be an object")
    command_ids = {item["id"] for item in expected["definitions"]["commands"]}
    if set(results) != command_ids:
        missing = sorted(command_ids - set(results))
        extra = sorted(set(results) - command_ids)
        raise ValueError(f"verification manifest command results are incomplete: missing={missing}, extra={extra}")
    for result_id, result in results.items():
        if not isinstance(result, dict):
            raise ValueError(f"verification result is not canonical: {result_id}")
        if set(result) != {"status", "exitCode", "outputDigest"}:
            raise ValueError(f"verification result is not canonical: {result_id}")
        if result.get("status") != "passed" or result.get("exitCode") != 0:
            raise ValueError(f"verification result did not pass: {result_id}")
        if not isinstance(result.get("outputDigest"), str) or not re.fullmatch(r"[0-9a-f]{64}", result["outputDigest"]):
            raise ValueError(f"verification result digest is invalid: {result_id}")
    unsigned = {key: manifest[key] for key in manifest if key != "manifestDigest"}
    if manifest.get("manifestDigest") != sha256_json(unsigned):
        raise ValueError("verification manifest digest is invalid")
    return json.loads(canonical_json(manifest))
