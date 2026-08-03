from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "build_dispatch_intents.py"
SPEC = importlib.util.spec_from_file_location("build_dispatch_intents", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def candidate(**updates):
    value = {
        "repo": "example/project",
        "num": 42,
        "url": "https://github.com/example/project/issues/42",
        "title": "Runtime bug",
        "category": "NEW_CLEAN_CANDIDATE",
        "score": 9,
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "llm_review": {"status": "ok", "decision": "NEW_CLEAN_CANDIDATE"},
    }
    value.update(updates)
    return value


def test_builds_exact_skill_prompt():
    result = MODULE.build(
        {"now": "2026-08-04T00:00:00Z", "candidate_details": [candidate()]}
    )
    intent = result["intents"][0]
    assert intent["prompt"] == (
        "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)\n"
        "https://github.com/example/project/issues/42"
    )
    assert len(intent["intentDigest"]) == 64


def test_human_review_and_llm_failure_are_not_dispatched():
    result = MODULE.build(
        {
            "candidate_details": [
                candidate(gate_decision="HUMAN_REVIEW", auto_spawn=False),
                candidate(llm_review={"status": "error"}),
            ]
        }
    )
    assert result["intents"] == []


def test_existing_unconsumed_intent_survives_empty_scan():
    existing = MODULE.build({"candidate_details": [candidate()]})
    result = MODULE.build({"candidate_details": []}, existing)
    assert [item["key"] for item in result["intents"]] == ["example/project#42"]
    assert result["newIntentCount"] == 0
