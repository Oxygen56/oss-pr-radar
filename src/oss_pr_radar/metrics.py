"""Controllable quality metrics for the opportunity-to-submit-ready loop."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .util import iso_z

QUALITY_FIELDS = (
    "fresh_state_verified",
    "ownership_verified",
    "policy_verified",
    "reproduction_verified",
    "root_cause_verified",
    "minimal_fix_verified",
    "regression_test_verified",
    "relevant_tests_green",
    "independent_review_passed",
)

# These are failures that fresh discovery or the live pre-dispatch gate should
# have caught before a user-visible task consumed the single implementation slot.
# Older controller versions used lowercase PREEXISTING_* values while current
# versions persist machine-readable uppercase authorization reasons.
FILTER_MISS_CLASSES = frozenset(
    {
        "ACTIVE_OR_CONDITIONAL_CLAIM",
        "ALREADY_FIXED",
        "DESIGN_APPROVAL_REQUIRED",
        "DESIGN_UNAPPROVED",
        "DUPLICATE",
        "EXISTING_PR_REQUIRES_COMPETITION_REVIEW",
        "ISSUE_ASSIGNED",
        "ISSUE_NOT_OPEN",
        "MAINTAINER_APPROVAL_REQUIRED",
        "OWNERSHIP",
        "PREEXISTING_CLAIM",
        "PREEXISTING_DUPLICATE",
        "PREEXISTING_POLICY_BLOCK",
        "SEMANTIC_PR_OVERLAP_REQUIRES_REVIEW",
        "STRONG_EXISTING_PR",
        "UNSOLICITED_PRS_BLOCKED",
    }
)


def canonical_failure_class(value: Any) -> str:
    return str(value or "").strip().replace("-", "_").upper()


@dataclass(frozen=True)
class SubmitReadyAssessment:
    ready: bool
    missing: tuple[str, ...]
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_submit_ready(evidence: dict[str, Any]) -> SubmitReadyAssessment:
    missing = tuple(field for field in QUALITY_FIELDS if evidence.get(field) is not True)
    return SubmitReadyAssessment(not missing, missing, dict(evidence))


def rolling_quality(path: Path, *, days: int = 30) -> dict[str, Any]:
    cutoff = iso_z(datetime.now(UTC) - timedelta(days=max(1, days)))
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """SELECT selected_at,submit_ready_at,failure_class,quality_json
               FROM outcomes WHERE selected_at>=?""",
            (cutoff,),
        ).fetchall()
        hard_escapes = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE created_at>=? AND event_type='HARD_GATE_ESCAPE'""",
            (cutoff,),
        ).fetchone()[0]
    finally:
        connection.close()
    selected = len(rows)
    submit_ready = sum(bool(row["submit_ready_at"]) for row in rows)
    failure_counts = Counter(
        canonical_failure_class(row["failure_class"])
        for row in rows
        if canonical_failure_class(row["failure_class"])
    )
    filter_misses = sum(failure_counts[name] for name in FILTER_MISS_CLASSES)
    return {
        "windowDays": days,
        "selected": selected,
        "submitReady": submit_ready,
        "submitReadyRate": round(submit_ready / selected, 4) if selected else None,
        "filterMisses": filter_misses,
        "filterMissRate": round(filter_misses / selected, 4) if selected else None,
        "hardGateEscapes": int(hard_escapes),
        "failureClassCounts": dict(sorted(failure_counts.items())),
        "qualityEvidence": [json.loads(row["quality_json"]) for row in rows],
    }
