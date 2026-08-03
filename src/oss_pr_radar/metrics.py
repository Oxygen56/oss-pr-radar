"""Controllable quality metrics for the opportunity-to-submit-ready loop."""

from __future__ import annotations

import json
import sqlite3
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
    filter_misses = sum(
        row["failure_class"]
        in {"preexisting_claim", "preexisting_duplicate", "preexisting_policy_block"}
        for row in rows
    )
    return {
        "windowDays": days,
        "selected": selected,
        "submitReady": submit_ready,
        "submitReadyRate": round(submit_ready / selected, 4) if selected else None,
        "filterMisses": filter_misses,
        "filterMissRate": round(filter_misses / selected, 4) if selected else None,
        "hardGateEscapes": int(hard_escapes),
        "qualityEvidence": [json.loads(row["quality_json"]) for row in rows],
    }
