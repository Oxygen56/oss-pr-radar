from pathlib import Path

import pytest

SKILL = Path("/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md")
REPO = Path(__file__).parents[1]


def test_reproduction_protocol_preserves_two_line_contract_and_read_only_boundary():
    if not SKILL.is_file():
        pytest.skip("requires the local Codex gh-issue-pr skill")
    text = SKILL.read_text(encoding="utf-8")

    assert "only this skill and one GitHub issue URL" in text
    assert "canonical two-line Radar task" in text
    assert "When `taskStage` is `REPRODUCTION_REQUIRED`" in text
    assert "run a focused read-only reproduction or mechanism check" in text
    assert '"stage": "REPRODUCED_VALIDATED"' in text
    assert "The controller, not the child, authenticates the evidence" in text
    assert "Do not edit repository files, commit, push, create a PR, or comment." in text
    assert "Any violating diff or lifecycle claim is a controller policy violation" in text
    assert not list(REPO.glob("**/SKILL.md.bak*"))
