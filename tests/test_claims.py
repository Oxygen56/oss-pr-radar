from oss_pr_radar.claims import detect_claims, detect_maintainer_approval


def comment(body, author="alice", association="NONE"):
    return {
        "body": body,
        "user": {"login": author},
        "author_association": association,
        "created_at": "2026-08-03T17:59:07Z",
    }


def test_conditional_claim_from_liteparse_case_is_detected():
    signals = detect_claims(
        [comment("have anyone started this? if not then i can try this one.")],
        current_actor="Oxygen56",
    )
    assert signals[0].kind == "conditional_claim"


def test_own_and_bot_comments_do_not_block():
    signals = detect_claims(
        [comment("I will take this", author="Oxygen56"), comment("working on this", author="bot[bot]")],
        current_actor="Oxygen56",
    )
    assert signals == []


def test_maintainer_approval_requires_privileged_association():
    assert detect_maintainer_approval(
        [comment("Please open a PR for this", association="MEMBER")]
    )
    assert not detect_maintainer_approval(
        [comment("Please open a PR for this", association="NONE")]
    )

