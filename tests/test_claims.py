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
        [
            comment("I will take this", author="Oxygen56"),
            comment("working on this", author="bot[bot]"),
        ],
        current_actor="Oxygen56",
    )
    assert signals == []


def test_issue_author_with_ready_fix_branches_is_an_active_claim():
    signals = detect_claims(
        [],
        current_actor="Oxygen56",
        issue={
            "body": "I have fixes for all three, each on its own branch, and can open PRs.",
            "user": {"login": "reporter"},
            "author_association": "NONE",
            "created_at": "2026-08-08T04:30:00Z",
        },
    )

    assert signals[0].author == "reporter"
    assert signals[0].kind == "active_claim"
    assert "fixes for all three" in signals[0].excerpt


def test_offer_to_send_small_pr_is_an_active_claim():
    signals = detect_claims(
        [
            comment(
                "If you would take it, I am happy to send a small PR "
                "adding the assertion with a test."
            )
        ],
        current_actor="Oxygen56",
    )

    assert signals[0].kind == "active_claim"
    assert "happy to send a small PR" in signals[0].excerpt


def test_maintainer_approval_requires_privileged_association():
    assert detect_maintainer_approval([comment("Please open a PR for this", association="MEMBER")])
    assert not detect_maintainer_approval(
        [comment("Please open a PR for this", association="NONE")]
    )
