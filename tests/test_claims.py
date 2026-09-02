from oss_pr_radar.claims import detect_claims, detect_maintainer_approval


def comment(
    body,
    author="alice",
    association="NONE",
    created_at="2026-08-03T17:59:07Z",
):
    return {
        "body": body,
        "user": {"login": author},
        "author_association": association,
        "created_at": created_at,
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


def test_maintainer_commitment_to_figure_out_fix_is_an_active_claim():
    signals = detect_claims(
        [
            comment(
                "Thanks for the report! I'll definitely get this figured out "
                "before the upcoming release.",
                author="FoxxMD",
                association="OWNER",
                created_at="2026-08-30T16:20:25Z",
            )
        ],
        current_actor="Oxygen56",
    )

    assert len(signals) == 1
    assert signals[0].author == "FoxxMD"
    assert signals[0].association == "OWNER"
    assert signals[0].kind == "active_claim"
    assert "get this figured out" in signals[0].excerpt


def test_later_explicit_retraction_clears_same_author_claim():
    signals = detect_claims(
        [
            comment(
                "I'd like to work on this. I'll add regression coverage.",
                author="argszero",
                created_at="2026-08-26T02:36:59Z",
            ),
            comment(
                "Standing down — I see PR #45136 already addresses this. I'll defer to those.",
                author="argszero",
                created_at="2026-08-26T10:53:24Z",
            ),
        ],
        current_actor="Oxygen56",
    )

    assert signals == []


def test_retraction_does_not_clear_another_authors_claim():
    signals = detect_claims(
        [
            comment("I will take this", author="alice"),
            comment(
                "Standing down",
                author="bob",
                created_at="2026-08-03T18:59:07Z",
            ),
        ],
        current_actor="Oxygen56",
    )

    assert [signal.author for signal in signals] == ["alice"]


def test_new_claim_after_retraction_is_active_again():
    signals = detect_claims(
        [
            comment(
                "I will take this",
                author="alice",
                created_at="2026-08-03T17:00:00Z",
            ),
            comment(
                "Standing down",
                author="alice",
                created_at="2026-08-03T18:00:00Z",
            ),
            comment(
                "I can work on this after all",
                author="alice",
                created_at="2026-08-03T19:00:00Z",
            ),
        ],
        current_actor="Oxygen56",
    )

    assert [signal.author for signal in signals] == ["alice"]
    assert signals[0].kind == "active_claim"


def test_out_of_order_or_undated_retraction_does_not_clear_claim():
    signals = detect_claims(
        [
            comment(
                "Standing down",
                author="alice",
                created_at="2026-08-03T16:00:00Z",
            ),
            comment(
                "I will take this",
                author="alice",
                created_at="2026-08-03T17:00:00Z",
            ),
            comment("Standing down", author="bob", created_at=""),
            comment("I will take this", author="bob", created_at="not-a-time"),
        ],
        current_actor="Oxygen56",
    )

    assert [signal.author for signal in signals] == ["alice", "bob"]


def test_negated_or_temporary_retraction_fails_closed():
    signals = detect_claims(
        [
            comment(
                "I will take this",
                author="alice",
                created_at="2026-08-03T17:00:00Z",
            ),
            comment(
                "I'm not standing down",
                author="alice",
                created_at="2026-08-03T18:00:00Z",
            ),
            comment(
                "Standing down for now",
                author="alice",
                created_at="2026-08-03T19:00:00Z",
            ),
        ],
        current_actor="Oxygen56",
    )

    assert [signal.author for signal in signals] == ["alice"]


def test_same_comment_reclaim_wins_over_retraction_phrase():
    signals = detect_claims(
        [
            comment(
                "I was standing down, but I can work on this after all.",
                author="alice",
                created_at="2026-08-03T18:00:00Z",
            )
        ],
        current_actor="Oxygen56",
    )

    assert [signal.author for signal in signals] == ["alice"]


def test_explicit_no_longer_working_is_a_retraction_not_a_new_claim():
    for retraction in ("I'm no longer working on this", "I'm not working on this"):
        signals = detect_claims(
            [
                comment(
                    "I will take this",
                    author="alice",
                    created_at="2026-08-03T17:00:00Z",
                ),
                comment(
                    retraction,
                    author="alice",
                    created_at="2026-08-03T18:00:00Z",
                ),
            ],
            current_actor="Oxygen56",
        )

        assert signals == []


def test_instructions_or_tentative_withdrawal_do_not_clear_claim():
    signals = detect_claims(
        [
            comment(
                "I will take this",
                author="alice",
                created_at="2026-08-03T17:00:00Z",
            ),
            comment(
                "Please stand down",
                author="alice",
                created_at="2026-08-03T18:00:00Z",
            ),
            comment(
                "I am considering withdrawing my interest",
                author="alice",
                created_at="2026-08-03T19:00:00Z",
            ),
        ],
        current_actor="Oxygen56",
    )

    assert [signal.author for signal in signals] == ["alice"]


def test_hypothetical_or_qualified_stand_down_does_not_clear_claim():
    for body in (
        "I considered standing down, but haven't made a decision.",
        "If I end up standing down, I'll say so.",
        "I'm not working on this alone; Bob and I are pairing.",
        "I won't work on this until Monday, then I'll resume.",
        "Standing down — for now.",
        "I'm standing down — unless the maintainer asks me to continue.",
        "I'm not working on this — yet.",
        "I won't work on this — until Monday, then I'll resume.",
        "They claim I'm standing down. That is incorrect.",
        "I'm not saying I am standing down.",
        "I am withdrawing my claim?",
        "Standing down — PR #8 exists. I'll defer to no one.",
        "Standing down — PR #8 exists. They say I'll defer to it, but I won't.",
        "Standing down — PR #8 exists. I'll defer to those, then I'll take this next week.",
        "Standing down — PR #8 exists. I'll defer to those while I keep working on the fix.",
        "Standing down — PR #8 exists. I'll defer to those and resume later.",
        ("Standing down — PR #8 exists. I'm not actually standing down, but I'll defer to those."),
        "Standing down — PR #8 exists. I won't stop working, but I'll defer to those.",
        "Standing down — PR #8 exists. I'll keep working, but I'll defer to those.",
        "Standing down — PR #8 exists. I still claim this, but I'll defer to those.",
        "Standing down — PR #8 exists. I plan to resume, but I'll defer to those.",
    ):
        signals = detect_claims(
            [
                comment(
                    "I will take this",
                    author="alice",
                    created_at="2026-08-03T17:00:00Z",
                ),
                comment(
                    body,
                    author="alice",
                    created_at="2026-08-03T18:00:00Z",
                ),
            ],
            current_actor="Oxygen56",
        )

        assert signals
        assert {signal.author for signal in signals} == {"alice"}

def test_maintainer_approval_requires_privileged_association():
    assert detect_maintainer_approval([comment("Please open a PR for this", association="MEMBER")])
    assert not detect_maintainer_approval(
        [comment("Please open a PR for this", association="NONE")]
    )
