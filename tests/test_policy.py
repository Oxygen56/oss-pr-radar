from oss_pr_radar.policy import predict_candidate


def candidate_with_weak_pr():
    return {
        "repo": "owner/repo",
        "num": 7,
        "title": "Streaming tool-call state is lost",
        "track": "agent_ai_infra",
        "category": "PR_COMPETITION_OPPORTUNITY",
        "gate_decision": "ALLOW_TO_WORK",
        "public_submission_allowed": True,
        "hardware_compatible": True,
        "submission_policy": "normal",
        "actionability_evidence": {
            "public_repro_signals": 2,
            "root_cause_signal": True,
            "maintainer_approved": False,
            "help_wanted": False,
        },
        "open_pr_assessment": {
            "status": "weak_pr_competition_possible",
            "prs": [
                {
                    "references_issue": True,
                    "issue_body_link": False,
                    "is_draft": True,
                    "test_files": 0,
                }
            ],
        },
        "related_issue_assessment": {"status": "none", "issues": []},
    }


def test_weak_direct_pr_is_not_treated_as_a_strong_duplicate():
    prediction = predict_candidate(candidate_with_weak_pr())
    assert prediction.tier == "BUILD_AND_HOLD"
    assert prediction.reason_code == "WEAK_PR_COMPETITION_PRIVATE_AUDIT"


def test_strong_direct_pr_still_drops():
    candidate = candidate_with_weak_pr()
    candidate["category"] = "NEW_CLEAN_CANDIDATE"
    candidate["open_pr_assessment"]["status"] = "covered_strong"
    prediction = predict_candidate(candidate)
    assert prediction.tier == "DROP"
    assert prediction.reason_code == "DUPLICATE"


def test_algorithm_track_requires_qualified_mechanism_evidence():
    candidate = candidate_with_weak_pr()
    candidate.update(
        {
            "track": "llm_algorithm",
            "category": "NEW_CLEAN_CANDIDATE",
            "open_pr_assessment": {"status": "none", "prs": []},
            "algorithm_evidence": {
                "score": 4,
                "mechanism_count": 1,
                "qualified": False,
                "operational_only": True,
            },
        }
    )

    prediction = predict_candidate(candidate)

    assert prediction.tier == "DROP"
    assert prediction.reason_code == "ALGORITHM_EVIDENCE_WEAK"


def test_bounded_algorithm_dependency_wait_is_watched_not_dropped():
    candidate = candidate_with_weak_pr()
    candidate.update(
        {
            "track": "llm_algorithm",
            "category": "WAIT_MAINTAINER",
            "gate_decision": "HUMAN_REVIEW",
            "auto_spawn": False,
            "open_pr_assessment": {"status": "semantic_overlap_requires_review", "prs": []},
            "actionability_evidence": {
                "needs_confirmation": True,
                "wait_reasons": ["DEPENDENCY", "OWNERSHIP_REVIEW"],
            },
            "algorithm_evidence": {
                "score": 6,
                "mechanism_count": 2,
                "qualified": False,
                "code_path_signal": True,
                "operational_only": False,
            },
        }
    )

    prediction = predict_candidate(candidate)

    assert prediction.tier == "WATCH"
    assert prediction.reason_code == "DEPENDENCY_OR_OWNERSHIP_REVIEW"
