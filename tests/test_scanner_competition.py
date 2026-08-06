from datetime import UTC, datetime

from oss_pr_radar.scanner import Radar


def radar(tmp_path):
    return Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )


def test_one_stale_direct_pr_remains_a_competition_opportunity(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 9}])
    monkeypatch.setattr(
        instance,
        "assess_single_pr",
        lambda *args: {
            "number": 9,
            "url": "https://github.com/a/b/pull/9",
            "references_issue": True,
            "issue_body_link": False,
            "technical_complete": False,
            "score": 12,
            "test_files": 0,
            "state": "OPEN",
            "is_draft": True,
            "age_days": 45,
            "gaps": ["缺少测试文件", "仍是 draft"],
            "strengths": ["明确关联 issue"],
        },
    )
    result = instance.assess_open_prs("a/b", 7, "Streaming bug")
    assert result["status"] == "weak_pr_competition_possible"


def test_active_direct_draft_blocks_competing_task(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 9}])
    monkeypatch.setattr(
        instance,
        "assess_single_pr",
        lambda *args: {
            "number": 9,
            "url": "https://github.com/a/b/pull/9",
            "references_issue": True,
            "issue_body_link": False,
            "technical_complete": False,
            "score": 12,
            "test_files": 0,
            "state": "OPEN",
            "is_draft": True,
            "age_days": 2,
            "gaps": ["缺少测试文件", "仍是 draft"],
            "strengths": ["明确关联 issue"],
        },
    )

    result = instance.assess_open_prs("a/b", 7, "Streaming bug")

    assert result["status"] == "covered_strong"
    assert "CI 状态只作诊断" in result["summary"]


def test_merged_direct_pr_is_strong_coverage(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 9}])
    monkeypatch.setattr(
        instance,
        "assess_single_pr",
        lambda *args: {
            "number": 9,
            "url": "https://github.com/a/b/pull/9",
            "references_issue": True,
            "issue_body_link": False,
            "technical_complete": False,
            "score": 10,
            "test_files": 0,
            "state": "MERGED",
            "is_draft": False,
            "gaps": ["CI/check 信息不足"],
            "strengths": ["明确关联 issue"],
        },
    )
    result = instance.assess_open_prs("a/b", 7, "Streaming bug")
    assert result["status"] == "covered_strong"


def test_maintainer_owned_direct_pr_is_strong_despite_failed_ci(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 9}])
    monkeypatch.setattr(
        instance,
        "assess_single_pr",
        lambda *args: {
            "number": 9,
            "url": "https://github.com/a/b/pull/9",
            "references_issue": True,
            "issue_body_link": False,
            "technical_complete": True,
            "maintainer_owned": True,
            "score": 61,
            "test_files": 1,
            "state": "OPEN",
            "is_draft": False,
            "gaps": ["存在失败 CI/check"],
            "strengths": ["明确关联 issue", "由仓库维护者或协作者提交"],
        },
    )
    result = instance.assess_open_prs("a/b", 7, "Streaming bug")
    assert result["status"] == "covered_strong"


def test_nontechnical_triage_failure_does_not_create_pr_competition(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 1726}])
    monkeypatch.setattr(
        instance,
        "pr_detail",
        lambda *args: {
            "number": 1726,
            "title": "fix(mcp): get_episodes returns recent episodes",
            "url": "https://github.com/getzep/graphiti/pull/1726",
            "body": (
                "Fixes #1062. The uuid-ordered query returns an arbitrary stable slice. "
                "This adds a recency query while preserving the pagination helper, and "
                "documents the compatibility boundary and regression coverage."
            ),
            "state": "OPEN",
            "isDraft": False,
            "updatedAt": "2026-08-03T21:55:35Z",
            "files": [
                {"path": "graphiti_core/nodes.py"},
                {"path": "tests/test_episode_recency_ordering.py"},
                {"path": "tests/test_node_int.py"},
            ],
            "additions": 396,
            "deletions": 7,
            "changedFiles": 6,
            "statusCheckRollup": [
                {"name": "ruff", "conclusion": "SUCCESS"},
                {
                    "name": "triage",
                    "workflowName": "PR Triage",
                    "conclusion": "FAILURE",
                },
            ],
            "reviewDecision": "REVIEW_REQUIRED",
            "comments": [],
            "closingIssuesReferences": [{"number": 1062}],
        },
    )

    result = instance.assess_open_prs(
        "getzep/graphiti",
        1062,
        "get_episodes returns stale old data",
        "get_episodes uses ORDER BY uuid DESC instead of recency",
    )

    assert result["status"] == "covered_strong"
    assert result["prs"][0]["ignored_nontechnical_failed_checks"] == ["triage"]
    assert "存在失败 CI/check" not in result["prs"][0]["gaps"]


def test_vercel_authorization_failure_is_not_competition_evidence(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 20661}])
    monkeypatch.setattr(
        instance,
        "pr_detail",
        lambda *args: {
            "number": 20661,
            "title": "fix(workflows): preserve nested watch state",
            "url": "https://github.com/mastra-ai/mastra/pull/20661",
            "body": (
                "Fixes #20660. This fixes the nested workflow watch root cause and adds "
                "focused regression coverage for all affected state transitions. The "
                "implementation remains scoped to the workflow runtime path."
            ),
            "state": "OPEN",
            "isDraft": False,
            "updatedAt": "2026-08-04T12:00:00Z",
            "files": [
                {"path": "packages/core/src/workflows/watch.ts"},
                {"path": "packages/core/src/workflows/watch.test.ts"},
            ],
            "additions": 120,
            "deletions": 20,
            "changedFiles": 2,
            "statusCheckRollup": [
                {"name": "unit", "conclusion": "SUCCESS"},
                {
                    "name": "Preview deployment",
                    "conclusion": "FAILURE",
                    "detailsUrl": "https://vercel.com/git/authorize",
                },
            ],
            "reviewDecision": "REVIEW_REQUIRED",
            "comments": [],
            "closingIssuesReferences": [{"number": 20660}],
        },
    )

    result = instance.assess_open_prs(
        "mastra-ai/mastra",
        20660,
        "Workflow watch loses nested state",
        "packages/core/src/workflows/watch.ts nested workflow watch state",
    )

    assert result["status"] == "covered_strong"
    assert result["prs"][0]["ignored_nontechnical_failed_checks"] == ["Preview deployment"]
    assert result["prs"][0]["ci_competition_weight"] == 0


def test_technical_ci_failure_alone_does_not_make_complete_pr_competitive(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 10}])
    monkeypatch.setattr(
        instance,
        "pr_detail",
        lambda *args: {
            "number": 10,
            "title": "fix(runtime): preserve streamed tool result",
            "url": "https://github.com/a/b/pull/10",
            "body": (
                "Fixes #7. Preserve the streamed tool result at the runtime boundary and "
                "cover synchronous and asynchronous tool-call paths with focused regression "
                "tests. The change does not alter unrelated provider behavior."
            ),
            "state": "OPEN",
            "isDraft": False,
            "updatedAt": "2026-08-04T12:00:00Z",
            "files": [
                {"path": "src/runtime/tool_stream.py"},
                {"path": "tests/test_tool_stream.py"},
            ],
            "additions": 90,
            "deletions": 12,
            "changedFiles": 2,
            "statusCheckRollup": [
                {"name": "unit tests", "conclusion": "FAILURE"},
            ],
            "reviewDecision": "REVIEW_REQUIRED",
            "comments": [],
            "closingIssuesReferences": [{"number": 7}],
        },
    )

    result = instance.assess_open_prs(
        "a/b",
        7,
        "Streaming tool result is lost",
        "src/runtime/tool_stream.py async tool call",
    )

    assert result["status"] == "covered_strong"
    assert result["prs"][0]["technical_failed_checks"] == ["unit tests"]
    assert result["prs"][0]["ci_competition_weight"] == 0


def test_stack_trace_basename_and_semantics_block_unlinked_covering_pr(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 1439}])
    monkeypatch.setattr(
        instance,
        "pr_detail",
        lambda *args: {
            "number": 1439,
            "title": "Add input layer to profiling plots (fixes #404)",
            "url": "https://github.com/fastmachinelearning/hls4ml/pull/1439",
            "body": (
                "activations_hlsmodel now handles multi-input X formats. "
                "Lists are converted to contiguous arrays before model.trace."
            ),
            "state": "OPEN",
            "isDraft": False,
            "updatedAt": "2026-02-16T10:35:50Z",
            "files": [
                {"path": "hls4ml/model/profiling.py"},
                {"path": "test/pytest/test_profiling_input_layer.py"},
            ],
            "additions": 201,
            "deletions": 4,
            "changedFiles": 2,
            "statusCheckRollup": [{"name": "pre-commit", "conclusion": "SUCCESS"}],
            "reviewDecision": "REVIEW_REQUIRED",
            "comments": [],
            "closingIssuesReferences": [{"number": 404}],
        },
    )

    result = instance.assess_open_prs(
        "fastmachinelearning/hls4ml",
        1515,
        "profiling.numerical() fails for multi-input models",
        'File ".../profiling.py", line 330, in activations_hlsmodel\n'
        "model.trace(np.ascontiguousarray(X))",
    )

    assert result["status"] == "semantic_overlap_requires_review"
    assert result["prs"][0]["overlapping_paths"] == ["hls4ml/model/profiling.py"]
