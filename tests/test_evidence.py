from oss_pr_radar.evidence import collect_evidence
from oss_pr_radar.repo_policy import PolicySnapshot


class CrossRepoClient:
    def __init__(self):
        self.detail_repos = []

    def issue(self, _repo, _number):
        return {"state": "open", "title": "Browser tool fails", "body": "Trace"}

    def comments(self, _repo, _number):
        return []

    def timeline(self, _repo, _number):
        return []

    def related_open_prs(self, _repo, _number, **_kwargs):
        return [
            {
                "number": 4342,
                "_repo": "OpenHands/software-agent-sdk",
                "_linked_from_timeline": True,
            }
        ]

    def pull_request(self, repo, number):
        self.detail_repos.append(repo)
        return {
            "number": number,
            "html_url": f"https://github.com/{repo}/pull/{number}",
            "state": "open",
            "draft": False,
            "body": "Fixes OpenHands/OpenHands#16270",
            "head": {"sha": "head"},
        }

    def pull_files(self, repo, _number):
        self.detail_repos.append(repo)
        return [{"filename": "tests/test_browser.py"}]

    def pull_reviews(self, repo, _number):
        self.detail_repos.append(repo)
        return []

    def check_runs(self, repo, _head):
        self.detail_repos.append(repo)
        return [{"conclusion": "success"}]


def test_collect_evidence_enriches_cross_repository_pr_in_its_own_repo():
    client = CrossRepoClient()
    policy = PolicySnapshot(
        status="NORMAL",
        digest="policy",
        files=(),
        ai_disclosure=False,
        ai_prohibited=False,
        assignment_required=False,
        unsolicited_pr_blocked=False,
        cla=False,
        dco=False,
        nonstandard_agreement=False,
    )

    evidence = collect_evidence(
        client,
        "OpenHands/OpenHands",
        16270,
        policy_snapshot=policy,
    )

    assert set(client.detail_repos) == {"OpenHands/software-agent-sdk"}
    assert evidence.pull_relations[0]["relation"] == "STRONG_EXACT_DUPLICATE"
    assert evidence.pull_relations[0]["url"].endswith("/pull/4342")


class ClaimedIssueClient(CrossRepoClient):
    def issue(self, _repo, _number):
        return {
            "state": "open",
            "title": "Diffusion rollout corrupts trajectories",
            "body": "I have fixes for all three on separate branches and can open PRs.",
            "user": {"login": "reporter"},
            "author_association": "NONE",
            "created_at": "2026-08-08T04:30:00Z",
        }

    def related_open_prs(self, _repo, _number, **_kwargs):
        return []


def test_collect_evidence_treats_issue_author_fix_as_active_claim():
    policy = PolicySnapshot(
        status="NORMAL",
        digest="policy",
        files=(),
        ai_disclosure=False,
        ai_prohibited=False,
        assignment_required=False,
        unsolicited_pr_blocked=False,
        cla=False,
        dco=False,
        nonstandard_agreement=False,
    )

    evidence = collect_evidence(
        ClaimedIssueClient(),
        "sgl-project/sglang",
        34000,
        policy_snapshot=policy,
    )

    assert evidence.claims[0]["author"] == "reporter"
    assert evidence.claims[0]["kind"] == "active_claim"


class RetractedClaimClient(ClaimedIssueClient):
    def comments(self, _repo, _number):
        return [
            {
                "body": (
                    "Standing down — I see PR #45136 already addresses this. I'll defer to those."
                ),
                "user": {"login": "reporter"},
                "author_association": "NONE",
                "created_at": "2026-08-08T05:30:00Z",
            }
        ]


def test_collect_evidence_drops_issue_author_claim_after_explicit_retraction():
    policy = PolicySnapshot(
        status="NORMAL",
        digest="policy",
        files=(),
        ai_disclosure=False,
        ai_prohibited=False,
        assignment_required=False,
        unsolicited_pr_blocked=False,
        cla=False,
        dco=False,
        nonstandard_agreement=False,
    )

    evidence = collect_evidence(
        RetractedClaimClient(),
        "sgl-project/sglang",
        34000,
        policy_snapshot=policy,
    )

    assert evidence.claims == ()
