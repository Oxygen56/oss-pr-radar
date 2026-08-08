# Architecture

## Product Contract

The radar optimizes for one controllable outcome: among opportunities selected
for implementation, how many become a narrowly scoped, reproduced, tested, and
independently reviewed SubmitReady change. Maintainer review speed and merge
timing are external labels, not the north-star metric.

## Control Plane

1. **Discovery** reads recently updated open issues with overlapping windows and
   bounded backfill. Repository feeds and search discovery are both used; every
   artifact identifies fixed, queried, matched, qualified, and inspected repos.
2. **Evidence** reads every comment and timeline page, recursive policy files,
   related PR details/files/checks/reviews, issue ownership, and hardware scope.
   Unlinked PRs are held for review when a stack-trace path or distinctive file
   basename overlaps the PR diff and the issue/PR semantics also overlap;
   generic names such as `utils.py` never establish coverage by themselves.
   Check failures are diagnostic only. Preview/auth/policy statuses are
   classified separately, and even a technical failure cannot authorize a
   competing PR without a material root-cause, critical-path, or test gap.
3. **Decision** applies hard gates first. DeepSeek may reject, downgrade, or
   classify semantic competition; it cannot produce a positive authorization.
   `llm_algorithm` is a separate track whose snapshot must bind concrete
   mechanism evidence and a reference, numerical, or controlled-experiment
   validation path. Repository identity alone never qualifies algorithm work.
4. **Cloud handoff** validates the immutable report and signs a promptless,
   expiring intent with HMAC. The signed intent preserves the selected track and
   algorithm evidence. Cloud notifications use a durable, per-candidate-state
   outbox only for maintainer decisions and actionable status changes; a clean
   candidate is not announced as dispatched until the local controller records
   the real Codex task.
5. **Local authorization** verifies the signature, leases an intent in SQLite,
   repeats all live gates, and creates the canonical prompt locally. Before
   calling the desktop task API it records `CREATING`; the returned
   `clientThreadId` is persisted before any polling.
6. **Task identity** binds issue, Codex task ID, project, source repository,
   worktree, first user input, and expected timestamped lifecycle title. The
   selected project must be the exact source repository and must advertise a
   Git repository; parent folders and the radar repository are invalid targets.
   When worktree creation returns only an asynchronous client ID, a later
   reconciliation may bind the task only if creation start time, canonical
   prompt, repository origin, and a previously unbound worktree identify
   exactly one task. `CREATING` does not expire with the lease, so a late task
   cannot race a replacement.
7. **Delivery** gives the child a Git-ignored workspace context containing the
   controller-captured issue, comments, ownership, related-PR, policy, and
   hardware evidence. The child treats that snapshot as untrusted data, never
   requests network or elevated permission, writes either `AUDIT_NO_GO` or
   SubmitReady evidence locally, and never opens the external ledger, writes Git
   metadata, or performs public actions. For `FIX_READY`, the child leaves an
   exact changed-file allowlist plus proposed branch and commit message. The
   controller validates that allowlist, creates the local commit, and ingests the
   result. A late AI-disclosure finding remains a local-fix outcome and cannot
   create a publication request.
8. **Publication** rechecks the exact clean commit, branch, diff, evidence,
   ownership, duplicates, policy, DCO, identity, fork owner, base branch, PR
   title, and PR body digest. A permit expires quickly and is consumed by the
   verified PR.

## Lifecycle

`QUALIFIED -> LEASED -> CREATING -> DISPATCHED -> AUDIT_PASS -> FIX_READY -> PR_OPEN -> CI_GREEN -> MAINTAINER_ACCEPTED -> MERGED`

`AUDIT_NO_GO` is a terminal no-value outcome and is the only lifecycle state
that authorizes automatic task archival. Archival remains blocked until the
same task has first acknowledged its `[无价值]` title state. If later evidence
recovers the current task to a valuable state, a separately verified restore
receipt unarchives it before title synchronization resumes. Archive state is
derived from the latest archive/restore event, not historical presence. Shadow observations
do not enter the SubmitReady denominator.

Visible task titles progress through `GO`, `本地修复就绪`, `存在发布请求`,
`PR已开`, `已合并`, or terminal `无价值`, while preserving the original dispatch timestamp. A
dispatched task with no outcome can receive one write-ahead, exact-prompt
recovery attempt; an ambiguous recovery is surfaced instead of retried.

## State Ownership

- `radar-state`: cloud JSON checkpoints with SHA-256 manifest and compare-and-swap publish.
- `state/radar_ledger.sqlite3`: local authoritative leases, lifecycle, task identity,
  quality evidence, publication requests, permits, effects, and receipts.
- GitHub Actions artifacts: per-run immutable scan and receipt transport.
- macOS Keychain: local dispatch HMAC key.

No API credential, task prompt, private evidence file, or local ledger is stored
on the state branch.

Repository-policy cache entries are part of the integrity-checked cloud state.
They contain decisions and source blob SHAs, not credentials. A changed blob or
decision-contract digest invalidates the entry before task authorization.
Discovery and live authorization use the same policy-path selector and text
classifier, so post-PR review instructions cannot be mistaken for a pre-PR
assignment requirement by only one stage. Explicit issues-only contribution
policies, including `CONTRIBUTORS.md` rules that accept issues or prompts but
reject source pull requests, are hard-blocked before dispatch.

Actionable opportunities remain in the watchlist and signed queue until local
dispatch. Private Codex task concurrency is independent of publication rollout
mode; an optional `RADAR_MAX_ACTIVE_TASKS` limit can be set explicitly, while
the default does not serialize investigations. Hourly watch evidence forces a rescan on ownership,
closure, strong-PR, or policy changes. Duplicate suppression and transient API
failures do not withdraw an otherwise-valid intent; every task and publication
still performs its own live gate.
