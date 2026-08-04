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
3. **Decision** applies hard gates first. DeepSeek may reject, downgrade, or
   classify semantic competition; it cannot produce a positive authorization.
4. **Cloud handoff** validates the immutable report and signs a promptless,
   expiring intent with HMAC. Notification messages use a durable outbox.
5. **Local authorization** verifies the signature, leases an intent in SQLite,
   repeats all live gates, and creates the canonical prompt locally.
6. **Task identity** binds issue, Codex task ID, project, source repository,
   worktree, first user input, and expected timestamped lifecycle title. The
   selected project must be the exact source repository and must advertise a
   Git repository; parent folders and the radar repository are invalid targets.
7. **Delivery** records either `AUDIT_NO_GO` or SubmitReady evidence. Only the
   latter can create a publication request.
8. **Publication** rechecks the exact clean commit, branch, diff, evidence,
   ownership, duplicates, policy, DCO, identity, fork owner, base branch, PR
   title, and PR body digest. A permit expires quickly and is consumed by the
   verified PR.

## Lifecycle

`QUALIFIED -> LEASED -> DISPATCHED -> AUDIT_PASS -> FIX_READY -> PR_OPEN -> CI_GREEN -> MAINTAINER_ACCEPTED -> MERGED`

`AUDIT_NO_GO` is a terminal no-value outcome and is the only lifecycle state
that authorizes automatic task archival. Shadow observations do not enter the
SubmitReady denominator.

Visible task titles progress through `GO`, `本地修复就绪`, `存在发布请求`,
`PR已开`, and `已合并`, while preserving the original dispatch timestamp. A
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
assignment requirement by only one stage.
