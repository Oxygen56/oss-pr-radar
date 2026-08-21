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
   A missing model configuration becomes a typed semantic-review retry. When the
   configured service is unavailable, a versioned deterministic fallback preserves
   only unusually strong, already-authorized Agent/AI-infra candidates with complete
   reproduction and code-path evidence. Every fallback is explicitly marked; all
   algorithm, policy, assignment, disclosure, competition, and confirmation risks
   remain fail-closed. The scanner and signed intent expose one canonical
   outcome for the issue; model review cannot leave a contradictory second
   status behind.
   `llm_algorithm` is a separate track whose snapshot must bind concrete
   mechanism evidence and a reference, numerical, or controlled-experiment
   validation path. Repository identity alone never qualifies algorithm work.
4. **Cloud handoff** validates the immutable report and signs a promptless,
   expiring intent with HMAC. The signed intent preserves the selected track and
   algorithm evidence. Cloud notifications use a durable, per-candidate-state
   outbox only for maintainer decisions and actionable status changes; a clean
   candidate is not announced as dispatched until the local controller records
   the real Codex task.
5. **Local authorization** imports the signed queue on a five-minute local
   schedule that does not consume a Codex turn. It verifies the signature,
   leases an intent in SQLite, repeats all live gates, and creates the canonical
   prompt locally. Before calling the desktop task API it records `CREATING`; the returned
   `clientThreadId` is persisted before any polling.
6. **Task identity** binds issue, Codex task ID, project, source repository,
   worktree, first user input, and expected timestamped lifecycle title. The
   visible Codex project is always the single `github` project rooted at
   `/Users/oxygen/Documents/github`; repository isolation is provided by the
   controller-managed worktree bound in the private task context. The source
   repository origin must match the issue, and the worktree must belong to that
   source checkout; arbitrary parent folders and the Radar repository are
   invalid implementation targets.
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
   create a publication request. Disclosure policy is not allowed to mask a
   second semantic blocker: private dispatch accepts `WAIT_MAINTAINER` only when
   the signed review reason is `DISCLOSURE_ONLY`; design, assignment, evidence,
   duplicate, and unclassified waits never create a task.
8. **Publication** rechecks the exact clean commit, branch, diff, evidence,
   ownership, duplicates, policy, DCO, identity, fork owner, base branch, PR
   title, and PR body digest. A permit expires quickly and is consumed by the
   verified PR.

## Local Runtime Plane

The local execution plane has three mutually bounded workers:

- The 20-second fast worker performs only local context/result ingestion and
  writes a durable request for slow work. It never clones, fetches, starts a
  Codex turn, publishes, or drains.
- One serialized slow worker owns network access, Git/Codex work, publication,
  and event drain. Failures persist exponential backoff, so a timeout cannot
  turn the fast schedule into a long-running network process.
- A separate five-minute queue importer verifies signed queue data and imports
  write intents only. It has its own lock and cannot invoke the slow worker.
The fast and slow workers use independent `fast-worker.lock` and
`slow-worker.lock` files. Only narrow Ledger transactions and operation-journal
writes are shared; the slow network workflow never holds the fast lock.

Runtime health is an independent execution-plane fact. It requires a real
process/version check when a PID is present, a recent successful cycle, bounded
consecutive failures, zero nonzero exit state, fresh queue import, reconciled
publication effects, acceptable disk/log budgets, a verified immutable release,
and an unchanged policy digest. `state/runtime-health.json` and the append-only
operation log are operational evidence; `state/radar_ledger.sqlite3` remains
the lifecycle authority.

Deployments are clean-source-only immutable directories under `releases/` with
per-file SHA-256 entries and a manifest digest. `current-release` is the only
activation pointer. Previous releases and durable runtime state are retained for
rollback; a damaged or dirty release cannot become active.

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
recovery attempt. Recoveries use the same single-task limit: one active or
authorized recovery keeps every later failed task in a visible queue. An
ambiguous recovery is surfaced instead of retried.

Incomplete validation is evidence-driven rather than timer-driven. A task that
made no progress remains waiting until its controller review, local code,
dependency plan, policy revision, or validation evidence fingerprint differs
from the evidence used for the previous continuation. A new result identifier
alone cannot wake the task. There is no fixed cooldown; genuinely changed
evidence can continue immediately.

## State Ownership

### Target-Branch Binding

Every newly dispatched issue carries a live `targetBase` object containing the
selected branch and the exact remote commit SHA. The controller passes that
binding through the task context, ledger, worktree, merge/commit handoff, and
publication request; publication re-resolves the branch and accepts only the
same commit or a verified fast-forward. A missing or ambiguous live repository
or issue snapshot holds the task before a publishable task is created.

Historical contexts with an explicit `targetBase: null` retain a narrow
compatibility path. Their result digest may be upgraded in memory only when it
is exactly the pre-target-binding digest and all existing identity, worktree,
policy, and receipt checks pass. Legacy publication rechecks the prepared
default branch and its bound SHA immediately before publication; divergence or
an unverifiable branch blocks the action.

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
mode. The default is five durable tasks across issue dispatch, existing-PR
follow-up, and validation continuation. The host must prove that concurrent
project-root turns are isolated before raising this limit; this deployment was
validated with independent concurrent turns in the same Codex project.
`RADAR_MAX_ACTIVE_TASKS=0` disables the bound explicitly.
This is a safety limit on active Codex implementation turns, not a discovery
limit: scanning, evidence collection, queueing, PR refresh, notifications, and
publication reconciliation continue independently. When a task releases the
slot, the local event drain immediately advances the next highest-priority
item. The local signed-queue import also advances newly discovered work within
five minutes. Publishable normal-policy fixes are ordered ahead of private-only
disclosure or legal-review work, so a candidate that cannot be submitted
automatically cannot delay one that can. The hourly heartbeat is only the
reconciliation fallback.
Continuing the same intent for validation or an existing PR update excludes
that intent from the WIP count, so the safety limit cannot deadlock its own
continuation. The independent reviewer shares this same single-writer lane: it
is deferred while any issue task owns an active turn, and a result waiting only
for that review blocks dispatch of a new issue task. This prevents a background
review from interrupting the user-visible issue conversation. Before any new
commit is published, a controller-owned `codex exec` review runs ephemerally in
a read-only sandbox against the exact committed diff;
PR follow-up commits and merge-conflict resolutions use their controller-bound
parent scope. The reviewer starts in an isolated non-repository directory, does
not load target-repository project instructions, and receives a secret-free
environment. Its private receipt lives outside the issue worktree; a task-authored
boolean in `result.json` cannot satisfy the independent-review gate or create a
publication request. The privileged publication boundary repeats this check for
all pending or granted requests, including legacy queue entries. A transport
failure rotates the durable review cursor to the next candidate; there is no
time-based review cooldown and one broken candidate cannot starve the queue.
The root-task owner polls persisted turn status as a watchdog, so a lost
completion notification cannot leave a private app-server alive indefinitely.
Hourly watch evidence forces a rescan on ownership,
closure, strong-PR, or policy changes. Duplicate suppression and transient API
failures do not withdraw an otherwise-valid intent; every task and publication
still performs its own live gate.
