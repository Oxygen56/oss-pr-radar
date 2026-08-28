# Operations

## Schedules

- `radar.yml`: every hour at minute 17 in `Asia/Shanghai`.
- Local Codex heartbeat dispatcher: every hour at minute 30, reusing one
  controller task after the GitHub scan's delay budget.
- Local completion collector: every 20 seconds, ingesting existing workspace
  results, advancing existing publication requests without an LLM, and invoking
  one serialized event drain only when a result or lifecycle transition releases
  task capacity. The same local process imports the latest signed cloud queue
  every five minutes and advances new work without consuming a Codex heartbeat
  turn.
- Health watchdog: every hour at minute 55.
- The local dispatcher also runs the health check, so scheduler failure is not
  monitored only by another workflow on the same scheduler.

GitHub scheduled workflows may be delayed under load. The scanner uses a
two-hour update window plus bounded backfill, so one delayed run does not lose
an issue. The local dispatcher runs the bound health check with `--repair`: when
neither a successful scan nor a still-active scan is recent, it dispatches one
manual fallback run. The GitHub health watchdog is intentionally read-only and
only reports freshness; it has no local runtime authorization and cannot repair
or notify. A recent active fallback suppresses a second repair, and workflow
concurrency serializes a late natural run behind it.
The desktop controller never waits inside its execution window for that run to
finish. It skips only queue sync and continues live revalidation of unexpired
local signed intents. The five-minute local importer picks up the completed
cloud queue independently, so a delayed or quota-blocked Codex heartbeat cannot
stop new issue tasks.

All public `local_dispatch_bridge.py` operations require an explicit
`--runtime-root` bound to the active release and a valid operational
authorization. This applies even to commands whose primary result is a
listing, because reconciliation paths may update managed ledger or lifecycle
records. There is no unauthenticated or skip-auth CLI mode. The
`publication_executor.py` `push` and `create-pr` commands are internal bridge
children and reject direct calls without the same runtime binding. Workflow
health inspection remains available as a read-only check, but `--repair` and
`--notify` require the binding and authorization before any GitHub or Feishu
action.

Deferred inspections are oldest-first and receive a dedicated 24-item budget
in addition to the 30-item fresh-issue budget; there is no recheck cooldown. A
terminal rejection drains the item. A transient evidence or semantic-model
failure stays typed as retryable while the underlying issue snapshot is fresh.
Semantic-service outages do not stop the whole pipeline: the scanner may retain an
already-authorized Agent/AI-infra candidate only under the strict deterministic
fallback contract documented in the architecture. This never applies to algorithm,
policy, assignment, disclosure, competition, or confirmation-sensitive candidates.
After 24 hours without a new issue update, that retry is retired as
`deferred_expired`; a later issue update naturally creates a new evidence epoch
and re-arms inspection. Candidates that exceed the per-run notification cap are
stored as `candidate_overflow` instead of being silently lost.

Within the fresh-issue budget, up to 12 positions are reserved for the
`llm_algorithm` track and unused positions are backfilled by either track. The
final shortlist reserves three candidate positions per track, then fills unused
capacity by score. This is a fairness mechanism, not a weaker quality threshold.

Watchlist evidence and open-PR follow-up run in parallel jobs. Watchlist items
use three bounded workers and share one policy snapshot per repository; open PR
checks use four bounded workers. Scanner policy text is reused only when the
repository policy blob SHAs and the decision-contract digest are unchanged.

Deferred rechecks have a separate 24-item budget. Ordering uses the first
deferred timestamp rather than the latest retry timestamp, and previously
actionable candidates retain their score and receive priority. This prevents a
busy fixed-repository feed from pushing the same opportunity to the back on
every hourly run. Rechecks and fresh issues are interleaved before the
wall-clock deadline, so a backlog cannot consume the entire useful prefix of a
scan. Fresh issues with bug/performance labels, public reproduction or root
cause signals, and a recent creation timestamp are inspected first. The scan
report records policy-migration selections
separately, and recomputes the remaining count after LLM review and notification
staging so it matches the durable `seen.json` state.

## Rollout Modes

- `shadow`: verify signed handoff and live decisions; create no task.
- `canary`: create normal private tasks, but serialize automatic public publication.
- `active`: create normal private tasks and use the regular publication path.

Use `canary` as the normal production mode until the rolling publication sample
is large enough. Publication rollout is independent of private task dispatch;
one blocked implementation must never prevent other qualified issues from
receiving their own worktrees.

## Recovery

- Treat `docs/controller-heartbeat.md` as the single source of truth for the
  desktop automation. The saved automation prompt should only select the fixed
  runtime directory and require that protocol; do not duplicate the checklist
  in desktop configuration.
- Deploy local controller updates only through `scripts/deploy_local_runtime.py`.
- The deployment source must be clean. The deployer creates a new immutable
  `releases/<commit>-<manifest-digest>/` directory, verifies every file hash,
  then atomically moves `current-release` together with the verified
  `state/runtime-health.json` deployment identity (`releaseVersion`,
  `policyDigest`, `manifestVerified`, and `deploymentDirty`). Existing worker
  observations and other runtime state are preserved. A private, recoverable
  activation journal protects the pointer/health pair across a crash; any
  write failure restores both sides, and a pending journal keeps strict
  acceptance fail-closed until recovered. It never overwrites a previous
  release or durable state; rollback uses the same transaction to point at a
  previously verified release and update its identity.
- Repair task title drift with `local_dispatch_bridge.py title-reconcile`; it applies
  and verifies lifecycle titles through the local Codex app-server protocol.
- A missing or corrupt state manifest stops the scan. Run
  `python scripts/state_branch.py migrate` once for a legacy branch.
- If the local lifecycle database is missing or replaced, queue sync verifies
  each controller-owned task context against its byte-identical worktree mirror,
  digest, permissions, repository origin, and managed path. It then rebuilds
  completed task, consumed publication records, and the exact digest of any
  clean result already represented by a published commit before accepting any
  new intent. The local publication agent performs this recovery before result
  ingestion and stops the whole cycle on any recovery or ingestion error. A
  mismatch therefore fails closed before duplicate task creation or publication.
- An expired or tampered intent is ignored locally.
- An expired ordinary lease can be reclaimed only before task creation starts;
  a `CREATING` record remains exclusive until the exact asynchronous task is
  reconciled or the desktop API explicitly rejects the call without returning
  an external ID.
- A live lease is exclusive even if two controller runs reuse the same owner
  label. Only a stale lease or an asynchronous creation stuck beyond the
  threshold produces a deduplicated Feishu dispatch alert. Plain `PENDING`
  backlog is queue state, not a dispatch failure.
- Before reserving asynchronous task creation, the local bridge refreshes the
  source index, materializes only the current remote default-branch snapshot,
  and prepares a deterministic isolated worktree under
  `~/Documents/github/.oss-pr-radar/worktrees/`. The Codex task itself starts in
  the single `github` project and consumes a per-issue bootstrap context from
  `.oss-pr-radar/task-contexts/`. New contexts use the bounded, reversible
  `.oss-pr-radar/task-contexts/v2/<owner-token>/<repo-token>/<issue>.json`
  layout; legacy root-level names remain readable only when their repository
  identity is unambiguous. This keeps UI ownership stable while preserving
  repository isolation and avoiding lazy partial-clone timeouts.
- Before queue sync, `orphan-list` reconciles asynchronous worktree creations
  whose real task ID appeared after the controller's initial lookup. Only one
  unbound task matching creation start time, canonical prompt, exact GitHub
  project root, and prepared worktree can be committed; legacy repository-project
  worktrees remain supported. Ambiguity fails closed. A bound
  `clientThreadId` remains visible in alerts and is never silently reclaimed.
- `context-sync` writes a Git-ignored task context and repairs legacy contexts
  by attaching a fresh controller-side live audit. `ingest-results` validates
  the exact issue, thread, worktree, audit digest, and context digest before
  recording lifecycle evidence. Child tasks never use GitHub/network commands,
  external database access, interactive approval, or Git-metadata writes. The
  controller commits only the child's exact `changedFiles` allowlist and applies
  DCO sign-off with the configured Git identity when required.
- Active open PRs that directly target the issue block another implementation
  regardless of draft, test, or CI status. Only a direct PR stale for at least
  30 days without a maintainer signal can enter private competition review.
- Root PR templates and AI/CLA/DCO policy files are read before nested
  `AGENTS.md` or translated contribution copies. Non-standard contribution
  relicensing agreements are filtered before task creation.
- A task that remains dispatched without an outcome for 90 minutes enters the
  local recovery list. Only an obviously empty or `完成`-only task may receive
  one repeat of the exact canonical prompt. The reservation is written before
  the message; an ambiguous send is reported and never retried automatically.
- An asynchronous task creation that returned a client ID but still has no
  uniquely matching Codex task after 70 minutes is reported as safely
  abandonable. `creation-abandon` rechecks the local task catalog and requires
  the original owner, stored creation token, client ID, age threshold, and
  fresh abandonment nonce before releasing it for a later signed intent.
- Cloud notification state is deduplicated per candidate and material evidence
  state, so adding another candidate to a scan cohort cannot resend unchanged
  issues. The compact candidate-state index is retained independently from the
  seven-day event log, so event cleanup cannot re-arm an unchanged notification.
  Lifecycle watch messages are emitted only for actionable human or PR follow-up.
  Task-created messages are sent locally, one per committed thread, with a
  provider UUID and Ledger receipt.
- Open-PR follow-up separates notification evidence from task-actionable
  evidence. Cancelled jobs, aggregate status checks, and failures unrelated to
  the PR's changed files may notify but do not wake a Codex task. A maintainer
  change request, still-current maintainer or review-bot thread, merge conflict,
  or branch-attributable failed check creates a
  durable wake digest. The controller prepares the exact live PR head, refreshes
  the private task context, and, for conflicts, aligns the signed target-branch
  head and records the complete conflict-file set from a temporary merge before
  restoring a clean worktree and sending the canonical prompt to the original
  task. A fast-forwarding target branch is captured in that prepared snapshot;
  a divergent or rewritten base is rejected. A changed base head creates a new
  wake digest. The wake receipt is committed only after that send succeeds.
- A validated follow-up patch creates a `PR_UPDATE` publication request bound to
  the exact existing PR URL, public branch, and previous remote head. The
  executor permits only a fast-forward push and verifies that the same open PR
  now points to the permitted commit; it never opens a second PR.
- A PR follow-up reservation records its prepared commit and immutable evidence
  snapshot in the append-only ledger. Later audit refreshes cannot replace that
  parent binding or dispatch a second follow-up while the task is active.
  A follow-up whose managed worktree contains uncommitted changes is isolated
  as `worktree_dirty`; the bridge preserves those changes, reports a quarantine
  warning, and continues to the next serialized candidate instead of failing
  the whole drain. A pending lifecycle title is likewise an eventual-sync
  warning while its task is active, not a controller failure.
  Legacy reservations are repaired
  only when the worktree head is the original PR head or a verifiable
  controller-created base-integration merge. An older incomplete reservation is
  closed as superseded only when the ledger contains a later ingested PR
  follow-up result for the same opportunity.
- A publication side effect records `ATTEMPTED` before execution. Ambiguous
  results become `RECONCILE_REQUIRED` and are never blindly retried. Recovery
  only reads the exact remote branch or pull request bound to the original
  request digest. A successful pull request atomically marks the effect
  successful, consumes the permit, records `PR_OPEN`, and releases dispatch
  capacity. An expired permit can reconcile an existing ambiguous effect but
  can never authorize a new public attempt; a consumed success may only replay
  its stored receipt.
- Stage or activate the local completion collector only through the explicit
  release-bound `--stage`, `--activate`, or steady-state `--ensure` modes; the
  production controller uses `--ensure` after operational authorization. The
  20-second fast worker
  only ingests local receipts and enqueues slow work. The installer registers the
  slow worker and five-minute queue importer from their separate specs; their
  `fast-worker.lock` and `slow-worker.lock` are independent. Shared Ledger and
  operation writes are short-lived and idempotent, so slow network work cannot
  block receipt registration. Their stdout and stderr are stored
  under `~/Library/Logs/oss-pr-radar/` and rotated before a new one-shot run.
  `python scripts/runtime_audit.py` is read-only and must be used for service
  health: a loaded LaunchAgent is not healthy when its real PID/version,
  successful-cycle freshness, failure streak, exit code, queue-import age,
  pending publication effects, disk, log, release, or policy checks fail. A
  publishable fix with incomplete SubmitReady evidence is reported once as
  `validationDeferred` and settles as non-terminal `VALIDATION_PENDING`. It is
  titled as valuable work awaiting validation, releases dispatch capacity, and
  never enters the no-value cleanup queue. The controller consumes
  `validation-followup-list` and reserves the exact result digest. During that
  reservation, the bridge computes, validates, and runs any required
  lockfile-scoped Cargo, Go, Python, or Node dependency prefetch itself; this
  includes Go test/vet/build gates and locked Python pytest, Ruff, Pyright, or
  pre-commit environments. The controller never interprets or executes
  dependency commands. It then resumes the same task once. A changed result
  digest rearms validation without duplicating the previous wake-up. If the
  app server returns a durable receipt proving that no target turn started,
  the local collector retires the failed reservation after one minute and
  retries the same serialized work item. It never releases a reservation on an
  ambiguous or materialized turn. A sent follow-up that remains on the same
  validation result for 90 minutes is surfaced in the `stale` list as an
  operational failure; it is not silently treated as healthy or automatically
  sent again.
  The same intent is excluded from the global WIP count while its validation
  turn is reserved; another active intent still blocks it. A committed
  `FIX_READY` result whose independent-review field is incomplete is reviewed by
  an ephemeral, read-only controller process, including commits that update an
  existing PR. The isolated reviewer does not load the target repository's
  project instructions or secret environment variables. The result advances only
  when the controller-private receipt is bound to the exact commit and evidence
  digest; the review creates no sidebar task and performs no public action.
  Pending and granted publication requests are rechecked at the privileged
  execution boundary, so a legacy request cannot inherit a task-authored pass.
  Reviewer transport failures persist a fair-rotation cursor and move the next
  cycle to another candidate; no time-based review cooldown is used.
  Broad validation failures must be compared against the same gate on the
  parent baseline. They may be treated as unrelated only when the failure set
  is entirely pre-existing and all changed-path functional, type, format, and
  repository-specific gates that actually apply to the changed paths pass.
  Missing optional provider or all-extras dependencies in an unrelated registry
  check are recorded as not applicable or environment-limited, not as a changed-
  path failure. Explicitly interrupted validation turns are
  different: the controller may
  recover the same task as soon as its detached owner has exited and no newer
  result was ingested. The first-turn `root-task-worker` and continuation
  `task-turn-worker` both count as owners. While either worker is alive the task
  remains `terminal_turn_worker_draining`, because its in-flight checks may
  still write the awaited result. A later result with complete evidence may advance it to
  `FIX_READY`. A
  policy-blocked fix may settle as local `FIX_READY`
  only when the technical evidence is complete and `policy_verified` is the
  sole missing field. The controller gives that policy check one continuation;
  if it remains the only missing field, the task settles with
  `REPOSITORY_POLICY_EVIDENCE_REQUIRED` and never creates a publication request.
  The hourly
  controller repeats ingestion and publication as a fallback.
- For controller-owned commits, the publication base is taken from the
  prepared checkout's `origin/HEAD`. A child-provided release or stale branch
  hint cannot create a permanently blocked publication request.
- New tasks persist the live `targetBase` branch and SHA through the context,
  ledger, worktree, controller handoff, and publication request. Publication
  rechecks that branch immediately before the external action and accepts only
  the same commit or a verified fast-forward. Historical `targetBase: null`
  tasks use the prepared default branch only after its bound SHA is rechecked;
  drift or an unavailable branch blocks publication.
- Controller terminal feedback retains the state branch stale-write guard. On
  concurrent cloud writes it restores and merges again with bounded backoff,
  so a short scanner or watchdog publish does not exhaust immediate retries.

## Quality Review

Run `local_dispatch_bridge.py --runtime-root <runtime-root> metrics --days 30`. Review:

- `submitReadyRate`: primary metric;
- `filterMissRate`: selected tasks later blocked by pre-existing ownership,
  duplicate, or policy evidence;
- `hardGateEscapes`: must remain zero;
- failure classes and exact quality evidence for calibration.

Merge, review, and CI outcomes are retained for diagnosis but are not used as a
quota or discovery score. A failed status alone never makes an existing PR a
competition opportunity.

## Local Dispatcher Order

The desktop heartbeat runs only the exact active-release command
`.venv/bin/python current-release/scripts/controller_cycle.py --root <runtime-root> --code-root <runtime-root>/current-release`.
The command owns health repair,
interrupted creation, queue sync, PR refresh, ingestion, restoration, titles,
cleanup, publication, notifications, final audit, and one serialized drain.
The drain always prioritizes existing PR follow-up, validation continuation,
and recoverable work before a new issue. New tasks use write-ahead creation, the
single `github` project, an isolated source worktree, and an exact task receipt.
Valid pending intents are ordinary queue state and publication canary state does
not cap private task creation. No heartbeat step manually interprets a queue,
renames a task, archives a task, or calls the desktop task API.
Within new issue work, normal-policy candidates that can be published are
processed before disclosure- or legal-review-only candidates. Both classes
remain durable; the ordering only prevents a non-publishable task from delaying
a directly actionable PR.
The local completion collector also reconciles lifecycle titles and archives
exact `[无价值]` `AUDIT_NO_GO` tasks immediately after ingesting a result, so a
completed no-go task does not remain visible as valuable or wait for the next
hourly heartbeat to be cleaned up. The same event then advances at most one next
task under the shared drain lock. An idle 20-second cycle performs no live audit
and creates no task.

Stage 7 keeps executable code under the verified immutable release while
`state`, `.venv`, and `reports` stay under the runtime root. The local ledger
cutover is reversible and pointer-only:

```bash
python current-release/scripts/stage7_cutover.py prepare \
  --runtime-root <runtime-root> --source <ledger-copy> \
  --quiesce-token <writer-stop-proof>
python current-release/scripts/stage7_cutover.py activate \
  --runtime-root <runtime-root> --manifest <prepared-manifest>
python current-release/scripts/stage7_cutover.py status --runtime-root <runtime-root>
python current-release/scripts/stage7_cutover.py rollback \
  --runtime-root <runtime-root> --manifest <activated-manifest>
```

The complete first-deployment order starts by running the deployer from an
accepted clean candidate checkout, because a new runtime has no
`current-release` yet:

```bash
python <accepted-clean-source>/scripts/deploy_local_runtime.py \
  --source <accepted-clean-source> --target <runtime-root>
```

This verifies the source before changing the target. It creates the immutable
release and pointer, and atomically adds the complete runtime-owned set
`/current-release`, `/releases/`, `/reports/`, `/state/`, and `/.venv/` to the
target repository's private `.git/info/exclude`; it does not modify tracked
production files or overwrite existing exclude rules. The tracked
`state/.gitkeep` exception remains tracked and is not hidden by the exclude.
The candidate repository's `.gitignore` contains the same local-runtime rules
for new repositories. The complete order is then: stop and sign live service
evidence, bootstrap the retained legacy ledger, create the authoritative live
snapshot, verify the Stage 6 report and detached envelope, run the Stage 6
rehearsal, prepare the managed ledger without any live-state input, rehearse Git
preservation restore in an isolated clone, activate the pointer (which revokes
any old operational authorization), generate and validate managed-counts evidence
against the exact Stage 6 projection, issue the short-lived worker-staging
authorization, stage the three worker plists unloaded, update the two automations,
generate the automation snapshot from the actual TOML files and staged plist bytes,
run strict preflight, issue the operational authorization (which revokes only the
staging permit), activate the workers, and finally run strict final acceptance. If any preflight fails,
roll back the pointer and do not load or run a worker. Worker installation is
split into these two release-bound commands:

```bash
python current-release/scripts/stage7_evidence.py worker-staging-authorization \
  --runtime-root <runtime-root> \
  --managed-counts-evidence <managed-counts-evidence>
python current-release/scripts/install_local_publication_workers.py \
  --runtime-root <runtime-root> --stage
# Update both automations, then generate <automation-snapshot> from their actual
# TOML files and the three staged plist files.
python current-release/scripts/stage7_evidence.py operational-authorization \
  --runtime-root <runtime-root> \
  --managed-counts-evidence <managed-counts-evidence> \
  --automation-snapshot <automation-snapshot>
python current-release/scripts/install_local_publication_workers.py \
  --runtime-root <runtime-root> --activate
```

`--status` is a runtime-bound read-only check. `--stage` requires the short-lived
signed stage-only authorization; `--activate`, `--ensure`, and `--uninstall`
require the active immutable release and full operational authorization before
any plist write or service operation. The
historical `install_local_publication_agent.py` entrypoint is only a
compatibility forwarder to the three-worker installer; it cannot generate,
install, or start the old monolithic or fast-only service.

Rollback is the final pointer-only step and retains both ledger versions. The
exact machine-readable order and arguments are exported by
`current-release/scripts/automation_command_contracts.py`; do not reconstruct
these commands in an automation prompt.

Before the Stage 6 compact rehearsal, create the authoritative live PR input
from the legacy database. This command makes a private stable source backup,
replays the same pre-migration inputs used by Stage 6, and performs only
read-only GitHub requests. It writes one atomic 0600 file only after every PR
has been observed successfully:

```bash
python current-release/scripts/snapshot_managed_pr_states.py \
  --source <legacy-ledger-source> \
  --legacy-db <legacy-war-room-db> \
  --legacy-reports <legacy-reports-dir> \
  --followup <followup-snapshot> \
  --quiesce-token <writer-stop-proof> \
  --out <live-states.json> \
  --workers 4 --max-attempts 3
```

The output is bound to the source SQLite logical generation, including WAL
state, the legacy database generation, the legacy reports and follow-up
digests, and the exact managed PR key-set digest. If any input changes before
or after the GitHub reads, the command fails closed and leaves no partial
output. Pass this exact file to the Stage 6 rehearsal; do not construct live
states by hand. The terminal output is only a compact receipt; full
observations remain in the private 0600 file.

Stage 6 verification results are generated, never typed into the report. From
the active release, use a dedicated verification root and report root:

```bash
python current-release/scripts/stage6_manifest.py \
  --artifact-root <verification-report-root> \
  --verification-out <verification-root>/verification-manifest.json \
  --run
```

This executes every versioned check and atomically writes the standalone 0600
verification manifest. Instead of `--run`, `--results <captured-results.json>`
may provide exactly those passing command results. Missing, extra, failed,
skipped, non-zero, or malformed results are rejected before either output is
created. The versioned `code-integrity` verifies the release manifest or exact clean
development root and does not search a parent Git repository; run `git diff
--check` separately for local development hygiene. Keep `<verification-root>` and the final rehearsal root separate, then
pass the standalone file directly to the compact rehearsal:

```bash
python current-release/scripts/stage6_compact_rehearsal.py \
  --artifact-root <final-rehearsal-root> \
  --verification-manifest <verification-root>/verification-manifest.json \
  --source <source-ledger> --legacy-db <legacy-db> \
  --legacy-reports <legacy-reports> --followup <followup> \
  --live-states <live-states.json> --code-head <verified-head> \
  --observed-at <snapshot-observed-at>
```

The Codex automation files use their actual application format. Generate the
signed snapshot only from the two current TOML files; it validates the exact
shared durable thread target for both heartbeats, the daily 09:00 schedule,
timestamps, prompt template, active-release command and worker plists:

```bash
python current-release/scripts/stage7_evidence.py automation-snapshot \
  --runtime-root <runtime-root> \
  --heartbeat-toml <heartbeat-automation.toml> \
  --daily-toml <daily-automation.toml> \
  --out <automation-snapshot.json>
```

Generate managed counts only from an independently verified Stage 6 public
report and detached envelope. The runtime ledger is checked against that
baseline; it cannot create its own expected baseline:

```bash
python current-release/scripts/stage7_evidence.py managed-counts \
  --runtime-root <runtime-root> --report <stage6-report.json> \
  --envelope <stage6-envelope.json> --code-head <verified-release-head> \
  --out <managed-counts-evidence.json>
```

Before activation, rehearse the signed Git preservation archive. Rehearsal
uses a no-hardlink clone and checks tracked binary patch bytes plus every
untracked file's bytes, mode and digest. `apply` is allowed only for the exact
clean repository identity and stages the complete restore before changing it;
any failure restores the pre-apply clean state without broad cleanup:

```bash
python current-release/scripts/stage7_cutover.py restore \
  --manifest <prepared-manifest> --repo <source-repo> --mode rehearse
python current-release/scripts/stage7_cutover.py restore \
  --manifest <prepared-manifest> --repo <exact-clean-repo> --mode apply
```

The default acceptance output is `PUBLIC_SAFE`: absolute local paths and
token-like values are redacted. Use `--private` only for restricted local
operations evidence. Raw SQLite/WAL/SHM files, Git patches, API payloads and
full private manifests must never be copied into a shareable report.

Stage 6's versioned YAML check explicitly parses `.github/workflows/ci.yml`,
`.github/workflows/health.yml`, and `.github/workflows/radar.yml` one by one
with Ruby Psych. A parse error in any file makes the check fail; hidden
workflow directories are part of the acceptance scope.

Prepare never changes the active ledger pointer. Activation and rollback only
atomically replace that pointer; every versioned SQLite file remains retained.
On a first deployment, stop all workers and record a service-stopped evidence
file, then retain the legacy database before preparing the managed ledger:

```bash
python current-release/scripts/stage7_cutover.py bootstrap \
  --runtime-root <runtime-root> --legacy-source <legacy-ledger> \
  --service-stopped-evidence <stopped-evidence> \
  --quiesce-token <writer-stop-proof>
```
Bootstrap accepts only the pre-managed legacy database and only when the
current-ledger pointer is absent. It never substitutes for managed prepare.

DeepSeek Harness runs as a separate product automation. It does not share the
Radar ledger, scanner state, task WIP slot, task contexts, controller command,
or quality metrics; only the user's common GitHub identity and normal repository
policies are shared.
`githubNaturalScheduleHealthy` refers only to GitHub Actions cron delivery;
`operationalHealthy` also accepts a recent successful or currently active
manual/fallback scan. Historical rolling-window gaps are reported separately in
`githubNaturalScheduleWarnings`; they do not describe a current outage or
trigger a duplicate fallback. The desktop heartbeat's own trigger is a separate
signal.
An issue task waits up to three minutes for its workspace-local context. A
missing file ends privately without Plan Hub, external ledger access, elevated
permission, or inferred authorization.
