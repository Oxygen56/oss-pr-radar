# Operations

## Schedules

- `radar.yml`: every hour at minute 17 in `Asia/Shanghai`.
- Local Codex heartbeat dispatcher: every hour at minute 45, reusing one
  controller task after the GitHub scan's delay budget.
- Local completion collector: every 20 seconds, ingesting only existing
  workspace results and advancing existing publication requests without an LLM.
- Health watchdog: every hour at minute 55.
- The local dispatcher also runs the health check, so scheduler failure is not
  monitored only by another workflow on the same scheduler.

GitHub scheduled workflows may be delayed under load. The scanner uses a
two-hour update window plus bounded backfill, so one delayed run does not lose
an issue. Both the watchdog and the local dispatcher run the health check with
`--repair`: when neither a successful scan nor a still-active scan is recent,
they dispatch one manual fallback run. A recent active fallback suppresses a
second repair, and workflow concurrency serializes a late natural run behind it.
The desktop controller never waits inside its execution window for that run to
finish. It skips only queue sync, continues live revalidation of unexpired local
signed intents, and retries sync at the end or on the next hourly cycle.

Deferred inspections are oldest-first and receive a dedicated 24-item budget
in addition to the 30-item fresh-issue budget; there is no recheck cooldown. A
terminal rejection drains the item; a transient evidence lookup failure remains
eligible for retry. Candidates that exceed the per-run notification cap are
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

- A missing or corrupt state manifest stops the scan. Run
  `python scripts/state_branch.py migrate` once for a legacy branch.
- An expired or tampered intent is ignored locally.
- An expired ordinary lease can be reclaimed only before task creation starts;
  a `CREATING` record remains exclusive until the exact asynchronous task is
  reconciled or the desktop API explicitly rejects the call without returning
  an external ID.
- A live lease is exclusive even if two controller runs reuse the same owner
  label. Only a stale lease or an asynchronous creation stuck beyond the
  threshold produces a deduplicated Feishu dispatch alert. Plain `PENDING`
  backlog is queue state, not a dispatch failure.
- Before queue sync, `orphan-list` reconciles asynchronous worktree creations
  whose real task ID appeared after the controller's initial lookup. Only one
  unbound task matching creation start time, canonical prompt, repository
  origin, and Codex worktree can be committed; ambiguity fails closed. A bound
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
- Cloud notification state is deduplicated per candidate and material evidence
  state, so adding another candidate to a scan cohort cannot resend unchanged
  issues. The compact candidate-state index is retained independently from the
  seven-day event log, so event cleanup cannot re-arm an unchanged notification.
  Lifecycle watch messages are emitted only for actionable human or PR follow-up.
  Task-created messages are sent locally, one per committed thread, with a
  provider UUID and Ledger receipt.
- A publication side effect records `ATTEMPTED` before execution. Ambiguous
  results become `RECONCILE_REQUIRED` and are never blindly retried. Recovery
  only reads the exact remote branch or pull request bound to the original
  request digest. A successful pull request atomically marks the effect
  successful, consumes the permit, records `PR_OPEN`, and releases dispatch
  capacity. An expired permit can reconcile an existing ambiguous effect but
  can never authorize a new public attempt; a consumed success may only replay
  its stored receipt.
- Install or refresh the local completion collector with
  `python scripts/install_local_publication_agent.py`. Its stdout and stderr are
  stored under `~/Library/Logs/oss-pr-radar/`; an idle cycle is silent. The
  hourly controller repeats ingestion and publication as a fallback.

## Quality Review

Run `local_dispatch_bridge.py metrics --days 30`. Review:

- `submitReadyRate`: primary metric;
- `filterMissRate`: selected tasks later blocked by pre-existing ownership,
  duplicate, or policy evidence;
- `hardGateEscapes`: must remain zero;
- failure classes and exact quality evidence for calibration.

Merge, review, and CI outcomes are retained for diagnosis but are not used as a
quota or discovery score. A failed status alone never makes an existing PR a
competition opportunity.

## Local Dispatcher Order

The single-thread desktop heartbeat runs health with fallback repair, asynchronous
task reconciliation, queue sync,
real dispatch-failure alerts, PR lifecycle refresh, live
claim/revalidation, write-ahead creation, exact-project worktree creation, task
receipt verification, workspace context sync, result ingestion, publication
advancement, one-shot recovery, title synchronization, and `AUDIT_NO_GO`
cleanup in that order. Valid pending intents are ordinary queue state and must
not be treated as a failed run; publication canary state does not cap private
task creation.
`githubNaturalScheduleHealthy` refers only to GitHub Actions cron delivery;
`operationalHealthy` also accepts a recent successful or currently active
manual/fallback scan. The desktop heartbeat's own trigger is a separate signal.
An issue task waits up to three minutes for its workspace-local context. A
missing file ends privately without Plan Hub, external ledger access, elevated
permission, or inferred authorization.
