# Operations

## Schedules

- `radar.yml`: every hour at minute 17 in `Asia/Shanghai`.
- Local Codex heartbeat dispatcher: every hour at minute 45, reusing one
  controller task after the GitHub scan's delay budget.
- Health watchdog: every hour at minute 55.
- The local dispatcher also runs the health check, so scheduler failure is not
  monitored only by another workflow on the same scheduler.

GitHub scheduled workflows may be delayed under load. The scanner uses a
two-hour update window plus bounded backfill, so one delayed run does not lose
an issue. Both the watchdog and the local dispatcher run the health check with
`--repair`: when neither a successful scan nor a still-active scan is recent,
they dispatch one manual fallback run. A recent active fallback suppresses a
second repair, and workflow concurrency serializes a late natural run behind it.

Deferred inspections are oldest-first and receive a dedicated 24-item budget
in addition to the 30-item fresh-issue budget; there is no recheck cooldown. A
terminal rejection drains the item; a transient evidence lookup failure remains
eligible for retry. Candidates that exceed the per-run notification cap are
stored as `candidate_overflow` instead of being silently lost.

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
- `canary`: create and automatically deliver at most one active task.
- `active`: no canary WIP cap; all other gates remain unchanged.

Use `canary` as the normal production mode until the rolling sample is large
enough to justify higher concurrency. The WIP cap is a throughput control, not
a quality KPI or a publication-policy bypass.

## Recovery

- A missing or corrupt state manifest stops the scan. Run
  `python scripts/state_branch.py migrate` once for a legacy branch.
- An expired or tampered intent is ignored locally.
- An expired ordinary lease can be reclaimed only before task creation starts;
  a `CREATING` record remains exclusive until the exact asynchronous task is
  reconciled or the desktop API explicitly rejects the call without returning
  an external ID.
- A live lease is exclusive even if two controller runs reuse the same owner
  label. A signed intent waiting at least 70 minutes, or a stale lease, produces
  a deduplicated Feishu dispatch alert.
- Before queue sync, `orphan-list` reconciles asynchronous worktree creations
  whose real task ID appeared after the controller's initial lookup. Only one
  unbound task matching creation start time, canonical prompt, repository
  origin, and Codex worktree can be committed; ambiguity fails closed. A bound
  `clientThreadId` remains visible in alerts and is never silently reclaimed.
- `context-sync` writes a Git-ignored task context into each registered
  worktree. `ingest-results` validates the exact issue, thread, worktree, and
  context digest before recording lifecycle evidence. Child tasks never need
  external database access or interactive approval.
- A task that remains dispatched without an outcome for 90 minutes enters the
  local recovery list. Only an obviously empty or `完成`-only task may receive
  one repeat of the exact canonical prompt. The reservation is written before
  the message; an ambiguous send is reported and never retried automatically.
- Notification send attempts use a provider UUID and a durable receipt. A
  provider success followed by a lost receipt remains a documented residual
  duplicate risk after the provider's one-hour deduplication window.
- A publication side effect records `ATTEMPTED` before execution. Ambiguous
  results become `RECONCILE_REQUIRED` and are never blindly retried. Recovery
  only reads the exact remote branch or pull request bound to the original
  request digest. A successful pull request atomically marks the effect
  successful, consumes the permit, records `PR_OPEN`, and releases dispatch
  capacity. An expired permit can reconcile an existing ambiguous effect but
  can never authorize a new public attempt; a consumed success may only replay
  its stored receipt.

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
dispatch-age alerts, PR lifecycle refresh, live
claim/revalidation, write-ahead creation, exact-project worktree creation, task
receipt verification, workspace context sync, result ingestion, publication
advancement, one-shot recovery, title synchronization, and `AUDIT_NO_GO`
cleanup in that order. A canary WIP limit may leave valid pending intents in
the queue; this is normal and must not be treated as a failed run.
`githubNaturalScheduleHealthy` refers only to GitHub Actions cron delivery;
`operationalHealthy` also accepts a recent successful or currently active
manual/fallback scan. The desktop heartbeat's own trigger is a separate signal.
An issue task waits up to three minutes for its workspace-local context. A
missing file ends privately without Plan Hub, external ledger access, elevated
permission, or inferred authorization.
