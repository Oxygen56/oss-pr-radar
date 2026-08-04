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

Deferred inspections are oldest-first and receive a dedicated 10-item budget
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
every hourly run.

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
- An expired lease can be reclaimed; a dispatched receipt is idempotent.
- A live lease is exclusive even if two controller runs reuse the same owner
  label. A signed intent waiting at least 70 minutes, or a stale lease, produces
  a deduplicated Feishu dispatch alert.
- A task that remains dispatched without an outcome for 90 minutes enters the
  local recovery list. Only an obviously empty or `完成`-only task may receive
  one repeat of the exact canonical prompt. The reservation is written before
  the message; an ambiguous send is reported and never retried automatically.
- Notification send attempts use a provider UUID and a durable receipt. A
  provider success followed by a lost receipt remains a documented residual
  duplicate risk after the provider's one-hour deduplication window.
- A publication side effect records `ATTEMPTED` before execution. Ambiguous
  results become `RECONCILE_REQUIRED` and are never blindly retried.

## Quality Review

Run `local_dispatch_bridge.py metrics --days 30`. Review:

- `submitReadyRate`: primary metric;
- `filterMissRate`: selected tasks later blocked by pre-existing ownership,
  duplicate, or policy evidence;
- `hardGateEscapes`: must remain zero;
- failure classes and exact quality evidence for calibration.

Merge, review, and CI outcomes are retained for diagnosis but are not used as a
quota or discovery score.

## Local Dispatcher Order

The single-thread desktop heartbeat runs health with fallback repair, queue sync,
dispatch-age alerts, PR lifecycle refresh, live
claim/revalidation, exact-project worktree creation, task receipt verification,
one-shot recovery, title synchronization, and `AUDIT_NO_GO` cleanup in that
order. A canary WIP limit may leave valid pending intents in the queue; this is
normal and must not be treated as a failed run.
An issue task's first `task-context` lookup waits briefly only when the ledger
shows a live lease for that exact issue, closing the create-thread/receipt race
without treating an unregistered prompt as authorization.
