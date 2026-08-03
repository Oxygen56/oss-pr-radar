# Operations

## Schedules

- `radar.yml`: every hour at minute 17 in `Asia/Shanghai`.
- Local Codex dispatcher: every hour at minute 45, after the GitHub scan's delay budget.
- Health watchdog: every hour at minute 55.
- The local dispatcher also runs the health check, so scheduler failure is not
  monitored only by another workflow on the same scheduler.

GitHub scheduled workflows may be delayed under load. The scanner uses a
two-hour update window plus bounded backfill, so one delayed run does not lose
an issue.

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

The desktop automation runs health, queue sync, PR lifecycle refresh, live
claim/revalidation, exact-project worktree creation, task receipt verification,
one-shot recovery, title synchronization, and `AUDIT_NO_GO` cleanup in that
order. A canary WIP limit may leave valid pending intents in the queue; this is
normal and must not be treated as a failed run.
