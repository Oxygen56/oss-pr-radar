# OSS PR Radar Heartbeat Controller Protocol

This file is the authoritative protocol for the `oss-pr-radar` desktop
heartbeat. The heartbeat is a controller, not an issue implementation task.

## Fixed boundary

- Work only in `/Users/oxygen/Documents/github/oss-pr-radar`.
- Do not scan issues manually, create tasks manually, rename or archive tasks
  manually, or wait for an issue worktree context.
- Do not run Agent Done-Gate Harness. DeepSeek Harness has its own automation,
  task capacity, state, and metrics.
- The controller owns live GitHub evidence, the durable ledger, task lifecycle,
  Feishu delivery, and policy-permitted publication.
- Public GitHub content must never disclose AI, Codex, automation, credentials,
  or private filesystem paths. A repository that requires AI disclosure may
  receive a private Codex task, but automatic public publication stays blocked.

## One command

From the fixed root, run exactly:

```text
.venv/bin/python scripts/controller_cycle.py
```

This command is the only hourly orchestration entry point. It deterministically:

1. repairs and verifies the 20-second local completion service;
2. checks GitHub scheduling and triggers one bounded repair when needed;
3. reconciles interrupted task creation and exact duplicate tasks;
4. imports a fresh signed queue when safe;
5. refreshes open PR state and ingests completed task results;
6. restores valuable archived tasks, fixes lifecycle titles, and archives only
   exact no-value or duplicate tasks;
7. advances policy-permitted publication and synchronizes task contexts;
8. drains at most one user-visible action, with strict priority:
   existing PR follow-up, validation continuation, recovery, then new issue;
9. sends deduplicated Feishu notifications and dispatch alerts;
10. runs a final fixed-point audit and emits one JSON result.

The single exception is an explicit `desktopHandoff` in the compact result. It
means the Codex desktop app already owns that existing task, so a second local
app server cannot resume it. Send exactly `desktopHandoff.prompt` to
`desktopHandoff.threadId` with the desktop thread tool, once, then stop. The
next controller cycle reconciles the materialized turn and continues the same
task; do not create a replacement task or manually commit the reservation.

The command uses controller and drain locks. `controller_already_running` and
`drain_already_running` are healthy overlap suppression, not failures. Do not
repeat individual lifecycle operations after the command returns.

## Result contract

Use only the final JSON as the run result:

- `ok=true`: no genuine controller failure and no unresolved lifecycle blocker.
- `summary.drainAction`: the one action advanced in this run, or `none`.
- `summary.pendingCount`: ordinary signed queue backlog, not a failure.
- `finalBlockers`: exact durable queues that still require recovery.
- `desktopHandoff`: one idempotent existing-task continuation that must use the
  desktop thread tool because the task has an active desktop writer.
- `failures`: actual failed stages from their latest execution.
- `stages.workflowHealth`: current scheduler and fallback evidence.
- `stages.quality`: SubmitReady, filter-miss, and hard-gate metrics.

An existing active task, serialized queued work, an environment-blocked
validation, policy-suppressed publication, or historical schedule warning is
not a controller execution failure. A publication is real only when the ledger
contains `publicationReceipt.prUrl`.

## Event-driven ownership

The hourly heartbeat is reconciliation and fallback. Normal throughput is
event-driven: the local completion service ingests a terminal result, performs
title/archive/publication reconciliation, and immediately calls the same
serialized drain to advance the next highest-priority task. It does not poll or
re-audit held candidates every 20 seconds when nothing changed.

## User-facing output

- Write for a user who does not know this system's internal vocabulary. Never
  expose queue counts or say controller, drain, dispatch, follow-up, recovery,
  validation environment, quarantine, terminal blocker, receipt, stage, WIP,
  or worktree in the user-facing message.
- When `ok=true` and one issue advanced, say only which issue started or
  continued, whether a PR already exists, and `你无需操作`. Translate every
  internal action into one of: `已开始处理`, `已继续检查现有 PR`, or
  `正在完成发布前检查`.
- When `ok=true` and no issue advanced, return exactly one useful sentence:
  `运行正常；当前没有需要你处理的事情。` Do not report ordinary backlog or
  harmless waiting states.
- When `ok=false`, describe the real user-visible impact and affected issue in
  plain Chinese. Mention an internal name only if there is no accurate plain
  description. Do not paste logs, credentials, prompts, or the full JSON.
