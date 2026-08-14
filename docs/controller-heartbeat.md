# OSS PR Radar Heartbeat Controller Protocol

This file is the authoritative protocol for the `oss-pr-radar` heartbeat. The
heartbeat prompt must point here instead of embedding a second copy of the
protocol.

The initial file-read command must return this file's full content in tool
output. Never redirect it to `/dev/null`, truncate it, or combine it with a
long-running command.

## Role and boundaries

- This is the desktop controller, not an issue task. Work only in
  `/Users/oxygen/Documents/github/oss-pr-radar` and never wait for an issue
  worktree context.
- Do not scan issues directly, read or update memory, use Plan Hub, run the old
  Agent Done-Gate Harness, or emit progress commentary.
- The controller owns live GitHub evidence, the durable ledger, lifecycle
  transitions, Feishu notifications, task dispatch, and permitted publication.
- Issue tasks consume controller snapshots. They must not request network,
  filesystem, or other routine approvals.
- Never disclose AI, Codex, or automation in public GitHub content. If a
  repository requires disclosure, suppress automatic publication and report the
  policy conflict.

Set these fixed values:

```text
ROOT=/Users/oxygen/Documents/github/oss-pr-radar
PY=/Users/oxygen/Documents/github/oss-pr-radar/.venv/bin/python
BRIDGE=/Users/oxygen/Documents/github/oss-pr-radar/scripts/local_dispatch_bridge.py
PROJECT_ID=5e41d21c-cba3-4be0-9a02-7eef35b67625
PROJECT_PATH=/Users/oxygen/Documents/github
LEASE_OWNER=heartbeat-019f71c3-4f26-7030-b126-25f8cfbac4c4
```

Every command below runs from `ROOT`. For commands that can exceed one tool
yield, especially `claim --prepare`, the tool wrapper must emit the complete
`exec_command` result with `text(JSON.stringify(result))`, not only
`text(result.output)`. If that result contains `session_id`, poll that exact ID
with `write_stdin` until an `exit_code` is returned. `functions.wait` waits only
for the outer tool cell and is not a substitute for polling the returned command
session. Empty output accompanied by a session ID means still running, never
"no result"; do not release the claim while that session exists.

## 1. Runtime and health

1. Run `scripts/install_local_publication_agent.py`, then run it again with
   `--status`. Record `localPublicationAgentHealthy`; installation is an
   idempotent repair, not a user-maintenance request.
   A valid historical context whose worktree was removed, or whose local mirror
   is temporarily absent after workspace recreation, is reported under
   `unavailable`; it is a durable recovery warning and must not block unrelated
   queue sync, result ingestion, or publication. `context-sync` repairs a
   missing mirror when the managed worktree is otherwise valid.
2. Run `scripts/check_workflow_health.py --max-effective-age-minutes 110
   --repair`. Record `operationalHealthy`, `githubNaturalScheduleHealthy`,
   `repairTriggered`, `repairSuppressedReason`, `recentActive`, and `fallback`.
   `GITHUB_ACTIONS_BILLING_BLOCKED` is an external account blocker: do not
   dispatch more repair workflows while it is present, and report the billing
   action once instead of treating repeated zero-step jobs as code failures.
3. Never wait for GitHub Actions. If a remote scan is active, skip only the
   remote `sync` step and continue consuming valid local queues.
4. `githubNaturalScheduleHealthy=false` describes a current scheduler failure.
   Historical rolling-window gaps appear only in
   `githubNaturalScheduleWarnings` and never make a fresh scheduler unhealthy.
   When `operationalHealthy=true`, `sync` is required whenever
   `recentActive=false`; historical warnings must never suppress ingestion of
   the current signed cloud queue.

## 2. Reconcile interrupted creation

Run `orphan-list` before `sync`.

- `orphan-list` is the authoritative reconciliation query. It reads the local
  desktop task index, including archived tasks, and compares exact prompts,
  project roots, creation windows, and existing ledger bindings. Do not call
  the global `list_threads` API; it is unnecessary and can stall on a large
  task history.
- A unique match must agree on intent, exact first prompt, GitHub project,
  prepared worktree, and thread identity.
- For a unique match, run `orphan-commit`. It applies and verifies the desired
  title itself; do not call `set_thread_title`.
- Report `blocked` entries exactly and do not guess a binding.
- Preserve unmatched `CREATING` entries while `abandonable=false`.
- If `abandonable=true`, the bridge has already proved that local session
  storage, including archived tasks, contains no matching task. Use the
  returned `abandonNonce` with `creation-abandon`. `clientThreadId` may be
  absent when creation was reserved before the desktop API was called. Let the
  signed queue decide whether to enqueue again; do not create a replacement
  directly.

## 3. Refresh controller state

Run in this order:

1. `publish-terminal-feedback`
2. `sync` whenever `operationalHealthy=true` and `recentActive=false`
3. `refresh-prs`
4. `list`
5. `alerts --min-age-minutes 70 --notify`

A normal `PENDING` item is not a dispatch timeout. Only a stale lease or stale
`CREATING` entry is an alert. A sync or signature failure prevents accepting a
new remote queue but never discards a valid local intent.

## 4. Existing PR follow-ups

Run `pr-followup-list` before dispatching new issues.

If `sync` reports `prFollowup.status=stale_suspended`, the verified cloud PR
snapshot is too old to authorize a task wake. Do not dispatch from an older
local row or retry the same follow-up manually; fresh cloud state re-arms it.

Entries under `activeDeferred` are already being handled by a recently active
task. They are not failures and must not be reserved, resent, or reported as a
stalled follow-up. Entries under `queuedDeferred` wait behind another durable
issue, PR-follow-up, or validation task under the shared global WIP limit.
Process only `candidates`.

Entries under `restoreRequired` are valuable existing-PR tasks that the desktop
currently marks archived. Unarchive each exact `threadId`, rerun
`pr-followup-list`, and then process the resulting candidate. This is routine
lifecycle repair and does not require user approval. A missing managed worktree
is recreated by `pr-followup-reserve` from the verified PR head before the wake
is reserved. Report `blocked` entries exactly; never create a replacement task
for a missing thread.

For each candidate, process one transaction at a time:

1. `pr-followup-reserve --thread-id <threadId> --wake-digest <wakeDigest>`
   may return `deferred=true` when the live PR head, base, or conflict state no
   longer matches the verified cloud snapshot. This is a successful stale
   snapshot invalidation: do not send or commit that wake. A later cloud import
   may create a fresh wake only after its `checkedAt` advances.
2. Run `pr-followup-deliver --thread-id <threadId> --wake-digest <wakeDigest>`.
   The bridge resumes the same desktop task, starts the exact canonical turn,
   and commits the reservation only after the app-server returns that turn ID.
   Never call `send_message_to_thread`, create another task, or create another
   worktree.

An unknown worker outcome remains frozen and is never released by elapsed time.
If `commitReady=true`, rerun `pr-followup-deliver`; it reconciles the already
materialized target turn without starting another one. If `retryable=true`, an
exact negative worker receipt proves that no target turn started; rerun
`pr-followup-deliver` with the same wake digest so the bridge can replace that
failed attempt safely. Report any remaining unresolved entry with its exact
task, PR URL, and wake digest. Cancellation-only checks, aggregate checks, and
failures unrelated to branch files are not actionable candidates.

## 5. Dispatch new issue tasks

Existing work has strict priority over discovery. Before claiming any new issue,
run `ingest-results`, then re-run `pr-followup-list`,
`validation-followup-list`, and `recovery-list --min-age-minutes 90`. Finish one
actionable PR follow-up, validation continuation, or recoverable existing task
before using the global task slot for a new issue. Environment-blocked or
unchanged-no-progress validation does not block new discovery. The bridge
enforces this gate and may return `reason=higher_priority_existing_work`; when
it does, do not audit or claim another new intent in that run. Process the
reported existing-work class and re-check the lists instead.

Process every eligible `PENDING` intent sequentially:

1. Claim one intent with `claim --intent-id <id> --owner LEASE_OWNER
   --lease-minutes 30 --prepare --task-project-id PROJECT_ID`.
2. If it cannot reach `DISPATCHED` or `CREATING` and creation has not started,
   release it with `claim-release --reason <machine-readable-reason>`.
3. Never batch claims and never leave a lease without `creationStartedAt`.

For a successful claim:

- Require `taskProjectPath=PROJECT_PATH`, a worktree below
  `PROJECT_PATH/.oss-pr-radar/worktrees/`, and a source origin matching the
  issue repository.
- Do not call `create_thread`: from an automation controller it creates a
  delegated subagent that is not a user-visible GitHub project task.
- Run `creation-start` immediately before `root-task-create`, then pass the
  claim's exact intent, project, source repository, worktree, and title time
  together with the creation token. The bridge uses the desktop app-server to
  create an `appServer` root task at `PROJECT_PATH`, persists its exact two-line
  prompt, binds the worktree, and starts the skill turn.
- Treat `root-task-create` success as the completed creation receipt. It must
  return a real task ID; do not separately call `creation-bind` or `commit`.
- An explicit create rejection with no ID may use `creation-cancel`. Timeout,
  disconnect, or unknown result must remain `CREATING` for orphan recovery.
- A client-ID-only result may be reconciled for at most 90 seconds using only
  `orphan-list`, then completed with `orphan-commit`.
- A real task ID is completed with `commit` using the exact project, project
  cwd, prepared worktree, source repository, and `titleTime` returned by claim.
  `commit` applies and verifies the desired title itself; do not call
  `set_thread_title` and do not call `title-commit` manually.
- `commit` and `orphan-commit` must write matching context digests to both the
  worktree context and the issue-keyed bootstrap context under
  `PROJECT_PATH/.oss-pr-radar/task-contexts/`.
- After every successful commit, run `dispatch-notifications --notify`.

Only `claim` receives `--owner`; all later lifecycle commands read the stored
lease owner. `authorized=false`, `shadow=true`, or `claimed=false` never creates
a task. Private task concurrency defaults to one durable task across issue
dispatch, existing-PR follow-up, and validation continuation so a later
app-server root turn cannot interrupt an earlier one. The bridge checks this
limit before performing another expensive live audit; `task_wip_limit` leaves
the pending intent untouched for a later run. An explicit
`RADAR_MAX_ACTIVE_TASKS=0` removes the limit only on hosts with proven isolated
root-turn execution.

## 6. Results, publication, and validation

Run:

1. `context-sync`
2. `ingest-results`
3. `publish-terminal-feedback`
4. `publication-run`
5. `context-sync`
6. `dispatch-notifications --notify`

`context-sync` covers valuable `DISPATCHED` and `COMPLETED` tasks and writes the
current stage, live evidence, and publication receipt into both context copies.
For an active PR follow-up it preserves the ledger-bound prepared commit and
immutable follow-up snapshot while refreshing unrelated live evidence; legacy
unbound snapshots are recovered only from a verifiable controller merge.
If a task is waiting for routine network or privilege approval, send once to
the same task: `控制器证据已补齐。取消当前联网或提权请求；只使用已验证 task-context 的 liveAudit.evidence 和 worktreePath 继续，不运行 gh、curl、git fetch、联网安装，不请求人工权限。`

Accept only identity-matching terminal results. A no-code PR follow-up must be a
fresh `PR_OPEN` result with the exact follow-up digest; prose alone is not a
completed handoff. `publication-run` independently rechecks the permit and live
GitHub state, then may fork, push, and open or update the PR. `busy=true` is
normal background ownership: continue without waiting or retrying.
An interrupted publication effect remains write-ahead recorded. After its
writer is stale, `publication-run` reconciles the exact remote branch and PR.
It may retry an idempotent push only when live state proves the earlier attempt
had no effect and still matches the permitted previous head; otherwise it
preserves the reconciliation block.

Run `validation-followup-list`. For each candidate:

Items under `queuedDeferred` wait behind the same global WIP limit as issue and
PR-follow-up work. Do not reserve or send them until they return under
`candidates`.

- Reserve with the exact task and result digest. The bridge itself computes,
  validates, and runs any required lockfile-scoped dependency prefetch before
  reserving; the controller must never inspect or execute dependency commands.
  A failed prefetch leaves the candidate unreserved and must be reported.
- Run `validation-followup-deliver --thread-id <threadId> --result-digest
  <resultDigest>`. The bridge resumes the same task and commits only after the
  app-server receipts the exact new turn.
- Unknown worker outcomes remain unresolved and are never released or resent
  by age. If `commitReady=true`, rerun `validation-followup-deliver` to commit
  the already materialized turn without creating another one. If
  `retryable=true`, an exact negative worker receipt proves that no target turn
  started; rerun the same delivery safely instead of freezing the queue.
- Report entries stale after 90 minutes as `validationFollowupStalled`; this is
  a delivery watchdog, not a general review cooldown.
- A validation turn that the independent desktop view marks `interrupted` may
  enter `recovery-list` immediately, but only after the exact detached
  owner has exited. Both the first-turn `root-task-worker` and continuation
  `task-turn-worker` are active ownership. `terminal_turn_worker_draining` is
  not a stalled task; never start a second turn while either owner is present.
- Entries under `environmentBlocked` have a real dependency failure but no
  deterministic lockfile-scoped preparation path. Report the exact task and
  reason, but do not send a validation continuation that cannot change the
  evidence.
- `blockedNoProgress` means the same task completed a continuation but returned
  exactly the same missing evidence. Do not resend it automatically. Report the
  key and unchanged gap as an environment/no-progress block. A changed or
  reduced missing set becomes eligible immediately; this is not a time cooldown.

## 7. Recovery, titles, and cleanup

1. Run `recovery-list --min-age-minutes 90`; only the single item under
   `recoverable` is authorized for this round. Entries under `queuedDeferred`
   stay queued behind it, and any `activeDeferred` item suppresses all new
   recovery sends until that task reaches a terminal state. Any entry under
   `unresolved` also suppresses the complete recovery queue until the prior
   delivery is receipted. After `recovery-reserve`, run `recovery-deliver` with
   the same task and recovery nonce. If `commitReady=true`, rerun
   `recovery-deliver`; it commits the already materialized turn without
   creating another one. If `retryable=true`, an exact negative worker receipt
   proves that no target turn started; rerun `recovery-deliver` with the same
   nonce. Unknown worker outcomes remain frozen and are never abandoned by age.
   Never send the next queued item while a delivery result is unknown. Use one write-ahead
   recovery only for tasks with no recent activity and no structured result. This includes an
   existing-PR follow-up that was sent successfully but never returned its
   required identity-matched result. Recently active tasks must not be woken,
   except when the bridge reports `immediateRecovery=true` for a terminal
   desktop error. In that case reserve and send the returned canonical recovery
   prompt once; never improvise a retry or send a second recovery.
2. Run `restore-list`. Unarchive each exact candidate, then use `restore-commit`
   with its nonce. Recheck until empty.
3. Run `title-reconcile`. This command compares live desktop titles, repairs
   drift through the supported app-server protocol, and commits ledger receipts
   transactionally. Then run `title-list`; it must be empty. Never use
   `set_thread_title` or manual `title-commit` in the heartbeat.
4. Run `cleanup-list`. Archive only exact `[无价值]` `AUDIT_NO_GO` candidates,
   then run `cleanup-commit`. Recheck until empty. Never archive valuable,
   active, unknown, fix-ready, publication, open-PR, or merged tasks.
5. Run `duplicate-task-title-reconcile --min-age-minutes 30`, then
   `duplicate-task-list --min-age-minutes 30`. Every returned item is a stale,
   unbound raw task whose exact issue prompt already has a different
   ledger-bound canonical task. Archive each exact returned `threadId`, then
   re-run both commands until the duplicate list is empty. Never archive the
   returned `canonicalThreadId`.

## 8. Final fixed-point gate

Run a final health check without `--repair` and run
`scripts/install_local_publication_agent.py --status` again, then repeat the relevant reconcile
sequence: `orphan-list`, `pr-followup-list`, `context-sync`, `ingest-results`,
`validation-followup-list`, `publish-terminal-feedback`, `publication-run`,
`context-sync`, `dispatch-notifications --notify`, `list`, `alerts`,
`recovery-list`, `restore-list`, `title-reconcile`, `title-list`, and
`cleanup-list`, followed by duplicate title reconciliation and
`duplicate-task-list --min-age-minutes 30`.

Before reporting success, prove these six queues are empty:

- `orphan-list`
- `pr-followup-list` candidates, unresolved, and errors (`activeDeferred` may
  remain while its task is actively working; `restoreRequired` and `blocked`
  must be empty)
- `validation-followup-list` candidates, unresolved, stale, and errors;
  `blockedNoProgress` may remain only when each key and unchanged gap is included
  in the final operational summary
- `recovery-list` blocked and unresolved must be empty; `recoverable` must be
  empty after any authorized send. `activeDeferred` and `queuedDeferred` may
  remain only as the explicit serialized work queue reported in the final
  operational summary.
- `restore-list`
- `title-list`
- `cleanup-list`
- `duplicate-task-list`

Also prove that every completed task result has passed through `ingest-results`.
If any gate remains nonempty, report the exact failing stage rather than a
successful summary.

The final fixed-point results are authoritative. If an earlier attempt reported
an error but the same stage was rerun successfully and its final queue is empty,
count it only as a repaired transient condition; do not list it as a failed
stage. Derive `genuine failed stages` solely from the last execution of each
gate plus unresolved durable state, never from an accumulated narrative of the
whole heartbeat.

Return one concise Chinese paragraph containing only the operational summary:
local publication agent and health state, natural schedule state, repairs or
fallback, reconciled creation, contexts/results/validation/feedback/publication,
dispatch and notification counts, recovery/restore/title/archive counts,
remaining pending/alerts, validation no-progress blocks, policy suppressions,
unavailable historical worktrees, schedule warnings, and genuine failed stages. Expected policy filters, explicit
validation no-progress blocks, and historical schedule gaps are warnings, not
execution failures. Never print credentials.
