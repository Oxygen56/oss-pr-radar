# Managed Ledger Contract

The managed tables are an additive schema. Existing Radar tables, publication
effects, and receipts remain authoritative for their established callers while
the managed Ledger is introduced through a database-copy migration. A rollback
drops only `managed_*` tables and triggers.

## Identity and events

- An opportunity is `owner/repo#issue`.
- A task retains `task_id`, `thread_id`, and `worktree_path`.
- A pull request is `owner/repo#number` plus its observed `head_sha`.
- A CI run is recorded against both `pr_key` and `head_sha`; a later head is a
  different evidence point.
- A result is keyed by `task_id + pr_key + head_sha + result_digest`.
- Lifecycle events are append-only and deduplicated by an idempotency key. Each
  event stores source, provenance, and `observed_at`.

## State rules

`queued`, `done`, `FIX_READY`, and worker completion are processing evidence,
not contribution completion. `needs_human` maps to `DECISION_REQUIRED` and
`skipped` maps to `SUPERSEDED` or `WAITING_EXTERNAL`. `PATCHED` reaches
`PORTFOLIO_READY` only when a commit, objective validation evidence, and a new
head SHA are all present. A repeated result is idempotent; a new classification
supersedes the previous current classification and leaves an append-only event.

The five mutually exclusive result classifications are:
`scan_false_positive`, `state_drift`, `blocked_pre_task`, `task_no_go`, and
`censored`. Cohort observations at 14, 30, and 60 days use `censored` when no
external success or failure was observed after the horizon; it is never counted
as either outcome.

## External actions

Only a GitHub actor of type `User`, not a bot/App, with `OWNER`, `MEMBER`, or
`COLLABORATOR` association is a maintainer. Five open, automatically created,
unanswered PRs is the hard
per-repository cap at both task creation and publication. A verified maintainer
invitation or assignment is an explicit exemption.

Public communication is stored locally as a draft by default. An automatic
reply is only authorized by deterministic checks for a verified maintainer's
explicit mechanical request, completed work, objective validation, and no
semantic, legal, security, disclosure, or policy uncertainty. The reply key is
`pr_key + maintainer_event_key + result_digest`; failed checks remain an explicit
`DRAFT` with a `DECISION_REQUIRED` reason, and this module never sends it.

## War Room projection

`export_projection` is read-only. It exposes only the user buckets
`DECISION_REQUIRED`, `SYSTEM_PROCESSING`, `WAITING_EXTERNAL`, and
`PORTFOLIO_READY`, while each item retains its internal detailed state for
diagnostics. War Room is therefore a projection and cannot advance the Ledger.
