# Automation run receipts

The two local automation entry points (`oss-pr-radar` and
`daily-github-open-pr-status-review`) append one `STARTED` and one
`COMPLETED` record to:

```text
<runtime-root>/state/automation-runs.ndjson
```

Each record is sealed with a digest.  The terminal record includes the process
exit code, whether the wrapper emitted a JSON result, the result's hash, the
bound release, and a bounded summary of GitHub/Feishu effects.  The log is
append-only and readers share the writer lock, so a half-written last line is
not treated as a successful run.

To inspect one automation without changing state:

```text
<runtime-root>/.venv/bin/python <active-release>/scripts/automation_audit.py \
  --runtime-root <runtime-root> \
  --automation-id oss-pr-radar
```

`ok` means both receipt integrity and the recorded command outcome are clean;
`runStatus` distinguishes `healthy`, `failed`, and `unknown`.  A
`SCHEDULER_EVIDENCE_MISSING` warning is separate: the current Codex heartbeat
does not provide a trusted per-trigger envelope, so these receipts prove the
local command boundary, not that the upstream scheduler fired.  GitHub
Actions natural-schedule health remains an independent check; a manual
fallback run must not be counted as a natural schedule run.

After each terminal receipt, a derived, regenerable report is written under
`<runtime-root>/state/automation-audit-<automation-id>.json`.  The append-only
log remains authoritative if disk pressure prevents refreshing that view.
