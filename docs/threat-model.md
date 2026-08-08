# Threat Model

## Protected Assets

- GitHub and Feishu credentials
- dispatch signing key
- local Codex task/project identity
- source worktrees and commits
- public fork branches and pull requests
- policy, duplicate, ownership, and SubmitReady evidence

## Main Risks And Controls

| Risk | Control |
| --- | --- |
| Prompt injection in issue text | Read-only scan; no tool-capable LLM; prompt generated locally from a fixed function |
| LLM authorizes low-quality work | Model has no positive vote; deterministic scan and live gates must both pass |
| Truncated comments hide a claim | REST pagination; any critical-source failure produces HOLD |
| Existing PR is missed | Exact issue links, timeline references, title search, PR files, checks, reviews, and local live recheck |
| Repository policy drift | Recursive policy snapshot with source hashes, repeated before task and publication |
| Cloud queue tampering | Versioned contract, HMAC signatures, nonce, TTL, and local verification |
| Duplicate task creation | Write-ahead `CREATING`, persisted `clientThreadId`, intent idempotency, and exact late-task reconciliation |
| Wrong project or worktree | Exact origin, Codex SQLite, first input, title, cwd, and Git common-directory checks |
| Child task requests broad local access | Git-ignored workspace context/result protocol; controller alone owns external ledgers and publication |
| Unsafe automatic PR | SubmitReady evidence, exact task identity, independent live broker, short-lived permit bound to commit and full PR payload |
| Duplicate push/PR after timeout | Write-ahead effect record, exact remote reconciliation, no retry after ambiguity |
| Accidental task archival | Only `AUDIT_NO_GO`, current unarchived task, fresh cleanup nonce, post-archive receipt; recovered current tasks require a verified unarchive and restore receipt |
| Secret leakage | Secrets only in Actions secret store, environment, or Keychain; never in reports, prompts, state, or logs |

## Explicit Non-Goals

- Accepting CLA or other legal agreements
- Answering public AI-use disclosure fields
- Publishing security-sensitive work
- Treating merge count or maintainer response time as a performance target
- Inferring authorization from a task prompt, issue label, model score, or old receipt
