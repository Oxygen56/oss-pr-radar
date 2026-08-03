# OSS PR Radar

High-signal discovery for code-level pull-request opportunities in agent runtimes,
tool calling, MCP, structured output, workflow engines, and inference serving.

The radar combines deterministic GitHub evidence collection with a constrained
DeepSeek semantic review. It is intentionally conservative: the model may reject
or downgrade a candidate, but it cannot override repository policy or upgrade a
`HUMAN_REVIEW` gate.

## What It Checks

- Open, recently created or updated issues in mature AI infrastructure repositories
- Assignment, stale, support, docs-only, and low-value signals
- Full issue body and recent comments, including maintainer associations
- Repository contribution, assignment, CLA/DCO, and AI disclosure policies
- Directly linked and semantically overlapping open pull requests
- Competing PR tests, CI, activity, scope, and root-cause coverage
- Reproduction path, expected code surface, hardware compatibility, and impact

## Decision Pipeline

1. GitHub search finds recently updated open issues.
2. Deterministic gates remove assigned, stale, trivial, unsupported, or covered work.
3. Deep inspection reads issue discussion, repository policy, and competing PRs.
4. DeepSeek reviews the remaining small candidate set as untrusted data.
5. Deterministic post-gates prevent model upgrades and validate the report contract.
6. Qualified candidates are sent to Feishu and written to the scan artifact.

The DeepSeek stage returns one of:

- `NEW_CLEAN_CANDIDATE`
- `PR_COMPETITION_OPPORTUNITY`
- `WAIT_MAINTAINER`
- `REJECT`

## Local Run

Requirements:

- Python 3.11+
- GitHub CLI (`gh`) authenticated with public repository read access
- `DEEPSEEK_API_KEY`

```bash
python -m pip install -e .
oss-pr-radar \
  --window-hours 2 \
  --seen state/seen.json \
  --state state/runtime.json \
  --scan-out reports/latest_scan.json \
  --dry-run
```

Optional notification variables:

- `FEISHU_APP_ID`
- `FEISHU_APP_SECRET`
- `FEISHU_CHAT_ID`

The API endpoint defaults to `https://api.deepseek.com` and the model defaults to
`deepseek-v4-flash`. Override them with `DEEPSEEK_BASE_URL` and `DEEPSEEK_MODEL`.

## GitHub Actions

The included workflow runs at minute 17 of every hour in `Asia/Shanghai` and can
also be started manually from the Actions page. Minute 17 avoids GitHub's busier
top-of-hour scheduling window.

Configure these repository secrets:

- `DEEPSEEK_API_KEY`
- `FEISHU_APP_ID`
- `FEISHU_APP_SECRET`
- `FEISHU_CHAT_ID`

The `radar-state` branch stores only the seen ledger, runtime watermark, and LLM
cache. Scan reports are uploaded as short-lived Actions artifacts. No API key is
written to either location.

## Safety Boundaries

- GitHub issue and comment content is treated as prompt-injection-capable input.
- The LLM has no tools, credentials, shell, GitHub write access, or publication path.
- Missing or failed LLM review disables automatic dispatch for that candidate.
- Repository policy and duplicate-PR gates remain deterministic.
- This cloud workflow does not create local Codex tasks or modify local worktrees.

Creating Codex tasks requires a separate local bridge because GitHub-hosted runners
cannot operate the desktop app or local repositories. Every run publishes a
`dispatch_intents.json` handoff containing only candidates that passed both the
deterministic gate and DeepSeek review. Each prompt is exactly the `gh-issue-pr`
skill entry followed by the issue URL.

## Development

```bash
python -m pip install pytest
pytest
python -m compileall -q src scripts
```
