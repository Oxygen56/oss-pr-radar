"""Strict GitHub CLI adapter with pagination and per-source failures."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote


class GitHubError(RuntimeError):
    def __init__(self, message: str, *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


Runner = Callable[[list[str], int], str]
Sleeper = Callable[[float], None]

_HTTP_HEADERS = re.compile(r"HTTP/\S+ \d{3}[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n")


def _is_rate_limit_error(error: BaseException | str) -> bool:
    message = str(error).casefold()
    return "rate limit" in message or bool(re.search(r"\bhttp\s+429\b", message))


_PROXY_ENV_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


def _is_connectivity_github_error(error: BaseException | str) -> bool:
    message = str(error).strip().casefold()
    if isinstance(error, subprocess.TimeoutExpired):
        return True
    if re.search(r"\b(?:unexpected\s+)?eof(?:\s+while\s+reading)?\b", message):
        return True
    if "unexpected end of json input" in message:
        return True
    if "ssl_error_syscall" in message or re.search(r"\bssl\s+syscall\b", message):
        return True
    return any(
        marker in message
        for marker in (
            "timed out",
            "timeout",
            "temporarily unavailable",
            "error connecting to api.github.com",
            "check your internet connection",
            "failed to connect",
            "couldn't connect",
            "connection reset",
            "connection refused",
            "tls handshake timeout",
            "network is unreachable",
            "no route to host",
        )
    )


def is_transient_github_error(error: BaseException | str) -> bool:
    """Return whether a read failed for a retryable transport/server reason."""

    message = str(error).strip().casefold()
    return (
        _is_connectivity_github_error(error)
        or _is_rate_limit_error(error)
        or bool(re.search(r"\bhttp\s+(?:408|5\d\d)\b", message))
        or ("too many files changed" in message and "http 422" in message)
    )


def _default_runner(args: list[str], timeout: int) -> str:
    # Keep reset headers on failures, including errors halfway through pagination.
    if args[:2] == ["gh", "api"] and "--include" not in args:
        args = [*args, "--include"]
    started = time.monotonic()
    proxy_env = os.environ.copy()
    proxy_configured = any(proxy_env.get(name) for name in _PROXY_ENV_NAMES)
    direct_env = dict(proxy_env)
    for name in _PROXY_ENV_NAMES:
        direct_env.pop(name, None)

    def invoke(env: dict[str, str], call_timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1.0, call_timeout),
            env=env,
        )

    direct_timeout = float(timeout) if not proxy_configured else min(float(timeout), 10.0)
    try:
        completed = invoke(direct_env, direct_timeout)
    except subprocess.TimeoutExpired:
        if not proxy_configured:
            raise
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 1.0:
            raise
        completed = invoke(proxy_env, remaining)

    direct_error = (completed.stderr or completed.stdout or "GitHub command failed").strip()
    if (
        completed.returncode != 0
        and proxy_configured
        and _is_connectivity_github_error(direct_error)
    ):
        remaining = timeout - (time.monotonic() - started)
        if remaining > 1.0:
            completed = invoke(proxy_env, remaining)
    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "GitHub command failed").strip()
        retry_after = None
        headers = _HTTP_HEADERS.findall(completed.stdout)
        if headers and _is_rate_limit_error(error):
            values = dict(
                (key.casefold(), value.strip())
                for key, value in re.findall(r"(?m)^([^:\r\n]+):[ \t]*(.*)\r?$", headers[-1])
            )
            try:
                if "retry-after" in values:
                    retry_after = max(0.0, float(values["retry-after"]))
                elif values.get("x-ratelimit-remaining") == "0":
                    retry_after = max(0.0, float(values["x-ratelimit-reset"]) - time.time())
            except (ValueError, KeyError):
                pass
        raise GitHubError(error[:1000], retry_after=retry_after)
    return _HTTP_HEADERS.sub("", completed.stdout)


@dataclass
class GitHubClient:
    runner: Runner = _default_runner
    timeout: int = 45
    retry_delays: tuple[float, ...] = (0.25, 1.0)
    sleeper: Sleeper = time.sleep
    rate_limit_wait_budget: float = 180.0

    def api(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        paginate: bool = False,
        accept: str | None = None,
    ) -> Any:
        args = ["gh", "api", "-X", "GET", endpoint]
        if paginate:
            args.extend(["--paginate", "--slurp"])
        if accept:
            args.extend(["-H", f"Accept: {accept}"])
        for key, value in (params or {}).items():
            args.extend(["-f", f"{key}={value}"])
        rate_limit_waited = 0.0
        for attempt in range(len(self.retry_delays) + 1):
            delay = self.retry_delays[attempt] if attempt < len(self.retry_delays) else 0.0
            try:
                raw = self.runner(args, self.timeout)
                data = json.loads(raw)
                break
            except json.JSONDecodeError as exc:
                if attempt >= len(self.retry_delays):
                    raise GitHubError("GitHub returned invalid JSON") from exc
            except (GitHubError, subprocess.TimeoutExpired) as exc:
                if attempt >= len(self.retry_delays) or not is_transient_github_error(exc):
                    raise
                if _is_rate_limit_error(exc):
                    delay = getattr(exc, "retry_after", None)
                    if delay is None:
                        delay = 60.0 * (2**attempt)
                    if rate_limit_waited + delay > self.rate_limit_wait_budget:
                        raise
                    rate_limit_waited += delay
            self.sleeper(delay)
        if not paginate:
            return data
        if not isinstance(data, list):
            raise GitHubError("paginated GitHub response is not a list")
        flattened: list[Any] = []
        for page in data:
            if isinstance(page, list):
                flattened.extend(page)
            elif isinstance(page, dict) and isinstance(page.get("items"), list):
                flattened.extend(page["items"])
            else:
                flattened.append(page)
        return flattened

    def issue(self, repo: str, number: int) -> dict[str, Any]:
        value = self.api(f"repos/{repo}/issues/{number}")
        if not isinstance(value, dict) or value.get("pull_request"):
            raise GitHubError("issue not found")
        return value

    def comments(self, repo: str, number: int) -> list[dict[str, Any]]:
        value = self.api(
            f"repos/{repo}/issues/{number}/comments",
            params={"per_page": 100},
            paginate=True,
        )
        return [item for item in value if isinstance(item, dict)]

    def timeline(self, repo: str, number: int) -> list[dict[str, Any]]:
        value = self.api(
            f"repos/{repo}/issues/{number}/timeline",
            params={"per_page": 100},
            paginate=True,
            accept="application/vnd.github+json",
        )
        return [item for item in value if isinstance(item, dict)]

    def repository(self, repo: str) -> dict[str, Any]:
        value = self.api(f"repos/{repo}")
        if not isinstance(value, dict):
            raise GitHubError("repository metadata is invalid")
        return value

    def branch(self, repo: str, branch: str) -> dict[str, Any]:
        value = self.api(f"repos/{repo}/branches/{quote(branch, safe='')}")
        if not isinstance(value, dict) or not isinstance(value.get("commit"), dict):
            raise GitHubError("repository branch is invalid")
        return value

    def related_open_prs(
        self,
        repo: str,
        number: int,
        *,
        issue_title: str = "",
        timeline: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        queries = [
            f'repo:{repo} is:pr "#{number}" in:body',
            f'repo:{repo} is:pr "issues/{number}" in:body',
        ]
        terms = [
            term.casefold()
            for term in re.findall(r"[A-Za-z][A-Za-z0-9_+-]{3,}", issue_title)
            if term.casefold()
            not in {
                "with",
                "from",
                "this",
                "that",
                "when",
                "issue",
                "error",
                "fails",
                "failure",
            }
        ]
        unique_terms = list(dict.fromkeys(terms))[:3]
        if len(unique_terms) >= 2:
            queries.append(f"repo:{repo} is:pr is:open {' '.join(unique_terms[:2])} in:title")
        found: dict[str, dict[str, Any]] = {}
        for event in timeline or []:
            source = (event.get("source") or {}).get("issue") or {}
            url = str(source.get("html_url") or "")
            match = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", url, re.I)
            if match:
                source_repo = match.group(1)
                source_number = int(match.group(2))
                found[f"{source_repo.casefold()}#{source_number}"] = source | {
                    "_linked_from_timeline": True,
                    "_timeline_event": str(event.get("event") or ""),
                    "_repo": source_repo,
                }
        for query in queries:
            result = self.api(
                "search/issues",
                params={"q": query, "per_page": 100},
                paginate=True,
            )
            for item in result:
                if isinstance(item, dict) and isinstance(item.get("number"), int):
                    found[f"{repo.casefold()}#{item['number']}"] = item | {"_repo": repo}
        return list(found.values())

    def pull_request(self, repo: str, number: int) -> dict[str, Any]:
        value = self.api(f"repos/{repo}/pulls/{number}")
        if not isinstance(value, dict):
            raise GitHubError("pull request is invalid")
        return value

    def pull_files(self, repo: str, number: int) -> list[dict[str, Any]]:
        value = self.api(
            f"repos/{repo}/pulls/{number}/files",
            params={"per_page": 100},
            paginate=True,
        )
        return [item for item in value if isinstance(item, dict)]

    def pull_reviews(self, repo: str, number: int) -> list[dict[str, Any]]:
        value = self.api(
            f"repos/{repo}/pulls/{number}/reviews",
            params={"per_page": 100},
            paginate=True,
        )
        return [item for item in value if isinstance(item, dict)]

    def pull_review_threads(self, repo: str, number: int) -> list[dict[str, Any]]:
        owner, name = repo.split("/", 1)
        query = """query($owner:String!,$name:String!,$number:Int!){
          repository(owner:$owner,name:$name){pullRequest(number:$number){
            reviewThreads(first:100){nodes{
              isResolved isOutdated path
              comments(first:100){nodes{
                author{login __typename} authorAssociation body url createdAt
              }}
            }}
          }}
        }"""
        args = [
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-F",
            f"owner={owner}",
            "-F",
            f"name={name}",
            "-F",
            f"number={number}",
        ]
        value: Any = None
        started = time.monotonic()
        last_error: BaseException | None = None
        for attempt in range(len(self.retry_delays) + 1):
            retry_delay = self.retry_delays[attempt] if attempt < len(self.retry_delays) else 0.0
            remaining = float(self.timeout) - (time.monotonic() - started)
            if remaining <= 0:
                if isinstance(last_error, json.JSONDecodeError):
                    raise GitHubError("GitHub review threads response is invalid") from last_error
                if last_error is not None:
                    raise last_error
                raise GitHubError("GitHub review threads request timed out")
            try:
                raw = self.runner(args, remaining)
                value = json.loads(raw)
                break
            except json.JSONDecodeError as exc:
                last_error = exc
                if attempt >= len(self.retry_delays):
                    raise GitHubError("GitHub review threads response is invalid") from exc
            except (GitHubError, subprocess.TimeoutExpired) as exc:
                last_error = exc
                if attempt >= len(self.retry_delays) or not is_transient_github_error(exc):
                    raise
                if _is_rate_limit_error(exc):
                    retry_delay = getattr(exc, "retry_after", None)
                    if retry_delay is None:
                        retry_delay = 60.0 * (2**attempt)
                    if retry_delay >= float(self.timeout) - (time.monotonic() - started):
                        raise
            remaining = float(self.timeout) - (time.monotonic() - started)
            delay = min(retry_delay, max(0.0, remaining))
            if delay <= 0:
                if isinstance(last_error, json.JSONDecodeError):
                    raise GitHubError("GitHub review threads response is invalid") from last_error
                if last_error is not None:
                    raise last_error
                raise GitHubError("GitHub review threads request timed out")
            self.sleeper(delay)
        try:
            nodes = value["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
        except (KeyError, TypeError) as exc:
            raise GitHubError("GitHub review threads response is invalid") from exc
        if not isinstance(nodes, list):
            raise GitHubError("GitHub review threads response is incomplete")
        return [item for item in nodes if isinstance(item, dict)]

    def open_pull_requests_by_author(self, author: str) -> list[dict[str, Any]]:
        value = self.api(
            "search/issues",
            params={
                "q": f"author:{author} is:pr is:open",
                "sort": "updated",
                "order": "desc",
                "per_page": 100,
            },
            paginate=True,
        )
        return [item for item in value if isinstance(item, dict)]

    def check_runs(self, repo: str, ref: str) -> list[dict[str, Any]]:
        pages = self.api(
            f"repos/{repo}/commits/{quote(ref, safe='')}/check-runs",
            params={"per_page": 100},
            paginate=True,
            accept="application/vnd.github+json",
        )
        runs: list[dict[str, Any]] = []
        for page in pages:
            if not isinstance(page, dict):
                continue
            values = page.get("check_runs")
            if isinstance(values, list):
                runs.extend(item for item in values if isinstance(item, dict))
        return runs

    def check_annotations(self, repo: str, check_run_id: int) -> list[dict[str, Any]]:
        value = self.api(
            f"repos/{repo}/check-runs/{check_run_id}/annotations",
            params={"per_page": 100},
            paginate=True,
            accept="application/vnd.github+json",
        )
        return [item for item in value if isinstance(item, dict)]

    def compare(self, repo: str, base: str, head: str) -> dict[str, Any]:
        value = self.api(f"repos/{repo}/compare/{quote(base, safe='')}...{quote(head, safe='')}")
        if not isinstance(value, dict):
            raise GitHubError("repository comparison is invalid")
        return value

    def repository_tree(self, repo: str, ref: str) -> list[dict[str, Any]]:
        value = self.api(f"repos/{repo}/git/trees/{quote(ref, safe='')}", params={"recursive": 1})
        if not isinstance(value, dict) or not isinstance(value.get("tree"), list):
            raise GitHubError("repository tree is incomplete")
        if value.get("truncated") is True:
            raise GitHubError("repository tree was truncated")
        return [item for item in value["tree"] if isinstance(item, dict)]

    def file_text(self, repo: str, path: str, ref: str) -> str:
        value = self.api(f"repos/{repo}/contents/{quote(path, safe='/')}", params={"ref": ref})
        if not isinstance(value, dict) or value.get("encoding") != "base64":
            raise GitHubError(f"cannot read repository file: {path}")
        try:
            return base64.b64decode(str(value.get("content") or "")).decode(
                "utf-8", errors="replace"
            )
        except (ValueError, TypeError) as exc:
            raise GitHubError(f"cannot decode repository file: {path}") from exc
