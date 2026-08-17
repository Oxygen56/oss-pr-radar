"""Strict GitHub CLI adapter with pagination and per-source failures."""

from __future__ import annotations

import base64
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote


class GitHubError(RuntimeError):
    pass


Runner = Callable[[list[str], int], str]


def _default_runner(args: list[str], timeout: int) -> str:
    completed = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        error = (completed.stderr or completed.stdout or "GitHub command failed").strip()
        raise GitHubError(error[:1000])
    return completed.stdout


@dataclass
class GitHubClient:
    runner: Runner = _default_runner
    timeout: int = 45

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
        raw = self.runner(args, self.timeout)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GitHubError("GitHub returned invalid JSON") from exc
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
        raw = self.runner(args, self.timeout)
        try:
            value = json.loads(raw)
            nodes = value["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
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
