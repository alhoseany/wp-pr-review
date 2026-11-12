#!/usr/bin/env python3
"""Collect PR data via the GitHub CLI (`gh`) and emit a single JSON object.

All `gh` invocations go through an injected `run` callable so the logic is
unit-testable without a network or monkeypatching.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from typing import Callable, Tuple

PR_URL_RE = re.compile(r"(?:https?://)?github\.com/([^/]+)/([^/]+)/pull/(\d+)")
SHORT_RE = re.compile(r"^([^/]+)/([^/#]+)#(\d+)$")
PATH_RE = re.compile(r"^([^/]+)/([^/]+)/pull/(\d+)$")

METADATA_FIELDS = ("number,title,author,body,state,baseRefName,headRefName,"
                   "labels,additions,deletions,files,url,"
                   "headRepository,headRepositoryOwner,isCrossRepository,headRefOid,"
                   "mergeable,mergeStateStatus")


def parse_pr_ref(ref: str) -> Tuple[str, str, int]:
    ref = ref.strip().rstrip("/")
    for rx in (PR_URL_RE, SHORT_RE, PATH_RE):
        m = rx.search(ref)
        if m:
            return m.group(1), m.group(2), int(m.group(3))
    raise ValueError(
        f"Unrecognized PR reference: {ref!r}. Use a PR URL, owner/repo#N, or owner/repo/pull/N.")


def _default_run(args, retries: int = 3, check: bool = True) -> str:
    """Run `gh <args>` with exponential backoff on rate limits.

    check=False returns stdout even on non-zero exit: `gh pr checks` exits
    non-zero when checks fail or are pending but still prints the results.
    """
    last = None
    for attempt in range(retries):
        proc = subprocess.run(["gh", *args], capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout
        last = proc.stderr
        if "rate limit" in (proc.stderr or "").lower():
            time.sleep((2 ** attempt) * 60)
            continue
        if not check:
            return proc.stdout
        break
    raise RuntimeError(f"gh {' '.join(args)} failed: {last}")


def _view_json(owner, repo, number, field, run) -> object:
    out = run(["pr", "view", str(number), "--repo", f"{owner}/{repo}", "--json", field])
    return json.loads(out)


_BLOCKING_CONCLUSIONS = {"FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED"}
_ADVISORY_CONCLUSIONS = {"NEUTRAL", "SKIPPED", "EXPECTED"}


def classify(conclusion, status) -> str:
    """Classify a single CI check into a category. First-match wins."""
    # Normalise
    if conclusion is not None:
        conclusion = str(conclusion).upper() if conclusion != "" else None
    if not conclusion:
        conclusion = None
    norm_status = str(status).upper() if status else ""

    if conclusion in _BLOCKING_CONCLUSIONS:
        return "blocking"
    if conclusion is None and norm_status != "COMPLETED":
        return "pending"
    if conclusion is None and norm_status == "COMPLETED":
        return "unknown"
    if conclusion in _ADVISORY_CONCLUSIONS:
        return "advisory"
    if conclusion == "SUCCESS":
        return "passing"
    return "unknown"


def normalize_check(entry: dict) -> dict:
    """Normalise a CheckRun or StatusContext entry to a common shape."""
    if "state" in entry and "conclusion" not in entry:
        # StatusContext
        state = (entry.get("state") or "").lower()
        if state in ("failure", "error"):
            conclusion = "FAILURE"
            status = "COMPLETED"
        elif state == "pending":
            conclusion = None
            status = "IN_PROGRESS"
        elif state == "success":
            conclusion = "SUCCESS"
            status = "COMPLETED"
        elif state == "expected":
            conclusion = "EXPECTED"
            status = "COMPLETED"
        else:
            conclusion = None
            status = "COMPLETED"
        name = entry.get("context")
        url = entry.get("targetUrl")
    else:
        # CheckRun
        conclusion = entry.get("conclusion")
        status = entry.get("status")
        name = entry.get("name")
        url = entry.get("detailsUrl")

    return {
        "name": name,
        "conclusion": conclusion,
        "status": status,
        "url": url,
        "category": classify(conclusion, status),
    }


def _thread_comment(node: dict) -> dict:
    line = node.get("line")
    if line is None:
        line = node.get("originalLine")
    return {
        "id": node.get("databaseId"),
        "in_reply_to_id": (node.get("replyTo") or {}).get("databaseId"),
        "author": (node.get("author") or {}).get("login"),
        "created_at": node.get("createdAt"),
        "path": node.get("path"),
        "line": line,
        "body": node.get("body"),
        "url": node.get("url"),
    }


_TEST_HEADING_RE = re.compile(
    r"\b(?:test(?:ing)?\s*(?:instructions?|steps?|plan|notes?|cases?)?|how\s+to\s+test|"
    r"steps\s+to\s+(?:test|reproduce|verify)|qa(?:\s+steps)?|verification(?:\s+steps)?|"
    r"to\s+test)\b", re.I)
_MD_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_BOLD_HEADING_RE = re.compile(r"^\s*(?:\*\*|__)(.+?)(?:\*\*|__)\s*:?\s*$")
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s+)?(.*\S)\s*$")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def parse_test_steps(body) -> dict:
    """Pull the author's test steps out of a PR description.

    Looks for a markdown heading, a bold line, or a "Label:" line naming a
    test section ("Testing Instructions", "How to test", "Steps to
    reproduce", "QA", ...) and returns the list items under it, up to the
    next heading of the same or a higher level. Without list items, the
    section's non-empty lines are returned. Template comments are ignored.

    Returns {"heading", "steps"}; both empty when the body has no such
    section. An empty result means the reviewer derives steps from the diff.
    """
    text = _HTML_COMMENT_RE.sub("", body or "")
    lines = text.splitlines()
    for i, raw in enumerate(lines):
        level, title = _heading(raw)
        if title is None or not _TEST_HEADING_RE.search(title):
            continue
        section = []
        for nxt in lines[i + 1:]:
            nlevel, ntitle = _heading(nxt)
            if ntitle is not None and (level == 0 or nlevel == 0 or nlevel <= level):
                break
            section.append(nxt)
        items = [m.group(1) for m in map(_LIST_ITEM_RE.match, section) if m]
        steps = items or [ln.strip() for ln in section if ln.strip() and ln.strip() != "---"]
        if steps:
            return {"heading": title.strip(), "steps": steps}
    return {"heading": "", "steps": []}


def _heading(line: str):
    """Return (level, title) for a heading-like line, else (None, None).

    Markdown headings carry their level; bold lines and short "Label:" lines
    are level 0 (they end at the next heading of any kind).
    """
    m = _MD_HEADING_RE.match(line)
    if m:
        return len(m.group(1)), m.group(2)
    m = _BOLD_HEADING_RE.match(line)
    if m:
        return 0, m.group(1)
    stripped = line.strip()
    if stripped.endswith(":") and 0 < len(stripped) <= 60 and not _LIST_ITEM_RE.match(line):
        return 0, stripped[:-1]
    return None, None


def own_activity(login: str, comments: list, reviews: list, review_threads: list) -> dict:
    """The reviewer's own prior activity on the PR, for re-review continuity."""
    def by(item):
        return ((item.get("author") or {}).get("login") if isinstance(item.get("author"), dict)
                else item.get("author")) == login

    return {
        "login": login,
        "reviews": [r for r in reviews if by(r)],
        "comments": [c for c in comments if by(c)],
        "review_comments": [c for t in review_threads for c in t.get("comments", []) if by(c)],
    }


HEAD_FIELDS = "headRefOid,mergeable,mergeStateStatus"


def head_state(owner: str, repo: str, number: int,
               run: Callable[[list], str] = None) -> dict:
    """Re-fetch only the head SHA and merge state (for head_at_emit)."""
    return _view_json(owner, repo, number, HEAD_FIELDS, run or _default_run)


def _fetch_review_threads(owner: str, repo: str, number: int, run: Callable[[list], str]) -> list:
    """Fetch review threads from GraphQL and parse into flat list.

    Returns list of {path, line, body, author, isResolved} dicts describing
    each thread's first comment, plus the whole conversation under
    "comments" ({id, in_reply_to_id, author, created_at, path, line, body,
    url}) so replies and resolutions are visible.
    Per-thread failures are skipped; one bad thread won't drop the rest.
    # NOTE: capped at first:100 review threads and 100 comments per thread
    # (no --paginate this batch); revisit if real PRs exceed.
    """
    query = (
        "query($owner:String!,$repo:String!,$number:Int!)"
        "{repository(owner:$owner,name:$repo){pullRequest(number:$number)"
        "{reviewThreads(first:100)"
        "{nodes{id isResolved isOutdated comments(first:100){nodes{databaseId url path line originalLine"
        " body createdAt author{login} replyTo{databaseId}}}}}}}}"
    )

    out = run(["api", "graphql", "-f", f"query={query}", "-F", f"owner={owner}",
               "-F", f"repo={repo}", "-F", f"number={number}"])
    data = json.loads(out)

    # Defensive second layer: a future gh may return GraphQL errors with a
    # zero exit code (exit-0 errors-envelope). The PRIMARY guard is the
    # exception path in collect() (gh 2.93 exits 1 on GraphQL errors, so
    # _default_run(check=True) raises). This inspects the errors array so an
    # exit-0 error still surfaces as threads_error instead of silently
    # dropping threads. Do NOT remove in favour of the exception handler.
    if data.get("errors"):
        raise RuntimeError(f"graphql errors: {data['errors']}")

    # Navigate to reviewThreads.nodes
    threads_data = (
        (data.get("data") or {})
        .get("repository", {})
        .get("pullRequest", {})
        .get("reviewThreads", {})
        .get("nodes", [])
    )

    review_threads = []
    for thread in threads_data:
        try:
            comments = thread.get("comments", {}).get("nodes", [])
            if not comments:
                continue  # Skip threads with no comments

            comment = comments[0]
            line = comment.get("line")
            if line is None:
                line = comment.get("originalLine")

            author = (comment.get("author") or {}).get("login")

            review_threads.append({
                "path": comment.get("path"),
                "line": line,
                "body": comment.get("body"),
                "author": author,
                "isResolved": thread.get("isResolved"),
                "isOutdated": thread.get("isOutdated"),
                "thread_id": thread.get("id"),
                "comments": [_thread_comment(c) for c in comments],
            })
        except Exception:
            continue

    return review_threads


def collect(owner: str, repo: str, number: int,
            run: Callable[[list], str] = _default_run) -> dict:
    meta = _view_json(owner, repo, number, METADATA_FIELDS, run)
    comments = _view_json(owner, repo, number, "comments", run).get("comments", [])
    reviews = _view_json(owner, repo, number, "reviews", run).get("reviews", [])
    try:
        # check=False: failing/pending checks exit non-zero but still print
        # result rows to stdout. ("No checks reported" also exits non-zero
        # with EMPTY stdout — ci_raw correctly stays "" in that case.)
        ci_raw = run(["pr", "checks", str(number), "--repo", f"{owner}/{repo}"],
                     check=False)
    except Exception:  # checks genuinely absent / gh error; non-fatal
        ci_raw = ""

    ci_error = None
    try:
        rollup_data = _view_json(owner, repo, number, "statusCheckRollup", run)
        rollup = rollup_data.get("statusCheckRollup") or []
        checks = [normalize_check(e) for e in rollup]
    except Exception as exc:
        # Fail-closed: surface the error rather than a silent empty checks list.
        # No errors-array defensive layer here (unlike _fetch_review_threads):
        # `gh pr view` collapses any GraphQL error to a non-zero exit code, so
        # there is no exit-0 errors-envelope to inspect on this path.
        checks = []
        ci_error = str(exc)

    threads_error = None
    try:
        review_threads = _fetch_review_threads(owner, repo, number, run)
    except Exception as exc:
        # Fail-closed: surface the error rather than a silent empty list.
        review_threads = []
        threads_error = str(exc)

    viewer_error = None
    own = None
    try:
        login = run(["api", "user", "--jq", ".login"]).strip()
        if not login:
            raise RuntimeError("gh api user returned no login")
        own = own_activity(login, comments, reviews, review_threads)
    except Exception as exc:
        # Non-fatal: own activity is a convenience view of data already above.
        viewer_error = str(exc)

    result = {
        "metadata": meta,
        "test_steps": parse_test_steps(meta.get("body")),
        "own": own,
        "comments": comments,
        "reviews": reviews,
        "ci": {"raw": ci_raw, "checks": checks},
        "files": meta.get("files", []),
        "review_threads": review_threads,
    }
    if ci_error is not None:
        result["ci_error"] = ci_error
    if threads_error is not None:
        result["threads_error"] = threads_error
    if viewer_error is not None:
        result["viewer_error"] = viewer_error
    if ci_error is not None or threads_error is not None:
        result["partial"] = True
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description="Collect PR data via gh as JSON.")
    p.add_argument("ref", help="PR URL, owner/repo#N, or owner/repo/pull/N")
    p.add_argument("--head", action="store_true",
                   help="print only headRefOid, mergeable and mergeStateStatus (for head_at_emit)")
    a = p.parse_args(argv)
    owner, repo, number = parse_pr_ref(a.ref)
    data = head_state(owner, repo, number) if a.head else collect(owner, repo, number)
    json.dump(data, sys.stdout, indent=2, default=str)
    print()


if __name__ == "__main__":
    main()
