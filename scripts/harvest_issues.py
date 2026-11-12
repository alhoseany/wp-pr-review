#!/usr/bin/env python3
"""Harvest GitHub issues linked to merged PRs and emit a JSON records file.

With --signals, harvest fix PRs that close no issue and acted-on review
threads instead (see gather_signals).

All `gh` invocations go through an injected `run` callable so the logic is
unit-testable without a network or monkeypatching.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


_ISO = "%Y-%m-%dT%H:%M:%SZ"
_ONE_YEAR_SECONDS = 365 * 24 * 3600
_SEARCH_JSON = "number,title,body,mergedAt,mergeCommit,closingIssuesReferences,files"

# Redaction — strip private links and PII from body/title text before it is
# stored in a record.  Records are ephemeral local staging, but they must never
# carry chat/helpdesk/share links or email addresses that could leak if a
# record file is mishandled.  Add your own hosts via HARVEST_REDACT_PATTERNS
# (comma-separated regexes).
_REDACT_URL_PATTERNS = [
    # Common chat / helpdesk SaaS hosts (any workspace or subdomain).
    r"https?://[^\s)>\]]*(?:slack\.com|zendesk\.com|intercom\.(?:com|io)|helpscout\.net)[^\s)>\]]*",
    r"https?://[^\s)>\]]*claude\.ai[^\s)>\]]*",                       # Claude share/session links
    r"https?://github\.com/user-attachments/[^\s)>\]]*",             # GH private attachments
    r"https?://(?:private-user-images|user-images)\.githubusercontent\.com[^\s)>\]]*",
]
_EMAIL_RE = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"


def _env_list(name):
    """Comma-separated env var -> list of non-empty stripped entries."""
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def _redact_patterns():
    return _REDACT_URL_PATTERNS + _env_list("HARVEST_REDACT_PATTERNS")


def _redact(text):
    """Replace private links (chat/helpdesk hosts, claude.ai sessions, GitHub
    private user-attachments, plus any HARVEST_REDACT_PATTERNS) and email
    addresses with `[redacted]`.  Leaves the rest of the text intact so a
    general pattern can still be distilled.  Returns the input unchanged when
    it is empty/None."""
    if not text:
        return text
    for pat in _redact_patterns():
        text = re.sub(pat, "[redacted]", text, flags=re.IGNORECASE)
    text = re.sub(_EMAIL_RE, "[redacted]", text)
    return text


def _default_run(args, retries: int = 3, check: bool = True) -> str:
    """Run `gh <args>` with exponential backoff on rate limits.

    check=False returns stdout even on non-zero exit.
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


def _parse_iso(value: str) -> int:
    """Parse a `YYYY-MM-DDTHH:MM:SSZ` timestamp to epoch seconds (UTC)."""
    return int(datetime.strptime(value, _ISO).replace(tzinfo=timezone.utc).timestamp())


def _fmt_iso(epoch: int) -> str:
    """Format epoch seconds to second-precision `YYYY-MM-DDTHH:MM:SSZ` UTC."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(_ISO)


def should_include(pr, watermark):
    """Decide whether a PR should be included in the harvest.

    Precedence: no_issue → stale → no_files → ok
    Returns (bool, reason_str).
    """
    # 1. no/empty closingIssuesReferences
    if not pr.get("closingIssuesReferences"):
        return (False, "no_issue")

    # 2. stale — mergedAt <= watermark.  None/absent merge date cannot be
    #    proven stale (None bypasses the compare) → include; dedupe absorbs
    #    any re-harvest.  Do NOT use `(pr.get("mergedAt") or "")` — an empty
    #    string is <= watermark and would silently stale-skip.
    merged = pr.get("mergedAt")
    if watermark and merged and merged <= watermark:
        return (False, "stale")

    # 3. no/empty files
    if not pr.get("files"):
        return (False, "no_files")

    return (True, "ok")


def build_record(pr, owner, repo, run):
    """Build harvest records for an includable PR — one per closing issue.

    Returns a List[dict].  Each closing ref is fetched from its OWN repo when
    the ref carries `repository{name, owner{login}}`, else from the base
    owner/repo.  The record's `repo` key reflects the issue's repo.

    Generalized-by-design: pinpoint fields (the fix commit hash and the exact
    changed-file paths) are NOT persisted, and body/title text is redacted of
    private links (chat/helpdesk hosts, claude.ai sessions, GitHub private
    user-attachments, HARVEST_REDACT_PATTERNS) and email addresses.  The stored record
    keeps only enough title/body text to distill a GENERAL pattern — never a map
    of an individual, possibly-unreleased fix.
    """
    pr_body = _redact(pr.get("body", ""))

    records = []
    for ref in pr.get("closingIssuesReferences", []):
        issue = ref["number"]
        repository = ref.get("repository") or {}
        name = repository.get("name")
        login = (repository.get("owner") or {}).get("login")
        if name and login:
            issue_repo = f"{login}/{name}"
        else:
            issue_repo = f"{owner}/{repo}"

        raw = run(["issue", "view", str(issue), "--repo", issue_repo,
                   "--json", "title,body"])
        issue_data = json.loads(raw)
        records.append({
            "repo": issue_repo,
            "pr": pr["number"],
            "issue": issue,
            "issue_title": _redact(issue_data["title"]),
            "issue_body": _redact(issue_data["body"]),
            "pr_body": pr_body,
        })
    return records


def gather(owner, repo, watermark, run=_default_run, limit=1000):
    """Windowed fetch of merged PRs → harvest records.

    Returns (records, raw_max_merged_at, complete):
      - records: deduped harvest records for includable PRs.
      - raw_max_merged_at: max mergedAt over ALL fetched PRs (incl. skipped),
        None excluded; None when nothing was fetched.
      - complete: True only when every window/slice short-paged (< limit).
    """
    records = []
    seen = set()
    all_merged = []
    state = {"complete": True, "aborted": False}
    created_at = {}

    def fetch(search_val):
        raw = run([
            "pr", "list",
            "--repo", f"{owner}/{repo}",
            "--search", search_val,
            "--limit", str(limit),
            "--json", _SEARCH_JSON,
        ])
        return json.loads(raw)

    def ingest(prs):
        for pr in prs:
            merged = pr.get("mergedAt")
            if merged:
                all_merged.append(merged)
            inc, _reason = should_include(pr, watermark)
            if not inc:
                continue
            for rec in build_record(pr, owner, repo, run):
                key = (rec.get("repo"), rec["pr"], rec["issue"])
                if key not in seen:
                    seen.add(key)
                    records.append(rec)

    def repo_created_epoch():
        if "epoch" not in created_at:
            raw = run(["repo", "view", f"{owner}/{repo}", "--json", "createdAt"])
            created_at["epoch"] = _parse_iso(json.loads(raw)["createdAt"])
        return created_at["epoch"]

    def slice_range(lo, hi):
        if state["aborted"] or lo > hi:
            return
        page = fetch(f"is:merged merged:{_fmt_iso(lo)}..{_fmt_iso(hi)}")
        ingest(page)
        if len(page) < limit:
            return
        if hi - lo <= 1:
            # Degenerate: a 1-second slice still returns a full page.  Warn
            # loudly and freeze the whole run — never silently drop data.
            print(
                f"WARNING: degenerate 1-second slice {_fmt_iso(lo)}..{_fmt_iso(hi)} "
                f"still returned a full page ({len(page)} rows); run marked incomplete.",
                file=sys.stderr,
            )
            state["aborted"] = True
            state["complete"] = False
            return
        mid = (lo + hi) // 2
        slice_range(lo, mid)
        slice_range(mid + 1, hi)

    # Initial query: first-run (no watermark) is plain `is:merged`; otherwise
    # windowed by `merged:>WATERMARK`.  No `--state`, no `sort:` token.
    initial_search = "is:merged" if not watermark else f"is:merged merged:>{watermark}"
    page = fetch(initial_search)
    ingest(page)

    if len(page) >= limit:
        # Full page → calendar-slice the covered range.  Lower bound = the
        # watermark if set, else the repo's creation date.  Upper bound = now.
        lower = _parse_iso(watermark) if watermark else repo_created_epoch()
        upper = int(datetime.now(timezone.utc).timestamp())
        if upper - lower > _ONE_YEAR_SECONDS:
            start = lower
            while start <= upper and not state["aborted"]:
                end = min(start + _ONE_YEAR_SECONDS - 1, upper)
                slice_range(start, end)
                start = end + 1
        else:
            slice_range(lower, upper)

    raw_max_merged_at = max(all_merged) if all_merged else None
    return records, raw_max_merged_at, state["complete"]


# ---------------------------------------------------------------------------
# Signals harvest — bug evidence that never reaches a closing issue.
#
#   kind "fix_pr":        a merged PR titled fix/hotfix/bugfix (or a revert)
#                         that closes no issue.
#   kind "review_thread": an inline review thread on a merged PR whose code
#                         changed afterwards (outdated) or that was resolved —
#                         a finding the author likely acted on.
#
# Every comment is tagged, never filtered: author type, bot kind, and whether
# it carries the "Drafted with Claude Code" marker (with its model list), so a
# later distill can decide which sources to trust.
# ---------------------------------------------------------------------------

_FIX_TITLE_RE = re.compile(r"\b(?:fix(?:e[sd])?|hot-?fix|bug-?fix|bug)\b", re.IGNORECASE)
_REVERT_TITLE_RE = re.compile(r"^\s*revert\b", re.IGNORECASE)
_CLAUDE_MARKER_RE = re.compile(r"Drafted with Claude Code([^<\n]*)", re.IGNORECASE)
_MAX_BODY = 4000

# Well-known public bots.  Add your own via HARVEST_AI_REVIEWERS /
# HARVEST_CI_BOTS (comma-separated logins, without the "[bot]" suffix).
AI_REVIEWER_LOGINS = {
    "copilot", "copilot-pull-request-reviewer", "gemini-code-assist",
    "coderabbitai", "sentry", "seer-by-sentry", "cursor", "semgrep-app",
}
CI_BOT_LOGINS = {
    "github-actions", "dependabot", "renovate", "codecov", "sonarqubecloud",
    "socket-security",
}


def _ai_reviewer_logins():
    return AI_REVIEWER_LOGINS | {x.lower() for x in _env_list("HARVEST_AI_REVIEWERS")}


def _ci_bot_logins():
    return CI_BOT_LOGINS | {x.lower() for x in _env_list("HARVEST_CI_BOTS")}


_SIGNALS_QUERY = """
query($owner: String!, $name: String!, $cursor: String, $first: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: MERGED, first: $first, after: $cursor,
                 orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title body mergedAt updatedAt
        closingIssuesReferences { totalCount }
        files(first: 100) { totalCount nodes { path } }
        reviewThreads(first: 50) {
          totalCount
          pageInfo { hasNextPage endCursor }
          nodes {
            id isOutdated isResolved path
            comments(first: 10) {
              totalCount
              nodes { author { login __typename } body }
            }
          }
        }
      }
    }
  }
}
"""

_THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 50, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id isOutdated isResolved path
          comments(first: 10) {
            totalCount
            nodes { author { login __typename } body }
          }
        }
      }
    }
  }
}
"""


def classify_author(author):
    """Return {author, author_type, bot_kind} for a GraphQL `author` node.

    bot_kind is "ai_reviewer" or "ci" for known bots, "bot" for any other
    app/`[bot]` account, and None for a human.  A deleted account (null
    author) is reported as login "ghost"."""
    author = author or {}
    login = author.get("login") or "ghost"
    typename = author.get("__typename") or "User"
    bare = login.lower()
    if bare.endswith("[bot]"):
        bare = bare[: -len("[bot]")]
    if bare in _ai_reviewer_logins():
        kind = "ai_reviewer"
    elif bare in _ci_bot_logins():
        kind = "ci"
    elif typename == "Bot" or login.lower().endswith("[bot]"):
        kind = "bot"
    else:
        kind = None
    return {"author": login, "author_type": typename, "bot_kind": kind}


def parse_claude_marker(body):
    """Detect the posted-comment marker this skill (and other Claude Code
    setups) append, e.g.
      <sub>🤖 Drafted with Claude Code · Models: Sonnet 4.5, Opus 4.1 · 3 Claude subagents</sub>

    Returns {claude_drafted, claude_models, claude_subagents}.  The bare
    "<sub>🤖 Drafted with Claude Code</sub>" form yields an empty model list."""
    m = _CLAUDE_MARKER_RE.search(body or "")
    if not m:
        return {"claude_drafted": False, "claude_models": [], "claude_subagents": None}
    models, subagents = [], None
    for part in m.group(1).split("·"):
        part = part.strip()
        if part.lower().startswith("model"):
            names = part.split(":", 1)[1] if ":" in part else ""
            models = [x.strip() for x in re.split(r",|\+|&|\band\b", names) if x.strip()]
        sm = re.match(r"(\d+)\s+(?:claude\s+)?subagents?", part, re.IGNORECASE)
        if sm:
            subagents = int(sm.group(1))
    return {"claude_drafted": True, "claude_models": models, "claude_subagents": subagents}


def _clip(text):
    text = _redact(text or "")
    if len(text) > _MAX_BODY:
        text = text[:_MAX_BODY] + " …[truncated]"
    return text


def _file_ext(path):
    """Extension only (".php", ".js", "" for none) — paths are not stored."""
    name = (path or "").rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[1].lower() if "." in name.strip(".") else ""


def build_fix_pr_record(pr, owner, repo):
    """Return a "fix_pr" record, or None when the PR does not qualify.

    Qualifies when it closes no issue, changed at least one file, and its
    title reads as a fix or a revert.  File paths are reduced to extensions."""
    if (pr.get("closingIssuesReferences") or {}).get("totalCount"):
        return None
    files = (pr.get("files") or {}).get("nodes") or []
    if not files:
        return None
    title = pr.get("title") or ""
    revert = bool(_REVERT_TITLE_RE.search(title))
    if not revert and not _FIX_TITLE_RE.search(title):
        return None
    return {
        "kind": "fix_pr",
        "repo": f"{owner}/{repo}",
        "pr": pr["number"],
        "thread": None,
        "revert": revert,
        "merged_at": pr.get("mergedAt"),
        "pr_title": _redact(title),
        "pr_body": _clip(pr.get("body")),
        "files_changed": (pr.get("files") or {}).get("totalCount", len(files)),
        "file_exts": sorted({_file_ext(f.get("path")) for f in files}),
    }


def build_thread_records(pr, owner, repo):
    """Return "review_thread" records for threads that are outdated or resolved.

    The first comment is the finding; the rest are the replies.  Each comment
    carries its author classification and Claude-marker tags; the thread-level
    fields copy the first comment's tags for easy filtering."""
    out = []
    for t in (pr.get("reviewThreads") or {}).get("nodes") or []:
        if not (t.get("isOutdated") or t.get("isResolved")):
            continue
        comments = []
        for c in (t.get("comments") or {}).get("nodes") or []:
            entry = classify_author(c.get("author"))
            entry.update(parse_claude_marker(c.get("body")))
            entry["body"] = _clip(c.get("body"))
            comments.append(entry)
        if not comments:
            continue
        first = comments[0]
        out.append({
            "kind": "review_thread",
            "repo": f"{owner}/{repo}",
            "pr": pr["number"],
            "thread": t.get("id"),
            "merged_at": pr.get("mergedAt"),
            "pr_title": _redact(pr.get("title") or ""),
            "outdated": bool(t.get("isOutdated")),
            "resolved": bool(t.get("isResolved")),
            "file_ext": _file_ext(t.get("path")),
            "author": first["author"],
            "author_type": first["author_type"],
            "bot_kind": first["bot_kind"],
            "claude_drafted": first["claude_drafted"],
            "claude_models": first["claude_models"],
            "reply_count": max((t.get("comments") or {}).get("totalCount", len(comments)) - 1, 0),
            "comments": comments,
        })
    return out


def _fetch_remaining_threads(pr, owner, repo, run):
    """Append the review threads past the first page to pr["reviewThreads"]["nodes"]."""
    threads = pr.get("reviewThreads") or {}
    info = threads.get("pageInfo") or {}
    while info.get("hasNextPage"):
        data = json.loads(run([
            "api", "graphql", "-f", f"query={_THREADS_QUERY}",
            "-f", f"owner={owner}", "-f", f"name={repo}",
            "-F", f"number={pr['number']}", "-f", f"cursor={info['endCursor']}",
        ]))
        if data.get("errors"):
            raise RuntimeError(f"GraphQL errors for {owner}/{repo}#{pr['number']} "
                               f"threads: {data['errors']!r:.300}")
        page = data["data"]["repository"]["pullRequest"]["reviewThreads"]
        threads["nodes"] = (threads.get("nodes") or []) + page["nodes"]
        info = page["pageInfo"]


def gather_signals(owner, repo, watermark, run=_default_run, page_size=25):
    """Page merged PRs newest-updated first and build signal records.

    Stops at the first PR whose updatedAt <= watermark: a PR merged after the
    watermark was necessarily updated after it too, so nothing newer can follow.
    Returns (records, raw_max_merged_at, complete) like gather(); complete is
    False only when GraphQL returned errors."""
    records, seen, merged_all = [], set(), []
    cursor = None
    complete = True
    while True:
        args = ["api", "graphql", "-f", f"query={_SIGNALS_QUERY}",
                "-f", f"owner={owner}", "-f", f"name={repo}",
                "-F", f"first={page_size}"]
        if cursor:
            args += ["-f", f"cursor={cursor}"]
        data = json.loads(run(args))
        if data.get("errors"):
            print(f"WARNING: GraphQL errors for {owner}/{repo}: {data['errors']!r:.300}",
                  file=sys.stderr)
            complete = False
            break
        conn = data["data"]["repository"]["pullRequests"]
        stop = False
        for pr in conn["nodes"]:
            if watermark and pr.get("updatedAt") and pr["updatedAt"] <= watermark:
                stop = True
                break
            merged = pr.get("mergedAt")
            if merged:
                merged_all.append(merged)
            if watermark and merged and merged <= watermark:
                continue
            _fetch_remaining_threads(pr, owner, repo, run)
            fix = build_fix_pr_record(pr, owner, repo)
            for rec in ([fix] if fix else []) + build_thread_records(pr, owner, repo):
                k = _signal_key(rec)
                if k not in seen:
                    seen.add(k)
                    records.append(rec)
        if stop or not conn["pageInfo"]["hasNextPage"]:
            break
        cursor = conn["pageInfo"]["endCursor"]
    return records, (max(merged_all) if merged_all else None), complete


def list_org_repos(owner, run=_default_run):
    """Return every repo in a GitHub org as ``owner/name``.

    Uses ``gh api --paginate`` so the result is not capped at the 30-repo
    default of ``gh repo list``. Includes public, private, forked, and
    archived repos the token can see (``type=all``). Order is
    case-insensitive and stable so a batch harvest walks the same sequence
    every run. Duplicate names from overlapping pages are dropped.
    """
    owner = (owner or "").strip()
    if not owner or "/" in owner or any(ch.isspace() for ch in owner):
        raise ValueError(
            f"org login must be a single owner name, got {owner!r}")
    raw = run([
        "api", "--paginate", "--method", "GET",
        f"orgs/{owner}/repos?per_page=100&type=all",
        "--jq", ".[].full_name",
    ])
    seen = set()
    repos = []
    for line in (raw or "").splitlines():
        name = line.strip().strip('"')
        if not name or "/" not in name or name in seen:
            continue
        seen.add(name)
        repos.append(name)
    repos.sort(key=str.lower)
    return repos


def read_watermark(path):
    """Return contents of watermark file stripped, or None if missing."""
    p = Path(path)
    if not p.exists():
        return None
    return p.read_text().strip()


def write_watermark(path, value):
    """Write value to watermark file."""
    Path(path).write_text(value)


def _issue_key(rec, base_repo=None):
    return (rec.get("repo") or base_repo, rec.get("pr"), rec.get("issue"))


def _signal_key(rec, base_repo=None):
    return (rec.get("kind"), rec.get("repo") or base_repo, rec.get("pr"), rec.get("thread"))


def write_records(records, path, base_repo=None, key=_issue_key):
    """Append records to `path`, dedupe by `key` (default (repo, pr, issue)),
    return the delta.

    Loads any existing list, appends only records whose key is new, and does
    NOT truncate.  Short-circuits (no write) when the delta is 0 so a 0-new
    run leaves the file content-equal.  Returns the count of NEW records added.
    """
    p = Path(path)
    existing = []
    if p.exists():
        try:
            loaded = json.loads(p.read_text())
            if isinstance(loaded, list):
                existing = loaded
        except (ValueError, OSError):
            existing = []

    def key_of(rec):
        return key(rec, base_repo)

    seen = set()
    merged = []
    for rec in existing:
        seen.add(key_of(rec))
        merged.append(rec)

    delta = 0
    for rec in records:
        k = key_of(rec)
        if k not in seen:
            seen.add(k)
            merged.append(rec)
            delta += 1

    if delta == 0:
        return 0

    with open(path, "w") as fh:
        json.dump(merged, fh, indent=2)
    return delta


def main(argv=None, run=_default_run):
    p = argparse.ArgumentParser(
        description="Harvest GitHub issues linked to merged PRs.")
    p.add_argument("--repo",
                   help="owner/repo to harvest (e.g. acme/my-plugin)")
    p.add_argument("--list-org", metavar="ORG",
                   help="Print every owner/repo in ORG, one per line, and exit. "
                        "Includes private, forked, and archived repos visible to the token.")
    p.add_argument("--signals", action="store_true",
                   help="Harvest fix PRs that close no issue and acted-on review "
                        "threads instead of closing issues.")
    p.add_argument("--page-size", type=int, default=25,
                   help="PRs per GraphQL page in --signals mode (default: 25)")
    p.add_argument("--limit", type=int, default=1000,
                   help="Search/slice page size (default: 1000, the Search cap)")
    p.add_argument("--watermark-file", default=None,
                   help="Path to watermark file (default: .harvest/watermark, "
                        "or .harvest/signals-watermark with --signals)")
    p.add_argument("--out", default=None,
                   help="Output path for records JSON (default: .harvest/records.json, "
                        "or .harvest/signals.json with --signals)")
    a = p.parse_args(argv)

    if a.list_org:
        try:
            repos = list_org_repos(a.list_org, run=run)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            raise SystemExit(2)
        for name in repos:
            print(name)
        return

    if not a.repo or a.repo.count("/") != 1:
        print("ERROR: --repo owner/repo is required unless --list-org is set.",
              file=sys.stderr)
        raise SystemExit(2)

    owner, repo = a.repo.split("/", 1)
    if a.watermark_file is None:
        a.watermark_file = ".harvest/signals-watermark" if a.signals else ".harvest/watermark"
    if a.out is None:
        a.out = ".harvest/signals.json" if a.signals else ".harvest/records.json"

    # Ensure output directories exist
    os.makedirs(os.path.dirname(os.path.abspath(a.watermark_file)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)

    watermark = read_watermark(a.watermark_file)

    if a.signals:
        records, raw_max_merged_at, complete = gather_signals(
            owner, repo, watermark, run=run, page_size=a.page_size)
        delta = write_records(records, a.out, base_repo=f"{owner}/{repo}", key=_signal_key)
    else:
        records, raw_max_merged_at, complete = gather(
            owner, repo, watermark, run=run, limit=a.limit)
        delta = write_records(records, a.out, base_repo=f"{owner}/{repo}")

    # Watermark rule: advance ONLY when the whole run is complete.  New value
    # is max(mergedAt) - 1 second, second-precision UTC.  Empty set, an
    # incomplete run, or a regression leaves the file untouched (monotonic).
    if complete and raw_max_merged_at:
        candidate = _fmt_iso(_parse_iso(raw_max_merged_at) - 1)
        if watermark is None or candidate > watermark:
            write_watermark(a.watermark_file, candidate)

    # Compute the on-disk store total.
    store_total = 0
    out_path = Path(a.out)
    if out_path.exists():
        try:
            loaded = json.loads(out_path.read_text())
            if isinstance(loaded, list):
                store_total = len(loaded)
        except (ValueError, OSError):
            store_total = 0

    # stdout: line-start anchors the shell parses (`^records_written=`,
    # `^store_total=`) — each on its own line.
    print(f"repo={owner}/{repo}")
    print(f"records_written={delta}")
    print(f"store_total={store_total}")


if __name__ == "__main__":
    main()
