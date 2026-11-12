#!/usr/bin/env python3
"""Duplicate-finding gate: check findings against what is already on the PR.

Before a review is posted, check every finding against every comment already
on the pull request: inline review comments, review bodies and conversation
comments, from any author (bots and your own earlier rounds included). A
duplicate must be dropped, or rewritten as a reference to the existing thread.

Read-only. It fetches three GET endpoints (paginated) with ``gh api``::

    repos/<repo>/pulls/<n>/comments     inline review comments
    repos/<repo>/pulls/<n>/reviews      review bodies
    repos/<repo>/issues/<n>/comments    conversation comments

For each finding it lists candidate matches:

* location: same ``path`` and a comment ``line`` or ``original_line`` within
  ``--window`` lines of the finding's line;
* text: normalized-token Jaccard similarity between the finding text and the
  comment body, at or above ``--threshold``.

A finding may carry an acknowledgement::

    "dedupe": {"status": "new" | "reference" | "dropped",
               "url": "<existing comment url, required for reference>",
               "note": "<free text>"}

Candidates on an acknowledged finding do not fail the gate. A ``reference``
ack must name a url that exists on the PR, and the finding text must cite it.

The score is lexical. It misses paraphrases, so the semantic duplicate check
stays a reviewer step; this gate catches the cheap cases.

    python3 scripts/dedupe_check.py <findings.json> [--json OUT]
        [--window 5] [--threshold 0.35]

Exit codes: 0 no unacknowledged candidates, 2 usage/load/validate/fetch
error, 3 unacknowledged candidates (or a bad ``reference`` ack) exist.
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, TextIO

DEFAULT_WINDOW = 5
DEFAULT_THRESHOLD = 0.35

EXIT_OK = 0
EXIT_ERROR = 2
EXIT_DUPLICATES = 3

STATUSES = ("new", "reference", "dropped")

# One normalized record per existing comment (see ``fetch_existing``).
Existing = Dict[str, Any]
Fetcher = Callable[[str, int], List[Existing]]
Getter = Callable[[str], List[Dict[str, Any]]]

_TAG = re.compile(r"<[^>]+>")
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_URL = re.compile(r"https?://\S+")
_TOKEN = re.compile(r"[a-z0-9_]+")

# Words that carry no signal: English filler plus the fixed labels of a
# rendered review comment (so two review comments do not match each other
# just because both have an impact table).
_STOP = frozenset(
    """
    a an and are as at be been but by can could did do does for from had has
    have if in into is it its may might more not of on or our so than that the
    their then there these this those to was were what when where which will
    with would you your we should also only any all via per
    caution warning note severity likelihood dimension impact ux functional
    data security customer customers verified fix details summary problem
    high medium low co authored noreply com code origin badge img shields io
    blocking reproduced nit
    """.split()
)


class DedupeError(Exception):
    """The existing comments could not be fetched or parsed."""


# --------------------------------------------------------------------------
# Fetching (read-only GETs)
# --------------------------------------------------------------------------


def _parse_pages(text: str) -> List[Dict[str, Any]]:
    """Parse ``gh api --paginate`` output into one flat list.

    ``gh`` usually merges array pages, but a run of separate JSON documents
    (``[..][..]``) is also accepted so a multi-page result is never lost.
    """
    decoder = json.JSONDecoder()
    pos = 0
    out: List[Dict[str, Any]] = []
    text = text or ""
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        value, pos = decoder.raw_decode(text, pos)
        if isinstance(value, list):
            out.extend(value)
        elif isinstance(value, dict):
            out.append(value)
    return out


def _gh_get(endpoint: str) -> List[Dict[str, Any]]:
    """GET ``endpoint`` (paginated) with ``gh api``.

    Read-only: the method is pinned to GET.

    Raises:
        DedupeError: On any ``gh`` failure or unparsable output.
    """
    try:
        proc = subprocess.run(["gh", "api", "--method", "GET", endpoint, "--paginate"],
                              capture_output=True, text=True)
    except Exception as exc:  # noqa: BLE001 - e.g. gh binary missing
        raise DedupeError(f"gh api {endpoint} failed: {exc}") from exc
    if proc.returncode != 0:
        raise DedupeError(f"gh api {endpoint} failed: {proc.stderr.strip()}")
    try:
        return _parse_pages(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DedupeError(f"gh api {endpoint} returned invalid JSON: {exc}") from exc


def _login(raw: Dict[str, Any]) -> str:
    """Return the author login of a raw GitHub object ("" when unknown)."""
    return (raw.get("user") or {}).get("login", "") or ""


def fetch_existing(
    repo: str, pr: int, get: Optional[Getter] = None
) -> List[Existing]:
    """Fetch every comment already on the PR, normalized.

    Args:
        repo: ``"<owner>/<repo>"`` slug.
        pr: Pull-request number.
        get: Injectable ``endpoint -> list of raw dicts`` seam (default: real
            read-only ``gh api`` GET).

    Returns:
        Records ``{source, id, author, url, body, path, line, original_line}``
        with ``source`` one of ``inline``, ``review``, ``conversation``.
        Reviews with an empty body are dropped.

    Raises:
        DedupeError: When any of the three GETs fails.
    """
    get = get if get is not None else _gh_get
    base = f"repos/{repo}"
    records: List[Existing] = []

    for raw in get(f"{base}/pulls/{pr}/comments"):
        records.append(
            {
                "source": "inline",
                "id": raw.get("id"),
                "author": _login(raw),
                "url": raw.get("html_url") or "",
                "body": raw.get("body") or "",
                "path": raw.get("path"),
                "line": raw.get("line"),
                "original_line": raw.get("original_line"),
            }
        )
    for raw in get(f"{base}/pulls/{pr}/reviews"):
        body = raw.get("body") or ""
        if not body.strip():
            continue
        records.append(
            {
                "source": "review",
                "id": raw.get("id"),
                "author": _login(raw),
                "url": raw.get("html_url") or "",
                "body": body,
                "path": None,
                "line": None,
                "original_line": None,
            }
        )
    for raw in get(f"{base}/issues/{pr}/comments"):
        records.append(
            {
                "source": "conversation",
                "id": raw.get("id"),
                "author": _login(raw),
                "url": raw.get("html_url") or "",
                "body": raw.get("body") or "",
                "path": None,
                "line": None,
                "original_line": None,
            }
        )
    return records


# --------------------------------------------------------------------------
# Similarity
# --------------------------------------------------------------------------


def tokens(text: str) -> frozenset:
    """Return the normalized token set of ``text``.

    Drops HTML comments and tags, and urls;
    lowercases; keeps ``[a-z0-9_]`` runs (so identifiers like ``apply_discount``
    stay whole); removes stop words and 1-2 character tokens; folds a plural
    ``s``.
    """
    text = _COMMENT.sub(" ", text or "")
    text = _TAG.sub(" ", text)
    text = _URL.sub(" ", text)
    out = set()
    for tok in _TOKEN.findall(text.lower()):
        if len(tok) < 3 or tok in _STOP:
            continue
        if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
            tok = tok[:-1]
        out.add(tok)
    return frozenset(out)


def jaccard(left: frozenset, right: frozenset) -> float:
    """Return ``|left & right| / |left | right|`` (0.0 when both are empty)."""
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _finding_variants(finding: Dict[str, Any]) -> List[frozenset]:
    """Return the finding-text token sets to compare against a comment.

    Three views, best score wins: title only, title + body, and every text
    field. A short bot comment matches the narrow views; a long prior round
    of ours matches the wide one.
    """

    def field_text(*names: str) -> str:
        return "\n".join(str(finding.get(name) or "") for name in names)

    views = (
        field_text("problem"),
        field_text("problem", "what_where"),
        field_text("problem", "what_where", "customer_impact", "fix"),
    )
    return [tokens(view) for view in views]


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


@dataclass
class Candidate:
    """One existing comment that may duplicate a finding."""

    source: str
    id: Any
    author: str
    url: str
    score: float
    reasons: List[str]
    path: Optional[str] = None
    line: Optional[int] = None


@dataclass
class FindingResult:
    """The dedupe outcome for one finding."""

    id: str
    path: str
    line: int
    candidates: List[Candidate] = field(default_factory=list)
    ack: Optional[Dict[str, Any]] = None
    problems: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """``clean``, ``acknowledged`` or ``unacknowledged``."""
        if self.problems:
            return "unacknowledged"
        if not self.candidates:
            return "clean"
        return "acknowledged" if self.ack else "unacknowledged"


@dataclass
class Report:
    """The dedupe outcome for a whole findings document."""

    repo: str
    pr: int
    window: int
    threshold: float
    existing_count: int
    results: List[FindingResult]

    @property
    def unacknowledged(self) -> List[FindingResult]:
        """Results that fail the gate."""
        return [r for r in self.results if r.status == "unacknowledged"]

    @property
    def exit_code(self) -> int:
        """``EXIT_DUPLICATES`` when anything is unacknowledged, else ``EXIT_OK``."""
        return EXIT_DUPLICATES if self.unacknowledged else EXIT_OK


def _valid_ack(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the finding's ack when it is a dict with a known status."""
    ack = finding.get("dedupe")
    if isinstance(ack, dict) and ack.get("status") in STATUSES:
        return ack
    return None


def _norm_url(url: Any) -> str:
    """Normalize a url for comparison."""
    return str(url or "").strip().rstrip("/")


def _near(line: Any, others: Sequence[Any], window: int) -> Optional[int]:
    """Return the smallest line distance within ``window``, else None."""
    best: Optional[int] = None
    for other in others:
        if isinstance(other, int) and not isinstance(other, bool):
            dist = abs(line - other)
            if dist <= window and (best is None or dist < best):
                best = dist
    return best


def match_finding(
    finding: Dict[str, Any],
    existing: Sequence[Existing],
    window: int = DEFAULT_WINDOW,
    threshold: float = DEFAULT_THRESHOLD,
) -> List[Candidate]:
    """Return the existing comments that may duplicate ``finding``.

    Candidates are ordered best first (score, then closeness).
    """
    variants = _finding_variants(finding)
    path = finding.get("path")
    line = finding.get("line")
    found: List[Candidate] = []

    for rec in existing:
        reasons: List[str] = []
        dist: Optional[int] = None

        if (
            rec.get("path")
            and rec.get("path") == path
            and isinstance(line, int)
        ):
            dist = _near(line, (rec.get("line"), rec.get("original_line")), window)
            if dist == 0:
                reasons.append(f"same line {line}")
            elif dist is not None:
                reasons.append(f"nearby line (within {dist} of {line})")

        body_tokens = tokens(rec.get("body") or "")
        score = max((jaccard(v, body_tokens) for v in variants), default=0.0)
        if score >= threshold:
            reasons.append(f"text similarity {score:.2f}")

        if not reasons:
            continue
        found.append(
            Candidate(
                source=str(rec.get("source")),
                id=rec.get("id"),
                author=str(rec.get("author") or ""),
                url=str(rec.get("url") or ""),
                score=round(score, 3),
                reasons=reasons,
                path=rec.get("path"),
                line=rec.get("line") or rec.get("original_line"),
            )
        )

    found.sort(key=lambda c: -c.score)
    return found


def _reference_problems(
    finding: Dict[str, Any], ack: Dict[str, Any], known_urls: set
) -> List[str]:
    """Return problems with a ``reference`` ack (empty when it holds up)."""
    url = _norm_url(ack.get("url"))
    problems: List[str] = []
    if not url:
        return ["reference ack has no url"]
    if url not in known_urls:
        problems.append(
            f"reference url {url} is not an existing comment on this PR"
        )
    # Only the fields that are posted count: the fix and verified text stay
    # in the local record, so a url cited there never reaches the PR.
    text = "\n".join(
        str(finding.get(name) or "")
        for name in ("problem", "what_where", "customer_impact", "reproduced")
    )
    if url not in text:
        problems.append(
            f"reference ack: the finding text does not cite {url}; rewrite the "
            f"finding as a reference to the existing thread"
        )
    return problems


def check(
    doc: Dict[str, Any],
    existing: Sequence[Existing],
    window: int = DEFAULT_WINDOW,
    threshold: float = DEFAULT_THRESHOLD,
) -> Report:
    """Check every finding of ``doc`` against ``existing``.

    Findings whose ack status is ``dropped`` are still reported but cannot
    fail the gate (they are never staged).
    """
    known_urls = {_norm_url(rec.get("url")) for rec in existing if rec.get("url")}
    results: List[FindingResult] = []
    for finding in doc.get("findings") or []:
        ack = _valid_ack(finding)
        result = FindingResult(
            id=str(finding.get("id")),
            path=str(finding.get("path")),
            line=finding.get("line"),
            candidates=match_finding(finding, existing, window, threshold),
            ack=ack,
        )
        if ack and ack["status"] == "reference":
            result.problems = _reference_problems(finding, ack, known_urls)
        results.append(result)
    return Report(
        repo=str(doc.get("repo")),
        pr=doc.get("pr"),
        window=window,
        threshold=threshold,
        existing_count=len(existing),
        results=results,
    )


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def format_report(report: Report) -> str:
    """Return the human-readable report."""
    lines = [
        f"dedupe: {report.repo}#{report.pr}: {report.existing_count} existing "
        f"comment(s) checked, window={report.window}, "
        f"threshold={report.threshold}"
    ]
    for res in report.results:
        tag = {
            "clean": "no candidates",
            "acknowledged": "candidates acknowledged",
            "unacknowledged": "UNACKNOWLEDGED",
        }[res.status]
        lines.append(f"{res.id}  {res.path}:{res.line}  [{tag}]")
        if res.ack:
            note = f" - {res.ack['note']}" if res.ack.get("note") else ""
            url = f" {res.ack['url']}" if res.ack.get("url") else ""
            lines.append(f"  ack: {res.ack['status']}{url}{note}")
        for cand in res.candidates:
            lines.append(
                f"  - @{cand.author or '?'} ({cand.source}) "
                f"{cand.url or '(no url)'} score={cand.score:.2f} "
                f"reason: {'; '.join(cand.reasons)}"
            )
        for problem in res.problems:
            lines.append(f"  ! {problem}")
    bad = report.unacknowledged
    if bad:
        lines.append(
            f"FAIL: {len(bad)} finding(s) with unacknowledged duplicates: "
            f"{', '.join(r.id for r in bad)}. Drop each one, rewrite it as a "
            f'reference, or add a "dedupe" ack after a human check.'
        )
    else:
        lines.append("OK: no unacknowledged duplicate candidates.")
    return "\n".join(lines)


def report_to_json(report: Report) -> Dict[str, Any]:
    """Return a JSON-safe dict of the report."""
    return {
        "repo": report.repo,
        "pr": report.pr,
        "window": report.window,
        "threshold": report.threshold,
        "existing_count": report.existing_count,
        "exit_code": report.exit_code,
        "findings": [
            {
                "id": r.id,
                "path": r.path,
                "line": r.line,
                "status": r.status,
                "ack": r.ack,
                "problems": r.problems,
                "candidates": [asdict(c) for c in r.candidates],
            }
            for r in report.results
        ],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def validate(doc: Any) -> List[str]:
    """Return the problems that stop the gate from running (empty when fine)."""
    if not isinstance(doc, dict):
        return ["findings file must hold a JSON object"]
    errors: List[str] = []
    if not isinstance(doc.get("repo"), str) or not _REPO.match(doc["repo"]):
        errors.append('"repo" must be "<owner>/<name>"')
    pr = doc.get("pr")
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        errors.append('"pr" must be a positive integer')
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return errors + ['"findings" must be a list']
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where} must be an object")
            continue
        for key in ("id", "path", "problem"):
            if not isinstance(f.get(key), str) or not f[key].strip():
                errors.append(f"{where}.{key} must be a non-empty string")
        line = f.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
            errors.append(f"{where}.line must be a positive integer")
        ack = f.get("dedupe")
        if ack is not None and not (isinstance(ack, dict) and ack.get("status") in STATUSES):
            errors.append(f"{where}.dedupe.status must be one of {', '.join(STATUSES)}")
    return errors


def run_check(
    doc: Dict[str, Any],
    fetch: Optional[Fetcher] = None,
    window: int = DEFAULT_WINDOW,
    threshold: float = DEFAULT_THRESHOLD,
) -> Report:
    """Fetch existing comments for ``doc`` and check its findings.

    Raises:
        DedupeError: When the existing comments cannot be fetched.
    """
    fetch = fetch if fetch is not None else fetch_existing
    try:
        existing = fetch(doc["repo"], doc["pr"])
    except DedupeError:
        raise
    except Exception as exc:  # noqa: BLE001 - any read failure is a fetch failure
        raise DedupeError(f"could not fetch existing PR comments: {exc}") from exc
    return check(doc, existing, window, threshold)


def main(
    argv: Optional[List[str]] = None,
    fetch: Optional[Fetcher] = None,
    out: Optional[TextIO] = None,
) -> int:
    """Run the dedupe CLI: 0 clean, 2 error, 3 unacknowledged candidates."""
    out = out if out is not None else sys.stdout
    parser = argparse.ArgumentParser(
        description="Check findings against comments already on the PR.")
    parser.add_argument("findings", help="path to the findings JSON file")
    parser.add_argument("--json", metavar="OUT", help="also write a JSON report")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW,
                        help="same-path line distance that counts as a match (default 5)")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help="minimum text similarity, 0-1 (default 0.35)")
    args = parser.parse_args(argv)

    if args.window < 0 or not 0.0 <= args.threshold <= 1.0:
        print("--window must be >= 0 and --threshold within 0..1", file=sys.stderr)
        return EXIT_ERROR

    try:
        with open(args.findings, encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"could not load {args.findings}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    errors = validate(doc)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return EXIT_ERROR

    try:
        report = run_check(doc, fetch, args.window, args.threshold)
    except DedupeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    print(format_report(report), file=out)
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as handle:
                json.dump(report_to_json(report), handle, indent=2)
                handle.write("\n")
        except OSError as exc:
            print(f"could not write --json report: {exc}", file=sys.stderr)
            return EXIT_ERROR
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
