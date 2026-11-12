#!/usr/bin/env python3
"""Render the local ``review.md`` from a findings document.

``findings.json`` is the single source of a review: this script writes the
rich local report from it, so nothing is typed twice. The report follows
``references/review-template.md``.

Usage::

    python3 scripts/render_review.py <findings.json> --pr-json <collect_pr.json> \\
        --repo-root <checkout> [--base-dir .] [--out <review.md>] [--fresh] \\
        [--skill-dir <skill>] [--date YYYY-MM-DD] [--check]

What the script derives, so the model never types it:

* the header (repo, branch, author, state, CI line) from the ``collect_pr``
  output, and the head OIDs from the document;
* the summary counts table (Found on the ORIGINAL severity, Confirmed /
  Partially valid on the FINAL severity, False positive from
  ``report.verified_out``);
* the binary recommendation (Approve / Request changes) and its reasons;
* Editor + GitHub links and the Evidence snippet, read from the checkout;
* the quoted pitfalls version line, read from the skill's references;
* the output path (``<pr>``, ``<pr>-2``, ... under ``.pr-reviews/<repo>/``);
* the test-steps sections, from the author's steps ``collect_pr`` parsed out of
  the PR body plus the status the model gives each one.

Line numbers are checked, not trusted: each finding's ``anchor`` must appear
on its cited lines, and every ``path:N`` in the text must resolve to a file in
the checkout with that many lines. The cited code is listed on stderr.

What the model supplies, as text: each finding's fields plus a ``report``
object (summary, questions, matrices, scenarios, ...). See ``REPORT_FIELDS``.

Exit codes: 0 written (or valid with ``--check``), 2 the document fails a
rule (every problem is listed on stderr and nothing is written), 1 an I/O
error.
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ("CRITICAL", "MAJOR", "MINOR", "INFO")
EMOJI = {"CRITICAL": "🔴", "MAJOR": "🟠", "MINOR": "🟡", "INFO": "⚪"}
VERDICTS = ("confirmed", "partial", "refuted")
DIMENSION_ROWS = ("UX", "Functional", "Data", "Security")
CI_CATEGORIES = ("blocking", "advisory", "pending", "unknown", "passing")

# report.compliance keys, in the order the Compliance trace prints them.
COMPLIANCE_FIELDS = (
    "scaling_triggers",
    "security_checklist",
    "known_bug_patterns_sections",
    "input_sink",
    "stored_consumer",
    "flag_matrix",
    "tests_run",
    "live_probes",
)
PRE_VERDICT_ITEMS = 8
TEST_STEP_STATUSES = ("passed", "failed", "not_run")
_STEP_LABEL = {"passed": "passed", "failed": "FAILED", "not_run": "not run"}

# A `path:N` or `path:N-M` citation in report or finding text. Cite another
# ref as `path@ref:N`; that form is not checked against the checkout.
_CITATION = re.compile(
    r"(?<![\w/.@-])((?:[\w.-]+/)*[\w.-]+\.(?:php|js|jsx|mjs|cjs|ts|tsx|vue|css|scss|"
    r"py|json|ya?ml|html?|twig|sh|sql|xml|md|txt)):(\d+)(?:-(\d+))?(?!\w|\.\w)")
_URL = re.compile(r"https?://\S+")
_SKIP_DIRS = {".git", "node_modules", "vendor"}

# Top-level ``report`` keys: (name, required).
REPORT_FIELDS = (
    ("summary", True),
    ("questions", True),
    ("recommendations", True),
    ("scenarios", True),
    ("compliance", True),
    ("test_steps", False),
    ("previous_delta", False),
    ("cross_issue", False),
    ("runtime_unverified", False),
    ("verified_out", False),
    ("head_delta_note", False),
    ("title", False),
)

# The skill folder is this script's parent's parent (scripts/ -> skill root).
_DEFAULT_SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VERSION_LINE = re.compile(r"^_Version:.*_$", re.MULTILINE)
_HEADING = re.compile(r"^#{2,3} (.+?)\s*$", re.MULTILINE)


class RenderError(Exception):
    """The document breaks one or more report rules."""

    def __init__(self, errors: List[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


# --- small helpers ---------------------------------------------------------

def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _lines(value: Any) -> List[str]:
    """Return a list of non-empty strings from a string or list value."""
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [v.strip() for v in value if isinstance(v, str) and v.strip()]
    return []


def final_severity(finding: Dict[str, Any]) -> str:
    return str(finding.get("severity", ""))


def original_severity(finding: Dict[str, Any]) -> str:
    return str(finding.get("original_severity") or finding.get("severity", ""))


def verdict_of(finding: Dict[str, Any]) -> str:
    """Return the reconcile verdict."""
    return str(finding.get("verdict") or "")


def _line_int(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return int(value)
    return None


def _owner_repo(doc: Dict[str, Any]) -> Tuple[str, str]:
    owner, _, name = str(doc.get("repo", "")).partition("/")
    return owner, name


# --- inputs from disk -----------------------------------------------------

def pitfalls_version_line(skill_dir: str) -> Optional[str]:
    path = os.path.join(skill_dir, "references", "verification-pitfalls.md")
    try:
        with open(path, encoding="utf-8") as handle:
            match = _VERSION_LINE.search(handle.read())
    except OSError:
        return None
    return match.group(0) if match else None


def bug_pattern_headings(skill_dir: str) -> Optional[set]:
    path = os.path.join(skill_dir, "references", "known-bug-patterns.md")
    try:
        with open(path, encoding="utf-8") as handle:
            return {m.group(1).strip() for m in _HEADING.finditer(handle.read())}
    except OSError:
        return None


def read_snippet(repo_root: str, path: str, line: int,
                 end_line: Optional[int]) -> Optional[str]:
    """Return the cited source lines (3-8 lines), or None if unreadable."""
    try:
        with open(os.path.join(repo_root, path), encoding="utf-8",
                  errors="replace") as handle:
            source = handle.read().splitlines()
    except OSError:
        return None
    if line > len(source):
        return None
    last = end_line if end_line and end_line >= line else line
    last = min(last, line + 7, len(source))
    first = line
    # Pad a short citation with context up to three lines.
    while last - first + 1 < 3 and (first > 1 or last < len(source)):
        if first > 1:
            first -= 1
        if last - first + 1 < 3 and last < len(source):
            last += 1
    return "\n".join(source[first - 1:last])


def next_review_path(base_dir: str, repo: str, pr: int) -> str:
    """Return ``.pr-reviews/<repo>/<pr>[-N]/review.md`` for the next round."""
    root = os.path.join(base_dir, ".pr-reviews", repo)
    candidate = os.path.join(root, str(pr))
    round_num = 1
    while os.path.exists(os.path.join(candidate, "review.md")):
        round_num += 1
        candidate = os.path.join(root, f"{pr}-{round_num}")
    return os.path.join(candidate, "review.md")


def latest_prior_exists(base_dir: str, repo: str, pr: Any, out: str) -> bool:
    """Return True when a review.md for an earlier round of this PR exists."""
    root = os.path.join(base_dir, ".pr-reviews", repo)
    pattern = re.compile(rf"^{re.escape(str(pr))}(-\d+)?$")
    try:
        entries = os.listdir(root)
    except OSError:
        return False
    target = os.path.abspath(out)
    for entry in entries:
        review = os.path.join(root, entry, "review.md")
        if pattern.match(entry) and os.path.isfile(review) \
                and os.path.abspath(review) != target:
            return True
    return False


def _source_lines(repo_root: str, path: str) -> Optional[List[str]]:
    try:
        with open(os.path.join(repo_root, path), encoding="utf-8",
                  errors="replace") as handle:
            return handle.read().splitlines()
    except OSError:
        return None


def _checkout_files(repo_root: str) -> List[str]:
    """Return the checkout's files, relative to its root."""
    try:
        out = subprocess.run(["git", "-C", repo_root, "ls-files"], capture_output=True,
                             text=True, check=True).stdout
        return [ln for ln in out.splitlines() if ln]
    except (OSError, subprocess.CalledProcessError):
        pass
    files = []
    for top, dirs, names in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        rel = os.path.relpath(top, repo_root)
        files += [n if rel == "." else os.path.join(rel, n) for n in names]
    return files


class _Citations:
    """Resolve `path:N` citations against the checkout at the reviewed head."""

    def __init__(self, repo_root: str, pr_files: List[str]) -> None:
        self.repo_root = repo_root
        self.pr_files = pr_files
        self._files: Optional[List[str]] = None
        self.resolved: List[Tuple[str, str, int, int, str]] = []
        self._seen: set = set()

    def resolve(self, cited: str) -> Tuple[Optional[str], str]:
        """Return (repo-relative path, '') or (None, why)."""
        cited = cited.lstrip("./")
        if os.path.isfile(os.path.join(self.repo_root, cited)):
            return cited, ""
        if self._files is None:
            self._files = _checkout_files(self.repo_root)
        hits = [f for f in self._files if f == cited or f.endswith("/" + cited)]
        in_pr = [f for f in hits if f in self.pr_files]
        if len(in_pr) == 1 or (len(hits) == 1):
            return (in_pr or hits)[0], ""
        if not hits:
            return None, "no such file in the checkout"
        return None, f"ambiguous ({len(hits)} files match; give more of the path)"

    def check(self, where: str, text: str) -> List[str]:
        errors = []
        for match in _CITATION.finditer(_URL.sub(" ", text)):
            cited, first = match.group(1), int(match.group(2))
            last = int(match.group(3)) if match.group(3) else first
            label = match.group(0)
            path, why = self.resolve(cited)
            if path is None:
                errors.append(f"{where}: cites {label}: {why}")
                continue
            source = _source_lines(self.repo_root, path) or []
            if first < 1 or last < first or last > len(source):
                errors.append(f"{where}: cites {label} but {path} has {len(source)} "
                              "lines at the reviewed head")
                continue
            if label not in self._seen:
                self._seen.add(label)
                self.resolved.append((label, path, first, last,
                                      source[first - 1].strip()))
        return errors


def _strings(value: Any, where: str):
    """Yield (location, string) for every string inside a JSON value."""
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            yield from _strings(item, f"{where}[{idx}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in ("url", "anchor"):
                yield from _strings(item, f"{where}.{key}")


def citations(doc: Dict[str, Any], pr_json: Dict[str, Any],
              repo_root: str) -> Tuple[List[str], List[Tuple[str, str, int, int, str]]]:
    """Check every `path:N` cited in the report and the findings.

    Returns (errors, resolved) where resolved lists (citation, path, first,
    last, text of the first cited line) for the reviewer to eyeball.
    """
    pr_files = [str(f.get("path")) for f in pr_json.get("files") or []
                if isinstance(f, dict)]
    cites = _Citations(repo_root, pr_files)
    errors = []
    for where, text in list(_strings(doc.get("report"), "report")) + \
            list(_strings(doc.get("findings"), "findings")):
        errors += cites.check(where, text)
    return errors, cites.resolved


def collected_steps(pr_json: Dict[str, Any]) -> List[str]:
    """Return the author's test steps that collect_pr parsed from the PR body."""
    block = pr_json.get("test_steps")
    steps = block.get("steps") if isinstance(block, dict) else None
    return _lines(steps)


def _step_numbers(item: Dict[str, Any]) -> List[int]:
    nums = item.get("steps")
    if isinstance(nums, int) and not isinstance(nums, bool):
        nums = [nums]
    if not isinstance(nums, list):
        return []
    return [n for n in nums if isinstance(n, int) and not isinstance(n, bool)]


# --- derived values -------------------------------------------------------

def ci_waivers(doc: Dict[str, Any]) -> Dict[str, str]:
    """Return {check name: reason} from the document's ``ci_advisory`` list.

    A team policy can make a failing check non-blocking (for example a
    coverage-percentage gate). Each entry names one check and says why;
    malformed entries are ignored here and reported by ``validate``.
    """
    out: Dict[str, str] = {}
    for item in doc.get("ci_advisory") or [] if isinstance(doc, dict) else []:
        if isinstance(item, dict) and _text(item.get("name")) and _text(item.get("reason")):
            out[_text(item["name"])] = _text(item["reason"])
    return out


def ci_summary(pr_json: Dict[str, Any],
               waived: Optional[Dict[str, str]] = None) -> Tuple[str, List[str], bool]:
    """Return (CI header text, blocking check names, ci_unavailable).

    Checks named in ``waived`` stay visible in the text, with their reason,
    but are not returned as blocking.
    """
    waived = waived or {}
    if pr_json.get("ci_error"):
        return "unavailable (fetch failed)", [], True
    checks = (pr_json.get("ci") or {}).get("checks") or []
    if not checks:
        return "none", [], False
    failing = list(dict.fromkeys(str(c.get("name")) for c in checks
                                 if c.get("category") == "blocking"))
    blocking = [n for n in failing if n not in waived]
    advisory = [f"{n} ({waived[n]})" for n in failing if n in waived]
    note = ("; non-blocking by team policy: " + ", ".join(advisory)) if advisory else ""
    if blocking:
        return "FAILING: " + ", ".join(blocking) + note, blocking, False
    if any(c.get("category") == "pending" for c in checks):
        return "pending" + note, [], False
    if advisory:
        noun = "check" if len(advisory) == 1 else "checks"
        return (f"no blocking failures ({len(advisory)} failed {noun} non-blocking by "
                "team policy: " + ", ".join(advisory) + ")"), [], False
    return "passing", [], False


def is_blocking_finding(finding: Dict[str, Any]) -> bool:
    if verdict_of(finding) == "refuted":
        return False
    if final_severity(finding) in ("CRITICAL", "MAJOR"):
        return True
    tags = {str(t).lower() for t in finding.get("tags") or []}
    return bool(tags & {"security", "payment"})


def recommendation(doc: Dict[str, Any], pr_json: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Apply the binary verdict rule; return (verdict, blocker reasons)."""
    reasons: List[str] = []
    for finding in doc.get("findings") or []:
        if is_blocking_finding(finding):
            reasons.append(
                f"{finding.get('id')} ({final_severity(finding)}"
                + (", " + "/".join(finding.get("tags")) if finding.get("tags") else "")
                + ")"
            )
    meta = pr_json.get("metadata") or {}
    mergeable = str(meta.get("mergeable") or "").upper()
    state = str(meta.get("mergeStateStatus") or "").upper()
    if mergeable == "CONFLICTING" or state == "DIRTY":
        reasons.append("not mergeable (conflicts)")
    elif not mergeable or mergeable == "UNKNOWN":
        reasons.append("mergeability unknown (re-fetch before approving)")
    if state == "BEHIND":
        reasons.append("behind its base branch")
    _, blocking, unavailable = ci_summary(pr_json, ci_waivers(doc))
    if unavailable:
        reasons.append("CI status unavailable (fetch failed)")
    reasons.extend(f"failing CI check: {name}" for name in blocking)
    return ("Request changes" if reasons else "Approve"), reasons


def counts(doc: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    table = {s: {"found": 0, "confirmed": 0, "partial": 0, "fp": 0} for s in SEVERITIES}
    for finding in doc.get("findings") or []:
        orig, final = original_severity(finding), final_severity(finding)
        if orig in table:
            table[orig]["found"] += 1
        verdict = verdict_of(finding)
        if final in table and verdict in ("confirmed", "partial"):
            table[final]["confirmed" if verdict == "confirmed" else "partial"] += 1
    for item in report.get("verified_out") or []:
        sev = str(item.get("severity", "")) if isinstance(item, dict) else ""
        if sev in table:
            table[sev]["found"] += 1
            table[sev]["fp"] += 1
    return table


# --- validation -----------------------------------------------------------

def validate(doc: Dict[str, Any], pr_json: Dict[str, Any], *, fresh: bool,
             repo_root: str, skill_dir: str, rereview: bool = False) -> List[str]:
    """Return every rule the document breaks (empty list = renderable)."""
    errors: List[str] = []
    report = doc.get("report")
    if not isinstance(report, dict):
        errors.append("report: required object (summary, questions, compliance, ...)")
        for idx, finding in enumerate(doc.get("findings") or []):
            errors.extend(_validate_finding(idx, finding, repo_root))
        return errors

    for name, required in REPORT_FIELDS:
        if required and name != "compliance" and not _lines(report.get(name)) \
                and not (name == "scenarios" and report.get(name)):
            errors.append(f"report.{name}: required and non-empty")

    for idx, sc in enumerate(report.get("scenarios") or []):
        if not isinstance(sc, dict):
            errors.append(f"report.scenarios[{idx}]: must be an object")
            continue
        for key in ("title", "setup", "steps", "expected"):
            if not _lines(sc.get(key)):
                errors.append(f"report.scenarios[{idx}].{key}: required")

    if rereview and not fresh and not _lines(report.get("previous_delta")):
        errors.append("report.previous_delta: required on a re-review (an earlier "
                      "round exists); mark each prior issue persisting/fixed/new")
    elif not fresh and report.get("previous_delta") is not None \
            and not _lines(report.get("previous_delta")):
        errors.append("report.previous_delta: empty; omit it on a first review")

    if not _text(doc.get("head")):
        errors.append("head: required (OID at review start)")
    if not _text(doc.get("head_at_emit")):
        errors.append("head_at_emit: required (OID re-fetched at emit)")
    elif _text(doc.get("head")) and doc["head"] != doc["head_at_emit"] \
            and not _text(report.get("head_delta_note")):
        errors.append("head moved during the review: re-review the delta and "
                      "set report.head_delta_note")

    errors.extend(_validate_compliance(report.get("compliance"), doc, skill_dir))

    for idx, item in enumerate(report.get("verified_out") or []):
        if not isinstance(item, dict) or not _text(item.get("title")) \
                or item.get("severity") not in SEVERITIES or not _text(item.get("reason")):
            errors.append(f"report.verified_out[{idx}]: needs title, severity, reason")

    ids = set()
    for idx, finding in enumerate(doc.get("findings") or []):
        errors.extend(_validate_finding(idx, finding, repo_root))
        if finding.get("id") in ids:
            errors.append(f"findings[{idx}].id: duplicate {finding.get('id')!r}")
        ids.add(finding.get("id"))
    errors.extend(_validate_test_steps(report.get("test_steps"), pr_json, ids))
    errors.extend(citations(doc, pr_json, repo_root)[0])

    meta = pr_json.get("metadata") or {}
    if not meta:
        errors.append("pr-json: missing metadata (pass the collect_pr output)")

    stated = _text(doc.get("recommendation"))
    errors.extend(_validate_ci_advisory(doc, pr_json))
    if stated:
        computed, _ = recommendation(doc, pr_json)
        if stated != computed:
            errors.append(f"recommendation: document says {stated!r} but the "
                          f"blocker rule gives {computed!r}")
    return errors


def _validate_test_steps(items: Any, pr_json: Dict[str, Any], ids: set) -> List[str]:
    """Every author step is accounted for once: passed, failed or not_run."""
    collected = collected_steps(pr_json)
    if items is None:
        items = []
    if not isinstance(items, list):
        return ["report.test_steps: must be a list of {steps|text, status, note}"]
    errors = []
    seen: Dict[int, int] = {}
    for idx, item in enumerate(items):
        where = f"report.test_steps[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: must be {{steps: [author step numbers] or text: "
                          "<your own step>, status, note}")
            continue
        if item.get("status") not in TEST_STEP_STATUSES:
            errors.append(f"{where}.status: must be one of {list(TEST_STEP_STATUSES)}")
        if not _text(item.get("note")):
            errors.append(f"{where}.note: required (what you ran and saw, or why not run)")
        nums = _step_numbers(item)
        if ("steps" in item) == bool(_text(item.get("text"))):
            errors.append(f"{where}: give exactly one of steps (author step numbers) "
                          "or text (a step of your own)")
        elif "steps" in item:
            if not nums or len(nums) != len(item["steps"] if isinstance(item["steps"], list)
                                           else [item["steps"]]):
                errors.append(f"{where}.steps: must be author step numbers")
            for n in nums:
                if not 1 <= n <= len(collected):
                    errors.append(f"{where}.steps: no author step {n} (collect_pr "
                                  f"found {len(collected)})")
                elif n in seen:
                    errors.append(f"{where}.steps: step {n} already listed in "
                                  f"report.test_steps[{seen[n]}]")
                else:
                    seen[n] = idx
        if item.get("status") == "failed" and item.get("finding") not in ids:
            errors.append(f"{where}.finding: a failed step needs the id of the "
                          "finding it produced")
    missing = [n for n in range(1, len(collected) + 1) if n not in seen]
    if missing:
        errors.append(f"report.test_steps: author step(s) {missing} not accounted for; "
                      "mark each passed, failed or not_run")
    return errors


def _validate_ci_advisory(doc: Dict[str, Any], pr_json: Dict[str, Any]) -> List[str]:
    """Each waiver names a check that is failing on this PR and says why."""
    items = doc.get("ci_advisory")
    if items is None:
        return []
    if not isinstance(items, list):
        return ["ci_advisory: must be a list of {name, reason}"]
    failing = {str(c.get("name")) for c in (pr_json.get("ci") or {}).get("checks") or []
               if c.get("category") == "blocking"}
    errors = []
    for idx, item in enumerate(items):
        where = f"ci_advisory[{idx}]"
        if not isinstance(item, dict) or not _text(item.get("name")) \
                or not _text(item.get("reason")):
            errors.append(f"{where}: needs a check name and the team-policy reason")
        elif _text(item["name"]) not in failing:
            errors.append(f"{where}: {item['name']!r} is not a failing check on this PR")
    return errors


def _validate_finding(idx: int, finding: Any, repo_root: str) -> List[str]:
    where = f"findings[{idx}]"
    if not isinstance(finding, dict):
        return [f"{where}: must be an object"]
    errors: List[str] = []
    for key in ("id", "path", "problem", "what_where", "fix", "verified", "detection"):
        if not _text(finding.get(key)):
            errors.append(f"{where}.{key}: required non-empty string")
    sev = final_severity(finding)
    if sev not in SEVERITIES:
        errors.append(f"{where}.severity: must be one of {list(SEVERITIES)}")
    if original_severity(finding) not in SEVERITIES:
        errors.append(f"{where}.original_severity: must be one of {list(SEVERITIES)}")
    verdict = verdict_of(finding)
    if verdict not in VERDICTS:
        errors.append(f"{where}.verdict: must be one of {list(VERDICTS)}")
    elif verdict == "refuted":
        errors.append(f"{where}: refuted findings go in report.verified_out, "
                      "not in findings")
    line = _line_int(finding.get("line"))
    if line is None:
        errors.append(f"{where}.line: must be a positive line number")
    anchor = _text(finding.get("anchor"))
    if not anchor:
        errors.append(f"{where}.anchor: required (a fragment of the code at line..end_line, "
                      "copied from the file at the reviewed head)")
    elif line is not None:
        source = _source_lines(repo_root, str(finding.get("path", "")))
        last = _line_int(finding.get("end_line")) or line
        if source is None:
            errors.append(f"{where}: cannot read {finding.get('path')} under --repo-root")
        elif not any(" ".join(anchor.split()) in " ".join(ln.split())
                     for ln in source[line - 1:max(last, line)]):
            found = [n for n, ln in enumerate(source, 1)
                     if " ".join(anchor.split()) in " ".join(ln.split())]
            hint = f"; it is at line(s) {found[:5]}" if found else "; not in the file"
            errors.append(f"{where}.anchor: {anchor!r} is not on {finding.get('path')}:"
                          f"{line}" + (f"-{last}" if last != line else "") + hint)
    if sev in ("CRITICAL", "MAJOR"):
        if not _text(finding.get("documented_intent")):
            errors.append(f"{where}.documented_intent: required on {sev} "
                          "(quote the comment, or 'None — checked at file:line')")
        dims = finding.get("dimensions")
        if not isinstance(dims, dict) or not all(_text(dims.get(k)) for k in DIMENSION_ROWS):
            errors.append(f"{where}.dimensions: {sev} needs all of {list(DIMENSION_ROWS)}")
        if line is not None and read_snippet(
                repo_root, str(finding.get("path", "")), line,
                _line_int(finding.get("end_line"))) is None:
            errors.append(f"{where}: cannot read {finding.get('path')}:{line} under "
                          "--repo-root for the Evidence snippet")
    if sev in ("CRITICAL", "MAJOR", "MINOR") and not _text(finding.get("likelihood")):
        errors.append(f"{where}.likelihood: required on {sev}")
    return errors


def _validate_compliance(comp: Any, doc: Dict[str, Any], skill_dir: str) -> List[str]:
    if not isinstance(comp, dict):
        return ["report.compliance: required object"]
    errors: List[str] = []
    for key in COMPLIANCE_FIELDS:
        value = _text(comp.get(key)) if key != "known_bug_patterns_sections" \
            else _lines(comp.get(key))
        if not value:
            errors.append(f"report.compliance.{key}: required (write 'N/A: <why>' "
                          "when it does not apply)")
    checklist = _lines(comp.get("pre_verdict_checklist"))
    if len(checklist) != PRE_VERDICT_ITEMS:
        errors.append(f"report.compliance.pre_verdict_checklist: needs exactly "
                      f"{PRE_VERDICT_ITEMS} answered items (got {len(checklist)})")

    pitfalls = comp.get("pitfalls_per_finding")
    finding_ids = [str(f.get("id")) for f in doc.get("findings") or [] if isinstance(f, dict)]
    if not isinstance(pitfalls, dict):
        if finding_ids:
            errors.append("report.compliance.pitfalls_per_finding: required map "
                          "of finding id -> pitfall numbers")
    else:
        for fid in finding_ids:
            if not pitfalls.get(fid):
                errors.append(f"report.compliance.pitfalls_per_finding: {fid} missing")

    if pitfalls_version_line(skill_dir) is None:
        errors.append(f"--skill-dir {skill_dir}: no _Version:_ line in "
                      "references/verification-pitfalls.md")

    matches = comp.get("known_bug_patterns_matches") or {}
    if not isinstance(matches, dict):
        errors.append("report.compliance.known_bug_patterns_matches: must map "
                      "pattern heading -> finding id")
    else:
        headings = bug_pattern_headings(skill_dir)
        if headings is None:
            errors.append(f"--skill-dir {skill_dir}: cannot read "
                          "references/known-bug-patterns.md")
        else:
            for heading in list(matches) + _lines(comp.get("known_bug_patterns_sections")):
                if heading not in headings:
                    errors.append(f"known-bug-patterns heading not found: {heading!r}")
    return errors


# --- rendering ------------------------------------------------------------

def _bullets(items: List[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _pitfall_refs(pitfalls: Any) -> str:
    if not isinstance(pitfalls, dict) or not pitfalls:
        return "none (no findings)"
    parts = []
    for fid, nums in pitfalls.items():
        nums = nums if isinstance(nums, list) else [nums]
        parts.append(f"{fid}→" + ",".join(
            n if str(n).startswith("#") else f"#{n}" for n in map(str, nums)))
    return " · ".join(parts)


def _render_compliance(doc, report, skill_dir) -> str:
    comp = report["compliance"]
    head, emit = doc["head"], doc["head_at_emit"]
    moved = "same" if head == emit else f"moved: {_text(report.get('head_delta_note'))}"
    matches = comp.get("known_bug_patterns_matches") or {}
    match_text = ", ".join(f"{h} → {fid}" for h, fid in matches.items()) or "none"
    checklist = _lines(comp.get("pre_verdict_checklist"))
    lines = [
        "## Compliance trace",
        "",
        f"- Head: {head} / {emit} — {moved}",
        "- Refs read:",
        f"  - review-methodology.md — Scaling triggers fired: {comp['scaling_triggers'].strip()}",
        f"  - verification-pitfalls.md — version line quoted: "
        f"\"{pitfalls_version_line(skill_dir)}\"; pitfalls checked per finding: "
        f"{_pitfall_refs(comp.get('pitfalls_per_finding'))}",
        f"  - security-hardening-checklist.md — {comp['security_checklist'].strip()}",
        f"  - known-bug-patterns.md — sections grepped: "
        f"{', '.join(_lines(comp['known_bug_patterns_sections']))}; matches: {match_text}",
        f"- Pre-verdict checklist ({PRE_VERDICT_ITEMS} items):",
    ]
    lines += [f"  {n}. {item}" for n, item in enumerate(checklist, 1)]
    for label, key in (("Input → sink matrix", "input_sink"),
                       ("Stored-value → consumer matrix", "stored_consumer"),
                       ("Flag set/clear/read matrix", "flag_matrix")):
        value = comp[key].strip()
        if "\n" in value:
            lines += [f"- {label}:", "", value, ""]
        else:
            lines.append(f"- {label}: {value}")
    lines.append(f"- Tests run: {comp['tests_run'].strip()}")
    lines.append(f"- Live probes: {comp['live_probes'].strip()}")
    return "\n".join(lines)


def _verification_line(finding: Dict[str, Any]) -> str:
    verdict = verdict_of(finding)
    orig, final = original_severity(finding), final_severity(finding)
    if verdict == "confirmed":
        mark = "✓ confirmed"
    else:
        mark = "⚠ partially valid" + (f" (severity {orig}→{final})" if orig != final else "")
    return f"{mark} — {finding['verified'].strip()}"


def _render_test_steps(items: List[Dict[str, Any]],
                       pr_json: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return (run steps block, not-run steps block) as markdown lines."""
    collected = collected_steps(pr_json)
    ran: List[str] = []
    not_run: List[str] = []
    for item in items:
        status = item["status"]
        label = _STEP_LABEL[status] + (f" ({item['finding']})" if status == "failed" else "")
        nums = _step_numbers(item)
        if nums:
            name = ("Step " if len(nums) == 1 else "Steps ") + ", ".join(map(str, nums))
            block = [f"- **{name}** — {label}: {item['note'].strip()}"]
            block += [f"  - Step {n}: {' '.join(collected[n - 1].split())}" for n in nums]
        else:
            block = [f"- **Own step:** {item['text'].strip()} — {label}: {item['note'].strip()}"]
        (not_run if status == "not_run" else ran).extend(block)
    return ([*ran, ""] if ran else []), ([*not_run, ""] if not_run else [])


def _render_finding(finding, doc, pr_json, review_md, repo_root) -> str:
    sev = final_severity(finding)
    owner, name = _owner_repo(doc)
    meta = pr_json.get("metadata") or {}
    branch = meta.get("headRefName") or doc.get("head") or ""
    path = str(finding["path"])
    line = _line_int(finding.get("line"))
    end_line = _line_int(finding.get("end_line"))
    anchor = f"#L{line}" + (f"-L{end_line}" if end_line and end_line != line else "")
    editor = os.path.relpath(os.path.abspath(os.path.join(repo_root, path)),
                             start=os.path.abspath(os.path.dirname(review_md)))
    github = f"https://github.com/{owner}/{name}/blob/{branch}/{path.lstrip('/')}"
    title = _text(finding.get("title")) or finding["problem"].strip()
    issue = finding["what_where"].strip()
    if _text(finding.get("customer_impact")):
        issue += " " + finding["customer_impact"].strip()
    config = _text(finding.get("config"))

    out = [f"#### {EMOJI[sev]} {sev} — {title}" + (f" ({config})" if config else ""), ""]
    loc = f"`{path}:{line}`" if not end_line or end_line == line else f"`{path}:{line}-{end_line}`"
    out += [f"- **File:** {loc} — [Editor]({editor}{anchor}) | [GitHub]({github}{anchor})", ""]
    for extra in _lines(finding.get("also")):
        out += [f"- **Also:** `{extra}`", ""]
    out += [f"- **Detection:** {finding['detection'].strip()}", ""]
    out += [f"- **Issue:** {issue}", ""]

    if sev in ("CRITICAL", "MAJOR", "MINOR"):
        snippet = read_snippet(repo_root, path, line, end_line) if line else None
        if snippet is not None and (sev != "MINOR" or finding.get("show_evidence")):
            lang = os.path.splitext(path)[1].lstrip(".") or "text"
            fence = "```"
            while fence in snippet:
                fence += "`"
            out += ["- **Evidence:**", "", f"{fence}{lang}", snippet, fence, ""]
    if sev in ("CRITICAL", "MAJOR"):
        out += [f"- **Documented intent:** {finding['documented_intent'].strip()}", ""]
    dims = finding.get("dimensions") if isinstance(finding.get("dimensions"), dict) else {}
    if sev in ("CRITICAL", "MAJOR") or (sev == "MINOR" and dims):
        out += ["- **Impact:**", "", "| Severity | Impact |", "|----------|--------|"]
        out += [f"| {row} | {_text(dims.get(row)) or 'None'} |" for row in DIMENSION_ROWS]
        out.append("")
    if sev != "INFO":
        likelihood = finding["likelihood"].strip()
        why = _text(finding.get("likelihood_note"))
        out += [f"- **Likelihood:** {likelihood}" + (f" — {why}" if why else ""), ""]
    out += [f"- **Suggestion:** {finding['fix'].strip()}", ""]
    if _text(finding.get("reproduced")):
        out += [f"- **Reproduced:** {finding['reproduced'].strip()}", ""]
    if _text(finding.get("dedupe", {}).get("status") if isinstance(finding.get("dedupe"), dict) else ""):
        ack = finding["dedupe"]
        note = f"{ack['status']}" + (f" — {ack['url']}" if _text(ack.get("url")) else "") \
            + (f" ({ack['note'].strip()})" if _text(ack.get("note")) else "")
        out += [f"- **Dedupe:** {note}", ""]
    out += [f"- **Verification:** {_verification_line(finding)}"]
    return "\n".join(out)


def render(doc: Dict[str, Any], pr_json: Dict[str, Any], *, review_md: str,
           repo_root: str, skill_dir: str, fresh: bool = False,
           date: Optional[str] = None, rereview: bool = False,
           extra_errors: Optional[List[str]] = None) -> str:
    """Validate and render the report; raise ``RenderError`` on any rule break."""
    errors = list(extra_errors or [])
    errors += validate(doc, pr_json, fresh=fresh, repo_root=repo_root,
                       skill_dir=skill_dir, rereview=rereview)
    if errors:
        raise RenderError(errors)
    report = doc["report"]
    meta = pr_json.get("metadata") or {}
    author = (meta.get("author") or {}).get("login", "?")
    ci_text, _, _ = ci_summary(pr_json, ci_waivers(doc))
    verdict, reasons = recommendation(doc, pr_json)
    rationale = "; ".join(reasons) if reasons else "no blockers"
    title = _text(report.get("title")) or meta.get("title") or f"#{doc['pr']}"

    parts: List[str] = [
        f"# PR Review: {title}",
        "",
        f"- **Repo:** {doc['repo']}",
        f"- **Branch:** {meta.get('headRefName', '?')} → {meta.get('baseRefName', '?')}",
        f"- **HEAD reviewed:** {doc['head']}",
        f"- **Author/State:** {author} / {meta.get('state', '?')}",
        f"- **Generated:** {date or datetime.date.today().isoformat()}",
        f"- **CI:** {ci_text}",
    ]
    if fresh:
        parts.append("- **Mode:** fresh review; earlier rounds were not read")
    parts += [
        f"- **Head:** {doc['head']} / {doc['head_at_emit']}",
        f"- **Recommendation:** {verdict} — {rationale}",
        "",
        _render_compliance(doc, report, skill_dir),
        "",
        "## Summary",
        "",
        "\n\n".join(_lines(report["summary"])),
        "",
        "| Severity | Found | Confirmed | Partially valid | False positive |",
        "|----------|-------|-----------|-----------------|----------------|",
    ]
    table = counts(doc, report)
    parts += [f"| {EMOJI[s]} {s} | {table[s]['found']} | {table[s]['confirmed']} | "
              f"{table[s]['partial']} | {table[s]['fp']} |" for s in SEVERITIES]
    parts.append("")

    if not fresh and _lines(report.get("previous_delta")):
        parts += ["## Previous review delta", "", _bullets(_lines(report["previous_delta"])), ""]

    parts += ["## Review Questions", "", _bullets(_lines(report["questions"])), ""]

    parts += ["## Findings", ""]
    findings = sorted(doc.get("findings") or [],
                      key=lambda f: SEVERITIES.index(final_severity(f)))
    if not findings:
        parts += ["No findings.", ""]
    part_names = []
    for f in findings:
        part = _text(f.get("part"))
        if part and part not in part_names:
            part_names.append(part)
    groups = [(p, [f for f in findings if _text(f.get("part")) == p]) for p in part_names]
    unparted = [f for f in findings if not _text(f.get("part"))]
    if unparted:
        groups.insert(0, ("", unparted))
    for part, items in groups:
        if part:
            parts += [f"### Part: {part}", ""]
        for finding in items:
            parts += [_render_finding(finding, doc, pr_json, review_md, repo_root), ""]

    if _lines(report.get("cross_issue")):
        parts += ["## Cross-Issue Interactions", "", _bullets(_lines(report["cross_issue"])), ""]

    parts += ["## Recommendations", "", _bullets(_lines(report["recommendations"])), ""]

    parts += ["## Manual Testing Scenarios", ""]
    for n, sc in enumerate(report["scenarios"], 1):
        steps = _lines(sc.get("steps"))
        parts += [f"### {n}. {sc['title'].strip()}", "",
                  f"- **Setup:** {_text(sc.get('setup'))}", "",
                  "- **Steps:**", ""]
        parts += [f"  {i}. {step}" for i, step in enumerate(steps, 1)]
        parts += ["", f"- **Expected:** {_lines(sc.get('expected'))[0]}", ""]
        edges = _lines(sc.get("edge_cases"))
        if edges:
            parts += ["- **Edge cases:**", ""] + [f"  - {e}" for e in edges] + [""]

    ran, not_run = _render_test_steps(report.get("test_steps") or [], pr_json)
    parts += ["## Verified by running the PR's test steps", ""]
    if ran:
        parts += ran
    elif not_run:
        parts += ["None of the documented test steps were run; see Runtime-unverified.", ""]
    else:
        parts += ["No documented test steps.", ""]

    unverified = not_run + ([_bullets(_lines(report.get("runtime_unverified"))), ""]
                            if _lines(report.get("runtime_unverified")) else [])
    if unverified:
        parts += ["## Runtime-unverified", ""] + unverified

    if report.get("verified_out"):
        parts += ["## Verified-out (false positives)", ""]
        parts += [f"- {EMOJI[i['severity']]} {i['severity']} — {i['title'].strip()}: "
                  f"{i['reason'].strip()}" for i in report["verified_out"]]
        parts.append("")

    return "\n".join(parts).rstrip() + "\n"


def _document_errors(doc: Any) -> List[str]:
    """Check the document envelope (repo, pr, findings list)."""
    if not isinstance(doc, dict):
        return ["document must be a JSON object"]
    errors = []
    owner, name = _owner_repo(doc)
    if not owner or not name:
        errors.append("repo: must be '<owner>/<repo>'")
    if not isinstance(doc.get("pr"), int) or isinstance(doc.get("pr"), bool) or doc["pr"] <= 0:
        errors.append("pr: must be an int > 0")
    if not isinstance(doc.get("findings"), list):
        errors.append("findings: must be a list (empty for a clean PR)")
    return errors


# --- CLI ------------------------------------------------------------------

def _load_json(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _print_verdict(doc: Any, pr_json: Any) -> int:
    """--verdict: apply the blocker rule to findings + PR data alone."""
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list) \
            or not all(isinstance(f, dict) for f in doc["findings"]) \
            or not isinstance(pr_json, dict):
        print("verdict: findings must be an object with a findings list of objects, "
              "and --pr-json an object", file=sys.stderr)
        return 2
    verdict, reasons = recommendation(doc, pr_json)
    ci_text, _, _ = ci_summary(pr_json, ci_waivers(doc))
    print(json.dumps({"recommendation": verdict, "reasons": reasons, "ci": ci_text}, indent=2))
    return 0


def _print_citations(resolved: List[Tuple[str, str, int, int, str]]) -> None:
    """List each cited line's code so a wrong line number shows at a glance."""
    if not resolved:
        return
    print("citations (check each one shows what the text claims):", file=sys.stderr)
    for label, path, first, last, code in resolved:
        span = f"{first}" + (f"-{last}" if last != first else "")
        print(f"  {label} -> {path}:{span}: {code[:120]}", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("findings", help="findings.json with a top-level 'report' object")
    parser.add_argument("--pr-json", required=True, help="collect_pr.py output for the PR")
    parser.add_argument("--repo-root", help="checkout root at the reviewed head (required unless --verdict)")
    parser.add_argument("--base-dir", default=".", help="project root holding .pr-reviews/")
    parser.add_argument("--out", help="explicit review.md path (default: next round dir)")
    parser.add_argument("--skill-dir", default=_DEFAULT_SKILL_DIR,
                        help="skill folder holding references/ (default: %(default)s)")
    parser.add_argument("--fresh", action="store_true", help="fresh review: no delta section")
    parser.add_argument("--date", help="Generated date (default: today)")
    parser.add_argument("--check", action="store_true", help="validate only; write nothing")
    parser.add_argument("--verdict", action="store_true",
                        help="print the recommendation and its blocker reasons; no report needed, "
                             "nothing written")
    args = parser.parse_args(argv)
    if not args.verdict and not args.repo_root:
        parser.error("--repo-root is required unless --verdict")

    try:
        doc = _load_json(args.findings)
        pr_json = _load_json(args.pr_json)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.verdict:
        return _print_verdict(doc, pr_json)
    if not isinstance(doc, dict):
        print("review.md not written: document must be a JSON object", file=sys.stderr)
        return 2
    _, name = _owner_repo(doc)
    out = args.out or next_review_path(args.base_dir, name, doc.get("pr"))
    rereview = latest_prior_exists(args.base_dir, name, doc.get("pr"), out)
    try:
        text = render(doc, pr_json, review_md=out, repo_root=args.repo_root,
                      skill_dir=args.skill_dir, fresh=args.fresh, date=args.date,
                      rereview=rereview, extra_errors=_document_errors(doc))
    except RenderError as exc:
        print(f"review.md not written: {len(exc.errors)} problem(s)", file=sys.stderr)
        for err in exc.errors:
            print(f"  - {err}", file=sys.stderr)
        return 2
    _print_citations(citations(doc, pr_json, args.repo_root)[1])
    if args.check:
        print(f"ok: {out} would be written", file=sys.stderr)
        return 0
    try:
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    verdict, _ = recommendation(doc, pr_json)
    print(json.dumps({"review_md": out, "recommendation": verdict}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
