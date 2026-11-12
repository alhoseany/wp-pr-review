#!/usr/bin/env python3
"""Scan the added lines of a PR diff for mechanical bug-pattern shapes.

Each hit is a LEAD, not a finding: it names a line worth reading and the
known-bug-patterns entries whose "Detect by" check it came from. Confirm every
lead by reading the code before it becomes a finding; most will be fine.

    scan_diff.py --pr owner/repo#N [--repo-root DIR] [--json]
    scan_diff.py --diff changes.diff [--repo-root DIR] [--json]

--repo-root points at a checkout of the PR head. File-level rules (a handler
with no nonce or capability check anywhere in its file) then read the whole
file; without it they only see the diff, which yields more leads.

Exit codes: 0 scanned (with or without leads), 1 I/O or gh error.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from typing import Callable, Dict, List, Optional

from collect_pr import parse_pr_ref

_DEFAULT_SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join("references", "known-bug-patterns.md")

PHP = (".php",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
SKIP_PARTS = ("vendor/", "node_modules/", "/build/", "/dist/", "languages/")
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".lock")
# Test code sets superglobals and hooks handlers on purpose; skipped unless --include-tests.
TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)/|(?:Test|-test|_test)\.php$|\.(?:test|spec)\.[jt]sx?$")

HANDLER_RE = re.compile(
    r"""add_action\s*\(\s*['"](wp_ajax_(?:nopriv_)?|admin_post_(?:nopriv_)?)""")

# Each rule: id, langs, a regex on an ADDED line, and optionally
#   unless       -- regex on the same line that clears the hit
#   unless_next  -- (n, regex): cleared when one of the next n new-side lines matches
#   file_lacks   -- regex that must be absent from the whole file for a hit
#   topic        -- regex over corpus headings ("### ...") naming the related entries
RULES = [
    {
        "id": "handler-without-nonce",
        "langs": PHP,
        "match": HANDLER_RE,
        "file_lacks": re.compile(r"check_ajax_referer|check_admin_referer|wp_verify_nonce"),
        "hint": "AJAX/admin-post handler in a file with no nonce check; confirm the "
                "callback verifies one before any state change.",
        "topic": r"nonce",
    },
    {
        "id": "handler-without-capability",
        "langs": PHP,
        "match": HANDLER_RE,
        "file_lacks": re.compile(r"current_user_can\s*\("),
        "hint": "AJAX/admin-post handler in a file with no current_user_can(); a nonce "
                "proves intent, not authorization.",
        "topic": r"current_user_can|capabilit",
    },
    {
        "id": "nopriv-handler",
        "langs": PHP,
        "match": re.compile(r"""['"](wp_ajax_nopriv_|admin_post_nopriv_)"""),
        "hint": "Logged-out entry point; check ownership of every id it reads, rate "
                "limiting, and what it creates or sends.",
        "topic": r"nopriv|unauthenticated|logged-out",
    },
    {
        "id": "sql-interpolation",
        "langs": PHP,
        "match": re.compile(
            r"""\$wpdb->(?:query|get_var|get_row|get_col|get_results)\s*\(\s*(?:"[^"]*\$|.*['"]\s*\.\s*\$)"""),
        "unless": re.compile(r"->prepare\s*\("),
        "hint": "Variable interpolated or concatenated into SQL outside "
                "$wpdb->prepare(); bind it through a placeholder.",
        "topic": r"prepare\(\)",
    },
    {
        "id": "request-input",
        "langs": PHP,
        "match": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\["),
        "unless": re.compile(
            r"sanitize_|absint\s*\(|intval\s*\(|\(int\)|\(bool\)|wp_unslash|esc_|"
            r"isset\s*\(|empty\s*\(|array_key_exists|wp_verify_nonce|check_admin_referer|"
            r"check_ajax_referer|in_array\s*\("),
        "hint": "Raw request value with no unslash/sanitize on the line; add it to "
                "the input-to-sink matrix and trace where it lands.",
        "topic": r"unslash",
    },
    {
        "id": "unescaped-echo",
        "langs": PHP,
        "match": re.compile(r"(?:\becho\b|\bprint\b|<\?=)\s*[^;]*\$"),
        "unless": re.compile(
            r"esc_(?:html|attr|url|js|textarea|xml)|wp_kses|absint\s*\(|intval\s*\(|"
            r"\(int\)|number_format|wp_json_encode|selected\s*\(|checked\s*\(|disabled\s*\("),
        "hint": "Variable echoed with no escaping function on the line; check the "
                "value's source and the output context.",
        "topic": r"escap",
    },
    {
        "id": "add-query-arg-current-url",
        "langs": PHP,
        "match": re.compile(r"add_query_arg\s*\("),
        "unless": re.compile(
            r"add_query_arg\s*\(.*(?:_url\s*\(|\$\w*(?:url|link|base|href)|get_permalink)"),
        "hint": "add_query_arg() with no visible base URL builds on the current "
                "request URI, carrying its params; pass an explicit base and escape it.",
        "topic": r"add_query_arg|explicit base URL",
    },
    {
        "id": "redirect-without-exit",
        "langs": PHP,
        "match": re.compile(r"\bwp_(?:safe_)?redirect\s*\("),
        "unless": re.compile(r"\b(?:exit|die)\b|return\s+wp_"),
        "unless_next": (3, re.compile(r"\b(?:exit|die)\b")),
        "hint": "Redirect with no exit/die in the next lines; execution continues "
                "after the Location header.",
        "topic": r"redirect.*exit|exit.*redirect",
    },
    {
        "id": "unserialize",
        "langs": PHP,
        "match": re.compile(r"\b(?:maybe_)?unserialize\s*\("),
        "unless": re.compile(r"allowed_classes"),
        "hint": "unserialize() without allowed_classes; confirm the value can never "
                "come from a request, cookie, remote response or editable storage.",
        "topic": r"unserializ",
    },
    {
        "id": "case-with-logical-operator",
        "langs": PHP + JS,
        "match": re.compile(r"\bcase\s+[^:]*(?:\|\||&&|\bor\b|\band\b)[^:]*:"),
        "hint": "`case 'a' || 'b':` evaluates the expression once and compares the "
                "boolean; use stacked case labels.",
        "topic": r"case .a.",
    },
    {
        "id": "secret-compared-with-equality",
        "langs": PHP,
        "match": re.compile(
            r"(?:token|secret|signature|hmac|api_key|apikey|_hash|hash_)\w*['\"\]]?\s*\)?\s*(?:===?|!==?)"
            r"|(?:===?|!==?)\s*\$\w*(?:token|secret|signature|hmac|api_key|hash)",
            re.I),
        "unless": re.compile(
            r"hash_equals|empty\s*\(|(?:===?|!==?)\s*(?:''|\"\"|null\b|false\b|true\b|0\b)", re.I),
        "hint": "Secret-looking value compared with ==/===; use hash_equals() so the "
                "comparison is constant-time.",
        "topic": r"hash_equals",
    },
    {
        "id": "broad-rewrite-capture",
        "langs": PHP,
        "match": re.compile(r"add_rewrite_rule\s*\(.*\(\.[*+]\??\)"),
        "hint": "Rewrite rule captures (.*) or (.+); constrain it to the expected "
                "character class.",
        "topic": r"rewrite-rule",
    },
    {
        "id": "request-uri-match",
        "langs": PHP,
        "match": re.compile(
            r"(?:strpos|stripos|str_contains|preg_match|strstr)\s*\([^;]*REQUEST_URI"),
        "hint": "Decision made by substring-matching REQUEST_URI; the attacker "
                "controls the query string.",
        "topic": r"REQUEST_URI",
    },
    {
        "id": "doing-cron-gate",
        "langs": PHP,
        "match": re.compile(r"DOING_CRON|wp_doing_cron\s*\("),
        "hint": "DOING_CRON is not authentication, and it is false under Action "
                "Scheduler's async runner; check what this gate is meant to allow.",
        "topic": r"DOING_CRON|doing_cron",
    },
    {
        "id": "float-cast-request-amount",
        "langs": PHP,
        "match": re.compile(r"(?:\(float\)|floatval\s*\(|\(double\))\s*(?:wp_unslash\s*\(\s*)?\$_(?:POST|GET|REQUEST)"),
        "hint": "(float) on a posted value truncates locale-formatted amounts "
                "(1.234,56 becomes 1.234).",
        "topic": r"float",
    },
    {
        "id": "unbounded-query",
        "langs": PHP,
        "match": re.compile(r"""['"](?:posts_per_page|numberposts|number)['"]\s*=>\s*-1\b"""),
        "hint": "Unbounded query; confirm the result set is small by design, and "
                "how the query layer treats -1.",
        "topic": r"number => -1",
    },
    {
        "id": "relative-include",
        "langs": PHP,
        "match": re.compile(r"""\b(?:require|include)(?:_once)?\b\s*\(?\s*['"]"""),
        "hint": "require/include with a relative path resolves against the include "
                "path and CWD; anchor it to __DIR__ or a plugin-dir constant.",
        "topic": r"require/include",
    },
    {
        "id": "do-shortcode-dynamic",
        "langs": PHP,
        "match": re.compile(r"do_shortcode\s*\([^)]*\$"),
        "hint": "do_shortcode() on a built string; if any part is user-written, "
                "shortcode syntax in it executes.",
        "topic": r"do_shortcode",
    },
    {
        "id": "asset-version-time",
        "langs": PHP,
        "match": re.compile(r"wp_(?:enqueue|register)_(?:script|style)\s*\(.*\b(?:time|microtime|rand|wp_rand)\s*\("),
        "hint": "Asset version from the clock defeats browser and CDN caching.",
        "topic": r"asset version",
    },
    {
        "id": "fetch-without-status-check",
        "langs": JS,
        "match": re.compile(r"\.then\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*\1\.json\s*\(\s*\)"),
        "hint": "fetch() response parsed without checking .ok/status; an error page "
                "or wp_send_json_error() reaches the success branch.",
        "topic": r"fetch\(\)",
    },
]

# Calls that hit the database, cache backend or network; inside a loop each is
# one round trip per iteration.
QUERY_CALL_RE = re.compile(
    r"\$wpdb->|get_post_meta\s*\(|get_user_meta\s*\(|get_term_meta\s*\(|get_option\s*\(|"
    r"get_posts\s*\(|new\s+WP_(?:Query|User_Query|Term_Query)|get_users\s*\(|get_terms\s*\(|"
    r"wp_remote_(?:get|post|request)\s*\(|update_post_meta\s*\(|update_option\s*\(")
LOOP_RE = re.compile(r"^\s*(?:\}\s*)?(?:foreach|for|while)\s*\(|\.forEach\s*\(|\.map\s*\(")

QUERY_IN_LOOP = {
    "id": "query-in-loop",
    "hint": "Query or remote call inside a loop; check the iteration count at "
            "scale and whether the data can be primed or fetched once.",
    "topic": None,
}


# --------------------------------------------------------------------------- diff

def parse_diff(text: str) -> Dict[str, List[dict]]:
    """Map each changed file to its new-side lines: {"line", "text", "added"}."""
    files: Dict[str, List[dict]] = {}
    current: Optional[List[dict]] = None
    new_line = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = None
            continue
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current = None
                continue
            if path.startswith("b/"):
                path = path[2:]
            current = files.setdefault(path, [])
            continue
        if raw.startswith("--- "):
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if m:
            new_line = int(m.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+"):
            current.append({"line": new_line, "text": raw[1:], "added": True})
            new_line += 1
        elif raw.startswith(" "):
            current.append({"line": new_line, "text": raw[1:], "added": False})
            new_line += 1
        elif raw.startswith("\\"):
            continue
        # "-" lines are old-side only.
    return files


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH_RE.search(path))


def _scannable(path: str) -> bool:
    p = "/" + path
    if any(part in p for part in SKIP_PARTS) or path.endswith(SKIP_SUFFIXES):
        return False
    return path.endswith(PHP + JS)


# ----------------------------------------------------------------------- corpus

def corpus_headings(skill_dir: str) -> List[str]:
    try:
        with open(os.path.join(skill_dir, CORPUS), encoding="utf-8") as fh:
            return [ln[4:].strip() for ln in fh if ln.startswith("### ")]
    except OSError:
        return []


def related(topic: Optional[str], headings: List[str], limit: int = 3) -> List[str]:
    if not topic:
        return []
    rx = re.compile(topic, re.I)
    return [h for h in headings if rx.search(h)][:limit]


# ------------------------------------------------------------------------- scan

def _file_text(path: str, lines: List[dict], repo_root: Optional[str]) -> str:
    if repo_root:
        try:
            with open(os.path.join(repo_root, path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            pass
    return "\n".join(ln["text"] for ln in lines)


def _loop_lines(lines: List[dict]) -> set:
    """New-side line numbers that sit inside a loop body visible in the diff.

    Brace depth is tracked from each loop header within one contiguous run of
    new-side lines; a gap in numbering (next hunk) ends the run.
    """
    inside = set()
    for i, ln in enumerate(lines):
        if not LOOP_RE.search(ln["text"]):
            continue
        depth = ln["text"].count("{") - ln["text"].count("}")
        opened = depth > 0
        prev = ln["line"]
        for nxt in lines[i + 1:]:
            if nxt["line"] != prev + 1:
                break
            prev = nxt["line"]
            if not opened:
                if "{" in nxt["text"]:
                    opened = True
                elif nxt["text"].strip().endswith((";", ":")):
                    inside.add(nxt["line"])  # brace-less single statement / alt syntax
                    if nxt["text"].strip().endswith(";"):
                        break
                    continue
            inside.add(nxt["line"])
            depth += nxt["text"].count("{") - nxt["text"].count("}")
            if opened and depth <= 0:
                break
    return inside


def scan(files: Dict[str, List[dict]], *, repo_root: Optional[str] = None,
         headings: Optional[List[str]] = None, include_tests: bool = False) -> dict:
    headings = headings or []
    leads = []
    scanned = 0
    tests_skipped = 0
    for path, lines in sorted(files.items()):
        if not _scannable(path):
            continue
        if not include_tests and is_test_path(path):
            tests_skipped += 1
            continue
        scanned += 1
        file_text = None
        by_line = {ln["line"]: i for i, ln in enumerate(lines)}
        for rule in RULES:
            if not path.endswith(rule["langs"]):
                continue
            for ln in lines:
                if not ln["added"] or not rule["match"].search(ln["text"]):
                    continue
                if rule.get("unless") and rule["unless"].search(ln["text"]):
                    continue
                if rule.get("unless_next"):
                    n, rx = rule["unless_next"]
                    i = by_line[ln["line"]]
                    if any(rx.search(x["text"]) for x in lines[i + 1:i + 1 + n]):
                        continue
                if rule.get("file_lacks"):
                    if file_text is None:
                        file_text = _file_text(path, lines, repo_root)
                    if rule["file_lacks"].search(file_text):
                        continue
                leads.append(_lead(rule, path, ln, headings))
        in_loop = _loop_lines(lines)
        for ln in lines:
            if ln["added"] and ln["line"] in in_loop and QUERY_CALL_RE.search(ln["text"]):
                leads.append(_lead(QUERY_IN_LOOP, path, ln, headings))
    leads.sort(key=lambda d: (d["path"], d["line"], d["rule"]))
    return {"files_scanned": scanned, "tests_skipped": tests_skipped, "leads": leads}


def _lead(rule: dict, path: str, ln: dict, headings: List[str]) -> dict:
    return {
        "rule": rule["id"],
        "path": path,
        "line": ln["line"],
        "text": ln["text"].strip()[:200],
        "hint": rule["hint"],
        "patterns": related(rule.get("topic"), headings),
    }


def format_text(result: dict) -> str:
    leads = result["leads"]
    skipped = result.get("tests_skipped")
    note = f" ({skipped} test file(s) skipped; --include-tests scans them)" if skipped else ""
    out = [f"scan_diff: {len(leads)} lead(s) in {result['files_scanned']} file(s){note}. "
           "Leads, not findings: read each before reporting it."]
    for d in leads:
        out.append(f"\n{d['path']}:{d['line']}  [{d['rule']}]")
        out.append(f"    {d['text']}")
        out.append(f"    {d['hint']}")
        for h in d["patterns"]:
            out.append(f"    see: {h}")
    return "\n".join(out)


# -------------------------------------------------------------------------- cli

def _gh_diff(ref: str, run: Callable[[list], str]) -> str:
    owner, repo, number = parse_pr_ref(ref)
    return run(["pr", "diff", str(number), "--repo", f"{owner}/{repo}"])


def _default_run(args: list) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def main(argv=None, run: Callable[[list], str] = _default_run) -> int:
    p = argparse.ArgumentParser(description="Scan a PR diff for bug-pattern leads.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pr", help="PR URL, owner/repo#N, or owner/repo/pull/N")
    src.add_argument("--diff", help="unified diff file ('-' for stdin)")
    p.add_argument("--repo-root", help="checkout of the PR head, for file-level rules")
    p.add_argument("--skill-dir", default=_DEFAULT_SKILL_DIR)
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--include-tests", action="store_true",
                   help="also scan test files (tests/, *Test.php, *.test.js, ...)")
    a = p.parse_args(argv)
    try:
        if a.pr:
            text = _gh_diff(a.pr, run)
        elif a.diff == "-":
            text = sys.stdin.read()
        else:
            with open(a.diff, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"scan_diff: {exc}", file=sys.stderr)
        if a.pr and ("too_large" in str(exc) or "HTTP 406" in str(exc)):
            print("scan_diff: GitHub will not serve this diff; scan the checkout instead:\n"
                  "  git -C <checkout> diff origin/<base>...HEAD | scan_diff.py --diff - "
                  "--repo-root <checkout>", file=sys.stderr)
        return 1
    result = scan(parse_diff(text), repo_root=a.repo_root,
                  headings=corpus_headings(a.skill_dir), include_tests=a.include_tests)
    if a.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        print(format_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
