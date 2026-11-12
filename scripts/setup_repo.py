#!/usr/bin/env python3
"""Prepare a repo for review: detect monorepo/plugin, checkout the PR branch,
and report the changed files. All `git` calls go through an injected `run`.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from typing import Callable, List, Optional

# Monorepo branch forms: "plugin-name/issue/123" or "issue/123-plugin-name"
_PREFIX_RE = re.compile(r"^([a-z0-9][a-z0-9\-]+)/(?:issue|feature|fix|release)/", re.I)
_SUFFIX_RE = re.compile(r"^(?:issue|feature|fix|release)/\d+-([a-z0-9][a-z0-9\-]+)$", re.I)
# Directory prefixes a monorepo puts in front of a plugin name (e.g. a branch
# "wallet/issue/1" living in "my-plugin-wallet/").  Set PLUGIN_DIR_PREFIXES
# (comma-separated) to match your layout; the substring fallback still applies.
def _common_prefixes() -> List[str]:
    return [x.strip() for x in os.environ.get("PLUGIN_DIR_PREFIXES", "").split(",")
            if x.strip()]


def parse_plugin_from_branch(branch: str) -> Optional[str]:
    for rx in (_PREFIX_RE, _SUFFIX_RE):
        m = rx.match(branch)
        if m:
            return m.group(1)
    return None


def resolve_plugin_dir(plugin_name: str, existing_dirs: List[str]) -> Optional[str]:
    if plugin_name in existing_dirs:
        return plugin_name
    for pref in _common_prefixes():
        cand = pref + plugin_name
        if cand in existing_dirs:
            return cand
    for d in existing_dirs:
        if plugin_name in d:
            return d
    return None


def filter_changed_files(files: List[str], plugin_dir: Optional[str]) -> List[str]:
    if not plugin_dir:
        return files
    prefix = plugin_dir.rstrip("/") + "/"
    return [f for f in files if f.startswith(prefix)]


def _default_run(args, cwd=None) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


def checkout_pr_branch(repo_path: str, branch: str, base: str = "main",
                       run: Callable = _default_run, pr_number: Optional[int] = None,
                       allow_branch_reset: bool = False) -> None:
    # Dirty-tree guard runs FIRST — never touch a repo with uncommitted work.
    dirty = run(["status", "--porcelain"], cwd=repo_path)
    if dirty.strip():
        raise RuntimeError(
            f"working tree at {repo_path} is dirty — stash or commit local "
            f"changes before review:\n{dirty}")

    # Freshness pin: make origin/<base> current before the base-presence check.
    run(["fetch", "origin", base], cwd=repo_path)

    # DIFF-ONLY-FALLBACK guard (F-02). NOTE: this handler is NOT the same as the
    # F-05 branch-existence handler below — they read an empty-string `run`
    # result OPPOSITE ways and MUST stay separate. Here an EMPTY return means the
    # base ref is PRESENT; only a RAISED RuntimeError means it is missing.
    try:
        run(["rev-parse", "--verify", "--quiet", f"origin/{base}"], cwd=repo_path)
    except RuntimeError:
        raise RuntimeError(
            f"DIFF-ONLY-FALLBACK: base ref origin/{base} is missing — cannot "
            f"establish a merge-base for the review diff")

    # Path selection keys on --pr-number PRESENCE. The pull/<N>/head fetch works
    # for fork AND same-repo PRs; the legacy same-origin path is kept only for
    # the existing test. SECURITY: there must be NO `git fetch` between the
    # pull/<N>/head fetch and the `checkout -B <branch> FETCH_HEAD` below — an
    # interleaved fetch would silently rewrite FETCH_HEAD. F-05's rev-parse
    # (fetch-free) is the only git call allowed between them.
    if pr_number is not None:
        run(["fetch", "origin", f"pull/{pr_number}/head"], cwd=repo_path)
        source = "FETCH_HEAD"
    else:
        run(["fetch", "origin"], cwd=repo_path)
        source = f"origin/{branch}"

    # F-05 local-work guard, layered BEFORE `checkout -B` (checkout -B silently
    # discards local commits). Branch existence = a non-empty rev-parse result;
    # a RAISED `rev-parse` reads as branch-absent — the guard cannot distinguish
    # that from an unrelated git failure (accepted; the subsequent `checkout -B`
    # would surface a genuinely broken repo).
    if not allow_branch_reset:
        try:
            existing = run(["rev-parse", "--verify", "--quiet", branch], cwd=repo_path)
        except RuntimeError:
            existing = ""
        if existing.strip():
            count_out = run(["rev-list", "--count", f"{source}..{branch}"], cwd=repo_path)
            ahead = int(count_out.strip() or 0)
            if ahead > 0:
                raise RuntimeError(
                    f"LOCAL-WORK-GUARD: local branch has {ahead} commits not on "
                    f"{source} — either your own local work (push/rename it), or "
                    f"a stale review branch whose tip the author force-pushed "
                    f"away (safe to reset)")

    run(["checkout", "-B", branch, source], cwd=repo_path)


def changed_files(repo_path: str, base: str, branch: str,
                  run: Callable = _default_run) -> List[str]:
    # Diff against the CREATED LOCAL branch, never FETCH_HEAD (a later fetch
    # rewrites it) nor a possibly-missing origin/<branch>.
    out = run(["diff", "--name-only", f"origin/{base}...{branch}"], cwd=repo_path)
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def main(argv=None):
    p = argparse.ArgumentParser(description="Checkout PR branch and report changed files.")
    p.add_argument("--repo-path", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--base", default="main")
    p.add_argument("--monorepo", action="store_true",
                   help="treat repo-path as a monorepo and scope to the branch's plugin")
    p.add_argument("--plugin-dirs", default="",
                   help="comma-separated existing plugin dir names (monorepo only)")
    p.add_argument("--pr-number", type=int, default=None,
                   help="PR number; fetches pull/<N>/head (works for fork and same-repo PRs)")
    p.add_argument("--allow-branch-reset", action="store_true",
                   help="skip the local-work guard and reset an existing local branch")
    a = p.parse_args(argv)

    checkout_pr_branch(a.repo_path, a.branch, a.base,
                       pr_number=a.pr_number, allow_branch_reset=a.allow_branch_reset)
    files = changed_files(a.repo_path, a.base, a.branch)

    plugin_dir = None
    if a.monorepo:
        name = parse_plugin_from_branch(a.branch)
        dirs = [d for d in a.plugin_dirs.split(",") if d]
        plugin_dir = resolve_plugin_dir(name, dirs) if name else None
        files = filter_changed_files(files, plugin_dir)

    json.dump({"repo_path": a.repo_path, "is_monorepo": a.monorepo,
               "plugin_dir": plugin_dir, "changed_files": files},
              sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
