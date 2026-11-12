#!/usr/bin/env python3
"""Find the latest review.md for a given PR.

Pure functions (no I/O) plus a thin CLI. Scans .pr-reviews/<repo>/<pr>*
directories, matches those with `review.md`, and returns the path from
the directory with the highest round number.
"""
import argparse
import os
import re
from typing import Optional


def latest_review(base_dir: str, repo: str, pr: str) -> Optional[str]:
    r"""Scan .pr-reviews/<repo>/ for dirs matching <pr>(-\d+)?; return path to
    review.md in the dir with max round, or None if no match.

    base_dir: root directory to scan within (typically ".")
    repo: repository name (e.g., "test-repo")
    pr: PR number as string (e.g., "123")

    Round numbers: bare <pr> → round 1, <pr>-N → round N. Returns the
    review.md path from the highest-round matching dir, or None if no
    qualifying dir exists or if .pr-reviews/<repo>/ is absent.
    """
    reviews_root = os.path.join(base_dir, ".pr-reviews", repo)

    # If the reviews directory doesn't exist, return None
    if not os.path.isdir(reviews_root):
        return None

    # Build regex pattern: ^<escaped_pr>(-\d+)?$
    pattern = f"^{re.escape(pr)}(-\\d+)?$"
    compiled = re.compile(pattern)

    # Scan for matching directories
    matches = {}  # { round_num: dir_name }

    try:
        entries = os.listdir(reviews_root)
    except OSError:
        return None

    for entry in entries:
        if not compiled.match(entry):
            continue

        entry_path = os.path.join(reviews_root, entry)
        if not os.path.isdir(entry_path):
            continue

        review_md = os.path.join(entry_path, "review.md")
        if not os.path.isfile(review_md):
            continue

        # Extract round number: bare pr → 1, pr-N → N
        if entry == pr:
            round_num = 1
        else:
            # entry = pr-N, extract N
            suffix = entry[len(pr) + 1:]  # Everything after "pr-"
            round_num = int(suffix)

        matches[round_num] = review_md

    # Return the path from the highest round
    if matches:
        max_round = max(matches.keys())
        return matches[max_round]

    return None


def main(argv=None):
    """CLI: --base-dir (default '.'), --repo (required), --pr (required).
    Prints the path to review.md or empty string; exits 0 either way.
    """
    p = argparse.ArgumentParser(description="Find the latest review.md for a PR.")
    p.add_argument("--base-dir", default=".",
                   help="base directory to scan within (default: .)")
    p.add_argument("--repo", required=True,
                   help="repository name (e.g., test-repo)")
    p.add_argument("--pr", required=True,
                   help="PR number as string (e.g., 123)")
    a = p.parse_args(argv)

    result = latest_review(a.base_dir, a.repo, a.pr)
    if result:
        print(result)
    else:
        print("")


if __name__ == "__main__":
    main()
