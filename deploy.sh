#!/usr/bin/env bash
# Deploy the wp-pr-review skill from this repo to the Claude Code skills dir.
# Development happens here; this script publishes a copy (no symlinks).
#
# Allowlist deploy: the deployed folder contains ONLY the files needed to run the skill.
# Everything else (tests, caches, dev docs, dotfiles, harvest records, prior reviews, OS junk)
# is left in the repo and never shipped.
set -euo pipefail

DEST="${CLAUDE_CONFIG_DIR:-${HOME}/.claude}/skills/wp-pr-review"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Deploying skill: ${SRC} -> ${DEST}"
mkdir -p "${DEST}"

# Ship set (and ONLY the ship set):
#   SKILL.md, README.md
#   references/*.md
#   scripts/{collect_pr,find_latest_review,links,setup_repo,render_review,scan_diff,dedupe_check}.py + harvest_issues.py + run-harvest.sh
# --delete prunes source-gone files; --delete-excluded also removes anything an earlier deploy
# left behind that is NOT in the allowlist (without it, `--exclude='*'` protects receiver files
# from deletion — the classic rsync gotcha that leaves stale .git/tests/caches behind).
rsync -a --delete --delete-excluded \
  --include='/SKILL.md' \
  --include='/README.md' \
  --include='/references/' \
  --include='/references/*.md' \
  --include='/scripts/' \
  --include='/scripts/collect_pr.py' \
  --include='/scripts/find_latest_review.py' \
  --include='/scripts/links.py' \
  --include='/scripts/setup_repo.py' \
  --include='/scripts/harvest_issues.py' \
  --include='/scripts/run-harvest.sh' \
  --include='/scripts/render_review.py' \
  --include='/scripts/scan_diff.py' \
  --include='/scripts/dedupe_check.py' \
  --exclude='*' \
  "${SRC}/" "${DEST}/"

echo "Deployed. Files in ${DEST}:"
find "${DEST}" -type f | sort
