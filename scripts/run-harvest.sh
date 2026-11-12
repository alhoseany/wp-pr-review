#!/usr/bin/env bash
# run-harvest.sh — deterministic gh harvest for every repo in an org.
#
# This script ONLY fetches merged-PR records (issues and signals) and writes them under .harvest/.
# It does NOT distill, promote, commit, or deploy anything.
# Those steps are performed by the agent + human workflow that wraps this script.
#
# Usage:
#   HARVEST_ORG=some-org ./scripts/run-harvest.sh
#       Harvest every repo in the org (public, private, forks, and archived
#       repos the gh token can see).
#   ./scripts/run-harvest.sh owner/repo [owner/repo ...]
#       Harvest only the named repos.
#   HARVEST_KINDS=signals ./scripts/run-harvest.sh
#       Run only one record kind (default: "issues signals").
#
# Requirements:
#   - gh CLI authenticated (gh auth status must pass)
#   - python3 in PATH
#   - Run from the repo root

set -euo pipefail

usage() {
  echo "Usage: HARVEST_ORG=<org> $0" >&2
  echo "   or: $0 owner/repo [owner/repo ...]" >&2
  echo "Set HARVEST_ORG or pass owner/repo arguments; there is no default org." >&2
}

if [ "$#" -eq 0 ] && [ -z "${HARVEST_ORG:-}" ]; then
  usage
  exit 2
fi

# ── Auth guard ────────────────────────────────────────────────────────────────
if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: gh CLI is not authenticated. Run 'gh auth login' first." >&2
  exit 1
fi

# ── Repo set ──────────────────────────────────────────────────────────────────
# No arguments: every repo in HARVEST_ORG (required in that case).
# Arguments: an explicit owner/repo list, for a one-repo or subset run.
# Listing goes through harvest_issues.py so pagination is not capped at
# `gh repo list`'s 30-repo default.
ORG="${HARVEST_ORG:-}"

if [ "$#" -gt 0 ]; then
  REPOS=("$@")
else
  list_output=$(python3 scripts/harvest_issues.py --list-org "${ORG}")
  REPOS=()
  while IFS= read -r repo; do
    [ -n "${repo}" ] || continue
    REPOS+=("${repo}")
  done <<< "${list_output}"
fi

if [ "${#REPOS[@]}" -eq 0 ]; then
  echo "ERROR: no repositories to harvest." >&2
  exit 1
fi

echo "Repos to harvest: ${#REPOS[@]}"

# ── Record kinds ──────────────────────────────────────────────────────────────
# issues:  closing issues of merged PRs  → records-<slug>.json
# signals: fix PRs with no closing issue + acted-on review threads
#          → signals-<slug>.json (own watermark, so the two never interfere)
KINDS="${HARVEST_KINDS:-issues signals}"

# ── Output dir ────────────────────────────────────────────────────────────────
mkdir -p .harvest

# ── Per-repo harvest ──────────────────────────────────────────────────────────
total=0
failed=()

for repo in "${REPOS[@]}"; do
  # Slug = basename of repo path, lowercased
  basename_part="${repo##*/}"
  slug=$(printf '%s' "${basename_part}" | tr '[:upper:]' '[:lower:]')

  for kind in ${KINDS}; do
    case "${kind}" in
      issues)
        watermark_file=".harvest/watermark-${slug}"
        out_file=".harvest/records-${slug}.json"
        mode_args=()
        ;;
      signals)
        watermark_file=".harvest/signals-watermark-${slug}"
        out_file=".harvest/signals-${slug}.json"
        mode_args=(--signals)
        ;;
      *)
        echo "ERROR: unknown HARVEST_KINDS entry '${kind}' (use issues, signals)." >&2
        exit 1
        ;;
    esac

    echo "── Harvesting ${repo} [${kind}] (slug: ${slug}) ──"
    if harvest_output=$(python3 scripts/harvest_issues.py \
      --repo "${repo}" \
      ${mode_args[@]+"${mode_args[@]}"} \
      --watermark-file "${watermark_file}" \
      --out "${out_file}"); then
      echo "${harvest_output}"

      # Parse per-repo delta and store total from the harvest tool's stdout contract.
      count=$(printf '%s\n' "${harvest_output}" | grep '^records_written=' | cut -d= -f2 || true)
      store_total=$(printf '%s\n' "${harvest_output}" | grep '^store_total=' | cut -d= -f2 || true)
      count="${count:-0}"
      store_total="${store_total:-0}"

      echo "  Records written: ${count}"
      echo "  Store total: ${store_total}"
      total=$(( total + count ))
    else
      echo "  FAILED (transient?) — skipped, re-run later" >&2
      failed+=("${repo} [${kind}]")
    fi
  done
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [ "${#failed[@]}" -gt 0 ]; then
  echo "Harvest partial. Total records written: ${total}"
  echo "Output files are in .harvest/ (deploy-excluded; watermarks preserved per repo)."
  echo "" >&2
  echo "The following repos failed and were skipped:" >&2
  for r in "${failed[@]}"; do
    echo "  - ${r}" >&2
  done
  echo "Re-run the script to retry failed repos." >&2
  exit 1
fi

echo "Harvest complete. Total records: ${total}"
echo "Output files are in .harvest/ (deploy-excluded; watermarks preserved per repo)."
