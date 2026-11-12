<!--
Canonical PR review shape. `scripts/render_review.py` RENDERS review.md in this shape from
findings.json (SKILL.md step 7); do not copy and fill this file by hand. Each <placeholder>
maps to a findings.json field (output-format.md → findings.json → review.md). Severity,
rich-block scaling, the binary verdict and CI rules, and link rules live in
`output-format.md` Conventions. Keep this file and the renderer's headings in sync.
-->
# PR Review: <title>

- **Repo:** <owner>/<repo>
- **Branch:** <head> → <base>
- **HEAD reviewed:** <sha>
- **Author/State:** <login> / <state>
- **Generated:** <YYYY-MM-DD>
- **CI:** <passing | FAILING: <which checks> | pending | no blocking failures (N failed checks non-blocking by team policy: <check (reason)>) | unavailable (fetch failed) | none>
- **Mode:** fresh review; earlier rounds were not read   (only on a `--fresh` render; a fresh review still takes the next round dir, so later re-reviews see it)
- **Head:** <OID at review> / <OID at emit>
- **Recommendation:** <Approve | Request changes> — <one-line rationale>

## Compliance trace
- Head: <OID at review start> / <OID at emit> — <same | moved: delta re-reviewed at <time>>
- Refs read:
  - review-methodology.md — Scaling triggers fired: <list of C dimensions run, or "A+B only: no trigger">
  - verification-pitfalls.md — version line quoted: "<paste the _Version:_ line>"; pitfalls checked per finding: <F1→#N,#N · F2→#N · …>
  - security-hardening-checklist.md — <APPLIED: sections used: <names> | N/A: PR touches no vuln-close, cap, nonce, sanitizer, or hostile-input walker>
  - known-bug-patterns.md — sections grepped: <names>; matches: <pattern heading → finding id | none>
- Pre-verdict checklist (8 items): <each answered in one line; "N/A + why" allowed, blank not allowed>
- Input → sink matrix: <table pasted | N/A: diff adds no request input>
- Stored-value → consumer matrix: <table pasted | N/A: diff persists/filters nothing>
- Flag set/clear/read matrix: <table pasted | N/A: no charge/credit-gating state touched>
- Tests run: <suite> @ <OID> — <pass/fail/skip> | NOT RUN — <reason>
- Live probes: <what was driven live | none — all findings static>

## Summary
<2-4 sentences: what the PR does and the headline findings. Note any unresolved
PR discussion threads worth attention.>

| Severity | Found | Confirmed | Partially valid | False positive |
|----------|-------|-----------|-----------------|----------------|
| 🔴 CRITICAL | n | n | n | n |
| 🟠 MAJOR | n | n | n | n |
| 🟡 MINOR | n | n | n | n |
| ⚪ INFO | n | n | n | n |

## Previous review delta   (re-reviews only — omit on first review or when `fresh` was requested)
<each issue from the previous round: **persisting** / **fixed** / plus issues **new** this round.>

## Review Questions
<the self-questioning pass (methodology step 3). Print rule:
- A+B (orientation + scenario) answers are ALWAYS printed, one line each:
  `Q → short answer / where-resolved (finding ref or file:line)`.
- A C question prints ONLY if it produced a finding or an unverified item; otherwise it
  silently seeds detection and is not listed here.
Unanswered questions route 3 ways: runtime/config-dependent → Runtime-unverified;
design/decision unclear → Recommendations; can't-answer-because-code-outside-the-fetched-diff
→ note in Summary or as an INFO finding.>

## Findings
### Part: <name>   (omit the part heading for small single-part PRs)

<!-- The per-finding block below is LOCAL ONLY. It is never posted as-is. Posted comments use the minimal format in output-format.md → Posted comments. -->

#### <emoji> <SEVERITY> — <short title>

- **File:** `path/file.php:120` — [Editor](rel#L120) | [GitHub](https://github.com/...#L120)

- **Detection:** <how it was found — the trace>

- **Issue:** <what's wrong>

- **Evidence:** (REQUIRED for CRITICAL/MAJOR; include when it clarifies for MINOR)

```php
<3-8 line snippet from the ACTUAL source at the cited lines>
```

- **Documented intent:** (REQUIRED for CRITICAL/MAJOR) <quote the docblock/inline comment AT and immediately AROUND the cited file:line, and state how it changes severity> — or the explicit literal: `None — checked docblock + adjacent comments at <file:line>; no documented intent.` Never omit this line on a CRITICAL/MAJOR finding; silence is not allowed.

- **Impact:** (full table REQUIRED for CRITICAL/MAJOR; optional for MINOR; omit for INFO)

| Severity | Impact |
|----------|--------|
| UX | <user experience impact or None> |
| Functional | <does behavior break?> |
| Data | <loss/corruption risk or None> |
| Security | <implications or None> |

- **Likelihood:** <Low | Medium | High> — <when/how it triggers> (REQUIRED for CRITICAL/MAJOR/MINOR)

- **Suggestion:** <concrete fix>

- **Reproduced:** <one line: what we ran and what we saw> (only when we reproduced it; else omit. Feeds the findings JSON `reproduced` field.)

- **Verification:** <✓ confirmed | ⚠ partially valid (severity X→Y) | ✗ false positive> — <1-2 sentence verdict with priority recommendation>

## Cross-Issue Interactions   (only when ≥2 confirmed issues share a code path/state — else omit)
<for each compounding pair/chain: trigger → issue A effect → feeds issue B → combined outcome;
note any severity re-evaluation it forces.>

## Recommendations
<3-6 bullet actionable rollup: the must-fix items in priority order, plus any
manual verifications the author should run (e.g. "test the no-JS path").>

## Manual Testing Scenarios
### <n>. <title>

- **Setup:** <preconditions>

- **Steps:** <numbered steps>

- **Expected:** <outcome>

- **Edge cases:** <bullets>

## Verified by running the PR's test steps   (rendered from `report.test_steps`: only passed/failed steps appear here; if none ran the body says so and points to Runtime-unverified; if the PR documented no test steps the body is the single line `No documented test steps.`)
<results of methodology step 7. Per step: command → exit/result → which finding it
confirms or refutes, plus any mutation and its restore evidence.
- *confirms* = the observed result matches the finding's predicted behavior.
- *refutes* = the observed result contradicts it. Ambiguous → stays in Runtime-unverified.
Promotion: an executed+confirmed item is MOVED here out of Runtime-unverified (command +
exit/result + finding ref), not duplicated. Bucket-D / not-run items stay in
Runtime-unverified with exact repro commands.>

## Runtime-unverified   (findings needing execution to confirm — omit only if none)
<each finding whose verdict depends on runtime behavior the review could not execute:
hook/filter ordering, config-specific branches (single vs multi gateway, JS on/off,
multisite, pro/lite), cache interactions. State the exact config + command/scenario
that would confirm or refute it, and the severity IF confirmed. A static pass reporting
no CRITICAL/HIGH has cleared only the statically-visible ones — list what remains here
so an APPROVE is never mistaken for "fully cleared."
Items the run step (methodology step 7) actually executed move to *Verified by running the
PR's test steps*; this section holds only what was NOT run (bucket D, or no documented steps).
The renderer lists the `not_run` entries of `report.test_steps` here first, with the author's wording.>

## Verified-out (false positives)
<bulleted list of dropped/false-positive items, if any.>
