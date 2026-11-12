# Output Format

Write the review to `.pr-reviews/<repo>/<pr>/review.md` (if that dir exists, append `-2`, `-3`, …). No GitHub writes. The `.pr-reviews/` directory is created at the ROOT of the project being reviewed (the invoking repo/dir), NEVER inside this skill's own directory.

## Structure
`review.md` is RENDERED from `findings.json` by `scripts/render_review.py` (SKILL.md step 7); never hand-write or hand-edit it. `references/review-template.md` documents the shape the renderer produces, and the rules below say what the JSON must carry. A test keeps the renderer's section headings in line with the template.

## Conventions
These conventions apply to the local `review.md` only. Nothing in this section is posted to GitHub; see **Posted comments** below.

- Severity emoji: 🔴 CRITICAL · 🟠 MAJOR · 🟡 MINOR · ⚪ INFO.
- Order findings by severity (CRITICAL first).
- Links come from `scripts/links.py` (invoke with `--repo-root <repo checkout root>` and `--file <source path relative to repo root>`; `--branch` may contain slashes).
- Every finding shows a Verification line (the two-pass result) ending in a verdict sentence.
- Impact-table column header is exactly `Severity` (not "Dimension"/"Category") and Evidence snippets come from the real source, not reconstructed from memory.
- The summary counts table reflects post-verification status (counts must match the findings); the **Found** column is the ORIGINAL-severity axis, while Confirmed/Partially valid/False positive reflect post-verification (FINAL) status — see the two-axis counting rule below.
- Two-axis counting rule: the summary counts table has two axes — the **Found** column tallies by the finding's ORIGINAL severity row; **Confirmed** / **Partially valid** / **False positive** tally by its FINAL severity row. A downgrade (e.g. MAJOR→MINOR) increments the MAJOR-row Found AND the MINOR-row Confirmed/Partially valid, so one finding may touch two rows (one per axis).
- Rich-block scaling: CRITICAL/MAJOR get the FULL block (Evidence + Documented-intent line + Impact table + Likelihood + verdict); MINOR gets Likelihood (table optional); INFO may be a single line. Keeps 20-finding reviews readable.
- Tag every config-dependent finding with the config it occurs in (e.g. "single-gateway only", "no-JS", "multisite") and rate severity at its WORST reachable config.
- If the project ships an e2e/integration harness and the PR is runtime-heavy, list "run <suite> under <configs>" as a merge condition — do not let a static pass imply those paths were cleared.
- Binary verdict: the recommendation is Approve or Request changes. "Comment" is retired. Any blocker gives Request changes; no blocker gives Approve. A blocker is any of: a MAJOR-or-higher, security or payment defect; a payment or subscription-state defect at any severity; the PR is not mergeable; the PR is behind its base (even when the merge is clean and CI is green); failing CI.
- CI verdict: a blocking check is a blocker, so the recommendation is Request changes (never Approve over a red gate). Per-check categories advisory/pending/unknown are noted, not blocking. Per-check `unknown` never blocks. Whole-CI `unavailable (fetch failed)` blocks Approve until the CI state is confirmed (see methodology).
  Blocking checks also appear as findings (🟡 MINOR minimum) in the Findings section.
- Runtime-unverified and tests-not-run: never post "could not test". Unblock the test first (local checkout copy, worktree, Docker, live drive). If it still cannot run, keep it out of the posted text, list it under Runtime-unverified in the local `review.md`, and report the blocker to the user in the hand-back. It does not change the binary recommendation by itself.
- Trace cap: a report whose Input→sink or Stored-value→consumer matrix is marked N/A while the diff touches an input or a write is incomplete; do not emit.
- Markdown spacing: put each stacked `**field:**` line on its own list item or separate it with a blank line (consecutive non-list lines collapse into one paragraph on render); keep a blank line before/after every table and code fence, and a blank line between findings. Within a finding, use a LOOSE list — put a blank line between each `- **Field:**` item so fields render with vertical spacing, not as a cramped block. Keep prose sections (Summary, Detection, Verification) to short paragraphs (≤3–4 sentences); split longer prose with blank lines rather than emitting one long block.

## Pre-emit compliance check (run before saving review.md)

The renderer enforces the formatting items (header list, spacing, loose lists, counts table) and refuses (exit 2) on a missing Documented-intent line, a blank Compliance-trace line, a pre-verdict checklist without 8 items, a moved head with no delta note, an unknown bug-pattern heading, or a stated recommendation that contradicts the blocker rule. Content quality is still yours. The list stays as the definition:

- [ ] **Header is a bullet list** — each metadata field (`Repo`, `Branch`, `HEAD reviewed`, `Author`/`State`, `Generated`) on its own `- ` line. Never stack bare `**field:**` lines with no blank line between them — they render as one wall of text.
- [ ] **CI** and **Recommendation** may live as `- ` bullets inside the header metadata list (header bullet format); CI may name FAILING: checks inline.
- [ ] Blank line before and after every table and every code fence; blank line between findings.
- [ ] Findings use LOOSE lists — a blank line between each `- **Field:**` item.
- [ ] **Documented-intent line present on every 🔴/🟠 finding** — each CRITICAL/MAJOR finding quotes the docblock/inline comment at & around its cited line (or states an explicit "None — checked at file:line"), and its severity is rated by IMPACT given that intent (documented-benign ⇒ INFO/MINOR; documented-harmful ⇒ stays CRITICAL/MAJOR). A finding missing this line is incomplete — do not emit the report.
- [ ] Summary counts table matches the actual findings.

- [ ] Compliance trace block present with every line filled (no blanks, no TODO)

- [ ] Tests run line present; a NOT RUN line stays local and the blocker goes to the user in the hand-back

- [ ] Head OID at emit equals head OID at review start, or a delta re-review note is present

## The Compliance trace block

Every review MUST end with this block, every line filled — the pre-emit check refuses to emit without it. Each line is a content proof produced from the file it attests to, not a tick.

```
## Compliance trace
- Head: <OID at review start> / <OID at emit> — <same | moved: delta re-reviewed at <time>>
- Refs read:
  - review-methodology.md — Scaling triggers fired: <list of C dimensions run, or "A+B only: no trigger">
  - verification-pitfalls.md — version line quoted: "<paste the _Version:_ line>"; pitfalls checked per finding: F1→#22,#26 · F2→#31 · …
  - security-hardening-checklist.md — <APPLIED: sections used: <names>> | <N/A: PR touches no vuln-close, cap, nonce, sanitizer, or hostile-input walker>
  - known-bug-patterns.md — sections grepped: <names>; matches: <pattern heading → finding id | none>
- Pre-verdict checklist (8 items): each answered in one line; "N/A + why" allowed, blank not allowed
- Input → sink matrix: <table pasted | N/A: diff adds no request input>
- Stored-value → consumer matrix: <table pasted | N/A: diff persists/filters nothing>
- Flag set/clear/read matrix: <table pasted | N/A: no charge/credit-gating state touched>
- Tests run: <suite> @ <OID> — <pass/fail/skip> | NOT RUN — <reason> (local only; blocker goes in the hand-back, never in posted text)
- Live probes: <what was driven live, or "none — all findings static; runtime-unverified section lists the rest">
```

## Posted comments

What goes on GitHub follows the reviewed repo's `.claude/rules/writing.md` and `github.md` when they exist. Read both before you write any posted text. If the repo has neither, use the format below with plain, short sentences and the team standards' wording rules, if they have any. Each inline comment uses this shape:

```
**Blocking:** <problem, one sentence>

<what goes wrong, where, and for whom, in a few plain sentences>

Reproduced: <one line, only when we reproduced it>

<optional attribution line, e.g. <sub>🤖 Drafted with Claude Code</sub>>
```

- Severity word: CRITICAL and MAJOR post as **Blocking**, MINOR as **Should fix**, INFO as **Nit**.
- One concern per comment, a few sentences. Never hard-wrap a paragraph.
- Leave out the `Reproduced:` line when we did not reproduce it.
- Attribution is optional. If the user or team asks for a marker line, it is the last line of the body; otherwise post no marker and no attribution of any kind.
- Never post: cost lines, badges, callouts, tables, HTML other than the final marker, emoji headers, impact tables, fix blocks, `Verified:` lines, likelihood sections, Co-Authored-By or Produced-by lines, or long text blocks.
- A pre-existing issue (one that predates the PR) never goes inline. Put it in the review summary or in a linked issue.
- A finding object may carry an optional `"reproduced": "<one line>"` string. The posted `Reproduced:` line is filled from it.

All full data stays local: `findings.json`, `review.md` (rich format, as above), and any local copy of the staged review payload.

## findings.json → review.md

`findings.json` is the single source; `scripts/render_review.py` renders `review.md` from it. The document is `{"repo": "<owner>/<repo>", "pr": <int>, "head": "<oid>", "head_at_emit": "<oid>", "findings": [...], "report": {...}}`.

- **Top level:** `head` (OID at review start), `head_at_emit` (re-fetched at emit with `collect_pr.py --head <ref>`), optional `recommendation` (if given it must equal the computed one), optional `ci_advisory` (list of `{name, reason}`: a failing check the loaded team standards declare non-blocking, such as a coverage-percentage gate; the name must match a failing check on the PR, and the CI line keeps it visible with its reason). Never waive a check the standards do not name.
- **Each finding:** `id`, `path`, `line`, `severity`, `likelihood`, `problem`, `what_where`, optional `customer_impact`, `fix`, `verified` (the verification note), `detection` (the trace), `verdict` (`confirmed` | `partial`; a `refuted` finding goes in `report.verified_out`, not in `findings`), optional `original_severity` (when verification changed it; drives the two-axis counts), `title` (defaults to `problem`), `end_line`, `also` (extra locations), `part` (decomposed PRs), `config` (e.g. "single-gateway only"), `likelihood_note`, `tags` (`security` / `payment` make it a blocker at any severity), `show_evidence` (MINOR snippet), `reproduced`, `dedupe`, and required `anchor` (a code fragment copied from the cited line; it must appear on `line`..`end_line` at the reviewed head). CRITICAL/MAJOR need `documented_intent` and all four `dimensions` (`UX`, `Functional`, `Data`, `Security`); their Evidence is read from `--repo-root` at `line`..`end_line`, so the cited lines must exist at the reviewed head.
- **`report` object:** `summary`; `questions` (list, one `Q → answer / where` line each); `recommendations` (list); `scenarios` (list of `{title, setup, steps[], expected, edge_cases[]}`); `compliance` (`scaling_triggers`, `security_checklist`, `known_bug_patterns_sections[]` and `known_bug_patterns_matches{heading: finding id}` — headings must exist in `known-bug-patterns.md` — `pitfalls_per_finding{id: [numbers]}` for every finding, `pre_verdict_checklist[8]`, `input_sink`, `stored_consumer`, `flag_matrix` (a table string or `N/A: <why>`), `tests_run`, `live_probes`); `test_steps` (list of `{steps: [author step numbers] | text: "<a step of your own>", status: passed|failed|not_run, note, finding (id, when failed)}`; every step `collect_pr` parsed must appear exactly once; passed/failed render under *Verified by running the PR's test steps*, not_run under *Runtime-unverified*; with no collected steps and no entries → "No documented test steps."), `previous_delta` (required on a re-review unless `--fresh`), `cross_issue`, `runtime_unverified`, `verified_out` (`{title, severity, reason}`), `head_delta_note` (required when the head moved), `title`.
- **Verdict only:** `python3 scripts/render_review.py <findings.json> --pr-json <collect_pr output> --verdict` prints `{recommendation, reasons, ci}` without a `report` object or checkout, and writes nothing.
- **Derived, never typed:** header fields and CI line (from `--pr-json`), recommendation and its reasons (MAJOR+, `security`/`payment` tag, conflicts, behind base, unknown mergeability, failing or unavailable CI), counts table, emoji, ordering, links, Evidence snippets, the quoted `_Version:_` line, the round dir, the author's test-step wording (from `--pr-json`).
- **Checked, never trusted:** each finding's `anchor` against its cited lines, and every `path:N` in the text against the checkout (file exists, line in range). The cited code is printed on stderr after a render or `--check`; read it.

## Lane output files

Each review lane writes its own findings file, never a shared one:

- Review lane writes `findings-review.json`; the adversarial lane writes `findings-adv.json`. Whoever reconciles the lanes (you, or the caller) writes the merged `findings.json`.
- Each finding object carries `"origin": "review" | "adversarial" | "pre-existing"`. After reconcile the reconciler adds `"verdict": "confirmed" | "partial" | "refuted"`.
