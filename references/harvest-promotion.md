# Harvest Promotion Gate

The gate that sits between raw harvested records and the live `known-bug-patterns.md`.
Auto-distilled patterns never ship unverified.

## Purpose

`scripts/run-harvest.sh` (which needs an org or a list of `owner/repo` arguments) runs
`harvest_issues.py` to mine merged PRs and writes every candidate under `.harvest/`
(gitignored), e.g. `.harvest/records-<repo-slug>.json`. Records carry a `repo` key and there is
one record per closing issue (multi-issue PRs yield multiple records).
A separate distill step turns those records into candidate patterns in `harvest-staging.md`.
This document encodes the rules the promotion step must apply before adding anything to
`known-bug-patterns.md`. The gate ensures that every promoted entry meets the same bar a
human reviewer would apply — concrete, greppable, and verified against a real shipped defect.
Records are EPHEMERAL local staging, not an archive: `.harvest/` is never committed or
shipped, and its records must be pruned after distillation once their patterns have been
promoted or rejected. The records may hold repo-internal detail (issue numbers, file paths,
commit hashes, and PR/issue body text). That detail is used only to VERIFY a candidate during
distillation and never reaches `known-bug-patterns.md` (see Rule 8).

## Inputs and Outputs

```
.harvest/records-<repo-slug>.json   (raw per-PR records from harvest_issues.py)
        │
        ▼  distill step
harvest-staging.md            (one candidate pattern per record, UNCURATED)
        │
        ▼  promotion gate  ◄── this document
known-bug-patterns.md         (survivors, placed in the matching theme section)
```

The distill step outputs `harvest-staging.md` with status `UNCURATED — promotion gate not
yet applied`. The promotion step reads that file, applies every rule in the ship-bar below,
and adds only the survivors to `known-bug-patterns.md`.

## Entry Shape

Every candidate in `harvest-staging.md` — and every entry that survives into
`known-bug-patterns.md` — must match this exact shape:

```
### <Imperative title in sentence case>

**What shipped:** **(security)** <one-paragraph description of the defect and its root cause, as a GENERALIZED bug class / mechanism — public API surface only (hook names, function categories, sink names), with NO repo, product, issue/PR number, file path, or commit hash>.

**Detect by:** <concrete greppable or structural heuristic a reviewer can apply mechanically>

---
```

- The `### ` heading uses a short imperative phrase (e.g. "Verify a nonce in every
  state-changing AJAX and admin handler"), not a sentence.
- The `**(security)**` marker is optional; use it only when the entry describes a
  vulnerability class.
- `What shipped` describes only the generalized mechanism. It carries NO repo or product name,
  issue/PR number, file path, or commit hash — those live in the ephemeral records and are
  used for verification only (Rule 3), never in the shipped entry (Rule 8).
- `Detect by` describes what to grep for, which function/class to inspect, or which
  structural property to verify — not a general "review carefully" instruction.
- The `---` separator is mandatory.
- No precedent counts, evidence comments, or dates in the entry.

## The Ship-Bar

Apply the rules in order. A candidate that fails any mandatory rule does not ship.

### Rule 1 — Auto-keep only if both anchors are present

A candidate passes auto-keep if and only if it has BOTH:

- A **concrete, greppable or structurally verifiable `detect-by`** heuristic (a grep
  pattern, a named method/property to inspect, a schema key to check — something a reviewer
  can execute mechanically); AND
- A **real anchor** in its source record: a file path, an issue number, and a commit hash.

A candidate that has a real anchor but a vague detect-by (e.g. "review carefully for edge
cases") must be rewritten or rejected. A candidate with a good detect-by but no issue/commit
anchor must be rejected — the anchor is how the reviewer confirms the defect actually shipped.

### Rule 2 — Reject vague detect-bys, one-off configs, and unsupported anchors

Reject the candidate (log a reason) if any of the following apply:

- `Detect by` contains only prose advice without a grep pattern, a named symbol to check,
  or a structural rule (e.g. "be careful about X", "check the logic", "review edge cases").
- The pattern describes a one-off configuration change or a pure feature addition rather than
  a repeatable bug class. Examples: a single hardcoded constant that was wrong, a missing
  `require` for a specific file, a missing option in a specific registry array. These are
  valid closed issues but not patterns a reviewer can apply to a future PR.
- The pattern only makes sense for one codebase or product and cannot be stated as a general
  WordPress/PHP/JS bug class (see Rule 8).
- The anchor (repo, issue, or commit) cannot be confirmed — see Rule 3.

Log the rejection with a reason so the run is auditable:

```
REJECTED  <title>
Reason:   detect-by is vague — no grep pattern or structural check
```

### Rule 3 — Mandatory anchor verification

Before a candidate is added, confirm:

1. The issue number exists in the cited repo (a `gh issue view <n> --repo <owner>/<repo>`
   lookup is sufficient; the title must match the defect described).
2. The file path cited in the record exists in the repo (a `git show <commit>:<file>`
   spot-read confirms both the commit hash and the file in one step).
3. The detect-by heuristic is consistent with what the fix commit actually changed (e.g. if
   detect-by says "grep for `->table_name` on a query object", the fix commit must show
   `->table_name` being replaced by `get_table_name()`).

A candidate whose anchors cannot be confirmed does not ship, even if the pattern class looks
useful.

### Rule 4 — Collapse the generic tail

Low-signal single-language nits — PHP version type-safety (`strtolower` on null, implicit
nullable params, undefined-array-key / `isset` guards, undeclared dynamic properties,
uninitialized variables in branches) and raw i18n wrappers (bare English connectors in
templates, `load_plugin_textdomain` from the wrong file, textdomain removed with no
replacement) — must be folded into the existing broad PHP/i18n entries rather than added as
individual entries.

The criterion: if five distinct PRs each generated a candidate for "PHP 8.x null passed to
string function", they produce one entry, not five.

Folding procedure:

1. Identify the appropriate existing broad entry (usually in
   `## PHP and WordPress API semantics`).
2. Extend that entry's `What shipped` paragraph with the new shape only if it adds a variant
   not already described.
3. If the detect-by can be made more precise by the new case, update it.
4. Do NOT create a new `### ` heading for the nit.

### Rule 5 — Merge duplicates

If two or more candidates describe the same root-cause class (same detect-by heuristic, same
structural failure mode), merge them into a single entry. Similarly, if a candidate matches an
EXISTING entry in `known-bug-patterns.md`, fold it into that entry rather than adding a new one.

Merge procedure:

1. Take the longest, most precise `What shipped` paragraph as the base.
2. Add any genuinely new variant as a short generalized clause ("Variants: …") inside the same
   `What shipped` paragraph — no repo, product, issue/PR number, file path, or commit hash
   (see Rule 8), and no precedent count.
3. Unify `Detect by` to cover all cases (add grep patterns, add class names, etc.).
4. Output ONE entry with ONE `### ` heading.

### Rule 6 — Dedupe by issue number (against the records, not the shipped file)

`known-bug-patterns.md` carries no issue numbers (Rule 8), so dedupe against the ephemeral
`.harvest/` staging instead. Keep a local issue→pattern map in `.harvest/` (never in the
shipped file) and skip any candidate whose issue already produced a promoted or folded
pattern in an earlier run:

```bash
grep -E "#<issue>([^0-9]|$)" .harvest/harvest-ledger.md
```

If it hits, the candidate is a duplicate; log it and move on. If a candidate's mechanism
matches an EXISTING generalized entry, fold it in (Rule 5) rather than adding a new heading.

### Rule 7 — (retired)

### Rule 8 — Generalize before shipping (corpus text must be publishable)

The records and the distill step use the real anchor (repo, issue/PR number, file path,
commit hash, and PR/issue body text) to VERIFY the defect under Rules 1 and 3. That anchor
stays in `.harvest/` and never reaches `known-bug-patterns.md`. Every shipped word must be
general enough to publish openly. Before a survivor is added, rewrite it so the entry carries
ONLY:

- a generalized bug CLASS / mechanism in `What shipped` — you MAY keep public API surface
  (WordPress core hooks and functions, PHP/JS built-ins, public library and documented
  third-party API names, sink names like `wp_kses_post`), but DROP everything that identifies
  a specific codebase; AND
- the concrete `Detect by` heuristic, kept intact.

Strip, with no exceptions:

- repo, org, company, product, and add-on names;
- issue/PR numbers, commit hashes, branch names, and file paths;
- plugin-specific identifiers — prefixed functions, hooks, classes, namespaces, option and
  meta keys, table names (replace with neutral placeholders such as `my_plugin_*`,
  `{prefix}_orders`, or a description like "a plugin's custom tables layer");
- quotes from PR/issue bodies, people's names, dates of runs, and precedent counts.

When in doubt, remove the specific detail rather than keep it. This is the rule that stops a
harvest from re-introducing an unreleased-fix map — an exploit map for holes that may not be
publicly released — into the shipped corpus, and keeps the corpus publishable.

## Placement Rule

`known-bug-patterns.md` is organized by fixed themes (its `## ` headings, listed with counts in
the header paragraph). There are no dated sections and no hotspot table.

- Put each survivor under the `## ` theme section that matches its bug class; if it spans two,
  pick the one a reviewer would check first (security-relevant classes go under the
  authorization, escaping, secrets, or files themes).
- When a survivor is the same class as an existing entry in that section, fold it into that
  entry (Rule 5) instead of adding a heading.
- Do not create new `## ` theme headings or dated sections; if nothing fits, use the closest
  theme.
- After adding entries, update the total and the per-theme counts in the header paragraph so
  they match the number of `### ` entries in each section.
