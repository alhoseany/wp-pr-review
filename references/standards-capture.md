# Standards Capture

Per-team coding standards are captured once and reused across all of that team's repos.

## Cache layout (workspace-local)
```
.pr-reviews/.standards/
├── registry.json
├── my-team/    standards.md  +  sources/
└── <team-key>/ standards.md  +  sources/
```

## registry.json
```json
{
  "repos": { "acme/my-plugin": "my-team" },
  "teams": { "my-team": { "label": "My Plugin", "captured_at": "YYYY-MM-DD", "sources": ["<url-or-path>"] } }
}
```

## Flow (run every review)
1. Resolve `owner/repo`. Read `.pr-reviews/.standards/registry.json` (create `{ "repos": {}, "teams": {} }` if absent).
2. **Known repo** (`repos[owner/repo]` exists) → read `teams[key]` and load `<key>/standards.md` silently. Done.
3. **Unknown repo** → suggest a team (match repo owner/name against existing `teams`) and ask the user to confirm the team, pick another existing team, or create a new one. Never bind a repo without confirmation.
   - **Existing team chosen** → add `repos[owner/repo] = key`; reuse standards.
   - **New team** → ask the user for one or more standards links (web URL, GitHub file URL, or local path). For each source: fetch web/GitHub URLs with WebFetch, read local paths with Read; write the raw content to `<key>/sources/<n>-<name>`. Then synthesize `<key>/standards.md` as a concise digest with these headings: Naming, Hooks/APIs, Security expectations, Safe (pre-sanitized) sources, Team conventions to recognize (version/release placeholders the team treats as correct usage, plus known false-positive patterns). Record the team in `teams` and the repo in `repos`.
4. **Staleness check** → if the team's `captured_at` is older than ~90 days, mention that the standards may be stale and offer a refresh — do not block the review.
5. **Refresh** → when the user says "update standards for <team>", re-fetch the recorded `sources` and rewrite `<key>/standards.md`.

## Notes
- "Snapshot" means copy the content now into `sources/`; do not re-fetch on later runs (except on explicit refresh).
- The cache is workspace-local; teams may commit `registry.json` + `sources/` to a shared location to share one standards set.
