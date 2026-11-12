# Security-Hardening Review Checklist

When a PR's purpose is to CLOSE a vulnerability (titles like "Guard…", "Require…",
"Sanitize…", "Scope…", "Sign…", "Hold… to a boundary"), reviewing the diff is not
enough — verify the fix is **complete** and **fails closed**, and hunt for the
sibling path the fix forgot. These checklists are distilled from real plugin
hardening PRs and the adversarial audits that cross-checked them.
Also read this file when a PR changes a capability check, a nonce, a settings
sanitizer, or adds a helper that walks untrusted structured input,
even if the title does not say Guard/Require/Sanitize.

## Cross-cutting rules (apply to EVERY hardening PR)

- **Enumerate every entry point to the same data/action, not just the one the PR touched.** A fix on the AJAX/refine path is void if the server-rendered page-load widget, a REST route (`show_in_rest`), a shortcode/block, a deprecated wrapper, or another API version (via class inheritance) reaches the same rows unchecked. *The most commonly missed sibling is the page-load preload of a widget whose AJAX refresh was scoped.* (Real miss: a product-search AJAX scope fix left the same dropdown's server-rendered options unfiltered.)
- **Enumerate every request key that reaches the same sink, not only the one the PR bound.** When a fix server-derives ONE identifier for a write, dump the full key set of every array forwarded to that write (`array_map`, whitelist-merge, `wp_parse_args` all preserve keys they do not strip) and check each key against the table's column list. The write layer must use an explicit allowlist of writable columns; "column exists" is not an allowlist. Paste the key → column table into the Compliance trace. (Real miss: `address[order_id]` survived the address write and re-parented the row onto another order after the row id had been bound server-side.)
- **Verify a removed, raised, or weakened capability check was not reverted inside the PR.** `git log -p --follow` the file(s) holding the guard; list every commit that touches the capability string, nonce check, or status allowlist. A guard raised then reverted is an OPEN scope decision: report both hashes, quote the revert's message, do not mark the vector closed. Ask the author to state the accepted risk in the PR body. (Real miss: a manage-level capability reverted to a view-level one per an issue reference; the review lane wrote "CLOSED".)
- **CSRF ≠ authorization.** A nonce, per-object or global, proves page provenance only. Name the capability that gates the mutation and confirm a holder cannot address someone else's object. If the PR's own fix is "bind the nonce to the id", the authorization question is still open.
- **Verify the check runs on the value the platform actually passes.** A plugin router that dispatches any prefixed action (`do_action( 'myplugin_' . $_REQUEST['myplugin_action'], $_GET|$_POST )` on `init`/`admin_init`, or an `admin_post_*`/`wp_ajax_*` handler that forwards the request array) passes the whole `$_GET`/`$_POST` **array** as arg 1 — so a handler's "id" parameter can be an attacker array an ORM silently resolves by primary key. Trace the ID/param to its true source; confirm positive-path tests drive the real router/builder, not just `do_action` with hand-built scalars. Guard on an argument the dispatcher CANNOT supply (a required arg 2 only the internal emitter passes), never on the shape of arg 1 alone.
- **When one subscriber of a shared hook is hardened, audit ALL co-subscribers of that hook for the identical request-dispatch write.** A per-subscriber guard leaves siblings exposed: grep `add_action('<hook>', …)` / the subscriber map for every callback on the action and confirm each one either carries the same guard or cannot write under a request dispatch. Give required-arg callbacks a safe default so a stray dispatch is a clean early return, not an `ArgumentCountError` fatal. (Real miss: a GeoIP hardening left the campaign-logger + auto-register co-subscribers of the plugin's order-built hook writing to a coerced order id.)
- **Check gate ORDER — a fail-closed proof/token gate placed first also blocks legitimate authorized users.** When a hardening PR adds a proof requirement (signed hash, receipt token, nonce) to an access check, verify WHERE it sits relative to the capability/owner checks. If the new proof gate runs BEFORE `current_user_can()` / owner check and returns on failure, then capability no longer bypasses it — an admin/owner reaching the resource without a freshly-minted proof is locked out too (fails closed = safe, but breaks the feature). Confirm every legitimate entry point (admin buttons, account-page links, emailed links) mints the proof, or put the capability/owner check first so authorization can still short-circuit the guest-proof. (Real miss: a URI-validation gate was the first check in an invoice view-permission function, so a stricter signed-hash requirement blocked admins/owners, not just guests — the skill-review approved it; the adversarial pass caught it.)
- **Escape once, at the sink; trace the value's true origin.** Flag a value escaped in PHP AND rendered through an escaping template delimiter (`{{ }}` / `_.escape`) — that double-encodes (`A & B` → `A &amp; B`). Conversely, when PHP stops escaping a value, confirm every template sink escapes it. And trace where a JS-template field actually comes from: a value safe on the server-rendered path can be unsafe when the same template is fed a DOM-derived value (e.g. a Chosen `option.text`, `.val()`) that the browser already decoded, bypassing the server escaper. Match the escaper to context (`esc_html`/`_.escape` for text+quoted-attr; `esc_url` for URLs; `wp_json_encode` for `<script>`/localized data).
- **Fail closed, and check the fail direction of every new branch.** Empty/absent/unresolvable input (no token, no price, missing status, `realpath` false) must DENY/drop, never grant, fall back to `0`, or default-allow. A scoping filter that returns "keep" on a malformed/missing status is a hole.
- **Confirm the check uses the same identity the endpoint authenticated.** API-key user (`user_can($this->user_id, …)`) vs cookie session (`current_user_can()`) vs an `$override` flag — a mismatch either leaks (too loose) or silently breaks legit callers (too strict, a functional regression to flag).
- **Gate sub-fields, not just the top-level record.** Price tiers, files, meta, notes, and stats each need their own check; hiding the post is not hiding its price list.
- **Compare error responses for an enumeration oracle.** "Not found", "wrong type", and "forbidden" should be byte-, shape-, and timing-identical, or a sequential-ID sweep distinguishes a real-but-hidden record from a missing one.

## Public-read access control / info disclosure

- Unauthenticated single-object fetch by ID enforces `post_status === publish` OR an explicit capability; list/collection queries pin `post_status` to public statuses so draft/pending/private/future/trash never appear.
- Cast/validate the ID (`absint`) so a slug or array can't smuggle past the numeric branch.
- Check the status allowlist covers ALL hidden statuses, and that custom `map_meta_cap` rules don't accidentally grant a low-priv role.

## Signed-token / fail-open auth

- The signature covers the WHOLE authenticated payload (every attacker-suppliable field: ids, price/tier, quantity, amounts) — try swapping one field and prove validation fails.
- Reject empty/absent token BEFORE any decode/restore; compare with `hash_equals` (never `==`/`!=`); the "nothing saved" path returns failure, not success.
- The signing key is server-side + a real CSPRNG secret; when one key backs multiple token types, each payload has a distinct constant prefix so a token for feature A can't validate for feature B.

## Request-supplied object IDs / IDOR on state-changing actions

- Trace the object ID to its true source on every hook the handler subscribes to; confirm a request cannot supply an ID for someone else's object.
- For a guest/unauthenticated state-changing flow where ownership can't be asserted, the control must be that the action is **not request-invocable at all** (refuse router dispatch) — a type/shape check is necessary; confirm it is also sufficient given how the framework routes requests.
- Grep every `do_action` site of the hook; confirm the request-reachable ones can't supply a resolvable ID (check arg count + arg type at each).

## Path traversal / directory-boundary enforcement

- The boundary compare runs on `realpath()` output for BOTH the candidate file and every allowed root — never the raw/user string (a pre-canonical check is defeated by `../` and symlinks).
- Anchor the prefix with a trailing separator on both sides (`strpos($f,$dir)===0` alone is a sibling-dir bug: `/rootEVIL/`).
- `realpath` false / empty ⇒ deny (fail closed).
- Enumerate every serving branch (attachment-ID paths, URL-to-path conversion, x-sendfile/nginx `X-Accel-Redirect`, symlink delivery) — each must pass the same boundary check or be provably downstream of it. One un-gated `readfile`/redirect re-opens the hole.

## Result scoping / capability-filtered queries

- The scope filter is applied server-side in the QUERY (or as a post-query per-item cap check), not just hidden in the UI; it covers status (draft/private/pending/future) and hidden sub-items (price tiers, bundle children).
- Per-caller caching keys on the full identity that changes visibility (user id + resolved capability/status set) AND every request modifier that changes the result set — a key on identity alone that ignores modifiers trades a security bug for a stale-data bug.

## Settings / options sanitization and save-time allowlists

- Trace the SAVE path, not only the render path: which keys pass the allowlist because they belong to another section/tab or were already stored, and do they reach the CURRENT section's sanitize loop or merge raw into `$output`? (pitfall 24)
- For EVERY declared type in the type map, list the real registered settings of that type and confirm a sanitizer class exists; a type with no implementation falls to the Fallback, so read the Fallback and rate on what it keeps (quotes, `;{}`, `<`). (pitfall 30)
- Trace every surviving key to its render sink; inline CSS/JS via `wp_add_inline_style` / `wp_add_inline_script`, class/style attributes, and invoice/email templates are not auto-escaped.
- Check the other direction too: legitimate UI keys dropped on a fresh store or on first save (a drop regression is a functional finding).
- Live probe: save a hostile value through the real settings form for one setting of each declared type, then load every consumer page.

## New parser, walker, or recursive helper on hostile structured input

- Confirm the helper bounds recursion depth and detects cycles (self-referencing serialized arrays `a:1:{i:0;R:1;}`, nested JSON, tree walks).
- Feed it: cyclic input, maximally deep input, empty input, wrong scalar type. A crash, memory-exhaustion, or fatal the OLD code did not have is a PR-introduced finding even though the named vector is closed. (pitfall 23)
- Check every caller now routes through the new helper; a sibling `unserialize()` / `json_decode()` site left on the old path is the forgotten sibling.
