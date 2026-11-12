# Known Bug Patterns

Bug classes that shipped in real WordPress plugins and were later fixed, written as general
patterns. When reviewing a PR, check whether the changed code repeats one of them. Each entry says
what went wrong and how to detect it. Entries marked **(security)** describe a vulnerability class.

415 patterns, grouped by theme:

- [Authorization and nonces](#authorization-and-nonces) (52)
- [Escaping, sanitizing and injection](#escaping-sanitizing-and-injection) (27)
- [Secrets and privacy](#secrets-and-privacy) (13)
- [Files and paths](#files-and-paths) (14)
- [SQL and database](#sql-and-database) (29)
- [Caching and performance](#caching-and-performance) (20)
- [Hooks and render lifecycle](#hooks-and-render-lifecycle) (42)
- [State, locks and background jobs](#state-locks-and-background-jobs) (21)
- [Dates, numbers and money](#dates-numbers-and-money) (18)
- [Payments and subscriptions](#payments-and-subscriptions) (28)
- [Forms, settings and exports](#forms-settings-and-exports) (26)
- [Remote APIs and HTTP](#remote-apis-and-http) (23)
- [JavaScript and the block editor](#javascript-and-the-block-editor) (30)
- [PHP and WordPress API semantics](#php-and-wordpress-api-semantics) (39)
- [Install, upgrade, uninstall and multisite](#install-upgrade-uninstall-and-multisite) (13)
- [Back-compat and structure](#back-compat-and-structure) (15)
- [Tests](#tests) (5)

## Authorization and nonces

### Verify a nonce in every state-changing AJAX and admin handler

**What shipped:** **(security)** A `wp_ajax_` handler, `admin_init` handler, `admin-post` action, list-table `process_bulk_action()` or upgrade routine checks a capability (or nothing) and then writes data, sends mail, or returns sensitive data without verifying a nonce, so a forged cross-site request from a logged-in admin's browser performs the action. Common shapes: a dismiss link `?dismiss=1` that updates an option on `admin_init`; bulk actions that run on any request carrying the right `action` parameter although the table already prints the `bulk-{plural}` nonce; a nonce still generated with `wp_nonce_url()` after the action moved to AJAX but never checked by the new handler; one handler in a file checks a nonce while its siblings do not.

**Detect by:** For every `wp_ajax_`, `wp_ajax_nopriv_`, `admin_post_` and `admin_init` handler in the diff, grep the body for `check_ajax_referer`, `check_admin_referer` or `wp_verify_nonce`. Rate a missing check as serious only when the handler mutates state, sends mail, or exposes private data; idempotent read-only handlers are low severity. When one handler in a file verifies a nonce, tabulate every sibling handler and flag each state-changing one that does not. In `WP_List_Table` subclasses, confirm bulk actions verify `bulk-{plural}` plus a capability before acting. Also confirm a nonce that the page generates is actually verified by the handler that receives it.

---

### Check current_user_can() in state-changing handlers, not only a nonce

**What shipped:** **(security)** An admin handler that changes stored data verifies a nonce but no capability; a nonce proves intent, not authorization. Variants gate on `is_user_logged_in()` only, or on a nonce printed for every logged-in user, so a Subscriber can drive admin features. Listeners on `admin_init` that act on `$_GET` are also reachable by logged-out users, because `admin-ajax.php` fires `admin_init` before dispatch. Handlers dispatched from `$_GET` that do their work and then render the same URL repeat the side effect on every reload.

**Detect by:** For each handler on `admin_post_*`, `wp_ajax_*`, `admin_init`, `load-*` or a plugin action router that writes data, confirm a specific `current_user_can()` check alongside `wp_verify_nonce()`/`check_admin_referer()`. Flag handlers gated only by a nonce, `is_user_logged_in()` or `is_admin()`. For `$_GET`-dispatched actions, require `wp_safe_redirect()` plus `exit` to a URL without the action parameter, carrying the result in a separate notice parameter.

---

### Enforce the same guard on every path to the same operation or resource

**What shipped:** **(security)** One privileged operation or resource is reachable through several entry points (bulk action, alternate flow, lifecycle hook, AJAX, REST, export, shortcode, block, dispatcher mode), and some apply a weaker guard than the canonical handler. Examples: a bulk handler derives its capability from the requested action label so bulk trash falls back to the edit capability; a restore route checks only `is_user_logged_in()` plus a nonce localized on every admin screen while its sibling requires a management capability and `edit_post`; a multi-action handler checks edit once and then runs a delete branch under a nonce shared with harmless row actions; a log viewer or settings tab is gated on a delegable 'view' capability; a merge endpoint checks 'duplicate' rights instead of 'merge' plus `edit_post` on both posts. Surface variants: one API mode returns personal data without the capability check its siblings run, a single-item path skips the moderation or verification filter the listing applies, and a shortcode re-evaluates access on one condition instead of calling the shared permission helper that the full-page path uses.

**Detect by:** For each destructive or privileged operation or protected resource, list every entry point and build a table of the guards each applies (capability, nonce, ownership, verification, status filters); flag any member weaker than the canonical handler or missing a guard most siblings enforce. Confirm every enforcement surface calls the same shared permission helper in the same order. Never derive the capability from a request value. Flag capability decisions made before `check_admin_referer`, comments that name a different capability than the `current_user_can()` call below them, `handle_bulk_actions-*` callbacks without per-object `current_user_can( 'publish_post'|'delete_post', $id )`, and nonce actions shared by safe and destructive operations. Check where each nonce is localized: if it is printed for any logged-in user (for example on `profile.php`), it is not an authorization boundary.

---

### Check per-object type, status and ownership, not a role-wide capability

**What shipped:** **(security)** Handlers load a caller-supplied id with `get_post()`, `get_comment()`, an attachment lookup or raw SQL and act on whatever it names, treating a role-wide capability (`edit_posts`, a custom `edit_<type>s` capability) or nothing as permission. Lower-privileged or anonymous callers then receive other authors' draft, private, pending, trashed or password-protected content through search, AJAX, public API single-item branches, keyless update or changelog endpoints that resolve by id, title or slug across every status, and listing queries without `post_status = 'publish'` and `post_password = ''`. Write variants delete any attachment a submitter references, approve or delete any comment regardless of `comment_type`, or show another customer's order from an id in the URL. Read paths often remove the query filter that hides such objects without adding a status check, and response filters add hidden data after the gate has refused. `is_post_publicly_viewable()` alone is not enough: it ignores `post_password` and depends on the post type's `publicly_queryable` flag.

**Detect by:** Grep `get_post(`, `get_comment(`, `get_page_by_path(`, `wp_delete_post(`, `wp_delete_comment(`, `wp_delete_attachment(`, `wp_update_comment(` and `get_attached_file(` with ids from requests, shortcode or block attributes, or form fields. After loading, require that the type is the one the handler owns, that reads check `current_user_can( 'read_post', $id )` or publish status plus `! post_password_required( $post )` (or `comment_approved`), and that writes and private reads check the owner matches the current user or a per-object capability or signed token; a missing owner must deny. In public endpoints force `'post_status' => 'publish'` and return the same not-found response for hidden and nonexistent ids. Flag `'post_status' => 'any'|'all'`, `remove_filter()` around a lookup with no status check after it, enrichment filters that run after a refusal, and REST routes that check only the route capability.

---

### Verify the nonce before any side effect

**What shipped:** **(security)** A side effect runs before the nonce or allowlist check that authorizes it. Two callbacks share one AJAX hook, and a priority-1 preflight that checks only capability calls the gateway's refund before the priority-10 handler verifies the nonce. A resend-receipt handler checks capability but no nonce and takes the recipient from the request. A connect endpoint subscribes the submitted email, or makes remote token calls, on the lines before the referrer or return-URL allowlist runs.

**Detect by:** For shared AJAX/action hooks, list every `add_action` priority. Each callback that has side effects must verify the nonce itself. Within a handler, confirm nonce and allowlist checks come before any remote call, email or write. Flag handlers that take a recipient or target from the request instead of deriving it from the object.

---

### Stop execution after a failed capability or nonce check

**What shipped:** **(security)** An AJAX handler checks `current_user_can()` and on failure echoes a JSON error but does not exit, so the privileged work still runs and its output is returned. The same happens when a custom response helper sends JSON without dying, when the handler assumes an overridable helper exits, and when a list-table bulk action prints an error notice and continues to the delete.

**Detect by:** In every `wp_ajax_*`, `admin_post_*`, REST and bulk-action handler, find each failed `current_user_can()`, `wp_verify_nonce()` or `check_ajax_referer( ..., false )` branch and confirm it ends in `wp_die()`, `wp_send_json_error()`, `exit` or `return`. Flag branches that only echo, set a notice or call a helper with no `return` after it.

---

### Bind write nonces to the target object and authorize the object separately

**What shipped:** **(security)** An admin write handler verifies a nonce whose action is a bare literal and gates the write on a read-level capability while sibling write handlers require the write capability, so a nonce minted on one object's screen validates a write against any other object's id. The opposite mistake adds a nonce bound to the object id next to an unchanged role-wide capability check and calls it the authorization fix: nonces prove intent, not ownership, so the capability still lets any holder act on any object.

**Detect by:** For mutating handlers that take an object id, check that the nonce action includes the id (`'my_plugin_update_' . $id`) and that `wp_verify_nonce()` uses the same id from the request. Compare the capability with sibling write handlers for the same resource and flag 'view'/'read' capabilities on writes. Flag `wp_verify_nonce( ..., 'action_' . $object_id )` added beside an unchanged generic `current_user_can( 'view_*' )`; require an ownership or object-level check (`current_user_can( 'edit_post', $id )` style).

---

### Do not treat a nonce as identity or CSRF protection for logged-out visitors

**What shipped:** **(security)** Handlers registered on `wp_ajax_nopriv_*` or front-end `init`/`template_redirect` POST hooks (update a payment method, delete a list item, upload a file, change a guest cart or session) are gated only by a nonce not scoped to any object, or by a mere `isset( $_POST[...] )` routing check, and never check ownership or a capability for the id in the request. A nonce for user 0 with no session token is the same for every guest and can be read from any page, so it ties the request to no visitor: any visitor can change the id and act on another user's record, upload into the media library, or forward the request to a gateway and read the full response. Tokens published to every visitor have the same weakness when used to pick which record or recipient to act on, and requiring guest nonces on cached pages also rejects real submissions with stale nonces.

**Detect by:** Grep `wp_ajax_nopriv_` registrations and `init`/`template_redirect` POST handlers and read each one. Confirm `isset()` routing is not mistaken for authorization. Require that the handler loads the record named by the request id, checks its type, and checks ownership (session or guest token bound to the record) or `current_user_can()` for that object. If a nonce is the CSRF defense, its action must include a per-visitor secret stored in the visitor's session; guest nonces must not be treated as proof of identity or eligibility. Check that nonce failures on cacheable pages do not block legitimate guests, and question whether the action needs a `nopriv` registration at all.

---

### Apply capability checks on every path, not only when a flag is passed

**What shipped:** **(security)** A helper enforces `current_user_can()` only when the caller passes a capability argument. Front-end callers pass none, so a crafted `$_GET` parameter reaches the protected mode (for example a preview or editor mode) for anonymous or low-privilege users, exposing other users' data or poisoning page caches. Returning the raw request value when no capability is given has the same effect.

**Detect by:** For any function that gates behaviour on a capability or identity check, list every input source and every caller. Flag `if ( $capability ) { ...check... }` guards where callers can omit the argument, and any `$_GET`/`$_REQUEST` value that switches into a privileged mode. The default must be to deny.

---

### Make access gates fail closed when a status, tier or key is missing

**What shipped:** **(security)** A guard denies only when a looked-up status is present and wrong, as in `if ( $status && 'active' !== $status )`, so once the resource is deleted the lookup returns empty and the action proceeds. An entitlement check that filters by a price-option or tier id drops that filter when the id is null and then matches any tier, over-granting access; sibling methods return every option's files when none is named, or fall back to the cheapest tier when a stored id is missing. Other variants: a restriction check wraps a scalar meta value into an array of the wrong shape so `empty( $row['key'] )` is always true and legacy protected content is treated as unrestricted, and a plan-feature lookup with a `?? FREE` default treats any unknown or misspelled feature key as available on every plan.

**Detect by:** Grep access and plan checks for `if ( $value && <expected> !== $value )`, `?? <permissive default>`, `unset( $args['<option>_id'] )`, `if ( empty( $tier_id ) )` branches that skip a `WHERE` clause, and defaults that pick the first or cheapest option. Confirm that empty, false, null and unknown keys deny by default, and that 'no tier specified' matches only untiered records or denies, never everything. Check normalization of legacy meta formats produces the shape the checks read, and that free or always-allowed features are listed explicitly.

---

### Parenthesize mixed && and || conditions that guard security checks

**What shipped:** **(security)** A guard mixes `&&` and `||` without parentheses, so an auto-confirm flag on the right of `||` bypasses every check on the left, including the nonce. Nonce guards written as `if ( ! isset( $_POST['n'] ) && ! wp_verify_nonce( ... ) )` pass for any non-empty value, and guards that verify a nonce only when the parameter is present let requests that omit it through. A related flaw places a state-changing call after an `if`/`elseif` chain instead of inside the branch that verified success, so it runs on any fallthrough. Conditions such as `! is_array( $x ) || ! is_object( $x )` are always true.

**Detect by:** Grep conditions combining `&&` and `||` without grouping, especially where one operand is a nonce, capability or signature check, and confirm the actual precedence matches the intent. Flag `! isset( ... ) && ! wp_verify_nonce(`, `isset( $nonce ) && ! wp_verify_nonce(`, and negated-OR type checks. Check that state changes after a conditional chain sit inside the verified branch.

---

### Use the same nonce action and field name at creation and verification

**What shipped:** **(security)** A nonce is created with one action string (or by `WP_List_Table`'s `bulk-{plural}` convention) and verified with another, or the AJAX handler reads a different request field name than the localized JS sends, so every request fails (and the check tends to get disabled). Hardcoding the list-table bulk action also breaks in non-English locales, because core builds it from a translatable plural label.

**Detect by:** For each `check_ajax_referer()`/`wp_verify_nonce()`/`check_admin_referer()`, find the matching `wp_create_nonce()`/`wp_nonce_field()`/`wp_nonce_url()` and the JS payload key, and diff the action and field strings (underscore vs hyphen too). For list-table bulk actions verify against `'bulk-' . $this->_args['plural']`. Never pass a nonce action through `__()`.

---

### Verify that a child row belongs to the parent that was authorized

**What shipped:** **(security)** A handler checks the caller's permission on a parent object (an order, a customer, a form), then reads or writes a child row (an address, an activation, a line item, an entry) by its own id from the request with no constraint tying it to that parent. A caller authorized for one parent can then act on any other parent's children, and a mutating AJAX handler with no nonce lets a forged request change state with any pairing of ids.

**Detect by:** Grep for updates or lookups using an id straight from the request (`absint( $_POST['id'] )`); trace back to the authorization check and confirm the child is fetched with a query constrained by both its id and the authorized parent's id, or that the handler loads the parent and verifies `$item->parent_id === $parent_id`. Confirm mutating AJAX/REST handlers that take two related ids verify a nonce first and check that the parent exists.

---

### Authorize user-meta writes and per-user reads for the request-supplied user id

**What shipped:** **(security)** A profile-save handler takes the target user id from the request, checks only a management capability, and writes admin-configurable field keys with `update_user_meta()`. Nothing checks `edit_user` for that user or blocks reserved keys such as `{prefix}capabilities`, so a manager can grant roles on any account. A reserved-key denylist built from the current blog prefix misses other sites' keys on multisite and keys such as `session_tokens` or `_application_passwords`. On the read side, shortcodes and exports render a user's records for a `user_id` from attributes or the request without checking that the viewer is that user. Handlers that take an author or owner id from hidden form fields let users act as anyone.

**Detect by:** Grep `update_user_meta(`, `add_user_meta(` and `wp_update_user(` where the user id comes from request or form data, and require `current_user_can( 'edit_user', $user_id )` with `$user_id > 0`. When the meta key is configurable, use an allowlist, or a denylist covering `{$wpdb->base_prefix}(\d+_)?(capabilities|user_level|user-settings|user-settings-time)`, `session_tokens` and `_application_passwords`. In shortcodes and exports, require `get_current_user_id() === $user_id || current_user_can( <manage cap> )`. Acting identity must come from `get_current_user_id()`, never a hidden field.

---

### Consult the object in map_meta_cap before granting meta capabilities

**What shipped:** **(security)** A `map_meta_cap` filter returns an empty `$caps` array (nothing required) for a group of capabilities whenever the user has a plugin role, including object-level meta caps such as `edit_post` and `delete_post`. Ignoring `$args[0]` grants edit and delete on every post of every author, and the same group grants site-wide primitives the feature never needs.

**Detect by:** In every `map_meta_cap` callback, flag `$caps = array()` or returning `[]`/`['exist']` in a branch that includes meta caps (`edit_post`, `delete_post`, `read_post`, `edit_user`, custom singular caps). Meta caps must load the object from `$args[0]` and check ownership and status; primitive caps should be limited to what the feature uses.

---

### Give privileged custom post types their own capabilities

**What shipped:** **(security)** A post type whose published records act as live site configuration (pricing rules, settings, templates) is registered with `'capability_type' => 'post'`, no `capabilities` map and `public => true`, so authors can create and publish it. Nesting the menu under a privileged parent hides the list screen but not `post-new.php` or `post.php`, which check the post type's own caps, and the `save_post` handler does not check the post type.

**Detect by:** Grep `register_post_type(` for internal or configuration types registered with `'capability_type' => 'post'` or none, and require a custom `capability_type` with `map_meta_cap => true` or an explicit `capabilities` map to an admin capability, plus `public => false` for non-content types. Confirm every `save_post` callback bails unless the post type matches (or uses `save_post_{post_type}`). Menu placement is not access control.

---

### Guard handlers on prefixed hooks that request routers can fire

**What shipped:** **(security)** Many plugins have a router that fires `do_action( 'myplugin_' . $_REQUEST['action'], $_REQUEST )`. Any internal action hook with that prefix can then be fired by an unauthenticated request, with the raw superglobal array as its argument. Handlers that attach to internal lifecycle hooks (order built, after-order actions, object deleted, cron maintenance) and have no origin, capability or cron guard become public entry points. They can overwrite order fields, create and log in accounts, send or suppress emails, run maintenance jobs, or delete child records whose ids are read from the request array as an `IN()` list. WordPress slices extra hook arguments to the accepted-args count and does not pad missing ones, so a handler that relies on a second, internally supplied argument still runs with it absent.

**Detect by:** Find the plugin's request-to-hook router and list every `add_action` on hooks that share its prefix. Each handler must validate its argument types (`is_numeric()` and >= 1, not `! empty()`), require the data-carrying arguments only an internal dispatch supplies, and check capability, nonce or cron context before writing. Delete listeners must confirm the parent object is actually gone. Name new internal signals with a namespace the router cannot build (`myplugin/order_built`), or add them to the router's blocklist.

---

### Compare secret tokens with hash_equals()

**What shipped:** **(security)** An unauthenticated endpoint authorizes a privileged action solely by comparing a request token with a stored HMAC using `!==`. With no nonce, capability check or rate limit and a long-lived secret, an attacker gets unlimited timing samples.

**Detect by:** Grep `===`/`!==`/`==`/`!=`/`strcmp(` where either side is an HMAC, signature, token, API key or `hash_hmac(` result, especially in `wp_ajax_nopriv_`, REST `permission_callback`, webhook and magic-link handlers. Require `hash_equals( $known, $user_supplied )` with both cast to string, plus rate limiting or expiry for privileged actions.

---

### Match hosts exactly in allowlists

**What shipped:** **(security)** Host checks use substring or loose patterns before attaching credentials or tokens: an unescaped regex `/(?:^|.)example\.com$/` matches `evilexample.com`; `strpos( $url, '//trusted.example/path' ) !== false` accepts any URL containing that text in its query string; `strpos( $url, $site_url )` makes `example.com` match `my-example.com`.

**Detect by:** For every allowlist that decides whether to send a secret, token or redirect, confirm the URL is parsed with `wp_parse_url()` and scheme, host (exact or `.`-anchored suffix) and path are compared separately. In regexes, every literal dot must be escaped and the boundary must be `(^|\.)`. Test mentally with `evil-target.com`, `target.com.evil.com` and `evil.com/?u=target.com`.

---

### Do not make access decisions by substring-matching REQUEST_URI

**What shipped:** **(security)** A redirect that keeps a restricted role out of wp-admin exempts requests whose `$_SERVER['REQUEST_URI']` contains `admin-ajax.php` or `async-upload.php`, so adding that string to any query string opens any admin screen. Percent-encoded paths such as `/wp-%61dmin/` skip raw-URI checks while the server still routes them, and `strstr()` checks for `?p=ID` or `/slug` fragments match prefixed ids or every URL when the configured value is empty.

**Detect by:** Grep `strpos`, `stripos`, `strstr`, `str_contains` and `preg_match` on `$_SERVER['REQUEST_URI']` or `PHP_SELF` used in access or routing decisions. Require `wp_doing_ajax()`, `$GLOBALS['pagenow']`, `is_admin()`, `get_queried_object_id()` or a parsed, decoded path compared exactly, and handle an empty configured value explicitly.

---

### Check authorization before any lookup whose result changes the response

**What shipped:** **(security)** A handler checks whether a request-supplied id has records before checking whether the current user may see them, so ids with no records return quietly and others return 403: an enumeration oracle. Public endpoints that answer differently for a nonexistent key and a key owned by someone else (different code, message, status or timing) let attackers enumerate valid keys, emails or order ids.

**Detect by:** In handlers taking a target id or key from the request, list the checks in order. Flag any existence or data lookup whose outcome selects a different response before the capability/ownership check. Not-found and not-owned branches must return identical code, message and status, ideally asserted in a test.

---

### Persist and verify the OAuth state parameter

**What shipped:** **(security)** An OAuth or connect-flow start step sends no `state`, or mints one without storing it, so the callback cannot tell whether the site started the flow. Some callbacks run on `template_redirect` keyed on generic query parameters with no nonce or capability check, and others use `wp_create_nonce()` as the state, which is reusable for its whole lifetime rather than single-use.

**Detect by:** For each OAuth/connect flow, confirm (1) the start step generates a random state (`wp_generate_password()` or `random_bytes()`) and stores it in a short-lived, user-scoped transient or user meta, (2) the callback compares it with `hash_equals()`, rejects on mismatch or absence, and deletes it after use, and (3) authorize, complete and disconnect handlers run in admin context behind `current_user_can()` and a per-action nonce.

---

### Validate the signed token before trusting the resource id it accompanies

**What shipped:** **(security)** A logged-out visitor gets a receipt or order session from a sequential order id plus a weak or missing second factor: id plus email with no throttle, a request id copied into the session by a gateway return handler, or a recovery link that takes only the id. Where a request does carry an id plus a signed hash for it, the handler may resolve the resource from the id alone and never compare the token, and the 'not authorized' branch may render a fallback link or redirect that embeds a freshly generated valid token, handing the missing credential to the caller. A gateway confirmation handler that runs on every front-end request can read an order id from the query string and render its details with an unrelated gateway token as the only other parameter.

**Detect by:** Every guest grant of order access, recovery or session-key write must require the signed per-object hash or token, compared with `hash_equals()` before the id is used to resolve or render anything, must be rate-limited, and must refuse objects owned by another account. Inspect every denial branch for links or redirects that mint a fresh valid token for the requested resource. Grep `template_redirect`/`the_content` callbacks that take an order id from `$_GET`; a gateway token in the request proves nothing unless the code checks that it belongs to that object.

---

### Do not link existing records to an account by an unverified email

**What shipped:** **(security)** Registration, or account creation during guest checkout, attaches an existing guest customer record and its orders to the new account based only on the email typed into the form, so anyone who knows a guest buyer's email takes over their history. Variants: a `nopriv` handler with no nonce looks up a customer by a request email to grant a returning-customer discount (and the differing totals reveal whether the email exists), and a post-payment handler calls `wp_set_auth_cookie()` for the user linked to the order's email, which a guest can set to a victim's address.

**Detect by:** Grep registration, account-creation and order-linking code for lookups by email that transfer ownership, grant discounts, or call `wp_set_auth_cookie()`; require email verification before linking, record the authenticated user from `get_current_user_id()` at order creation, and never derive identity from an email the request supplied.

---

### Sign in exactly the user that passed authentication

**What shipped:** **(security)** A custom login form looks up the account twice in different orders: the password check by login then email, the sign-in by email then login. Because one user's login can equal another user's email, a correct password for one account sets the auth cookie for another.

**Detect by:** In custom login handlers, flag multiple `get_user_by( 'login'|'email' )` lookups and any `wp_set_auth_cookie()`/`wp_set_current_user()` whose id is not the exact `WP_User` returned by the authentication call. Prefer one `wp_authenticate()` or `wp_signon()` call.

---

### Use wp_verify_nonce when the code should return on failure

**What shipped:** A handler writes `if ( ! check_admin_referer( 'action' ) ) { return; }`. `check_admin_referer()` (and `check_ajax_referer()` by default) dies on failure, so the `return` branch never runs, and AJAX callers get a bare `-1` or an 'are you sure' page instead of the intended handling.

**Detect by:** Grep `if ( ! check_admin_referer(` and `if ( ! check_ajax_referer(` without `$stop = false`. Use `wp_verify_nonce()`, or pass `false` as the third argument to `check_ajax_referer()`, when the code means to handle the failure itself.

---

### Generate nonces at render time, never in stored or cacheable output

**What shipped:** Nonces expire after 12 to 24 hours, even for logged-out visitors, but they get baked into output that lives longer. Admin notices are stored in an option with their dismiss URL already built by `wp_nonce_url()`, so the dismiss link fails forever while the notice keeps showing. Front-end widget HTML carries a `wp_create_nonce()` value that later public AJAX calls verify, and page caches serve that HTML for days, so cached pages fail the check and the widget renders nothing. Emails and saved markup fail the same way.

**Detect by:** Grep for `wp_nonce_url(`, `wp_create_nonce(` or `_wpnonce` inside values passed to `update_option()`, `add_option()`, `set_transient()`, user meta or a notice registry, and in content that is emailed; store the action and arguments and build the nonce at render time. Grep front-end render paths (shortcodes, blocks, widgets, `wp_localize_script` on public pages) for nonces output to logged-out visitors and the matching checks in `wp_ajax_nopriv_*` handlers. If the page can be cached, fetch the token via an uncached request or use a non-expiring HMAC (keyed from `wp_salt()`, compared with `hash_equals()`) for non-privileged reads.

---

### Account for nonces that a mid-flow login or missing field invalidates

**What shipped:** A post-checkout hook verifies a nonce from the submitted order data, but only some gateways send that nonce, and the check is redundant when the hook only fires after the host has already validated the request. When checkout logs in or creates the user during the request, nonces created earlier are bound to user 0 and fail on the follow-up request (for example a payment-confirmation AJAX call). Front-end code that sends `X-WP-Nonce` to a REST route that authenticates with its own token hits the same problem: a stale nonce (minted as a guest before login, or for another site on multisite) makes core's `rest_cookie_check_errors` return 403 before `permission_callback` runs.

**Detect by:** When a diff adds `wp_verify_nonce()` in a hook that fires late in a multi-step flow, confirm every path that reaches the hook actually supplies the nonce. If the flow can call `wp_set_current_user()`, `wp_signon()` or automatic account creation between nonce creation and verification, require the nonce to be regenerated and handed back to the client after login. For `fetch`/`apiFetch` calls with `X-WP-Nonce`, check whether the session can change after render and whether the route authenticates otherwise; if so, drop the nonce or refresh it after login.

---

### Do not let a filter bypass a nonce or capability check

**What shipped:** **(security)** A nonce or permission result is passed through `apply_filters()` or a filter can short-circuit the verification, so any plugin or a stray `__return_true` disables CSRF or capability protection for a state-changing request.

**Detect by:** Grep for `apply_filters` around `wp_verify_nonce`, `check_ajax_referer` or `current_user_can` results, or before an early `return true` in verification helpers. Security verdicts should not be filterable to true.

---

### Identify the affected user from the object, not get_current_user_id()

**What shipped:** A refund or status handler falls back to `get_current_user_id()` to find the purchaser. The action is run by an admin, or by cron/webhook as user 0, so the code updates the admin's (or no) user data and the customer's record is unchanged.

**Detect by:** In hooks fired by admin, cron, webhook or gateway actions on another user's object (refund, cancel, status transition, `save_post`), grep for `get_current_user_id()` / `wp_get_current_user()` used to identify the owner. Require the owner id from the object itself (its user id field, `post_author`, customer record).

---

### Require non-zero ids in ownership comparisons

**What shipped:** **(security)** An access gate allows access when `(int) get_post_field( 'post_author', $id ) === (int) get_current_user_id()`. For a missing post the author is `''`, which casts to `0`, and a logged-out visitor's id is also `0`, so guests pass whenever the referenced object does not exist.

**Detect by:** Grep equality checks between a cast owner, author or customer id and the current user id. Require that both sides are non-zero and the object exists before the comparison, so a missing object or a guest never matches.

---

### Apply ownership checks to every representation of a file field

**What shipped:** **(security)** An ownership check (author match or edit capability) is added for a file field only when it carries an attachment ID. The same field can also carry a raw local path or URL, and that branch reaches the sink with no ownership check. A related variant resolves an attachment from a URL with a helper that accepts an author-id argument but never applies it, so any user's attachment is resolved and re-parented.

**Detect by:** When an authorization check keys off one representation of a value (for example `attachment_id`), grep the same handler/sanitizer for sibling branches that accept another representation of the same logical field (raw path, URL, slug, GUID) and confirm each gets an equivalent check rather than falling through an unguarded `else`. Check that helper parameters such as `$author_id` or `$user_id` are actually used in the lookup.

---

### Rate-limit unauthenticated state-creating entry points

**What shipped:** **(security)** A public, unauthenticated route that creates accounts or other records applies no throttling, even though the codebase already has a rate limiter used by another feature. A related entry point also ignores the site setting that is meant to disable the flow entirely.

**Detect by:** List unauthenticated write-capable entry points (registration, password reset, contact or signup forms, guest checkout account creation, `wp_ajax_nopriv_*`, public REST routes). If the codebase has a limiter, grep its call sites and confirm each entry point uses it. Confirm each entry point checks the setting that enables the flow, not only the UI that links to it.

---

### Make rate limiters fail closed and count at the right point

**What shipped:** **(security)** A throttle skips all checks when the client identifier is empty, records the attempt only after the expensive action succeeds, checks the same limit twice, or resets the counter on success, so the limit can be exceeded. Conversely, a limiter that increments before nonce and field validation locks out users who merely mistyped the form.

**Detect by:** In rate-limit code: an empty or unknown identifier must fail closed; the attempt must be recorded after validation but before the side effect, regardless of outcome; each limit is checked once; success must not clear the abuse counter. Require tests for failed-validation attempts and empty identifiers.

---

### Verify CAPTCHA and honeypot fields on the server

**What shipped:** **(security)** A public form renders a CAPTCHA and runs it in the browser, but the server handler never sends the response token to the provider's verification endpoint, so a direct POST bypasses it. A honeypot field rendered with no server check has the same problem. The opposite failure also occurs: when keys are not configured, verification rejects every submission or login.

**Detect by:** For each form that loads `grecaptcha`, `hcaptcha` or `turnstile`, grep its handler for reading `g-recaptcha-response`, `h-captcha-response` or `cf-turnstile-response` and calling the provider's `siteverify` endpoint, requiring `success` true. Confirm honeypot fields are checked server-side. Check behaviour when keys are missing: an explicit skip, not a lockout.

---

### Gate custom script and raw-HTML settings on unfiltered_html

**What shipped:** **(security)** A settings save stores 'custom CSS/JS', header/footer code or raw-HTML fields and prints them unescaped, gated only by `manage_options` or a delegable plugin capability. On multisite or with `DISALLOW_UNFILTERED_HTML`, site admins lack `unfiltered_html`, so they can store script that runs for super admins and visitors.

**Detect by:** Grep settings savers and REST/AJAX save handlers for keys like `custom_js`, `custom_css`, `*_script`, `header_code`, `tracking_code` or raw-HTML fields. Confirm the write (and rendering back into the form) is gated on `current_user_can( 'unfiltered_html' )`, or the value is dropped/`wp_kses`ed otherwise. Script fields cannot be sanitized into safety, so the capability is the control.

---

### Do not install request-supplied package URLs, and gate plugin installs on plugin capabilities

**What shipped:** **(security)** An admin AJAX handler that installs companion plugins takes the package URL from the request and passes it to the upgrader without a scheme or host allowlist, so any admin-context XSS becomes arbitrary code installation. Gating install/activate on `manage_options` lets a multisite subsite admin install code network-wide, since `install_plugins`/`activate_plugins` are Super-Admin-only there.

**Detect by:** Grep `Plugin_Upgrader`, `->install(`, `download_url(`, `activate_plugin(` in `wp_ajax_*` callbacks. Confirm the package URL is not read from the request, or is checked with `wp_parse_url()` for `https` and an exact host in a fixed allowlist (no credentials or non-default ports), and that the capability is `install_plugins`/`activate_plugins`/`deactivate_plugins`, never `manage_options`.

---

### Do not treat DOING_CRON as an authorization check

**What shipped:** **(security)** WordPress defines `DOING_CRON` in `wp-cron.php` before anything authenticates the request. A plugin action router that boots in that request and gates privileged background routines (upgrades, webhook syncs) on `DOING_CRON` or a wrapper around it lets anyone run them by requesting `wp-cron.php` with the routine's action parameter.

**Detect by:** Grep `DOING_CRON`, `wp_doing_cron()` and plugin cron-check helpers used as the sole gate on a callback that a request parameter can trigger (a plugin action router reading `$_GET`/`$_POST`). Privileged background work should run only from a scheduled event hook or queued background job, with request-driven routers refusing those action names regardless of cron state.

---

### Restrict request-supplied taxonomy and post-type slugs in lookups

**What shipped:** **(security)** A term-suggestion AJAX handler takes the taxonomy from the request and only checks that it is registered, so a user can enumerate terms from any taxonomy, including private ones. The query also has no result limit.

**Detect by:** For AJAX and REST handlers taking `taxonomy` or `post_type` from the request, require `is_object_in_taxonomy( $post_type, $tax )` or an allowlist, plus `current_user_can( get_taxonomy( $tax )->cap->assign_terms )` as core's tag search does, and a `number` limit on `get_terms()`.

---

### Do not let a request id choose which validation rules a save runs

**What shipped:** **(security)** A save handler builds its form or config object from an id in the request, falling back to the configured id only when absent, and loads the config from any post id without checking its type. A request can name a different form, so the intended form's required, honeypot and CAPTCHA checks never run, including on unauthenticated registration or login routes.

**Detect by:** Grep save handlers for `$_REQUEST['*_id']`/`$_POST['*_id']` used to load fields, validation rules or notifications. The handler should load its own configured id, or verify the loaded post's type matches the handler. Flag fallbacks like `isset( $_REQUEST['id'] ) ? ... : get_option( ... )` in save paths.

---

### Key per-user transients and caches by user

**What shipped:** **(security)** An OAuth CSRF `state` value is stored in a transient keyed only by mode, so two admins connecting at the same time overwrite each other's value and one flow fails or the wrong state is accepted.

**Detect by:** For transients, options or cache entries used in per-user flows (OAuth, wizards, previews), check whether the stored value depends on `get_current_user_id()` while the key does not. Include the user ID in the key, or use user meta.

---

### Validate OAuth identity claims from the token, not the request

**What shipped:** **(security)** A Google sign-in flow restricts logins to a Workspace domain by sending the `hd` hint in the authorization request, and treats the mere presence of the verified-email field as verified. The hint is only a UI filter, so any Google account, including unverified ones, can log in.

**Detect by:** In OAuth/OIDC login callbacks, confirm the returned ID-token/userinfo `hd` equals the allowed domain (strict, lowercased), `email_verified === true`, and `aud` matches the client ID. Flag `isset()`/`! empty()` checks on these claims and reliance on request parameters.

---

### Gate admin-only fields on user-profile hooks that also fire on the front end

**What shipped:** **(security)** Callbacks on `show_user_profile`/`edit_user_profile` (render) and `personal_options_update`/`edit_user_profile_update` (save) assume wp-admin, but community, forum and membership plugins fire the same hooks on front-end profile editors. Admin-only settings fields then render and can be saved by the user from the front end.

**Detect by:** For callbacks on `show_user_profile`, `edit_user_profile`, `personal_options_update` and `edit_user_profile_update`, decide whether the fields are admin-only. If so, gate render and save with `is_admin()` and, on save, `current_user_can( 'edit_user', $user_id )` plus the capability that manages that field.

---

### Decide write-blocking meta and option guards on the old-to-new transition

**What shipped:** **(security)** A guard on user-meta write filters blocks any capabilities write whose new value contains the administrator role, without reading the stored value. For existing administrators every unrelated capability edit, even a no-op save, is aborted and reported as privilege escalation; the guard was meant only for transitions into the role.

**Detect by:** For callbacks on `update_user_metadata`, `add_user_metadata`, `update_{$meta_type}_metadata`, `pre_update_option_{$option}` or `set_user_role` that veto or alert on a write, confirm they read the current stored value (uncached, or the `$old_value` argument) and decide on the transition, not on the new value alone.

---

### Do not use the first entry of `$user->roles` as the user's role

**What shipped:** **(security)** Logging, exclusion or permission code takes one role with `$user->roles[0]` or `reset( $user->roles )`. The roles array is ordered by when each role was granted, not by privilege, so an account that was a subscriber before becoming staff keeps the low role first and is misclassified (for example its privileged activity is excluded from an audit log).

**Detect by:** Grep `$user->roles[0]`, `array_values( $user->roles )[0]`, `reset( $user->roles )`, `current( $user->roles )` and `array_shift(` on roles where the result drives authorization, exclusion or logging. Require checking the whole array (`array_intersect`) or a capability check (`user_can`).

---

### Evaluate stricter restriction options before guest or open-mode shortcuts

**What shipped:** **(security)** A 'can this user act' check returns true early when guest access is enabled, before evaluating a stricter option such as 'only verified purchasers'. Because that status can only be verified for logged-in users, guests bypass the stricter rule.

**Detect by:** In permission helpers, find early `return true` branches for guest, anonymous or open modes and confirm they come after every stricter restriction option or also check it. Test each pairing of settings.

---

### Give admin-selectable capability gates a fixed fallback

**What shipped:** A setting lets the site owner choose which capability may view a plugin screen, and menu registration, page render and AJAX handlers check only that value. An administrator who picks a capability their own role lacks loses access to the page, including the settings screen needed to undo it.

**Detect by:** Grep `current_user_can(` calls whose argument comes from `get_option()` or a settings array. Each needs a fallback such as `|| current_user_can( 'manage_options' )`, and the screen that edits the setting must use a fixed capability. Check menu registration, page render, `wp_ajax_` handlers and list-table actions.

---

### Do not mint a fresh nonce on an interstitial that auto-continues a state-changing action

**What shipped:** **(security)** A progress or confirmation page reachable by GET creates a nonce for the current user and auto-redirects to the action URL with it. Any cross-site link to the interstitial runs the action as the logged-in admin, so the nonce provides no CSRF protection.

**Detect by:** Find handlers that call `wp_create_nonce()`/`wp_nonce_url()` and in the same request auto-submit or redirect (JS `location`, meta refresh, `wp_redirect`) to a state-changing endpoint. The incoming request must carry a verified nonce and pass `current_user_can()`; forward only that nonce, never a newly minted one.

---

### Use a distinct nonce parameter for GET actions on list-table screens

**What shipped:** A state-changing GET link uses the default `_wpnonce` query arg and does not redirect after acting. A `WP_List_Table` on the same screen runs `check_admin_referer( 'bulk-...' )` whenever `_wpnonce` is present, reads the leftover nonce under a different action and calls `wp_die`, breaking the page.

**Detect by:** For `wp_nonce_url()`/`wp_nonce_field()` links handled on admin list screens, check whether another handler reacts to `_wpnonce`. Use a distinct `$name` argument, and `wp_safe_redirect()` + `exit` with `remove_query_arg()` after the action.

---

### Do not read the current user inside wp_login, and account for two-factor plugins

**What shipped:** **(security)** A `wp_login` callback calls `is_user_logged_in()` or `get_current_user_id()`, but the current user is not set yet in that request, so the login-time action never runs. Separately, recording 'last login' or granting access on `wp_login` counts password-only logins that two-factor plugins then interrupt; moving the callback to `PHP_INT_MAX` does not help, because at equal priority registration order decides.

**Detect by:** Find `wp_login`, `wp_authenticate` and `set_logged_in_cookie` callbacks that read the current user; require the `$user` argument the hook passes. For callbacks that record, notify or grant on `wp_login`, check whether they also need the two-factor plugin's completion hook. Flag code or tests that assume `PHP_INT_MAX` means 'runs last'.

---

### Pass a 403 response code to wp_die() on an authorization refusal

**What shipped:** Permission and nonce failures call `wp_die()` without `$args['response']`, so the refusal returns HTTP 500 instead of 403, polluting error monitoring and confusing clients.

**Detect by:** For each `wp_die()` reached after a failed `current_user_can()`, nonce or ownership check, require `array( 'response' => 403 )` (or 400 for bad input).

---

### Include descendant terms when checking membership in a hierarchical taxonomy

**What shipped:** An access check grants entitlement when a post's term ids intersect the allowed term ids, comparing direct assignments only. Posts assigned only to a child of an allowed parent are denied, even though the UI implies parent selection covers children.

**Detect by:** Grep `array_intersect(` / `in_array(` comparing `wp_get_post_terms`/`wp_get_object_terms`/`get_the_terms` ids against a configured term list for a hierarchical taxonomy. Require `get_ancestors( $term_id, $tax, 'taxonomy' )` on the post side, `get_term_children()` on the allowed side, or `tax_query` with `include_children => true`.

---

## Escaping, sanitizing and injection

### Escape gateway, remote and stored data on admin screens

**What shipped:** **(security)** Data from gateway callbacks, nopriv REST routes, remote APIs, public forms or free-text meta is stored without a sanitizer and printed without an escaper in wp-admin, which is stored XSS. Examples: order or log notes built from IPN fields and rendered through `wpautop( make_clickable() )`. Email-tag HTML built by concatenation that escapes some values and not others. Media tabs that print remote object names raw. Admin notices that concatenate `$_REQUEST`. List tables that echo names and emails. A diagnostics page that renders a stored remote error echoing a public request parameter. Inline `<script>` blocks that interpolate settings without `wp_json_encode()`. Validation messages that interpolate the submitted value into HTML. Note that `sanitize_text_field()` lets entity-encoded payloads through.

**Detect by:** For any value that comes from a callback, public route, remote response or user meta and is echoed in admin, confirm it is sanitized when stored (`wp_strip_all_tags()` for error text) and escaped at the sink (`esc_html`, `esc_attr`, `esc_url`, `wp_json_encode`). Grep `wpautop(`, concatenated HTML builders, bare `echo $` under `phpcs:disable` blocks, and `$_REQUEST`/`$_GET` inside notices.

---

### Escape every interpolated attribute value, not only the neighbouring ones

**What shipped:** **(security)** A render callback prints a stored value into `value="..."`, `class="..."` or a hidden input without `esc_attr()`, while the `id`/`name` attributes on the same line are escaped. A double quote in the stored value breaks out of the attribute (stored XSS), and a template helper that `printf()`s request data into `<input type="hidden" name="%s" value="%s">` becomes reflected XSS when an unauthenticated AJAX path reaches it. Helpers that return raw stored colors, class lists or framework directive strings for templates to echo have the same flaw.

**Detect by:** Grep templates and render callbacks for `="<?php echo $` and `printf(`/`sprintf(` with `%s` inside attribute quotes, and confirm each value goes through `esc_attr()` (or `esc_url()` for URLs). Check assembled class lists for `sanitize_html_class()` per class plus `esc_attr()` on output. Check helpers that return values meant for attributes, and request indexes printed with `%s` where siblings use `%d`.

---

### Treat DOM-decoded and localized values as raw text in client-side sinks

**What shipped:** **(security)** Server-side escaping does not survive into client sinks that inject HTML. The DOM decodes entities when an attribute or label is read back (`.attr()`, `option.text`, `dataset`), and `wp_localize_script()` decodes HTML entities too, so values that were `esc_html`'d in PHP can execute when they reach Underscore `{{{ }}}`, jQuery `.html()`/`.after()`/`.append()` with concatenated strings, or Vue `v-html`. When server-rendered HTML is compiled as a runtime Vue template (`<component :is="{template}">`, `new Vue({ template })`, `Vue.compile`), `esc_html()`/`wp_kses_post()` do not touch `{{ }}`, so third-party text containing a Vue expression runs in the admin session; fixing only one producer (for example the AJAX refresh) leaves the initial render vulnerable. Partial JS escapers that skip quotes also allow breakout from attributes in linkified captions.

**Detect by:** Grep `{{{` in `tmpl-*` templates, and grep `.html(`, `.after(`, `.append(`, `.before(`, `innerHTML`, `v-html` for values from the DOM, localized data or remote APIs; use text bindings (`.text()`, `v-text`, `{{ }}`) or build elements with `.attr()`/`.text()`. Grep admin JS for `:is="{template`, `template:` built from AJAX/localized HTML, `Vue.compile(`, `new Vue({ template`; trace whether the HTML carries untrusted text and confirm every producer (initial render and AJAX) neutralizes `{{`/`}}` (e.g. `&#123;&#123;`) or wraps the region in `v-pre`. Prefer never compiling server-rendered HTML that contains user text as a template.

---

### Build links with an explicit base URL, escape them for their context, and exit after redirects

**What shipped:** **(security)** `add_query_arg()` / `remove_query_arg()` called without a URL fall back to `$_SERVER['REQUEST_URI']`, so attacker-controlled query text is reflected into action links, filter links keep `paged` and land on an empty out-of-range page, and links re-rendered in an AJAX response point at `admin-ajax.php`. A URL built from session or request data is concatenated into a JS string without escaping (reflected XSS), and a URL escaped only with `esc_url()` inside an inline `onclick="window.open('...')"` breaks out of the string because the HTML parser decodes `&#039;` back to a quote before the JS runs. Separately, guard branches call `wp_safe_redirect()` without `exit`, so execution continues into the code the guard was meant to block.

**Detect by:** Grep `add_query_arg(` / `remove_query_arg(` calls with no URL argument and any URL built from `$_GET['page']` or `REQUEST_URI`; require an explicit base (`admin_url()`, `home_url()`) and `remove_query_arg( array( 'paged', ... ) )` when the link changes the result set. Grep URLs placed in `<script>` blocks or `on*="` attributes that interpolate `esc_url()`/`esc_attr()` output inside a JS string; use `wp_json_encode()`/`esc_js()`, a real `<a href>`, or bound listeners. Grep `wp_redirect(`/`wp_safe_redirect(` not followed by `exit;`.

---

### Encode request data placed in inline scripts with wp_json_encode()

**What shipped:** **(security)** Inline `<script>` blocks build `window.location = "..."` redirects, jQuery `.val('...')` calls or similar from raw `$_GET` values such as a search term or returned token, so a crafted link breaks out of the string and runs script (reflected XSS). Dead copies of such blocks, gated on a condition nothing sets, should still be removed because copied code tends to be live elsewhere.

**Detect by:** Grep `<script>` output and `window.location = "<?php echo` for interpolated `$_GET`/`$_REQUEST`/`$_SERVER` data without `wp_json_encode()` (or `esc_js()` inside a quoted string). Check URLs built with `add_query_arg()` from raw request data use `rawurlencode()` and are output with `esc_url()`. Check `data-*` attributes carrying request values use `esc_attr()`.

---

### Escape shortcode attributes at render time for their output context

**What shipped:** **(security)** A shortcode callback concatenates `$atts['class']` into a `class="..."` attribute and other attributes (messages, labels, format strings) into HTML text, or passes an attribute as the format string to `sprintf()`, with no escaper. Shortcode text is not tag-filtered on save, a single-quoted attribute value can contain a literal `"`, and `shortcode_parse_atts()` runs `stripcslashes()` so `\x3c`-style escapes become real `<` only at render. Any user who can save a shortcode (Contributor) gets stored script execution for visitors or an admin previewing the post.

**Detect by:** For every `add_shortcode()` callback, trace each `$atts[...]` value to the returned string and confirm it passes through `esc_attr()`/`sanitize_html_class()` (attributes), `esc_html()` or `wp_kses_post()` (text), or `esc_url()` (URLs) at the point of output. `wpautop()`, `shortcode_atts()` defaults and save-time kses are not escapers. Flag concatenation like `'<div class="x ' . $class . '">'` and `sprintf( $atts['format'], ... )`. Rate severity by the lowest role that can author shortcodes (Contributor).

---

### Neutralize shortcode syntax in untrusted text that reaches do_shortcode()

**What shipped:** **(security)** A block render callback builds `'[name id="' . esc_attr( $atts['id'] ) . '"]'` and passes it to `do_shortcode()`. `esc_attr()` does not encode `[`, `]` or spaces, so an id containing `]` closes the tag and appends an arbitrary second shortcode. The same applies to user-written or imported text (reviews, titles, author names) rendered inside post content: core runs `do_blocks()` on `the_content` at priority 9 and `do_shortcode()` at priority 11, so a `[shortcode]` planted by an unauthenticated visitor is expanded server-side. Encoding brackets as decimal `&#91;`/`&#93;` is not enough, because `do_shortcode()` finishes with `unescape_invalid_shortcodes()`, which turns exactly those entities back into brackets; hex `&#x5B;`/`&#x5D;` survive.

**Detect by:** Grep `do_shortcode(` whose argument is concatenated or built from block attributes, request data, meta, comments or other user text, and dynamic blocks or filters that print user-supplied text into `the_content`. Flag `esc_attr()`/`esc_html()`/`wp_kses_post()` as the only guard. Require calling the shortcode's PHP renderer directly with typed args (`absint()` ids, `ctype_digit()` validation) or encoding `[`/`]` as hex entities in untrusted text at each sink.

---

### Sanitize every sibling field the way the one sanitized field is

**What shipped:** **(security)** A save routine sanitizes or kses-filters one field but stores its siblings exactly as submitted. An address writer sanitizes `company` but not the other address fields, which list tables or email tags then print unescaped; a rich-text meta field is saved with only `addslashes()`/`wp_slash()` while sibling fields use `wp_kses()`. A role without `unfiltered_html` can store markup or script that runs wherever the field is rendered.

**Detect by:** When one field in a group is passed through a sanitizer, check that its siblings in the same write are too; one sanitized field next to several raw ones is the smell. Grep `update_post_meta(`/`update_option(`/`update_term_meta(` writes of HTML-capable request values for `wp_kses_post()` or `wp_kses( ..., $allowed )`. Confirm every output surface (list tables, email merge tags, PDFs) escapes the fields, with `wp_kses_post()` for intended markup.

---

### Sanitize every persisted field on both the insert and update paths

**What shipped:** **(security)** A model sanitizes a field in `update()` but writes it raw in `insert()`, or a save handler sanitizes only inside a branch gated on a request flag such as `$_POST['is_new']`. A request that omits the flag takes the unsanitized path and stores markup, which an admin or diagnostics screen later echoes unescaped (stored XSS).

**Detect by:** For models or save handlers with separate insert/update (create/edit) paths, list every persisted field and confirm each path sanitizes it. Flag sanitization inside `if ( $_POST['some_flag'] ... )` branches that only some requests take. Sanitize unconditionally right before the setter or DB write, and escape the same field on every admin output, including system-info or debug pages.

---

### Do not print sanitized plain text through wp_kses_post

**What shipped:** **(security)** Text that passed through `sanitize_text_field()` (so markup survives only as entities) is later printed through `wp_kses_post()` or `wp_kses_post( wpautop( ... ) )`. That rebuilds live tags and allows the `style` attribute, so buyer notes, REST-stored event data or author-supplied text gains markup and CSS on admin screens, emails or receipts.

**Detect by:** Grep `wp_kses_post(` in renderers for user-, buyer- or REST-supplied text. Plain-text fields must be printed with `esc_html()`. Fields that really need markup must use `wp_kses()` with a strict allowlist that excludes `style`.

---

### Use wp_kses, not strip_tags() with allowed tags, to sanitize HTML

**What shipped:** **(security)** An API response or template filters stored markup with `strip_tags()` and an allowed-tags list. `strip_tags()` keeps every attribute on allowed tags, so `onmouseover=` handlers and `javascript:` links pass through. A sibling field filtered only by `wpautop()` removes nothing, and rows saved before a newer write-side filter are returned unfiltered because the read path relies on that filter.

**Detect by:** Grep `strip_tags\(\s*[^,()]+,\s*['"]<` and `strip_tags( ..., array(` on markup that is printed or returned to a client and replace with `wp_kses_post()` or `wp_kses()`. Flag fields passed only through `wpautop()` next to filtered siblings, and read paths that depend on a write-side filter for rows that may predate it.

---

### Validate values written into CSS against a CSS grammar and strip tags before a style element

**What shipped:** **(security)** A setting or block attribute is escaped with `esc_attr()`, `esc_js()` or `sanitize_text_field()` and then interpolated into an inline `<style>` block, `wp_add_inline_style()`, or a JS-built stylesheet. Those escapers do not neutralize `}`, `;`, `/*`, `(` or `</style>`, so a value can close the rule and inject arbitrary CSS, or break out of the element. A custom-CSS setting echoed raw inside `<style>` (and again on a debug or system-info screen) lets `</style><script>...` run script for every visitor, even where the saving user lacks `unfiltered_html`; CSS sanitizers and `stripslashes()` do not stop it. Character denylists and `url(` blocklists miss `image-set()`, unclosed brackets and multi-field combinations, and rejected values emitted as empty custom properties defeat their `var()` fallbacks. The same wrong-context mistake appears when `esc_html_e()` output is placed inside a single-quoted JS string instead of `esc_js()`.

**Detect by:** Trace every value that reaches `wp_add_inline_style()`, an inline `<style>`, a `style` element's `textContent`, or a CSS string built by concatenation, including array keys. Require per-type validation (hex color regex, number plus allowed unit, enumerated keywords) or `safecss_filter_attr()` per declaration, and skip the declaration entirely when validation fails. For free-form custom CSS, require `wp_strip_all_tags()` or an explicit rejection of `<`, including on debug and system-info screens that print the same setting. Check PHP and JS copies of the same validator match. Flag `esc_html`/`esc_attr` output inside `<script>` string literals.

---

### Escape the final sprintf() output, not the format string

**What shipped:** **(security)** Output is built as `sprintf( wp_kses_post( __( '...%s...' ) ), $name, $amount )`, so the sanitizer runs over the translatable template only and the substituted values reach the page unescaped.

**Detect by:** Grep `sprintf( wp_kses_post(`, `sprintf( esc_html__(`, `sprintf( esc_html(`, `printf( wp_kses(` whose later arguments are not each escaped. Escape every argument for its context or wrap the whole `sprintf()` result.

---

### Assign the result of array_map() sanitization

**What shipped:** **(security)** A handler calls `array_map( 'sanitize_text_field', $input );` as a bare statement and then keeps using `$input`. `array_map()` returns a new array and does not change its argument, so the raw request data flows on while the code looks sanitized.

**Detect by:** Grep for `array_map(` at statement start whose result is not assigned, returned or passed (`^\s*array_map\(`), and for `array_walk(` callbacks that do not take the value by reference. The sanitized array must be the one used afterwards.

---

### Unslash request data before sanitizing it for storage

**What shipped:** A save handler runs `sanitize_text_field()` on `$_POST` values without `wp_unslash()` first. WordPress adds magic-quote slashes to superglobals, so every apostrophe is stored with a backslash, slashes double on each later save, and output shows `\'`. JSON-escaped unicode (`\u00e9`-style sequences) in the same text is mangled the same way.

**Detect by:** Grep save and AJAX handlers for `sanitize_text_field( $_POST[`, `sanitize_textarea_field( $_POST[`, or a `sanitize_*()` / `json_decode()` call on a value read from `$_POST`/`$_REQUEST` with no `wp_unslash()` (or `stripslashes_deep()`) in between. Flag fixes that add `stripslashes()` to one field instead of unslashing the whole payload once at the entry point.

---

### Escape once at the output sink, not at assignment and again at output

**What shipped:** Escaping is applied early, to a variable or a getter's return value, instead of at the sink. A getter returning `esc_html( get_the_title() )` shows filtered markup as literal tags and stops callers choosing the right escaper. A form value run through `esc_textarea()` on assignment and again on print re-encodes on every save, so the stored markup degrades progressively. A URL passed through `esc_url()` twice corrupts its query args.

**Detect by:** Grep `= esc_(html|attr|textarea|url)(` assignments and `return esc_*(` in getters/helpers whose result is later echoed, especially through another `esc_*`. Escape only at the echo, once, with the sink's escaper (`wp_kses_post()` where markup is intended). For values printed into a re-submitted form, confirm a save/reload cycle round-trips `<b>` and `&amp;` unchanged.

---

### Sanitize every key a settings save merges, not just the current section

**What shipped:** **(security)** A settings save handler sanitizes only the keys of the section being saved, then merges other keys (from another tab or previously stored values) into the output, so raw values supplied for those keys reach output sinks such as inline styles or scripts.

**Detect by:** In `sanitize_callback` / save handlers, compare the keys the sanitize loop iterates with the keys merged into the saved array; trace any unsanitized keys to inline style, script or HTML output.

---

### Give every declared setting type a sanitizer and fail closed otherwise

**What shipped:** **(security)** A settings type is declared in the schema but missing from the type-to-sanitizer map, so its values fall through to a permissive fallback sanitizer, or worse, a dispatcher with no default case saves them with no sanitization at all.

**Detect by:** Diff the list of declared setting types against the sanitizer class map; read the fallback path and confirm unmapped types are rejected or strictly sanitized rather than stored raw.

---

### Allowlist writable columns when updating a row from request data

**What shipped:** **(security)** A handler maps a request array into an ORM or `$wpdb->update()` call with no explicit writable-column allowlist, so a sibling key such as `customer_id`, `type` or `status` re-parents or re-types the row after the id was bound and authorized server-side.

**Detect by:** Trace request arrays into `$wpdb->update()` / model `update()` calls; require an explicit allowlist of writable keys and grep the request keys for parent ids, `id`, `type` and `status`.

---

### Pin unserialize() with allowed_classes instead of a token blocklist

**What shipped:** **(security)** A `maybe_unserialize()` call on untrusted data is guarded by a regex that only rejects the object token `O:`, so a payload using another object-bearing token such as `C:` passes and is deserialized with every class allowed. Blocklists over serialized syntax are always incomplete.

**Detect by:** Grep `unserialize(`/`maybe_unserialize(` on values that can come from requests, cookies, remote responses or user-editable storage. Require `unserialize( $value, array( 'allowed_classes' => false ) )` or a strict class allowlist, or switch to JSON. Flag any guard that inspects the serialized string with a regex or `strpos` instead.

---

### Bound recursion and queue growth when walking decoded input

**What shipped:** **(security)** A helper recurses over `unserialize()` or `json_decode()` output with no depth counter or visited set, so cyclic or very deep input crashes or exhausts memory. An iterative walker that caps the number of nodes processed can still blow up if it pushes children before checking the cap: a short payload of back-references (`a:200:{i:0;R:1;...}`) multiplies the queue first.

**Detect by:** Find recursive or queue-based walkers over decoded or unserialized data; require a depth limit or visited set and a size check before enqueuing children; test with `a:1:{i:0;R:1;}` and a payload of many back-references.

---

### Strip CR/LF from untrusted values passed to wp_mail()

**What shipped:** **(security)** A handler passes a subject built from user- or order-supplied data, or a recipient from a form, straight to `wp_mail()`. Core does not strip newlines from the subject, and the To address is parsed for headers, so a value containing `\r\n` can inject extra headers such as Bcc or Content-Type.

**Detect by:** For every `wp_mail(` call, trace `$to`, `$subject` and `$headers`. When any derive from request, form, order, webhook or other user-influenced data, require `is_email()`/`sanitize_email()` on recipients and `str_replace( array( "\r", "\n" ), ' ', $value )` (or equivalent) on the subject and every header value.

---

### Defang spreadsheet formulas in CSV exports of user-submitted data

**What shipped:** **(security)** Values that originate from a public form are stored verbatim and later exported to CSV. A submitter can enter `=HYPERLINK(...)` or a value starting with `+`, `-` or `@` that runs as a formula when staff open the export in a spreadsheet. Often the plugin already has a defang helper that is not applied on a newer import or export path.

**Detect by:** For every CSV writer (`fputcsv(`, `implode( ',',` building rows, `text/csv` responses), check that each user-derived cell passes through a helper that prefixes `'` when the value starts with `=`, `+`, `-`, `@`, tab or CR. When such a helper exists, grep every export and import path for it.

---

### Escape dynamic strings with preg_quote() before building a regex

**What shipped:** A regex is built by concatenating a variable (an API-supplied name, an editable path segment) straight into the pattern: `preg_match( '/' . $name . '/i', ... )`. A value containing the delimiter or any metacharacter raises 'Unknown modifier' warnings, returns null, or changes what the pattern matches, so a strip/replace acts on the wrong part of the string. Escaping only `/` by hand still leaves other metacharacters live.

**Detect by:** Grep `preg_match(`, `preg_match_all(`, `preg_replace(`, `preg_split(` whose pattern concatenates or interpolates a variable (`'/' . $`, `"/{$`, `'#' . $`). Each interpolated value must go through `preg_quote( $value, '<delimiter>' )` with the pattern's real delimiter; a hand-rolled `str_replace( '/', '\/', ... )` is incomplete. When no pattern semantics are needed, prefer `str_starts_with()`, `explode()` or `substr()`.

---

### Allow the same markup when storing and rendering notices

**What shipped:** A notice utility runs `sanitize_text_field()` on storage and `esc_html()` on render, so intentional HTML in notices (for example a 'reset password' link) is destroyed, or shown as literal tags.

**Detect by:** For message and notice helpers that support links, confirm storage and render use the same `wp_kses()` allowlist, and that no stage strips or escapes all markup.

---

### Do not run wp_kses_post() over output that contains forms

**What shipped:** Shortcode or template output containing `<form>`, `<input>` or `<button>` is passed through `wp_kses_post()`. The post allowlist strips form elements, so the rendered form silently loses its fields.

**Detect by:** Find `wp_kses_post( do_shortcode(` or `wp_kses_post` around template/form HTML; require escaping at the original sinks or a kses allowlist that includes the form tags.

---

### Use str_replace for literal URL rewrites

**What shipped:** A permalink filter rewrites one URL segment with a broad, unanchored `preg_replace`. The pattern also matches pagination segments or fragments, so on `/comment-page-2/#comment-5` it produces a 404 URL.

**Detect by:** Grep `preg_replace(` over URLs or permalinks. If the replacement is literal, use `str_replace`. Otherwise anchor the pattern, and test it against paginated (`/page/2/`, `/comment-page-2/`), query-string and fragment variants.

---

## Secrets and privacy

### Never send stored secrets to the browser

**What shipped:** **(security)** Settings fields holding API secrets, signing keys or OAuth client secrets are registered as plain text inputs, so the full secret is shown on the settings screen and exposed to shoulder-surfing, screenshots, screen-shares and autofill. Variants serialize the stored API key or webhook secret into a JS global via `wp_add_inline_script`/`wp_localize_script`, putting live secrets in the HTML of every admin page load, or return a signing key or internal account identifier in an AJAX JSON response although the client only uses a URL from it. Secrets should be write-only, with only a 'configured' flag sent to the browser.

**Detect by:** In settings registration arrays and `add_settings_field` callbacks, grep for keys matching `secret|token|api_key|signature|password|private_key|client_secret` and check they render `type="password"` or a masked/write-only control; when one secret on a screen is masked, check its siblings. Grep `wp_localize_script`/`wp_add_inline_script`/`wp_json_encode` payloads for the same keys. For every `wp_send_json_*` call or REST response, list the fields returned and confirm each is used by the client and is not a key, HMAC or signing secret, token or credential echoed from settings or a remote API.

---

### Do not commit API client secrets in tracked source

**What shipped:** **(security)** An OAuth token-exchange URL contains a `client_secret` literal in a tracked file, sometimes right next to code that already reads the same secret from a constant. Anyone with repository or package access gets the credential, and rotating it needs a release. Check the same request paths for disabled TLS verification (`CURLOPT_SSL_VERIFYPEER` off, `sslverify => false`).

**Detect by:** Grep diffs for `client_secret=`, `'secret' =>`, `api_key =`, `Bearer ` and long hex/base64 literals (`[a-f0-9]{32,}`) in request URLs or option defaults. Require secrets from constants, environment or options, and require the leaked value to be rotated, not only removed. Flag `sslverify => false` on token requests.

---

### Keep secrets and PII out of logs and error-tracker messages

**What shipped:** **(security)** Calls to an error-reporting helper (`captureMessage`, a logging wrapper, `error_log`) build the message by concatenating customer email, IP, totals and similar values. Trackers group by message, so one signal splits into many issues, and the PII lands in issue titles and server logs where vendor-side scrubbing does not reliably remove it. OAuth connect handlers that log the authorization code or access token to a debug log are worse, since such logs are often web-readable or pasted into support requests. Use a constant message and pass values as structured context, with an id or email domain instead of the address.

**Detect by:** Grep `captureMessage(`, `captureException(`, `error_log(`, `trigger_error(` and logging wrappers whose message concatenates or `sprintf`s variables named `email`, `ip`, `name`, `phone`, `address` or `total`; require a constant message with values as context and no raw email/IP. Flag any debug or log call near OAuth or token-exchange code that interpolates a code, token, secret or API key.

---

### Refuse webhook verification when the signing secret is not configured

**What shipped:** **(security)** A webhook listener computes the expected signature from stored secret settings that return a falsy value when never saved. The empty secret concatenates as an empty string, so on unconfigured sites the expected hash depends only on request-supplied values and any caller can forge a valid signature.

**Detect by:** In webhook and callback signature checks, confirm the secret is checked for non-empty before computing the expected value, and that the handler rejects the request (or does nothing) when it is empty. Prefer `hash_hmac()` keyed with the secret over concatenating it into a hashed string.

---

### Sign tokens and URLs with a server secret, not a hash of public inputs

**What shipped:** **(security)** Expiring download URLs carry a token computed as `md5()` over ids, the customer's own key and the requested expiry. Every input is public or chosen by the requester, so a user can mint valid URLs with any expiry, and `hash_equals()` is comparing a MAC with no key. Generation and validation maintained as separate copies of the formula drift, and a token that signs only a timestamp validates for every form or object.

**Detect by:** Grep `md5(`, `sha1(` and `hash( 'sha256',` whose output is compared with `hash_equals()` or `===` against a request parameter. Require `hash_hmac()` keyed with `wp_salt()` or a stored secret, with the expiry, target object and every authorizing field inside the signed payload, and one shared helper for generation and validation.

---

### Authenticate encrypted bearer tokens with a MAC or AEAD

**What shipped:** **(security)** A login-free link encodes a numeric id with a non-authenticated cipher mode such as AES-CBC and no MAC. CBC decryption is malleable: the first plaintext block depends directly on the IV, so with a predictable plaintext anyone holding one valid token can edit the IV to decrypt to a different id without the key. Variants accept any payload that decrypts, do not bind the token to the object it was minted for, or "confirm" the decrypted id against another value from the same request, which adds no verification.

**Detect by:** Grep `openssl_encrypt`/`openssl_decrypt` with `-cbc`, `-ctr`, `-cfb` or `-ofb` used to mint tokens later trusted for access. Require AES-GCM or `sodium_crypto_secretbox`, or an HMAC over IV and ciphertext checked with `hash_equals()` before decryption, with the target object id and expiry inside the authenticated payload. Flag handlers that compare a decrypted value with a second request value or cookie instead of a server-side record.

---

### Store secrets and rarely read options with autoload off

**What shipped:** **(security)** API keys, tokens and status payloads are saved with `update_option()` without the `$autoload` argument, so they are autoloaded on every request and exposed to anything that dumps `wp_load_alloptions()`. Each bundled copy of a library adds more.

**Detect by:** Grep `update_option(`/`add_option(` whose name contains `key`, `token`, `secret`, `password` or `credentials`, or that stores a large rarely read blob, and require `false` as the autoload argument. Note `update_option()` only applies `$autoload` when the option is created or its value changes, so existing installs need a migration.

---

### Remove a per-message mail filter after the send that added it

**What shipped:** **(security)** A notification adds an anonymous closure to an email-headers filter to set `Reply-To` to one customer's address and never removes it. When several deferred sends run in one request (a queued job batch), every later email, including other customers' messages, carries the first customer's address, leaking it and misrouting replies.

**Detect by:** Grep `add_filter(` on `wp_mail`, `wp_mail_from`, `wp_mail_from_name`, `wp_mail_content_type`, `phpmailer_init` or plugin email-header filters inside a send or render method. Each must be paired with `remove_filter()` of the same named callable (not an inline closure) in a `finally` or immediately after the send. Batched cron or queue runners make the leak cross-user.

---

### Validate salt strength before deriving identifiers or keys from salts

**What shipped:** **(security)** An integration derives a stable site identifier from `AUTH_KEY`/`SECURE_AUTH_KEY` and encrypts a shared secret with `NONCE_KEY`/`NONCE_SALT`. On sites with default, empty or duplicated salts, the identifier is predictable, which is enough to recover the secret from an unauthenticated registration endpoint.

**Detect by:** Flag code that derives identifiers, encryption keys or HMAC keys from WordPress salts without checking that each salt is defined, non-empty, not the `put your unique phrase here` placeholder, long enough, and distinct. Prefer a random value generated with `random_bytes()` and stored once.

---

### Detect and recover when salt-derived encryption keys change

**What shipped:** **(security)** A shared secret is stored encrypted with a key derived from site salts, with no way to detect a later salt rotation. After rotation the value cannot be decrypted and every webhook signature check fails.

**Detect by:** When credentials are encrypted with salt-derived keys, look for a key fingerprint or canary check and a recovery path (re-fetch or re-register, then re-encrypt). Decrypt-or-throw with no recovery means a salt change silently breaks the integration.

---

### Map every custom status into the privacy exporter and eraser

**What shipped:** **(security)** A new custom order or record status is registered but never added to the status-to-action map used by the personal-data eraser, so it falls through to a default of "do nothing". The eraser cannot anonymize those records, the erasure request aborts, and the customer can never be deleted.

**Detect by:** When a diff registers a new status, grep for every `switch`/map over statuses (privacy eraser and exporter callbacks registered via `wp_privacy_personal_data_erasers` / `wp_privacy_personal_data_exporters`, status lists for settings UIs, reports) and confirm the new status has an explicit entry rather than relying on the default branch.

---

### Clear OAuth tokens from the URL fragment immediately

**What shipped:** **(security)** An OAuth flow returns access and refresh tokens in `location.hash`. The handler script parses the fragment and clears it only after other setup, and not at all when expected params are missing, so other scripts on the page, browser extensions and the history entry can read live tokens.

**Detect by:** Grep JS for `location.hash` parsing of `access_token`, `refresh_token` or `code`. The handler should load early with no dependencies, copy the fragment and call `history.replaceState( null, '', location.pathname + location.search )` as its first statement on every path, including errors. Prefer a server-side code exchange over tokens in the URL.

---

### Gate telemetry recording on the opt-in, not only the send

**What shipped:** **(security)** Usage-tracking code checks the opt-in only before sending, while events, active-day counters or session metrics are recorded on admin hooks, and the tracking script is enqueued, on every site including those that never opted in. A check-in success or cron handler may also unconditionally re-set the 'enabled' flag, reversing a later opt-out. This collects data without consent and breaks WordPress.org guidelines.

**Detect by:** In every telemetry entry point (admin hooks, AJAX recorders, enqueue callbacks, cron senders), confirm the opt-in check runs before the first `update_option`, counter increment, `wp_enqueue_script` or `wp_remote_post()`. Flag code that writes enabled/opt-in state from a remote response or cron callback.

---

## Files and paths

### Reduce every request-derived path component to one safe segment before file operations

**What shipped:** **(security)** A handler composes a file or directory path from request, meta or remote values, sanitizing some components with `sanitize_file_name()` but others only with `sanitize_text_field()`, which keeps `../`, `/`, `*` and `?`. The composed path reaches `fopen( ..., 'w' )`, `unlink()`, `glob()` or `include`, so a low-privilege user can write, delete or wildcard-delete files outside the intended directory, or include an arbitrary PHP file (local file inclusion) when a slug from stored or remote data picks a template. A filter applied to the composed name is not re-validated after it runs.

**Detect by:** For every `fopen(`, `file_put_contents(`, `unlink(`, `wp_delete_file(`, `glob(`, `rename(`, `copy(`, `ZipArchive::open(`/`extractTo(` and `include`/`require` with a variable path, trace each component back to `$_GET`/`$_POST`/REST params, meta, remote data or `apply_filters()`. Require each component reduced to a single segment (`sanitize_file_name()`, `wp_basename()`, reject `..`) after any filter, slugs matched against an allowlist pattern such as `^[a-z][a-z0-9_-]*$` plus `file_exists()`, and the final path checked with a `realpath()` prefix test against the base directory. Prefer resolving the name from a stored record over the request.

---

### Validate uploads by extension and content, and contain import paths

**What shipped:** **(security)** An upload handler trusts the client's `$_FILES[...]['type']`, then `move_uploaded_file()`s the file under its original extension into a web-accessible directory, so a privileged-but-not-admin user can upload PHP. A later import step accepts the stored file path back from the request and checks only that it exists. Multi-extension names (`shell.php.csv`) are not normalized.

**Detect by:** Grep `move_uploaded_file(` and `$_FILES[...]['type']`. Prefer `wp_handle_upload()` with `wp_check_filetype_and_ext()` and a strict extension allowlist. For any file path received from the request, reject `..`, resolve it with `realpath()` and require it to sit under the plugin's upload directory. Store the file outside the web root or behind deny rules, and fold inner extensions with `sanitize_file_name()`.

---

### Add a trailing separator to directory-prefix containment checks

**What shipped:** **(security)** A check deciding whether a file lives in a directory uses `0 === strpos( $file_dir, $dir )` with neither side ending in `/`. `/plugins/foo` then matches `/plugins/foo-addon/...`, misclassifying files in sibling directories. In a security check the same flaw lets `/uploads/safe-evil` pass a containment test for `/uploads/safe`.

**Detect by:** Grep `strpos( $path, $dir ) === 0`, `str_starts_with(`, and `substr( $path, 0, strlen( $dir ) )` comparisons where `$dir` is not `trailingslashit()`-ed or suffixed with `DIRECTORY_SEPARATOR`, and, for security checks, where neither side is `realpath()`/`wp_normalize_path()`-resolved first.

---

### Stage private working files in a random, restricted, cleaned-up directory

**What shipped:** **(security)** A routine downloading or generating private files (archives, exports, audit logs containing emails) stages them in a fixed, guessable subdirectory of `wp_upload_dir()` with no deny rules, so they are web-fetchable, and failure paths leave them behind. Moving to the system temp dir under a fixed shared parent, or a hardcoded `/tmp/` path, is still unsafe: another system user can pre-create or symlink that parent and `wp_mkdir_p()` accepts it as existing; `wp_mkdir_p()` also copies the parent's (world-writable) permissions; and hosts with `open_basedir` or no writable `/tmp` fail outright.

**Detect by:** Grep `wp_upload_dir(`, `get_temp_dir()`, `sys_get_temp_dir()` and literal `/tmp/` near `mkdir(`, `wp_mkdir_p(`, `extractTo(`, `fopen(`, `file_put_contents(`. Flag private data under uploads without protection files or an unguessable name, fixed-name temp parents, `wp_mkdir_p()` followed by `chmod()` instead of `mkdir( $dir, 0700 )`, and cleanup that is not on every exit path (no `try`/`finally`, early `return` before removal). Prefer `wp_tempnam()` or a random per-run directory.

---

### Deny script execution in plugin-writable upload directories, not just listing

**What shipped:** **(security)** A plugin cache directory under `uploads/` that stores files fetched from remote URLs is protected only by an `.htaccess` containing `Options -Indexes`. That blocks directory listing but not direct requests or script execution, so any `.php` file that lands there runs under Apache. The fetch also follows the HTTP API's default number of redirects.

**Detect by:** Grep code that writes `.htaccess`/`index.php` into a directory created under `wp_upload_dir()`. Confirm the rules deny script execution (a `FilesMatch` deny for `php|phtml|phar`, or `Require all denied` for private files), and that existing installs rewrite the file on upgrade. For remote fetches that fill such directories, check `wp_remote_get()` sets a low explicit `redirection` and validates file type before writing.

---

### Check the result of file writes, DDL and installs before recording success

**What shipped:** `file_put_contents()` is called without checking for `false`, so a failed write is treated as success; an upgrade routine marks itself done even though its `ALTER TABLE` failed, so it never retries. A plugin-installer handler deletes onboarding transients and writes an 'activated' option before checking whether the install succeeded, leaving state that claims a plugin is active when it is not.

**Detect by:** Grep `file_put_contents(`, `fwrite(`, `copy(`, `rename(` and `$wpdb->query( "ALTER|CREATE` whose return is discarded before reporting success or marking an upgrade complete; require `false !==` checks and `$wpdb->last_error`. In install/activate handlers, confirm `update_option`/`delete_transient`/`set_transient` calls after `Plugin_Upgrader::install()` or `activate_plugin()` sit inside the success branch (`! is_wp_error( $result )`, `is_plugin_active()`).

---

### Lowercase file extensions before comparing them to an allowlist

**What shipped:** An upload validator takes the extension with `pathinfo( $name, PATHINFO_EXTENSION )` and compares it case-sensitively to a lowercase allowlist, so `.JPG` uploads of allowed types are rejected. With an exact-match blocklist the same mistake lets `.PHP`-style variants through.

**Detect by:** In `upload_mimes`, `wp_check_filetype_and_ext` and `wp_handle_upload_prefilter` callbacks and custom validators, grep for `PATHINFO_EXTENSION` / `strrchr(` results used in `in_array()`, `isset( $map[ $ext ] )` or `===` without `strtolower()`, and extension regexes without the `i` flag.

---

### Use the host's file mode instead of a hardcoded octal on created files

**What shipped:** **(security)** Writers that create log, export or cache files call `chmod( $file, 0664 )` with a literal mode, granting group-write and world-read on every host regardless of its configuration. Files holding customer data become readable by other accounts on shared hosting.

**Detect by:** Grep for literal octal modes (`0664`, `0666`, `0777`, `0644`) passed to `chmod()`, `mkdir()` or `WP_Filesystem` writes; require `FS_CHMOD_FILE` / `FS_CHMOD_DIR` (ideally through one shared helper) instead.

---

### Anchor require/include paths to __DIR__ or a plugin-dir constant

**What shipped:** A partial is loaded with a bare relative path (`require 'partial.php'`). PHP resolves it against `include_path` and the current working directory, not the including file, so in REST, cron, WP-CLI or alongside another plugin's `include_path` it loads the wrong file or fatals.

**Detect by:** Grep `require`/`include`/`require_once`/`include_once` whose argument is a string literal not starting with `__DIR__`, `dirname( __FILE__ )` or a plugin path constant.

---

### Check WP_Filesystem() before using $wp_filesystem

**What shipped:** A handler calls `WP_Filesystem();` and then `$wp_filesystem->put_contents()` unconditionally. When credentials are required (FTP/SSH method) or initialization fails, `WP_Filesystem()` returns false and `$wp_filesystem` is unusable, so the write fatals with `Call to a member function on null`.

**Detect by:** Grep `WP_Filesystem(` and confirm its return is checked (`if ( ! WP_Filesystem() ) { return; }`) and `$wp_filesystem` is non-null before `->put_contents`/`->get_contents`/`->mkdir`. In AJAX/REST contexts where no credentials form can render, require `request_filesystem_credentials()` handling or a direct-method fallback.

---

### Make path checks and path-to-URL conversion work on Windows

**What shipped:** `validate_file()` is used as a yes/no safety check on a plugin-built absolute path; on Windows a drive-letter path returns `2`, so `0 === validate_file()` fails and the screen breaks on every Windows host. Separately, `str_replace( WP_CONTENT_DIR, WP_CONTENT_URL, $path )` never matches when the path uses backslashes, producing a broken URL.

**Detect by:** Grep `validate_file(` and check that the caller only needs traversal rejection and handles return code `2`. Grep `str_replace(` or comparisons involving `WP_CONTENT_DIR`, `ABSPATH` or `WP_PLUGIN_DIR`; require `wp_normalize_path()` on both sides, or `plugins_url()`/`content_url()`.

---

### Derive asset URLs with plugins_url() or content_url(), not DOCUMENT_ROOT

**What shipped:** A bundled library computes its asset URL by stripping `realpath( $_SERVER['DOCUMENT_ROOT'] )` from its directory and prefixing scheme plus `HTTP_HOST`. Under `open_basedir`, `realpath()` returns `false`, nothing is stripped, and the absolute server path is embedded in enqueued CSS/JS URLs. The approach also breaks on symlinked, subdirectory and reverse-proxied installs.

**Detect by:** Grep `$_SERVER['DOCUMENT_ROOT']`, `$_SERVER['HTTP_HOST']`, `realpath(` and hand-built `"$protocol://$host/"` strings used for URLs. Require `plugins_url()`, `plugin_dir_url()`, `get_theme_file_uri()` or `content_url()` with `wp_normalize_path()` relative to `WP_CONTENT_DIR`. Flag `str_replace( realpath( ... ), ... )` with no `false` check.

---

### Pass a filesystem path, not a URL, to wp_insert_attachment()

**What shipped:** An upload helper calls `wp_insert_attachment( $attachment, $upload['url'] )`. The second parameter is an absolute filesystem path stored as `_wp_attached_file`; with a URL there, `get_attached_file()` resolves to a nonsense path, so `wp_delete_attachment()` removes the row but leaves the file on disk (breaking privacy erasure) and image size lookups fail.

**Detect by:** Grep `wp_insert_attachment(` and confirm the second argument is the `['file']` path from `wp_handle_upload()`/`media_handle_upload()` or `get_attached_file()`, never `['url']` or a `wp_get_attachment_url()` result. Apply the same check to `update_attached_file()` and direct `_wp_attached_file` meta writes, and look for a repair routine for rows already stored.

---

### Do not use a same-domain check as proof that a value is a local file path

**What shipped:** A file-delivery routine decides a stored value is a local path because its host matches the site's domain. A same-domain URL that is not a file (a REST endpoint, rewrite route or signed proxy) is then passed to filesystem functions, producing warnings or wrong behaviour.

**Detect by:** Grep helpers like `is_local_*`/`is_internal_*` that decide by host comparison. Anything that then calls `filesize()`, `file_exists()`, `realpath()` or `readfile()` must map the URL to a path under an allowed directory and confirm the path exists, not just that the domain matches.

---

## SQL and database

### Bind values through $wpdb->prepare() placeholders, never interpolation or sanitizers

**What shipped:** **(security)** A query builder interpolates stored or request values into `WHERE`, `IN()` or `LIKE` strings, sometimes after `sanitize_text_field()` and hand-written quotes, and the result is passed to `$wpdb->prepare()` with no bind arguments (or only `LIMIT` bound), so nothing is parameterized and second-order SQL injection is possible. `sanitize_text_field()`, `sanitize_key()` and `esc_sql()` do not make interpolation safe: the first keeps quotes and comment tokens, and `esc_sql()` does nothing in unquoted numeric context. Variants: the count query reuses the same `WHERE` without `prepare()`; a `DELETE ... WHERE id IN ($ids)` is "fixed" by dropping `prepare()`; a misplaced parenthesis passes the bind value to `$wpdb->query()` so `%s` is never substituted. Values decoded with `parse_str()` from a POSTed string bypass WordPress's slashing, so double-encoded quotes arrive live.

**Detect by:** Grep `$wpdb->prepare(` calls with a single argument or a query string built by concatenation, and query builders for `"'" . sanitize_`, `'{$`, `IN( {$`, `LIKE CONCAT(` and `implode(` outside `prepare()`. Check every `$wpdb->query/get_*` call wraps user or stored values in placeholders, including the count query. Fix in the shared builder: `implode( ', ', array_fill( 0, count( $values ), '%s' ) )` for IN lists, `%d` with `array_map( 'intval', ... )`, and `$wpdb->esc_like()` for LIKE. Verify parentheses put the arguments inside `prepare()`. Grep `parse_str( $_POST[` and `parse_str( $_REQUEST[` and treat results as unslashed raw input.

---

### Allowlist ORDER BY direction and identifiers instead of escaping them

**What shipped:** **(security)** A query builder passes a sort direction or column name from request or options input through `esc_sql()` and interpolates it into `ORDER BY`. `esc_sql()` only escapes quotes, and a keyword or identifier position needs no quote to break out, so the value can inject SQL.

**Detect by:** Grep for `esc_sql()` on values placed in `ORDER BY`, `ASC`/`DESC`, column or table positions; require a strict allowlist such as `'ASC' === strtoupper( $order ) ? 'ASC' : 'DESC'` and `in_array( $orderby, $allowed_columns, true )`.

---

### Bail on an empty key or id before using it as a lookup filter

**What shipped:** **(security)** A lookup filters by an identifier that can be empty, and the empty value matches rows it should not. An unauthenticated endpoint looks up a record by a request key with no non-empty check, so `WHERE key_column = '' LIMIT 1` matches a row with an empty key and returns that customer's name, email and order id. A privacy eraser resolves an email to a customer record and queries orders and logs by `customer_id => $customer->id`; for an email with no record the id is `0`, which matches every guest row, so erasing one commenter's data anonymizes or deletes every guest order and log.

**Detect by:** Grep by-key lookups reachable from unauthenticated handlers (`get_row( ... WHERE ... = %s )`, `get_by( 'key', ... )`) and require `is_scalar()` plus a non-empty, trimmed check before querying. Where an id resolved from a lookup (`get_user_by()`, a get-by-email helper, `url_to_postid()`, `absint( $_REQUEST[...] )`) is used as an equality filter (`'user_id' =>`, `'post_parent' =>`, `WHERE x_id = %d`) in a bulk read, update, delete or erase, confirm an `empty( $id )` bail precedes it; `0` means unassigned, not 'no filter'. Pay special attention to `wp_privacy_personal_data_erasers` and `_exporters` callbacks.

---

### Gate schema checks and DDL on a stored version, not a per-request probe

**What shipped:** On every request a plugin probes its tables or columns (`SHOW TABLES LIKE`, `INFORMATION_SCHEMA.COLUMNS`, `DESCRIBE`) in constructors or early hooks, which is slow on databases with thousands of tables, and runs `CREATE TABLE`/`ALTER TABLE` inline when the result is empty. During a database problem (lock-wait timeout, full disk, an empty result with only a warning) the probe fails, DDL runs from a front-end request, and its table lock stalls every later request. Memoizing the probe with `wp_cache_*` does not help without a persistent object cache, and caching only the positive result re-queries on every miss. A one-time migration hooked to `admin_init` that is never marked complete on fresh installs or when there is nothing to migrate runs its unbounded query forever, and activation routines called from bootstrap instead of `register_activation_hook()` repeat on every load.

**Detect by:** Grep constructors and `init`/`plugins_loaded`/`admin_init` callbacks for `SHOW TABLES LIKE`, `table_exists(`, `information_schema`, `dbDelta(`, `CREATE TABLE`, `ALTER TABLE`, `maybe_create_table()` and unbounded `get_posts()`. Require gating on a stored version option (`version_compare( get_option( 'my_plugin_db_version' ), X, '<' )`) run from a versioned upgrade routine. Confirm any lookup checks `$wpdb->last_error` before treating no rows as absent. Confirm fresh installs mark migrations complete and each migration marks itself complete on the nothing-to-do path. Flag `wp_cache_*` memos around install probes without a `wp_using_ext_object_cache()` check, and activation routines called outside the activation hook.

---

### Delete or update dependent records with their parent

**What shipped:** Deleting a parent record leaves child rows behind: log rows for a deleted item, entitlement records created by a deleted payment, or rows still active after the parent is trashed (a status change, not a delete). A cleanup job that runs a direct `DELETE` on parent rows and skips the repository delete also orphans personal-data child rows (IP addresses, queued emails) that the privacy exporter and eraser can no longer reach.

**Detect by:** For each delete or trash path on a primary record, grep the schema for tables with a foreign key to it (`parent_id`, `order_id`, `item_id`) and confirm each is deleted, cascaded, or updated. Treat trash and status changes as lifecycle events too. Flag raw `DELETE` statements that bypass the model's delete method, and check whether the orphaned rows hold personal data registered with `wp_privacy_personal_data_exporters`.

---

### Scope user and post queries in SQL instead of loading everything and filtering in PHP

**What shipped:** Code needing a small subset or a yes/no answer loads the whole collection and filters in a PHP loop: `get_users( [ 'fields' => 'all_with_meta' ] )` or `'number' => -1` with no role or meta constraint exhausts memory on sites with tens of thousands of users; a has-purchased check loads every order of a customer and walks their items, issuing thousands of queries on one page; each submitted id is validated with its own `get_post()` instead of one `post__in` query.

**Detect by:** Grep `get_users(`, `get_posts(`, `WP_Query`, `WP_User_Query` and plugin collection helpers with no `role__in`/`meta_query`/`number`/`posts_per_page` limit (or `-1`), especially with `fields => 'all_with_meta'`, followed by a `foreach` that filters or returns on the first match, and per-id `get_post()`/`get_user_by()` inside loops. Existence checks should be bounded (`number => 1`, `fields => 'ids'`); subsets should be expressed in query args or SQL.

---

### Read $wpdb->last_error immediately after the query it describes

**What shipped:** Code writes a row with `$wpdb->insert()`/`update()`, then fires actions or cascades that run more queries, and only then reads `$wpdb->last_error`. `wpdb::query()` clears `last_error` before every query, so the write's error is gone and failed writes are reported as successes.

**Detect by:** Grep `->last_error` and check it is read directly after the `$wpdb->insert/update/replace/query` it reports on. Flag any `do_action()`, `apply_filters()`, model `save()` or other `$wpdb` call between the write and the read, and reliance on a wrapper that itself runs more queries.

---

### Quote schema identifiers that are reserved words in newer MySQL

**What shipped:** A custom table's `CREATE TABLE`/`dbDelta()` schema uses bare column identifiers, and one of them (for example `manual`) became a reserved keyword in a newer MySQL release. Table creation fails with a 1064 syntax error, activation continues silently, and every later query against the missing table fails.

**Detect by:** In schema strings for `dbDelta()`, `CREATE TABLE`, `ALTER TABLE` and index definitions, check every column and key name against current MySQL 8.x and MariaDB reserved-word lists (`manual`, `rank`, `groups`, `window`, `function`, `system`, `lead`, `order`, `key`). Prefer backtick-quoting identifiers, and bump the table version so existing installs re-run the schema.

---

### Create custom tables with $wpdb->get_charset_collate(), not a hardcoded charset

**What shipped:** A `CREATE TABLE` hardcodes `DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci`. Three-byte utf8 cannot store emoji and some CJK characters, so those inserts fail or truncate, and the collation differs from core tables, which breaks joins and index use. Changing it later needs an explicit `ALTER TABLE ... CONVERT TO` migration for existing installs.

**Detect by:** Grep `CREATE TABLE` in install and upgrade code for a literal `CHARACTER SET`, `CHARSET=`, `utf8_general_ci` or `utf8 ` without `$wpdb->get_charset_collate()`. When an existing table's charset changes, require an upgrade routine that converts installed tables.

---

### Use %i or an allowlist for SQL identifiers, not prepare() %s

**What shipped:** A query builds `SUM(%s)` or `ORDER BY %s` with `$wpdb->prepare()` and a column name. `%s` emits a quoted string, so MySQL aggregates or sorts by the literal `'total'` and the result is 0 or unordered. Stripping quotes afterwards is a hack; use `%i` (WP 6.2+) or an allowlisted column.

**Detect by:** Grep `prepare(` format strings with `%s` in an identifier position: inside `SUM(`/`AVG(`/`COUNT(`/`MAX(`, after `ORDER BY`/`GROUP BY`, or as a table/column name. Require `%i` or a strict allowlist interpolated directly.

---

### Single-quote SQL string literals so they survive ANSI_QUOTES

**What shipped:** A query such as `SHOW TABLES LIKE "wp_table"` uses double quotes around a value. With `sql_mode` including `ANSI_QUOTES`, double quotes delimit identifiers, so the query is a syntax error and the plugin concludes its table is missing on every load.

**Detect by:** Grep `$wpdb->query|get_var|get_results|get_row|get_col(` arguments for `"` around values (`LIKE "`, `= "`). String literals must be single-quoted or, better, passed through `$wpdb->prepare( '... %s', $value )`; identifiers use backticks.

---

### Get a new row's id from the insert, not by querying the newest row

**What shipped:** After a row is inserted (often by another component), a handler finds 'its' row by querying the newest row in the table (`ORDER BY id DESC LIMIT 1`) with no constraint on the owner or object, then writes meta to it and passes its id to hooks. A concurrent insert wins the query, so data is stamped on another user's row.

**Detect by:** Grep `'orderby' => 'id'` with `'order' => 'DESC'` and `'number' => 1`, or `ORDER BY id DESC LIMIT 1`, used right after an insert or after a hook that triggers one. The id must come from the insert's return value, `$wpdb->insert_id`, or an `*_inserted`/`*_added` hook that passes it.

---

### Count distinct users, not usermeta rows

**What shipped:** `wp_usermeta` has no unique constraint on `(user_id, meta_key)`, so a user can hold two capabilities rows. `get_users( [ 'role' => 'administrator' ] )` adds `DISTINCT` only for OR meta relations, so a single-role query can return the same user once per matching row. A safety threshold counting the result over-counts, an index built from it stores duplicates, and a direct `SELECT meta_value ... LIMIT 1` picks an arbitrary row.

**Detect by:** Grep `count( get_users(`, `COUNT(*)`/`COUNT(user_id)` over `{$wpdb->usermeta}`, and lists from `get_users( [ 'role' => ... ] )` used for thresholds, limits or indexes. Deduplicate by ID (`array_unique( wp_list_pluck( $users, 'ID' ) )`, `COUNT(DISTINCT user_id)`). Direct usermeta reads with `LIMIT 1` need `ORDER BY umeta_id`.

---

### Select distinct terms, not one row per term assignment, for a term list

**What shipped:** A screen builds a taxonomy dropdown with `SELECT t.*, tt.*, tr.object_id` joined through `term_relationships`, loading a full term row per post-term assignment and deduplicating in PHP. On sites with many assignments, simply opening the screen exhausts memory.

**Detect by:** Grep raw SQL joining `term_relationships` that selects `t.*`/`tt.*` or lacks `DISTINCT`/`GROUP BY t.term_id` when the caller needs a term list. Prefer `get_terms( [ 'taxonomy' => ..., 'fields' => 'id=>name' ] )` or select only the needed columns with `DISTINCT`. Flag `array_unique()` or keyed dedupe loops right after such a query.

---

### Account for NULL in NOT IN catch-all buckets

**What shipped:** A report buckets rows with `CASE WHEN col IN (...)` and an 'other' bucket with `col NOT IN (...)`. Rows with NULL from a LEFT JOIN evaluate `NULL NOT IN (...)` to NULL, so they fall out of every bucket and bucket sums no longer match the total.

**Detect by:** Grep SQL for `NOT IN (`, `<>` and `!=` on columns that can be NULL (LEFT JOIN columns, optional meta values). Require `col IS NULL OR col NOT IN (...)` or `COALESCE()`. Also flag `NOT IN ( SELECT ... )` subqueries whose result can contain NULL, which makes the predicate never true.

---

### Treat MySQL's zero datetime as empty

**What shipped:** A `datetime` column written with an empty string through `$wpdb->insert()` is stored as `'0000-00-00 00:00:00'`. Read code that uses `empty()` or `! $date` to mean 'not set' treats it as a real date, so APIs return a zero date where the schema says `null` and status and date contradict each other.

**Detect by:** Grep reads of `datetime` columns guarded only by `empty(`, `isset(` or `?:`; require an explicit `'0000-00-00 00:00:00' ===` check or helper. Check write paths that pass `''` for a datetime column through `$wpdb->insert`/`update`.

---

### Wrap meta_query clauses in an outer array

**What shipped:** A query passes `'meta_query' => array( 'key' => ..., 'value' => ... )` with no inner array. `WP_Meta_Query` expects a list of clause arrays plus an optional `relation`, so it ignores the flat keys and the query returns every row unfiltered.

**Detect by:** Grep `'meta_query'\s*=>\s*array\(` and check the next token: `'key'`, `'value'` or `'compare'` instead of `array(` or `'relation'` means a flat, ignored clause. Apply the same check to `tax_query` and `date_query`.

---

### Do not use = or IN meta_query compares on serialized array values

**What shipped:** A `meta_query` matches a key whose value is stored as a serialized array using `=` or `IN`, which never matches. The stored shape needs a `LIKE` on the serialized token, or one meta row per value.

**Detect by:** For each new `meta_query` clause, check how the key is written (`update_post_meta`/`add_metadata` with an array value serializes it). If serialized, flag `=`/`IN` compares and require `LIKE` with a quoted token or normalized storage.

---

### Use query argument keys the query class actually supports

**What shipped:** A report passes `start`/`end` keys to a query helper whose class only understands a `date_query`-style argument. Unknown keys are dropped silently, so the date filter is ignored and totals cover all time.

**Detect by:** For every argument array passed to a query wrapper (`WP_Query`, `get_posts`, a plugin's own query class), check each key against the class's declared defaults or documented arguments. Pay special attention to date-range keys (`start`, `end`, `date_from`) versus `date_query`. Add a test that asserts a date-filtered count differs from the unfiltered count.

---

### Check how a custom query layer treats number => -1

**What shipped:** Callers pass `'number' => -1` to a custom-table query class expecting `WP_Query`-style 'no limit'. The query layer runs `number` through `absint()`, so `-1` becomes `1` and exports or listings return only the first row.

**Detect by:** Grep `'number' => -1` and `'limit' => -1` passed to anything other than `WP_Query`/`get_posts()` (custom query classes, table helpers). Check how the callee sanitizes the limit (`absint()`, `intval()`, `max( 1, ... )`); if it does not special-case `-1`, the call is capped. Also check `posts_per_page => -1` translated into a custom layer.

---

### Pass an explicit limit or batch loop to query wrappers in bulk operations

**What shipped:** A bulk operation or migration fetches rows through a query wrapper with a default `number` (often 20) and passes no limit, so only the first page is processed. `get_sites()` returns at most 100 sites by default, so a network migration leaves larger networks half-migrated without error.

**Detect by:** In bulk, migration, network-activation, uninstall and cron code, find `get_sites(`, `get_terms(`, `get_comments(`, `WP_Query` and custom query wrappers called without `number`/`posts_per_page`. Check the default and require an explicit unlimited value or a batched loop that runs until a short page is returned.

---

### Compute the query offset as (page - 1) * per_page

**What shipped:** A paged query computes its offset as `page * per_page`, so page 1 skips the first page of results and the last page comes back empty.

**Detect by:** For any `'offset' =>` or `LIMIT x, y` built from a page number, confirm it uses `( max( 1, absint( $paged ) ) - 1 ) * $per_page`.

---

### Page a batch cursor on a unique key, not a bare timestamp

**What shipped:** A resumable batch job pages with `WHERE created > :cursor ORDER BY created LIMIT n`. Rows sharing the boundary timestamp (bulk imports, records created in the same second) straddle the page break and the strict `>` skips them, so they are never processed.

**Detect by:** Grep batch, CLI and cron loops for a cursor on a single non-unique column (`post_date`, `created_at`, `date_modified`) compared with `>`/`<` and ordered by that column only. Require a composite `(ts, id)` cursor with `ORDER BY ts, id` and `WHERE ts > :ts OR (ts = :ts AND id > :id)`, or a primary-key cursor.

---

### Bound fetch-then-filter paging loops

**What shipped:** A loop fetches batches, filters them in PHP, and keeps paging while it has fewer results than wanted. When the filter removes every row, the loop pages through the whole table on every request.

**Detect by:** Find `while`/`do...while` loops that page `get_posts()` or queries and filter afterwards; require a maximum-batch bound and an exit when the raw batch is shorter than the page size.

---

### Unserialize imported values before saving them through meta APIs

**What shipped:** An import passes already-serialized strings from a database dump to `update_user_meta()`/`update_post_meta()`, which serialize again, producing double-serialized and unreadable meta.

**Detect by:** In import and migration code that reads raw dump values, confirm `maybe_unserialize()` runs before any `update_*_meta()` or `update_option()` call.

---

### Mark search columns as searchable in the query layer

**What shipped:** An admin list-table search for a partial key returns nothing because the column is not marked searchable in the query class's schema, and the search arguments are built in a legacy class while a different class runs the query.

**Detect by:** When a list-table search passes through a query class with a schema, confirm the searched columns are flagged searchable (or included in `search_columns`). Flag search-argument code that lives in a different class from the one that executes the query.

---

### Keep custom meta types consistent with the registered meta table and id column

**What shipped:** A custom-table meta wrapper calls `get_metadata()`/`update_metadata()` with a meta type string. WordPress resolves `$wpdb->{$type}meta` and the `{$type}_id` column from that string, so after the table is re-registered under a different name or its id column is renamed, the calls find no table and return `false` without running a query; every meta read and write silently no-ops. Changing the type string also renames every `{$meta_type}` metadata hook other code listens on.

**Detect by:** Grep `(get|add|update|delete)_metadata( '` with a non-core meta type. Confirm `$wpdb->{type}meta` is assigned at load and the table's object-id column is `{type}_id`. Flag a table rename or removed `$wpdb->...meta =` registration in the diff without a matching type-string change, and require a write-then-read round-trip test.

---

### Do not declare a column unsigned when writers can store negative values

**What shipped:** A line-items or ledger table declares `quantity` or `amount` as `bigint unsigned`, but refunds, credits or reversals store negated values. MySQL clamps them to 0 (or errors in strict mode) and those records lose their values.

**Detect by:** In `CREATE TABLE`/`dbDelta` schemas and data-layer column definitions, find `unsigned` on quantity, amount, delta, adjustment or balance columns, then check whether any writer stores a negative value there. A fix needs a schema migration.

---

### Resolve table names through the prefix-aware accessor

**What shipped:** Code reads a protected table-name property directly from another query object instead of calling its accessor method. PHP lets sibling subclasses of a common parent read protected properties directly, so `__get()` never runs and the unprefixed name (`items` instead of `wp_myplugin_items`) ends up in SQL, failing on any install. Bare table names hard-coded in JOINs fail the same way on non-default prefixes.

**Detect by:** Grep for a table-name or table-alias property read on any object other than `$this` and replace with the accessor method. Flag SQL strings with a literal table name not built from `$wpdb->prefix` or the class accessor, especially in cross-table JOINs. Test on an install with a non-default table prefix.

---

## Caching and performance

### Invalidate every cache key and group a write affects, on every write path

**What shipped:** Cached records and query results go stale under a persistent object cache because some write path does not clear every key variant (by id, email, user id, query hash) or bump the group's `last_changed`. Variants: a legacy write path does not bump the modern query's `last_changed`, so a cached 'not found' persists and duplicate-prevention is bypassed; an update changes a lookup column and refreshes only the new value's key, so get-by-old-value still returns the row; a joined list is not invalidated when the related row's foreign key changes; a counter incremented from another hook or a raw `$wpdb` write bypasses the cache layer, so limits can be exceeded and opt-outs ignored; cached misses are not cleared on insert; set and delete spell the group differently. Separately, a query class that stores a per-instance random sentinel (`random_bytes()`, `uniqid()`) as a default leaks it into the cache key so the cache never hits.

**Detect by:** When a diff adds `wp_cache_set()`/`wp_cache_add()`, list every key it is stored under and every write path (legacy and modern, insert, update, delete, status change, counters, bulk and raw `$wpdb` writes, sync hooks); each must `wp_cache_delete()` all keys, including keys for the old value of changed lookup columns and joined lists, or bump a `last_changed` salt. Compare group strings exactly between set and delete. Flag `wp_cache_set()` of aggregates with no invalidation. Grep for `random_bytes`, `uniqid` or `wp_generate_uuid4()` in query-class constructors or default arrays. Use `wp_cache_add_non_persistent_groups()` for request-scoped caches and test with a persistent cache drop-in.

---

### Key every cache on all inputs that change the result

**What shipped:** **(security)** A cache key omits or loses an input that changes the result, so different callers share one entry. A helper memoizes in a function-level `static` or `global` filled by the first call though the result depends on an argument, so a cron sweep over many users gets the first user's answer for all of them; an unkeyed `$has_run` guard has the same flaw. A query layer hashes only some query vars while clause filters (some reading `$_GET`) change the SQL, or a key omits a flag or parameter real callers vary on, so users see each other's data. A transient name concatenated from parameters and cut with `substr( ..., 0, 45 )` to fit the name limit collides for configurations sharing the first 45 characters.

**Detect by:** Grep `static $x;`/`static $x = null;`/`global $x;` used as a memo in functions that take a parameter; the cache must be an array keyed by it, and recursion guards keyed the same way. For caches keyed by `md5( serialize( $args ) )` or a slice of args, list every input that changes the SQL or response (all args, clause filters, `$_GET` reads in callbacks, current user, locale) and flag any missing; prefer keying on the final SQL. Flag cache keys passed through `substr(` or containing raw user input; use `md5()` of the full serialized parameter set with a short readable prefix. Check `wp_cache_set()` on persistent groups has an expiry or invalidation.

---

### Scope cached search results to the caller's audience

**What shipped:** **(security)** A search endpoint caches results in a site-wide transient keyed only on the search text, and the endpoint is also exposed through `wp_ajax_nopriv_`. An anonymous caller replaying a search string within the cache lifetime receives whatever a privileged user just saw, including draft or private items and their prices.

**Detect by:** Grep `set_transient` / `wp_cache_set` in search or listing handlers; confirm the key includes the user or capability level (or the cached query already restricts to publicly readable statuses), especially when the handler is reachable by `nopriv` callers.

---

### Gate and memoize expensive per-request work, including the empty result

**What shipped:** An expensive lookup (remote HTTP call, query, element-tree decode, derived computation) runs on every invocation in a request because nothing caches it or checks relevance first. Shapes: a front-end hook (`wp_enqueue_scripts`, `wp`, `wp_head`, `template_redirect`) decodes a large stored structure on every page view to look for one widget, or makes an uncached remote lookup with a long timeout; an updater's remote call inside `pre_set_site_transient_update_plugins`, which core applies several times per request, with hooks also registered twice and a leftover force-refresh flag; a lookup cached only when it finds a row, so misses re-query every call; a per-item display filter or list-table column helper rebuilding the same context or querying per row, sometimes through a fallback that builds a whole legacy object to read one field; a result saved to a transient that is never read back.

**Detect by:** Grep callbacks on front-end hooks, `pre_set_site_transient_update_plugins`, `site_transient_update_plugins`, `plugins_api`, `the_content`, display filters, list-table `column_*` methods and export loops for JSON decoding of meta, recursive tree walks, `wp_remote_*`, `$wpdb->`, `WP_Query` or `get_posts()` that run before a relevance check (`is_singular()`, post type, shortcode/block presence) or without a static/property memo or non-persistent `wp_cache_*`. Require a transient and a short explicit timeout for remote results. Find `add_action`/`add_filter` in a constructor also called from `plugins_loaded`/`init` with no did-run guard. In cache-on-hit code (`if ( $row ) { set_transient(...) }`), confirm misses store a sentinel. Look for hardcoded `$force_refresh = true`, transients set but never read, and fallbacks instantiating full model objects to read one meta key.

---

### Index the columns large-table queries filter, join and sort on

**What shipped:** Queries on large tables fall back to full scans or filesorts: a column used in a refund sub-query has no index; list views `ORDER BY date_created` with a status filter and no composite index; a lookup uses only the second column of a composite index; `WHERE a.id = X OR (b.meta_key = ... AND b.meta_value = X)` across a `LEFT JOIN` cannot use either index; `LIKE '%term%'` searches a large text column; a `LEFT JOIN` to a `GROUP BY` derived table has no index; a join compares columns with different charsets (utf8mb3 vs utf8mb4) so the index is not a candidate; per-row correlated subqueries or one query per item in a loop scale with the whole table instead of the page.

**Detect by:** In schema and upgrade files, confirm each column used together in `WHERE` and `ORDER BY` by main list queries has a matching composite index with the filtered column first. Run `EXPLAIN` on new queries against realistic data. Flag `OR` across joined tables, leading-wildcard `LIKE`, joins on derived tables or on `CAST(meta_value ...)`, joins between columns of different collation, correlated subqueries in SELECT lists, and queries inside `foreach` loops; replace them with `IN (...)` batches, `GROUP BY` queries or sub-selects.

---

### Exclude token, account and state-changing pages from page caches

**What shipped:** Responses for one-time tokens, magic links, account and billing pages, or post-action redirects are cached by the host's page cache. Users then see stale state or a cached error after a fix. `Cache-Control` headers alone do not bypass some server caches: LiteSpeed needs `X-LiteSpeed-Cache-Control: no-store`, and many cache plugins honour only the `DONOTCACHEPAGE` constant. Logged-in 'private' caches can still serve a stale billing page for minutes after a cancel.

**Detect by:** On routes that handle tokens, per-user account data or redirects, confirm the code defines `DONOTCACHEPAGE`, calls `nocache_headers()`, emits the server-specific no-store header, and fires any no-cache action a known cache plugin exposes. Do this before output starts, on success and error paths alike.

---

### Give cached remote results a TTL, invalidate them on input changes, and do not cache failures at full TTL

**What shipped:** A list fetched from a third-party API is cached with `set_transient( $key, $value )` and no expiration, and nothing deletes it when the credentials or settings that determine it are saved (or the deletion is hooked to a wrapper hook the core Settings API save path never fires). An empty or failed response fetched before credentials were valid stays cached forever with no way to clear it from the UI. An aggregator of remote sources marks a result complete or exhausted because it got fewer records than requested and caches that flag for the full TTL, even when the low count came from every source erroring, so output freezes on partial data.

**Detect by:** Grep `set_transient(`/`set_site_transient(`/`wp_cache_set(` with no or `0` expiration whose value comes from `wp_remote_*` or an SDK. Confirm a TTL and a `delete_transient()` on every option or credential save path that feeds the request (`update_option_{$option}`, the sanitize callback). Check that empty, error and partial outcomes (any `WP_Error`, non-empty `$errors`) get a short TTL or no cache, and that completeness or 'no more pages' flags are written only when no source errored.

---

### Do not make a blocking HTTP request back to the same site

**What shipped:** A request handler or `pre_http_request` override fetches a URL on the same site with a blocking HTTP call during page generation. Each request holds a PHP worker waiting for another worker to serve the loopback; under load the pool starves and requests time out. Reading the file or calling the code directly avoids it.

**Detect by:** Grep `wp_remote_get(`/`wp_remote_post(`/`wp_safe_remote_*(`/`pre_http_request` whose URL is built from `home_url(`, `site_url(`, `rest_url(`, `admin_url(`, `content_url(`, `plugins_url(` (or a configurable URL that may be the same host) on a synchronous front-end or admin path. Require a direct PHP or filesystem call, or `'blocking' => false` with a short timeout for fire-and-forget loopbacks.

---

### Keep remote calls and heavy work out of settings-array builders

**What shipped:** A callback that builds or filters the plugin's settings array, evaluated on many front-end and admin requests, calls a third-party API to populate a select's options and runs an upgrade routine inline. When the API is unreachable every page load blocks or fatals, locking the owner out of the site.

**Detect by:** Grep settings-registration callbacks (settings-array filters, `register_setting()` builders, `add_settings_field()` args) for `wp_remote_*`, SDK calls, expensive queries or upgrade routines. Confirm the expensive part runs only on its settings screen (`get_current_screen()` or page check), is cached, and handles `is_wp_error()`/exceptions so a failing API cannot break unrelated requests.

---

### Keep model constructors free of eager queries

**What shipped:** A model's `setup()` eagerly loads related data and backfills fields on every instantiation. When a list screen or API loop hydrates many objects, the nested lookups and magic `__get` frames add up to heavy query load and can exhaust the stack, producing a blank 503.

**Detect by:** In constructors or `setup()` methods of models loaded in bulk (list tables, REST collections), flag DB or network calls and creation of related objects. Move them into lazy getters or batch them per page.

---

### Do not force-recompute a site-wide aggregate on a per-transaction hot path

**What shipped:** Order completion calls an aggregate getter with a force flag, skipping its long-lived transient and running a full-table `SUM()` synchronously in the buyer's request. Refund and delete paths do the same.

**Detect by:** In callbacks on order complete, refund, delete or save, or any checkout path, grep for aggregate getters called with a force/refresh argument (`, true )`, `'force' => true`) and `SUM(`/`COUNT(*)` over a whole table. Require invalidating the cache and deferring the recompute to cron or Action Scheduler.

---

### Compute a batch job's total once with a COUNT query

**What shipped:** A stepped AJAX export computes its total for the progress percentage by fetching all matching rows (`number => -1`) and calling `count()` in PHP, on every step. Large sites time out.

**Detect by:** In batch processors (percentage/total methods, step callbacks), flag totals computed by fetching rows and `count()`ing them and totals not cached after step one. Use `COUNT(*)`, a count-only query arg, or `found_rows`, computed once, and add a running lock.

---

### Do not call wp_cache_flush() to invalidate one plugin's cache

**What shipped:** To invalidate cached query results keyed by a hash of the query args, a save path calls a full object-cache flush, wiping every group for the site (and every site sharing a persistent cache) on each save.

**Detect by:** Grep `wp_cache_flush(` (and `wp_cache_flush_group(` without a `wp_cache_supports( 'flush_group' )` check) in save/update paths. Require a group-scoped `last_changed` key (`wp_cache_get_last_changed()`/`wp_cache_set_last_changed()`) or deletion of known keys.

---

### Invalidate caches and fire hooks after COMMIT, not inside the transaction

**What shipped:** A row update inside a transaction or `FOR UPDATE` lock clears the object cache and fires hooks before COMMIT. A concurrent reader repopulates the cache with the pre-commit value, and third-party hook code runs while the lock is held.

**Detect by:** Find `START TRANSACTION`/`FOR UPDATE` blocks; require `wp_cache_delete`/`clean_*_cache` and `do_action` calls after COMMIT, or a single atomic conditional `UPDATE` without a transaction.

---

### Scope and cache scans of post_content for shortcode or block usage

**What shipped:** To show where a shortcode or block is used, a plugin runs a leading-wildcard `LIKE '%[shortcode%'` over `post_content` for every post type, uncached, on every editor or admin load, sometimes once per list item. On large `wp_posts` tables the editor hangs. A `save_post` handler that flushes the cache for every post type invalidates it on every write site-wide.

**Detect by:** Grep `post_content\s+LIKE`, `LIKE '%[`, `LIKE '%<!-- wp:` and `'s' =>` searches used to find placements. Require a `post_type IN (...)`/`post_status` predicate, a LIMIT or batching, a cached result (not cached on failure), and no execution on every page load. Invalidation on `save_post`/`deleted_post` should return early for unscanned post types, revisions and autosaves.

---

### Do not memoize the update_plugins transient filter result within a request

**What shipped:** A custom updater caches its `pre_set_site_transient_update_plugins` return value in a property to avoid duplicate API calls. `wp_update_plugins()` saves the transient twice per check (a pre-flight `last_checked` write, then the full response), and both fire the filter, so returning the cached pre-flight object erases update data for every other plugin.

**Detect by:** In `pre_set_site_transient_update_plugins`/`_themes` callbacks, look for a cached `$transient` returned from a property or static. Cache only the remote API response and always merge it into the `$transient` argument passed in.

---

### Reset a memoized property when its source object is replaced

**What shipped:** A class caches a derived flag (for example 'has purchases') in a property. When a later step replaces the underlying object (a different user resolved from a submitted email), the cached flag keeps the old object's answer.

**Detect by:** For properties memoized with a `null` sentinel (`if ( null === $this->x )`), find every setter or reassignment of the object they depend on and confirm the memo is reset there.

---

### Start PHP sessions only for the narrow request that needs them

**What shipped:** A filter forces a PHP session to start whenever `is_admin()` is true, which includes every `admin-ajax.php` request, to serve one upload flow. The session lock and headers on loopback and REST requests make Site Health's loopback test time out and break unrelated AJAX flows.

**Detect by:** Grep `session_start(` and filters that force sessions on, conditioned on `is_admin()`, `wp_doing_ajax()`, `REST_REQUEST` or nothing. Require the narrowest condition (a specific action plus a request marker) and `session_write_close()` before long work; flag sessions started on REST, loopback or cron requests.

---

### Use a stable asset version, not the current time

**What shipped:** `wp_enqueue_script()`/`wp_enqueue_style()` is given `time()` as the version, so every page load gets a new `?ver=` string, defeating browser and CDN caching and page-cache reuse.

**Detect by:** Grep `wp_enqueue_*`/`wp_register_*` version arguments for `time()`, `strtotime(`, `microtime(`, `date(` or `rand(`. Use the plugin version constant, or `filemtime()` only in development builds.

---

### Keep front-end styles out of the editor's admin shell

**What shipped:** A front-end stylesheet is enqueued on `enqueue_block_assets`, which fires on the front end, in the editor iframe and, in some editor configurations, in the admin page around the editor. With no post-type or block-presence check, it loads on every edit screen and overrides metabox and admin styling.

**Detect by:** Grep `enqueue_block_assets` callbacks that enqueue full front-end stylesheets. Gate them with `is_admin()` and a block-presence or post-type check, or register styles through block metadata (`style`/`editorStyle`) or `add_editor_style()` so they apply only inside the iframe.

---

## Hooks and render lifecycle

### Return the filtered value from every filter callback

**What shipped:** A callback on `admin_footer_text` is written as a void method with a bare `return;`. Filters must return a value; `null` passes a non-string to the next callback and core, raising PHP 8.1+ deprecations and breaking chained callbacks. A settings sanitize callback that writes its own option and returns an empty array on every path means the registered setting never saves.

**Detect by:** For every `add_filter( '<hook>', $cb )`, confirm all paths of `$cb` return a value of the filter's type (string for text/title filters, array for args/columns, the sanitized value for `sanitize_option_*` and `register_setting()` sanitize callbacks). Grep filter callbacks containing `return;`, an `@return void` docblock, or no return.

---

### Check add_filter() priority and accepted-args order and coverage

**What shipped:** **(security)** A content-restriction filter is registered as `add_filter( $hook, $cb, 2, 999 )` (priority 2, 999 args) where priority 999 with 2 args was intended, so later callbacks append restricted content after the replacement message. Restriction is also hooked only on `the_content`, missing other render filters the host uses for the same content. Separately, a callback needing old and new values is registered with the default one accepted argument.

**Detect by:** Grep `add_filter(`/`add_action(` with a small third argument and a large fourth, and any accepted-args count that does not match the callback's real parameters. For access-control or redaction filters, confirm the priority runs after every callback that can append content and that every render filter for the protected content type is hooked, not just `the_content`.

---

### Restore a temporarily changed hook at its original priority, in a finally block

**What shipped:** Code removes a filter around an operation and re-adds it at the default priority, or adds a temporary filter and removes it only on the success path. After an early `return` or a throwing call, the filter stays live for the rest of the request and affects later queries in a batch or cron run. Re-adding a core or third-party callback with `add_filter()` also moves it behind same-priority callbacks registered in between.

**Detect by:** Find `remove_filter`/`remove_action` paired with a later `add_filter`/`add_action`, and `add_filter(` calls inside method bodies paired with a `remove_filter()`. Require the priority captured from `has_filter()` and the restore in `finally`, with no `return`/`throw` between the pair. Prefer an argument or flag the callee reads over toggling hooks.

---

### Do not add a callback to a hook at a priority that is already running

**What shipped:** A constructor calls `add_action( 'init', ... )` at priority 10, but the object is created from an `init` callback at priority 10. WordPress iterates the current priority's callback list as it was, so a callback added at the running or an earlier priority is skipped for that request and never runs.

**Detect by:** When a diff adds `add_action`/`add_filter` inside a constructor or setup method, find which hook the object is created on. Flag `add_action( 'X', ... )` at a priority at or below the running priority of X. Use a later hook or priority, or call the method directly when `did_action( 'X' )`/`doing_action( 'X' )` is true.

---

### Register hooks unconditionally and guard at execution time

**What shipped:** Cron and Action Scheduler callbacks are registered only `if ( SomeFlag::is_enabled() )` at load time. In the cron context the flag reads false (a class it depends on is not loaded yet, or a getter falls back to a default instead of reading the stored option), so scheduled actions fire with no callbacks and the work never runs, while an ungated companion job proceeds and expires records.

**Detect by:** Grep for `add_action` / `add_filter` / `as_schedule_*` callback registration wrapped in a runtime condition; check whether the condition depends on load order or request context, prefer registering unconditionally and checking inside the callback, and confirm version/feature getters read the stored option rather than returning a default.

---

### Guard admin-only functions in code that can run on the front end

**What shipped:** A script-enqueue callback calls a helper that is only loaded in admin requests to bail early on other screens. Another plugin calls the same callback from a front-end dashboard, where the helper is undefined, and the page fatals with "Call to undefined function".

**Detect by:** In callbacks that can run outside `is_admin()` (shortcodes, `wp_enqueue_scripts`, REST, cron, front-end dashboards), grep for `get_current_screen()`, `is_plugin_active()`, `get_plugins()`, `add_meta_box()`, `wp_terms_checklist()`, `request_filesystem_credentials()` and plugin helpers defined in admin-only includes. Each needs a `function_exists()`/`is_admin()` guard or a `require_once ABSPATH . 'wp-admin/includes/...'`.

---

### Exclude WP-CLI, cron, REST and AJAX from browser-only redirects and gates

**What shipped:** A force-login gate hooked to `init` calls `wp_safe_redirect()` and `exit` for any logged-out request, so under WP-CLI it builds a redirect from undefined `$_SERVER` values and kills CLI commands mid-run. A post-activation redirect armed on every activation fires after programmatic activations (another plugin's wizard via AJAX/REST, `wp plugin activate`) and hijacks the next admin page load.

**Detect by:** Grep `init`, `admin_init` and activation callbacks that call `wp_redirect`/`wp_safe_redirect`/`exit`/`die` or set a redirect transient. Require early bails for `defined( 'WP_CLI' ) && WP_CLI`, `wp_doing_cron()`, `wp_doing_ajax()` and `REST_REQUEST`, or move front-end gates to `template_redirect` and REST gates to `rest_authentication_errors`. Flag unguarded reads of `$_SERVER['HTTP_HOST']`/`REQUEST_URI`.

---

### Use the object id a filter callback receives instead of global loop state

**What shipped:** A filter or action callback receives the target object's id or object but reads `global $post`, `get_the_ID()` or `$_GET` instead. When the hook runs outside the main loop (a shortcode, bulk edit, REST or cron), the global is a different object or unset, so the callback evaluates the wrong object and can fall back to a weaker access check or skip work.

**Detect by:** Grep hook callbacks that accept an id or object parameter for `global $post`, `get_the_ID()`, `get_queried_object()` or request superglobals in the same body. Each should use its parameter. Test the hook with a different object in context than the global one.

---

### Make side effects on change hooks idempotent and change-aware

**What shipped:** Derived records are created on a status-change hook guarded only by the old status not being 'complete', so toggling complete to pending to complete creates duplicates. A callback on a user-update hook syncs and fires follow-up writes on every user update without comparing the one field it cares about, so unrelated core updates (password-reset keys, meta touches) inside a bulk loop trigger it per user and exhaust memory.

**Detect by:** Grep `add_action(` on status-transition hooks (`transition_post_status`, `*_status_changed`, plugin status hooks) whose callbacks insert rows, send money or email, or grant access; require an idempotency guard keyed on the object (existing-row check or processed flag), not only an old-status check. For `profile_update`, `save_post`, `updated_option` and similar, confirm the callback compares the provided old value to the new one and returns early when unchanged before any lookup, write or `do_action()`.

---

### Run a listener after the listener that writes the data it reads

**What shipped:** An extension listens on a shared status-change action at priority 10 and reads a completion date that the host plugin's own listener on the same action writes at priority 100. On every new record the extension reads `false` and stores an invalid timestamp.

**Detect by:** For each `add_action()` on a shared lifecycle or status hook, find other listeners on the same hook and what they write (dates, meta, totals). If the callback reads a value another listener sets, its priority must be higher, or it must hook a later 'after' action.

---

### Guard conditional query tags that can run before the main query

**What shipped:** A callback on a filter that can be applied early in the request (before `wp`) calls a helper using `is_page()`, triggering a 'Conditional query tags do not work before the query is run' notice and always evaluating false at that point.

**Detect by:** For callbacks using `is_page()`, `is_singular()`, `is_front_page()`, `is_archive()` or wrappers, find the earliest hook they can run on. If that is before `wp`/`template_redirect` (`init`, `plugins_loaded`, option filters, registration filters), require a `did_action( 'wp' )` guard.

---

### Do not assume hook arguments are normalized when the hook fires early

**What shipped:** A callback on an early 'before add' hook uses `$options['option_id']` as an array key (`array_key_exists( $options['option_id'], $prices )`). At that point the host has not normalized the value yet, and for multi-option items it is an array, so PHP 8 throws `TypeError: Illegal offset type`.

**Detect by:** For callbacks on 'pre_'/'before_' hooks, check where the host normalizes each argument and whether that happens before or after the hook fires. Before using a hook argument as an array key, confirm it is checked with `is_scalar()` or `is_int()`.

---

### Send headers and cookies before output, behind a correct headers_sent() check

**What shipped:** A cookie is set behind an inverted guard (`if ( headers_sent() )` instead of `if ( ! headers_sent() )`), so it is attempted only after output has started, emitting 'headers already sent' warnings and never set in the normal case. Similarly, `status_header()` called from a render callback instead of `template_redirect` has no effect.

**Detect by:** Grep `setcookie(`, `header(`, `status_header(`, `wp_redirect(` and `nocache_headers(` in code reachable after output can start (shortcodes, `wp_head`, template hooks, AJAX after echo). Each should be guarded by `if ( ! headers_sent() )` (check the negation) or moved to `init`/`template_redirect`.

---

### Guard the_content callbacks against re-entry

**What shipped:** A `the_content` callback injects a listing whose template, in some themes, calls `the_content()` or `apply_filters( 'the_content' )` per item, re-entering the same callback and recursing until memory runs out.

**Detect by:** For callbacks on `the_content`, `the_excerpt` or `widget_text` that render templates, shortcodes or loops (`do_shortcode()`, `WP_Query` with `the_post()`), confirm they `remove_filter()` themselves before rendering (re-adding after) or use a static re-entrancy guard, and check `in_the_loop()`/`is_main_query()` for the target post.

---

### Do not migrate a setting inside its getter through hooked update APIs

**What shipped:** A setting getter detects a legacy value and normalizes it by calling a settings-update wrapper from inside the read. The update runs sanitize and update filters that call the same getter, which detects the legacy value again, recursing infinitely and taking sites down.

**Detect by:** Grep option and setting getters for `update_option(`, plugin update wrappers or `set_theme_mod(` (migrate-on-read). Trace the write path's `sanitize_option_*`, `pre_update_option_*` and `update_option_*` callbacks; if any calls the getter, the write recurses. Prefer a one-time upgrade routine, or a raw `update_option()` with a re-entrancy guard.

---

### Load repeatable templates with include, not include_once

**What shipped:** A shortcode or render callback loads its markup template with `require_once`/`include_once`. PHP includes the file once per request, so a second render (two instances, or an SEO plugin running `do_shortcode()` for a description first) returns an empty string. The template also hardcodes element `id`/`for` values, producing duplicate DOM ids across instances.

**Detect by:** Grep render, shortcode and block callbacks and output-buffered functions for `require_once`/`include_once` of template or view files. Templates without function or class declarations must use `require`/`include` or `load_template( $file, false )`. Flag hardcoded `id="..."`/`for="..."` in repeatable templates; use `wp_unique_id()`.

---

### Do not declare functions in templates included once per render

**What shipped:** A block render template declares helper functions at file scope. The render file is included once per block instance, so a request rendering two instances (an archive, a REST collection returning rendered content) dies with `Cannot redeclare function`, while single views work.

**Detect by:** In block render templates, template parts, shortcode views and any file loaded with `include`/`require` (not `_once`) per render, grep for top-level `function \w+(`. Move them to a once-loaded file or wrap in `if ( ! function_exists() )`. Test by rendering the block twice in one request.

---

### Avoid WordPress global names for local variables in included templates

**What shipped:** A template or view runs in global or shared scope and assigns a local named after a WP global (`$post`, `$page`, `$pages`, `$id`). Inside a Query Loop block or after `setup_postdata()` the global is clobbered or overwrites the local, causing type fatals or wrong output.

**Detect by:** In included templates, views and block render callbacks, grep for assignments to `$post`, `$page`, `$pages`, `$id`, `$more`, `$wp_query` or `$authordata`, and rename them to prefixed locals.

---

### Dedupe render output with a per-render flag, not did_action()

**What shipped:** A block render callback skips a section (and the hook that prints it) when `did_action()` reports the hook already fired. `did_action()` counts per request, so a second `do_blocks()` pass in the same request (page builder pre-render, SEO scanner, cache preloader) outputs HTML with the section silently missing.

**Detect by:** Grep render callbacks and template helpers for `if ( did_action( '...' ) )` used to skip output or `do_action()`. Scope the guard to the current render (a flag set and reset around the outer render, or keyed by block instance). Test by rendering twice in one request and asserting the section appears once in each output.

---

### Fire each hook once when markup moves into a render class

**What shipped:** Template markup is moved into a new render method that fires a `do_action()`, but the original `do_action()` stays in the template, so callbacks run twice and output is duplicated.

**Detect by:** When markup moves from a template into a class or function, grep the old and new locations for every `do_action`/`apply_filters` name and confirm each fires exactly once per render path.

---

### Keep a trailing do_action() reachable when branches gain returns

**What shipped:** A method is edited so both its `if` and `else` branches `return` a setter's result. The `do_action()` and follow-up call placed after the conditional become unreachable, so a documented hook silently stops firing.

**Detect by:** In diffs that add `return` statements inside `if`/`else` or `switch`, check that code after the conditional (especially `do_action(`, `apply_filters(` or follow-up calls) remains reachable on every path. Flag void or `maybe_*` methods that now `return $this->set_*()` in all branches.

---

### Match core's full return shape when a filter replaces a core function's result

**What shipped:** A plugin hooks `wp_count_comments` and, for the site-wide case, returns a hand-built `stdClass` with only some of core's properties. The dashboard widget and list-table status links read the missing properties, producing undefined-property warnings and wrong counts.

**Detect by:** For every short-circuit or replacement filter (`wp_count_comments`, `wp_count_posts`, `pre_option_*`, `pre_http_request`, `posts_pre_query`, `pre_get_*`) that returns a constructed value, compare its keys and types to core's own return shape. Flag a `new stdClass()` or literal array setting only a subset of core's properties.

---

### Compare has_action()/has_filter() with a callback against false

**What shipped:** `has_action()`/`has_filter()` called with a callback returns that callback's priority, which can be `0`, so a truthiness check treats a priority-0 registration as absent.

**Detect by:** Grep `has_action(`/`has_filter(` with a second argument used in `if()`, a ternary or `!`. Require `false !== has_action( $hook, $cb )`, or drop the callback argument when only 'any listener' matters.

---

### Pass a boolean default to apply_filters, not a callback name string

**What shipped:** A new on/off filter is given the string `'__return_false'` as its default. `apply_filters()` returns the string itself, which is truthy, so the feature is enabled, and strict `=== true` checks never match.

**Detect by:** Grep `apply_filters(` calls whose second argument is a quoted `'__return_*'` string; use a `true`/`false` literal.

---

### Use array union, not array_merge, in registry filter callbacks

**What shipped:** A callback on a shared registry filter (blocks, integrations, gateways keyed by slug) adds entries with `array_merge( $existing, $mine )`, so its string keys overwrite another plugin's entry with the same slug.

**Detect by:** In filter callbacks that return a keyed registry, check for `$existing + $mine` or an explicit `isset` guard when existing entries must win, and for a test with a colliding key.

---

### Keep a reference to closures that wrap hook callbacks

**What shipped:** A registration helper wraps callbacks in a closure before `add_action()`, so `remove_action()` and `has_filter()` with the original callable cannot find or detach it.

**Detect by:** Find helper methods that call `add_action( $hook, function() use ( $cb ) ... )`; require storing the closure for later removal, or registering the callable directly.

---

### Handle a null screen or null global $post in editor and admin asset callbacks

**What shipped:** A callback that loads editor assets assumes `get_current_screen()` and global `$post` are set. The same hook fires on screens without a post (the block widgets editor, the site editor, some admin pages), so the callback dereferences null and emits warnings or fatals.

**Detect by:** In `enqueue_block_editor_assets`, `admin_enqueue_scripts`, `add_meta_boxes` and `post_submitbox_*` callbacks, check every `$screen->`/`$post->` dereference for a null guard.

---

### Detect blocks in templates and nested inner blocks before falling back

**What shipped:** Shortcode-era fallback rendering runs in a block context it does not detect, so fields render twice. `has_block()` checks only the post content, not the FSE template that actually holds the block. Attribute searches do not recurse into inner blocks (group or columns). Shared render helpers run again in the editor. A shortcode-only setting override also applies to the block and overrides the block's own attribute.

**Detect by:** Grep fallback renders and setting overrides for a guard that detects the block in the post content and the current template (`$_wp_current_template_content`) and that recurses through `innerBlocks` (`parse_blocks`). Confirm editor and REST render contexts are excluded, and that shortcode-only overrides do not run on the block path.

---

### Never render a form inside another form

**What shipped:** A secondary feature renders a real `<form>` inside the main checkout form (or inside a block that sits in a form). Nested forms are invalid HTML: the browser drops the inner form tag, so its fields submit with the outer form. Code that removes or moves the inner form drifts across render paths (block, page builder, shortcode), so the inner form is dropped with no replacement on one path and output twice on another.

**Detect by:** Grep for `<form` output by hooks that fire inside another form's template. Move the output to a hook after the outer form closes. Use one shared rule for the move across every render path, and add a guard so the form renders only once.

---

### Scope output-suppression filters to the configuration that needs them

**What shipped:** To avoid a duplicate button, a handler adds `add_filter( 'some_button_html', '__return_empty_string', 99 )` whenever a block is present. In a configuration where the button renders inline (a single option instead of an AJAX-loaded fragment), the filter still applies and both copies disappear, leaving the page unusable.

**Detect by:** When a diff adds `__return_empty_string`, `__return_false` or another suppression filter to dedupe output, list the render configurations (single vs multiple options, AJAX vs inline, first vs repeated render) and confirm exactly one copy remains in each. Prefer removing the filter right after the render it targets.

---

### Render block template parts before wp_head() in block-theme templates

**What shipped:** A plugin page template for block themes calls `wp_head()` first and then `block_template_part( 'header' )`/`'footer'`. Blocks enqueue script modules while rendering and the import map prints in `wp_head()`, so modules enqueued by those parts (such as the Navigation block's interactivity module) are missing; the browser throws 'Failed to resolve module specifier' and interactive blocks do not run. Core's `template-canvas.php` renders the template before `wp_head()`.

**Detect by:** In plugin templates used on block themes, grep for `wp_head()` appearing before `block_template_part(`, `do_blocks(`, `render_block(` or `the_content()`. Require the block markup rendered into a buffer or variable before `wp_head()` and echoed afterwards.

---

### Include wp:post-content in page templates

**What shipped:** A registered block page template hardcodes a block in its content and leaves out `<!-- wp:post-content /-->`. Any page assigned the template renders only the static markup and hides the page's own content.

**Detect by:** Grep template content registered by the plugin (`register_block_template()`, template files) for page templates without `wp:post-content` where the page's content must still render.

---

### Register query vars only for requests that target the feature

**What shipped:** A plugin adds generic query vars (`token`, `key`, `version`) on `query_vars` for every request. On sites with a static front page, a POST to `/` with a field of the same name is parsed as a plugin API request, returning an empty response and breaking other plugins' forms.

**Detect by:** Flag `query_vars` filters that add common words without a plugin prefix, and API detection that relies on them. Prefix query vars and confirm the feature checks its own endpoint or rewrite rule before acting.

---

### Limit admin-notice suppression to the plugin's own screens

**What shipped:** A plugin removes all `admin_notices` callbacks on its pages, but its 'is our admin page' check returns true for the main Dashboard (`index.php`), so other plugins' notices disappear site-wide.

**Detect by:** Flag `remove_all_actions( 'admin_notices' )` or similar removals guarded by a broad page check. Confirm the check matches specific screen IDs via `get_current_screen()` and excludes core screens like `dashboard`.

---

### Hide admin pages before core consumers read the menu

**What shipped:** A plugin registers an admin page and then removes it from the menu in a late hook such as `admin_head`. Newer core surfaces that index the menu (command palette, admin bar, REST menu data) have already read it, so the hidden page stays reachable.

**Detect by:** Grep `remove_menu_page()` / `remove_submenu_page()` and check the hook and priority run before every consumer of `$menu` / `$submenu` (generally `admin_menu` at a late priority or `admin_init`), not just before screen render; or register hidden pages with a null parent instead.

---

### Use the hook suffix returned by add_menu_page(), not a hardcoded folder name

**What shipped:** Admin asset loading compares `$hook_suffix` with a literal `'toplevel_page_my-plugin/my-plugin.php'`. When the plugin is installed under a different directory name (renamed zip, `-master` suffix, mu-plugin), the check never matches and scripts never load.

**Detect by:** Grep `admin_enqueue_scripts` callbacks and `get_current_screen()->id` comparisons for literal plugin folder names. Compare against the value returned by `add_menu_page()`/`add_submenu_page()`, or a value derived from `plugin_basename( __FILE__ )`.

---

### Keep the parent page as the first submenu when a post type joins its menu

**What shipped:** A post type registered with `show_in_menu` set to a settings page's slug is appended to that parent's submenu during core menu build, before the settings page registers on `admin_menu`. WordPress points the top-level link at the first submenu entry, so the top-level menu opens the post type list instead of the settings page.

**Detect by:** When `register_post_type()` sets `show_in_menu` to another menu's slug, or `add_submenu_page()` targets a parent registered later, check that `$submenu[ $parent ][0]` is the parent's own page. Require the parent registered first, or a late `admin_menu` callback that reorders `$submenu[ $parent ]`.

---

### Handle user creation in user_profile_update_errors callbacks

**What shipped:** A validation callback on `user_profile_update_errors` assumes it runs only for existing users. The hook also fires when an admin creates a user (`$update = false`, no ID yet), so ID-based checks such as role lookups or password-history checks run against user 0 and wrongly block creation or skip the check.

**Detect by:** For callbacks on `user_profile_update_errors` (and `personal_options_update` / `edit_user_profile_update`), check that they accept the `$update` argument and branch on it before using `$user->ID`.

---

### Suppress core notifications when sending a custom email for the same event

**What shipped:** A custom comment type (feedback or reviews) sends its own styled email, but core's comment notification also fires, and the custom path does not run the content through its template-tag replacement, so recipients get a raw core email with untouched tags.

**Detect by:** When a plugin inserts comments and sends its own notification, confirm `notify_post_author`/`comment_notification_recipients` or `wp_new_comment_notify_postauthor` is filtered off for that type, and every custom email body passes through the tag-replacement step.

---

### Preserve the caller-supplied class in an admin notice helper

**What shipped:** An admin-notice helper overwrites the caller's `class` argument with a hardcoded `updated`, so every notice renders as a success regardless of type; a legacy string replacement also adds backslashes before apostrophes in the message.

**Detect by:** In notice helpers, trace the `class`/`type` argument through to the rendered markup and confirm it is not replaced by a literal; check messages are not run through `addslashes`-style replacements before output; prefer `wp_admin_notice()` or `notice notice-{type}` classes.

---

### Keep query args until their consumer has used them

**What shipped:** A URL carries a parameter (for example a discount code) that should be applied after a delayed action (add to cart). The action's redirect strips the parameter, and a hook that changes state in between undoes the early application, so the parameter is lost.

**Detect by:** Find the list of query args stripped on redirect. Confirm args still needed on the landing request survive it, and are removed only after they are used. Test with filters or hooks that change state between the two steps.

---

### Set explicit priorities on shared table-column hooks

**What shipped:** Several plugins add columns to the same front-end table through header and row hooks at the default priority. Column order then depends on load order, and header and row callbacks can end up in different positions, misaligning columns.

**Detect by:** When a diff hooks header/row actions that other plugins also use, confirm header and row callbacks share an explicit priority and the column order is correct when other column-adding plugins are active.

---

## State, locks and background jobs

### Use an atomic claim before acting on a pending status

**What shipped:** A confirmation handler reads a pending status once and then performs gateway calls with no lock or compare-and-set, so two overlapping requests (reload after timeout, double submit, webhook racing the synchronous path) both proceed, creating duplicate recurring profiles or overwriting complete with failed. `add_option()` is not a safe mutex: it pre-checks with `get_option()` then runs `INSERT ... ON DUPLICATE KEY UPDATE`, so both requests can get `true`. A forward transition may use a conditional `WHERE status = 'pending'` update while a retry path uses an unconditional one, reopening the race.

**Detect by:** Find read-then-act status gates with remote calls between the read and the write; require an atomic claim (`INSERT IGNORE` or a conditional `UPDATE ... WHERE status = %s` checking affected rows, or `add_post_meta( ..., true )` with unique) or an intermediate status set before the first remote call. Flag `add_option()` used as a lock and any unconditional status update on a path that competes with a conditional one.

---

### Give a hand-rolled lock a TTL, release it atomically, and restore transitional state on every failure path

**What shipped:** A hand-rolled lock (option row, meta row, transient, `GET_LOCK()`) or a transitional status (`processing`, a held flag, a reserved claim) guards a charge or other remote call. Variants: the claim has no expiry, so a killed process (FPM timeout, OOM) leaves it forever; release reads the stored token and then deletes by name, so another request that took over an expired lock has its lock deleted; release or restore runs only on the happy path or in a vendor-specific `catch`, so a `TypeError`, a throwing hook listener or another exception leaves the lock held or the record stuck; a 'committed' flag is set on HTTP 2xx before the response body's status is checked, so a declined result also skips the restore.

**Detect by:** For each new lock or claim helper, check that (a) acquire stores an expiry and a later acquire can take over an expired lock, and (b) release is one conditional statement (`DELETE ... WHERE option_name = %s AND option_value = %s`) or `RELEASE_LOCK`, not a read followed by `delete_option()`. Grep `GET_LOCK(`, `set_transient( '...lock'`, `add_option( '...lock'`, `wp_cache_add(` used as a mutex, and writes of `'processing'`-style states before a try block; confirm release/restore is in `finally` or `catch ( \Throwable $e )` with a rethrow. Confirm any flag that skips the restore is set only after the remote result's status field is checked.

---

### Claim usage limits atomically

**What shipped:** **(security)** A limit (download count, coupon `max_uses`) is enforced by reading a count, deciding in PHP, and writing the increment in a later phase. Concurrent requests all pass the check, so a one-use coupon completes several orders and a limited file is delivered several times.

**Detect by:** Grep for a limit read followed by an increment written later in the request (or in another request). Reserve the slot atomically, for example `UPDATE t SET used = used + 1 WHERE id = %d AND ( max = 0 OR used < max )` and check affected rows. Alternatively insert the claim row before delivery and roll back on failure.

---

### Make batch cron jobs drain their backlog with a predicate that excludes processed rows

**What shipped:** A scheduled batch deletes or processes a fixed `LIMIT` per run and returns with no check for remaining rows and no reschedule, so a backlog built while cron was disabled never clears. The opposite shape reschedules whenever the batch is full but selects with the same WHERE clause every run, so it keeps matching rows it just processed and loops indefinitely, making outbound calls each pass. `LIMIT n OFFSET step*n` over a 'needs fixing' condition skips rows because fixed rows leave the result set, and compensating the offset loops forever if the query still returns them. Jobs that make one blocking remote call per record with no wall-clock budget, retrying unresolvable records oldest-first, starve newer ones.

**Detect by:** In scheduled batch routines, look for a hardcoded `LIMIT` or batch size with no check of remaining rows and no conditional reschedule when the batch was full. In callbacks that call `wp_schedule_single_event()` / `as_schedule_single_action()` again when `count( $rows ) === LIMIT`, confirm the SELECT excludes rows already handled (cursor `id > last_id`, a status flag flipped by the run, or a `last_updated < cutoff` predicate); flag a WHERE identical on every invocation and `OFFSET` pagination over a result set the loop mutates. For jobs with remote calls, require a run-time budget, a short timeout, a break on transport failure, and a progress marker.

---

### Process cron work in bounded batches

**What shipped:** A daily scheduled handler queries every matching row (abandoned, expiring or cancellable records) and processes them all in one run. On large sites this takes many minutes, hits timeouts, or leaves a CLI-triggered process stuck.

**Detect by:** Flag cron or Action Scheduler callbacks that query without `number`/`LIMIT` and loop over every row inline. Look for a filterable batch size and a self-rescheduled follow-up when a full batch comes back, with an idempotent cursor or status change so rows are not processed twice.

---

### Catch exceptions inside cron and scheduled-action callbacks

**What shipped:** A shared method that throws on failure is also called from a WP-Cron or Action Scheduler callback. The uncaught exception fatals the whole run and later items in the batch are never processed.

**Detect by:** For a new or changed method that throws, trace its callers. If any path is a cron hook, a scheduled action or a `wp_doing_cron()` context, require a try/catch with logging there, or rethrow only outside cron.

---

### Use the same args to check, schedule and unschedule a scheduled event

**What shipped:** Core and Action Scheduler identify an event by hook plus serialized args. A duplicate-scheduling guard queries with an associative array while the job was scheduled with an indexed one, so it never matches and duplicates pile up. An unschedule wrapper uses `empty( $args )` to mean 'no args given', clearing every action for the hook. An uninstall routine calls `wp_clear_scheduled_hook( $hook )` with no args, which removes only events scheduled with an empty args array, so per-object events (`array( $id, $settings )`) keep firing after uninstall.

**Detect by:** For every `wp_next_scheduled()` / `as_next_scheduled_action()` / `as_has_scheduled_action()` / unschedule call, confirm the args have the same shape, keys, order and types as the schedule call. In wrappers, require `null === $args` rather than `empty()`. In `uninstall.php` and deactivation callbacks, flag one-argument `wp_clear_scheduled_hook()` when any schedule call for that hook passes args; require `wp_unschedule_hook( $hook )` or, for Action Scheduler, `as_unschedule_all_actions( $hook )`.

---

### Register custom cron recurrences before wp_schedule_event() uses them

**What shipped:** `wp_schedule_event()` accepts only recurrence keys returned by `wp_get_schedules()`; an unknown name makes scheduling fail and the job never runs. A common case: the `cron_schedules` filter adding a custom interval is attached on `init`, but the activation hook schedules the event during the activation request, before that callback has been added, so the recurring job is never created.

**Detect by:** Grep `wp_schedule_event(` and read the recurrence argument. It must be a core key (`hourly`, `twicedaily`, `daily`, `weekly`) or a key added by a `cron_schedules` filter registered before the call runs, including from `register_activation_hook` callbacks (add the filter at file load or inside the activation callback, not on `init`/`plugins_loaded`/`admin_init`). Check that the return value is handled.

---

### Register at least one unconditional callback for every scheduled hook

**What shipped:** A recurring hook is scheduled unconditionally, but all of its callbacks are feature-gated, or are added inside an init callback that returns early in some load orders (for example WP-Cron loopbacks). The action runs with no callbacks and Action Scheduler records it as failed, intermittently or every time.

**Detect by:** For each `as_schedule_recurring_action()`/`wp_schedule_event()` hook, confirm a callback is always registered, unconditionally and early, on every request type, including cron. Put feature checks inside the callback as no-ops, or unschedule the hook when no feature needs it.

---

### Migrate pending scheduled actions when renaming a scheduled hook

**What shipped:** Scheduled jobs are stored in WP-Cron or Action Scheduler rows by hook name. Renaming the hook leaves every already-queued action pointing at the old name, which has no callback, so queued work silently never runs.

**Detect by:** When a diff renames a tag used with `wp_schedule_event`, `wp_schedule_single_event`, `as_schedule_*` or `as_enqueue_async_action`, require a migration that reschedules pending rows under the new name, or keep a callback on the old name.

---

### Do not treat an in-progress background job as already queued

**What shipped:** `as_has_scheduled_action()` / `as_next_scheduled_action()` also match an action that is currently running. A write path that clears a cached aggregate and queues a rebuild only if none is scheduled sees the running action and queues nothing; the running job already read its inputs, so it caches a total that omits the new write. A self-rescheduling job that checks for an existing scheduled action before rescheduling sees its own in-progress run and never reschedules.

**Detect by:** Grep `as_has_scheduled_action(`, `as_next_scheduled_action(`, `wp_next_scheduled(` used as an 'already queued?' guard before scheduling a recalculation or a follow-up run. Under Action Scheduler, require the guard to check only pending actions (`as_get_scheduled_actions( array( 'hook' => ..., 'status' => ActionScheduler_Store::STATUS_PENDING ) )`) and exclude the running action, or have the job re-check for writes made after it started and reschedule itself.

---

### Clear pending-action meta on every early return and exception

**What shipped:** A lifecycle method writes 'pending action' meta (for example a scheduled-cancel marker) and then returns early when the gateway is missing or the API call returns false, or it throws, without removing the meta. A later cron run finds the stale meta and repeats the action, for example cancelling a subscription an admin has since reactivated.

**Detect by:** In methods that set scheduling or pending-state meta, check every `return` and `throw` after the write. Cleanup must happen in a `finally` block or equivalent. Also confirm that the cron consumer re-checks the record's current state before acting on old meta.

---

### Do not let a new write path move a revoked record back to a usable state

**What shipped:** **(security)** A new entry point (for example a remote deactivate action) calls an existing model method that sets status to inactive when its last child is removed, without checking the current status. A disabled or refunded record becomes inactive and can be reactivated. Similarly, a later upsert for the same email flips an unsubscribed row back to active while leaving its unsubscribe date set, re-entering it into automated emails.

**Detect by:** For each new write entry point, open every model method it calls and grep for `set_status(`, `->status =` and `'status' =>`; list which prior states each write can overwrite and confirm terminal or revoked states cannot become usable again; flag status guards that block only one transition.

---

### Change a record's status through the model's transition method, not a raw status write

**What shipped:** Code sets a record's status column or meta directly (`$wpdb->update( ..., array( 'status' => ... ) )`, or a raw `UPDATE ... SET status = %s WHERE id = %d AND status = %s` for a compare-and-set) where the model exposes a cancel/complete/set_status method. That skips what the method does: firing the transition action (`transition_post_status` or the plugin's own status-changed hook), writing the status-change note, updating the modified date, syncing child rows, cleaning the object cache and making any required remote call. Listeners and audit logs miss the change.

**Detect by:** When a diff writes a status column or meta directly, check whether the model has a transition method; if it does, require it. For any remaining raw `UPDATE ... SET status` or raw `post_status` write, confirm the code then fires the same transition action with old and new status, updates the modified date and cleans the cache.

---

### Skip side effects when a status update does not change the status

**What shipped:** A status-update endpoint writes, logs a note, or re-stamps a 'paid'/'completed' timestamp even when the requested status equals the current one. Some data layers report a no-op update as success, so a retried request adds misleading audit notes and moves the original date, shifting the record into a different report period.

**Detect by:** In a new status setter or endpoint, look for an early return when `$current === $new` before the write, the note and any date stamp. Check whether the update call returns success for unchanged rows (`$wpdb->update()` returns 0, which wrappers may treat as true). Endpoints clients may retry make this a data bug.

---

### Resume a chunked batch job without truncating output or skipping failed items

**What shipped:** Resumable CLI or cron jobs lose data on resume. An export reopens its output with `fopen( $path, 'w' )` on every run, truncating rows written by earlier chunks. An import advances its checkpoint by the full batch size or to the highest successful index even when some items failed, so the resumed run starts past the failures and never retries them.

**Detect by:** In any job with a resume or checkpoint option, check that `fopen()` on the output uses `'a'` when resuming from a non-empty cursor. Find where the checkpoint is saved and confirm it advances only past items that succeeded, or that failed items go to a retry list, rather than `$offset + $batch_size`.

---

### Write dependent fields together with a status change in every branch

**What shipped:** A sync computes a new expiration but writes it only in one mode; in another mode it updates only `status`, so a record reactivated from expired keeps its past expiration and is immediately expired again on the next read.

**Detect by:** Find status updates that reactivate a record; confirm every field the status depends on (expiration, next date) is written in the same update on every branch, and flag a computed value whose write is gated by a mode check the change detection does not share.

---

### Run recovery logic before the guard that requires the data it repairs

**What shipped:** A webhook listener runs its processing method only when a requirements check passes, and that check fails when a related local record is not found by a strict lookup. The fallback that would repair the missing link lives inside the processing method, so it never runs and the event is acknowledged and dropped.

**Detect by:** For each fallback or backfill, check where it is called relative to guard methods (`is_valid_request()`, `can_process()`); flag a repair step placed after a guard that reads the very field being repaired, especially in webhook handlers that already returned 200.

---

### Detect Action Scheduler runs as well as WP-Cron

**What shipped:** A 'doing cron' helper wraps `wp_doing_cron()`, which checks the `DOING_CRON` constant set only by WP-Cron. Action Scheduler runs jobs through its own async runner (and WP-CLI) without that constant, so code gated on the helper silently skips during scheduled jobs.

**Detect by:** Grep for `wp_doing_cron()` or `defined( 'DOING_CRON' )` guards in code that runs from Action Scheduler. Also check `did_action( 'action_scheduler_before_execute' )` or the runner's context, and `WP_CLI` where relevant.

---

### Distinguish 'no output this step' from 'no rows left' in batch jobs

**What shipped:** A batch tool marks itself done when a step produces no output, even though the step did read rows (they simply needed no action). If the latest page of records needs no fixes, the tool reports 'no data' and never processes older records.

**Detect by:** In batch `process_step()` methods, confirm completion is decided by the underlying query returning zero rows, not by an empty output array. Test with a first page that needs no changes followed by pages that do.

---

### Remove only the sent items when flushing a stored buffer

**What shipped:** A sender reads queued events from an option, posts them, then resets the option to empty. Events recorded by concurrent requests during the remote call are deleted unsent, and an empty payload still wipes the queue. Sibling buffers drained the same way have the same loss.

**Detect by:** Find queue or buffer options and transients drained by a cron or sender (`get_option` -> `wp_remote_post` -> `update_option( $name, array() )` / `delete_option`). Require removing only the sent keys after a fresh re-read, or an atomic swap, and no reset when nothing was sent.

---

## Dates, numbers and money

### Keep UTC and site-local time separate in date math

**What shipped:** Code mixes UTC timestamps with site-local ones. Examples: a UTC datetime stored in a custom table is shown with `date_i18n( $format, strtotime( $value ) )`, so the time displays in UTC or on the wrong day; a stored UTC expiration is compared with `current_time( 'timestamp' )` (offset-shifted), so records expire early or late by the GMT offset; a value already converted to local time goes through a helper that adds the offset again; report boundaries computed in site-local time (`strtotime( 'yesterday' )`) are compared with UTC-stored dates; a timezone label formatted from `'now'` shows the summer abbreviation for a winter date. Tests that hard-code an offset or abbreviation (`-4`, `EDT`) fail after a DST change. A stored UTC date string compared directly with a Unix timestamp or a site-local 'now' never matches, so time-based sends never happen.

**Detect by:** Grep for `current_time( 'timestamp' )` compared with stored UTC values (use `time()`), `date_i18n(` fed by `strtotime()` of a UTC string (use `get_date_from_gmt()` or `wp_date()`), integer offsets added to timestamps, `new DateTimeZone( 'EST' )`-style abbreviations instead of IANA names, and report ranges that mix `strtotime()` with `gmdate()`. For each conversion, trace whether the value is UTC or local at every step and confirm the offset is applied exactly once. Flag comparisons or arithmetic between stored date strings and `time()`/`strtotime()`/`current_time( 'timestamp' )` that do not first convert both sides to one type and timezone; for UTC columns compare with `time()` or `strtotime( $str . ' UTC' )`.

---

### Send and export machine-readable amounts, not display-formatted ones

**What shipped:** A refund amount for a payment-gateway API is built with the site's display formatter, so `1234.56` goes out as `"1,234.56"` and comma-decimal sites send `"12,50"`; the gateway rejects or misreads it. `number_format()` without explicit separators inserts commas, and unrounded floats are sent as amounts. CSV exports write locale-formatted amounts that importers reject, and titles with raw HTML entities (`&amp;`, `&#8211;`).

**Detect by:** In gateway, REST and webhook payload builders (`amount`/`value`/`total` keys), grep for `number_format(`, `number_format_i18n(` or display/format helpers; payload amounts must be `sprintf( '%.2f', ... )`, a normalize helper, or integer minor units with no locale separators. In CSV/JSON/XML exports, flag display formatters and `esc_html()`/`get_the_title()` on cell values; use raw rounded numbers and `html_entity_decode( ..., ENT_QUOTES, 'UTF-8' )` or `wp_specialchars_decode()`.

---

### Round computed money amounts to currency precision before storing

**What shipped:** A percentage-based amount is stored straight from float arithmetic (`9.6`) in a zero-decimal currency. Rows round for display (`10`) while totals come from `SUM()` over stored floats (`91.1999` to `91`), so rows do not add up to the total. Splitting a discount across lines and rounding each share independently leaves the shares a cent off the discount; the last line should take the remainder.

**Detect by:** Wherever an amount is computed (`* $rate / 100`, splits, discounts, averages) and saved, confirm it is rounded to the currency's decimal count before the write, not only at display. Flag inserts of amount columns fed by float math, `SUM()` totals over columns that display rounds per row, and allocation loops that round every share without assigning the remainder to the last one.

---

### Use a complete zero-decimal currency list when converting to minor units

**What shipped:** A gateway adapter converts amounts to minor units with its own short list of zero-decimal currencies and falls through to `amount * 100`. A charge or refund in any omitted zero-decimal currency (BIF, ISK, UGX, XAF, XOF and others) asks the gateway for 100 times the intended amount.

**Detect by:** Grep `* 100`, `/ 100`, `round( $amount * 100` next to gateway API calls, and local arrays of currency codes. Require the gateway library's canonical zero-decimal and three-decimal handling or a complete list, applied the same way on charge, refund and webhook amount parsing.

---

### Extract tax from tax-inclusive amounts instead of adding to them

**What shipped:** Tax is derived as `amount * rate` from an amount that already includes tax, or a charge is sent as `gross_amount + tax` when the gross already contains the tax. Each case overcharges. A rate helper also returns mixed units across its branches (a fraction in one, a percentage in another).

**Detect by:** Grep for `* $rate` and `amount + tax` sums on values documented or named as gross, total or recurring amounts. The tax contained in a gross amount is `amount - amount / ( 1 + rate )`. Check that every branch of a rate helper returns the same unit.

---

### Parse locale-formatted amounts with a separator-aware parser, not a float cast

**What shipped:** An edit form pre-fills an amount input with a display-formatted value (thousands separator, decimal comma), and the save handler parses it with `(float)` or `floatval()`, which stops at the first non-numeric character. Re-saving the record for any reason truncates `1,234.00` to `1` and `12,50` to `12`.

**Detect by:** For every input whose value is printed through a number or currency formatter, find its save path and flag `(float)`, `floatval()`, `(int)` or `intval()` on the raw posted value. Require the formatter's inverse sanitizer (or an unchanged-value short-circuit) and a test that posts the value exactly as rendered under a non-default separator setting.

---

### Pass a timestamp, not a date string, to date_i18n() and wp_date()

**What shipped:** A template passes a stored MySQL datetime string (`'2024-01-20 10:00:00'`) as the timestamp argument of `date_i18n()`. The function expects an integer and falls back to the current time, so every row shows today's date.

**Detect by:** Grep `date_i18n(`, `wp_date(`, `date(`, `gmdate(` whose second argument is a DB column or object property rather than an int. Convert first (`strtotime()`, `mysql2date()`, `get_post_timestamp()`), and confirm the stored string's GMT-vs-local meaning matches the function used.

---

### Avoid date_default_timezone_set() in plugin code

**What shipped:** Plugin code changes PHP's default timezone with `date_default_timezone_set()`. WordPress expects it to stay UTC, and every later `date()`/`strtotime()`/`DateTime` in the request inherits the change, so records created later get wrong dates. Setting it to the site's configured zone also fails for sites using a manual UTC offset, whose id (`GMT-08:30`-style) is not a valid zone.

**Detect by:** Grep `date_default_timezone_set(`; each call is a defect unless restored in a `finally` on every path. Use explicit zones: `new DateTimeImmutable( 'now', wp_timezone() )`, `wp_date()`. Flag `get_option( 'timezone_string' )` or derived ids passed to `DateTimeZone` without handling empty values or manual offsets (`wp_timezone()` handles both).

---

### Do not run relative date math against a value that may still be empty or a sentinel

**What shipped:** A refactor moves an end-of-month adjustment ahead of the assignment it depends on, so `strtotime( $expiration . ' +2 days' )` runs while `$expiration` is still `''` and resolves relative to now. Related cases: a stored start time can be a sentinel string like `'never'` and is passed as `strtotime()`'s base timestamp (a TypeError on PHP 8), a duration unit from configuration is not a time unit so `strtotime()` returns `false` and the UI shows a 1970 date, and a strict `===` compares `cal_days_in_month()` (int) with `date( 'j' )` (string) and is never true.

**Detect by:** Grep `strtotime(` and `date(` calls whose argument concatenates a variable; confirm the variable is assigned on every path before use and validated as a date or timestamp; check the second argument is an int; check for `false` returns; flag strict comparisons between `date()` output (string) and integer functions.

---

### Make a date range's end bound cover the whole final day

**What shipped:** A report normalizes both bounds of a date range to start of day and queries `date > start AND date < end`. The end bound becomes midnight of the last day, so everything on the final day (including today) is excluded. Re-parsing bounds a shared helper already converted to UTC shifts them again.

**Detect by:** In report and export date filtering, check the end bound is end of day (`23:59:59`, `endOfDay()`, or next-day exclusive) and that already-converted bounds are not re-parsed. Flag `startOfDay()`, `setTime( 0, 0 )` or `date( 'Y-m-d 00:00:00' )` applied to an end date, and `<` used with an end-of-day bound.

---

### Compare timestamps and tolerances in the same unit

**What shipped:** A webhook replay check compares a tolerance defaulted in seconds (`300`) against `Date.now()` minus a header timestamp produced as `round( microtime( true ) * 1000 )`. Both timestamps are milliseconds, so the window is 300 ms and normal clock drift rejects valid signed requests. The same class appears when PHP `time()` meets JS `Date.now()`.

**Detect by:** Grep `Date.now()`, `getTime()`, `microtime( true ) * 1000` and `time()` on either side of a comparison or subtraction against a window, TTL or skew. Confirm operands and threshold share a unit; flag `* 1000` or `/ 1000` on only one side, and seconds-named settings compared against millisecond differences.

---

### Compare and dedupe emails and normalized strings case-insensitively

**What shipped:** A handler checks whether an email is already on an account with a case-sensitive `in_array()` against only the primary address, so a case variant is added again as a new address. A related bug: code compares `strtoupper( $code )` with a lowercase literal, so one branch can never be true and its inverse always runs.

**Detect by:** Grep `in_array(`, `===`, `array_search(` and SQL `=` on email values and confirm both sides go through `strtolower()` (or a case-insensitive collation) and that all stored emails are searched. Grep `strtoupper(`/`strtolower(`/`.toUpperCase()`/`.toLowerCase()` results compared with a literal; the literal must be in the normalized case, or use `strcasecmp()`.

---

### Compute page counts from an unpaged total and round up

**What shipped:** A front-end list computes its total from the same paged query it renders (capped at the default page size) and computes pages with `round( $total / $per_page )`. Users never see more than one page, and a remainder below half a page is dropped. A batch routine computing steps with `round()` skips trailing items.

**Detect by:** Grep `round( $a / $b )` and `floor(` in page or step count math; it should be `ceil()` (or `max( 1, (int) ceil( ... ) )`). Confirm the total comes from `found_posts`, a `COUNT(*)` query, or a count-only arg, not `count()` on a result set that already has a page limit.

---

### Do not multiply quantity into a line total that already includes it

**What shipped:** Report code computes a line's value as `quantity * price` where the stored price is already the quantity-inclusive, post-discount line total, so multi-quantity lines are counted quantity-squared in reports and running totals.

**Detect by:** Grep `['quantity'] *`, `* $item['quantity']` and `->quantity *`. For each, confirm from the producing code or schema whether the multiplicand is a unit price or a line total; flag multiplication against fields named or documented as total, subtotal or amount. Require a test with quantity of 2 or more.

---

### Validate dates for calendar validity, not just format

**What shipped:** A date input is accepted when it matches a `YYYY-MM-DD` regex, so impossible dates such as February 31 pass and are rolled over by `strtotime()` or `DateTime` into another day.

**Detect by:** Find date params validated only with `preg_match` or `strtotime() !== false`; require `checkdate()` or a `DateTime::createFromFormat()` round-trip comparison.

---

### Verify a stored tax rate is still active before reusing it

**What shipped:** Renewal or derived orders reuse the tax rate referenced by the original order without checking that rate is still active. When an administrator updates a region's rate, the old row is deactivated, but renewals keep charging the stale rate.

**Detect by:** Find code that reads a stored rate id or rate value from a parent record to compute a new charge; require a check that the referenced rate is still active, falling back to the current active rate for the same region.

---

### Resolve inherited dates before storing or displaying a 0 timestamp

**What shipped:** A child record meant to inherit its parent's expiration stores or returns `0` when its own value is empty. The UI shows 0 as a 1970 date and treats the record as expired (or as lifetime, depending on the branch).

**Detect by:** In code that resolves inherited dates or limits, flag paths that return a raw `0`/epoch for a child without reading the parent. Check that every consumer handles `0` consistently: lifetime and unset must mean one thing everywhere.

---

### Do not build identity or dedup keys with an ASCII-only filter

**What shipped:** A dedup key is built with `preg_replace( '/[^a-zA-Z0-9]/', '', $name )`. Non-Latin names (CJK, Arabic, Cyrillic) collapse to an empty string, so distinct records share a key and later ones are silently dropped as duplicates.

**Detect by:** Grep `preg_replace` with `[^a-zA-Z0-9]` or `[^A-Za-z0-9_-]` (and `sanitize_key()` / `sanitize_title()` used for identity) on user-visible names that feed a unique key, hash or array index. Require a Unicode-aware class `/[^\p{L}\p{N}]/u`, or hash the raw value.

---

## Payments and subscriptions

### Recompute prices server-side instead of trusting client-supplied amounts

**What shipped:** **(security)** A cart or checkout path reads a price or discount from client-controlled input (a cart item options array, a request field) instead of recomputing it from the product or price record, so a caller can set an arbitrary price. Manual or programmatic order creation that takes item amounts from the request has the same flaw.

**Detect by:** Grep price/discount filters and order-creation helpers for monetary values read from cart item options, `$_POST` or `$_REQUEST`; require amounts to be derived from the database record keyed by a validated id.

---

### Reject webhook and IPN notifications that fail verification

**What shipped:** **(security)** IPN or webhook verification is skipped in test or sandbox mode, or a postback result other than a clean VERIFIED is processed anyway. With some IPN protocols the postback echoes the caller's own body, so an attacker can force the ambiguous result.

**Detect by:** Grep the verification branch of every payment notification handler. Verification (signature check or postback) must run in every mode, and anything other than an explicit success must stop processing.

---

### Check per-payment status, not just the API envelope, before completing an order

**What shipped:** **(security)** Order completion is gated on the gateway's request-level acknowledgement (`Ok`, `Success`), but the per-payment status inside it is Pending (eCheck, review, bank transfer) or declined, so the order is fulfilled before or without settlement. Variants: completing orders before the provider's asynchronous fraud review passes, and completing from an instant notification whose signature covers only ids, trusting unsigned status and amount fields instead of re-fetching the order from the API and matching the reference with `hash_equals()`.

**Detect by:** In completion paths, confirm the per-transaction status/response code is checked (completed/approved) and that pending payments leave the order pending with a note; for notifications, check which fields the signature covers and require a server-side re-fetch plus amount and reference matching before completing.

---

### Create the order before confirming the charge

**What shipped:** The browser confirms a payment intent (charging the customer) before the server has created the order, and a later AJAX request creates it. An interruption leaves an orphan charge. A retry or page reload rebuilds the charge request and mutates or re-creates an intent that already succeeded, or builds a new order, so the customer is charged a second time.

**Detect by:** In client-confirmed payment flows, confirm the order record exists before confirmation. Retry and reload handlers must read the existing intent status server-side; a succeeded intent must route to the existing order-completion path instead of being mutated or re-created, and recovery must complete the existing order instead of creating a new one. Use idempotency keys on intent creation and retries.

---

### Share an idempotency check between webhook and synchronous completion

**What shipped:** A webhook handler and a checkout or AJAX handler both complete the same credit or renewal, with no shared idempotency key or "already applied" marker, so the credit is applied twice when both run.

**Detect by:** Find every writer of a given credit, renewal or fulfillment; confirm they check and set the same idempotency marker on the order or subscription (ideally atomically) before applying.

---

### Treat an "already captured" gateway response as success, not a decline

**What shipped:** A confirmation handler's decline branch special-cases only one error code. A duplicate or "already completed" code, which the gateway returns because a previous timed-out or concurrent attempt already captured, falls through to marking the order failed and sending the shopper back to checkout, so a paying customer is charged again and the first capture has no local record.

**Detect by:** Inspect gateway error branches that mark orders failed; require duplicate/already-captured codes to re-read the remote order and complete (or leave pending), and confirm the transaction id is persisted immediately after an acknowledged capture, before later steps that could fail.

---

### Hold the lock across the gateway call when creating local records

**What shipped:** The local order or subscription row is created only after the gateway call returns, and no lock is held across the call, so a timeout, fatal or concurrent request during that window leaves an orphaned gateway object with no local record.

**Detect by:** Find gateway create calls followed by local inserts; require a pending local record (or a held lock/claim) before the remote call and reconciliation afterward. Treat a window as long as a gateway round trip as routine, not an edge case.

---

### Compare a gateway-notified amount numerically and against the order's stored currency

**What shipped:** An incoming payment notification's amount is compared loosely as a string and its currency is ignored, so a malformed or different-currency payment can pass. The opposite mistake: the handler compares the notified currency with the store's current base currency, so orders placed in another currency, or before the base currency changed, fail verification and stay pending.

**Detect by:** In webhook/IPN handlers, require `is_numeric()` validation and a numeric compare at currency precision, plus a currency equality check that reads the currency stored on the order or payment, not a site setting via `get_option()`, with case normalized on both sides.

---

### Normalize gateway refund amounts before deciding full versus partial

**What shipped:** A gateway notification handler compares the refunded amount to the order total to choose full or partial refund. The gateway reports refunds as negative amounts, so every full refund is recorded as partial. Comparing each refund to the original total means several partials adding up to the full amount never mark the order refunded; the comparison is a raw float compare without rounding, and the notification's currency is never checked against the order's. Separate notification channels carry duplicated copies of the logic that drift.

**Detect by:** In gateway notification handlers, find the full/partial refund branch. Confirm the amount goes through `abs()` (or the gateway's sign convention is handled), is rounded to currency decimals, is compared to the remaining refundable amount while accounting for already-recorded local refunds, and that currency is checked; zero amounts and already-refunded orders short-circuit. Flag duplicated decision logic across notification handlers.

---

### Do not extend access from a gateway's billing-period end without proof of payment

**What shipped:** An expiration sync copies a gateway's reported current-period end into a local subscription or access expiry without checking the gateway's subscription status or whether a completed payment covers the new period. Gateways can advance the period end even when the renewal charge fails, so a failed renewal grants a free cycle, and the free time compounds on later renewals.

**Detect by:** Grep gateway sync code for reads of `current_period_end`, `next_billing_date` or similar that flow into an expiration write. Require a check of the gateway's status (active or trialing, not past_due, unpaid or incomplete) and of a paid invoice or completed local order for that period.

---

### Route refunds and cancellations by an explicit per-order version marker

**What shipped:** After a store migrates a payment gateway integration from an older API version to a newer one, refunds and cancels are routed by the store-wide version option, or by a meta key or option that both paths write (or only the new path writes). Orders created before the migration, which only have the old API's identifiers, go down the new path and fail silently because it has no credentials for them. A cancel path gated on 'new API connected' fails once old credentials are removed, and a health check reports every old-path store as disconnected.

**Detect by:** In refund, cancel, capture and connection-status code, find the version discriminator. It must be an explicit per-order (or per-store) marker recording which API created the record, with the old path kept working for old orders. Flag store-wide options, meta-key presence checks and new-flow-only options used as version switches, and confirm both paths cannot satisfy them.

---

### Persist checkout data on the order before completion instead of reading the session

**What shipped:** Post-payment provisioning hooked to order completion reads the shopper's browser session or cart and returns early when it is empty. When the order is completed server-to-server (a gateway webhook, cron, or an admin completing a held order) there is no session, so the customer is charged and nothing is provisioned. The data must be frozen onto the order while the session is live.

**Detect by:** In handlers hooked to order/payment-complete actions, grep for session reads (`$_SESSION`, `$_COOKIE`, cart or session getters, `get_current_user_id()`) and early returns when empty. Check whether the same hook fires from webhook, REST, cron or admin contexts; the data must come from the order record or meta captured at checkout.

---

### Fire the same post-processing actions in overridden checkout paths, after records are written

**What shipped:** A gateway variant overrides the base checkout routine and returns before the action the base flow fires after creating subscription records. Other code hangs cleanup on that action, such as cancelling the subscription being replaced, so on the variant the old subscription stays active and the customer is billed twice. Firing the action before the records are written is also wrong: a failed write still triggers the irreversible cancellation with no replacement. The variant also builds records from the purchase session without checking that the session belongs to the order just captured.

**Detect by:** When a gateway or subclass overrides or short-circuits a base checkout routine, list every `do_action()` the base fires and confirm the override fires each one. For actions whose listeners cancel, refund or revoke, confirm the action fires after the records are written and passes only records that were written. Flag cart or session data used to write records with no check that its key matches the captured order.

---

### Check every status list in lifecycle queries for the missing status

**What shipped:** Status allow- and deny-lists in lifecycle queries leave out a status the job must handle. An expiration-reminder query excludes `pending` and `trash` but not `active`, so auto-renewing subscribers get both renewal and expiration notices. A renewal flow looks up the old subscription with a status allow-list of active, trialing and past due, leaves out `expired`, finds nothing, and skips cancelling the old gateway subscription, which can then bill again.

**Detect by:** List every status allow- or deny-list (a `WHERE status IN` clause or a query-arg array) in reminder, renewal, upgrade and cancellation code, and walk each status in the model through it. Ask whether a record in that state should be included, and whether a `can_<action>()`-style guard that rejects a status needs a context-specific override. A status left out of a lookup makes the action silently do nothing.

---

### Handle distinct terminal states separately instead of one early return

**What shipped:** A gateway cancel method returns `false` early for both an already-cancelled and a delinquent (unpaid) remote state via one `in_array()` check, without calling the API or flagging the record for attention. The local record is marked cancelled while the remote one stays active and could still collect payment. A related case: an atomic `UPDATE` treats a database error (`false`) and zero matched rows (`0`) as the same outcome.

**Detect by:** Grep `in_array( $status, array( ... ), true )` early returns in gateway or state-transition code; confirm each grouped state really needs identical handling and that guard/attention flags are set. For `$wpdb->query()` / `$wpdb->update()`, check `false` and `0` are distinguished with strict comparison.

---

### Set the charge amount before the overrides that change it

**What shipped:** A payment processor runs the free-trial or zero-total override (`$amount = 0`) first, then assigns `$amount` from the cart price further down, overwriting it. A trial combined with a discount then sends a non-zero amount to the gateway and charges the customer.

**Detect by:** In payment-processing functions, trace each assignment to the amount sent to the gateway. Initialization must come before every conditional override, and no later line may reset it. Add a test for trial plus discount and for zero-total carts.

---

### Recompute stored totals when their components change

**What shipped:** A charge, credit or proration reads a stored amount or total that a new discount, tax or line-item path no longer keeps in step, so the charged amount disagrees with its components.

**Detect by:** When a diff adds a path that changes discounts, taxes or line items, list every reader of the stored total/recurring amount and confirm the total is recomputed or the reader derives it from components.

---

### Re-validate a payment amount against the value recorded at creation, not the live total

**What shipped:** A later step in a multi-step checkout re-checks a payment intent's amount against the order's current total. In flows where the total legitimately changes after the intent is created, the guard rejects a payment it already validated correctly.

**Detect by:** Wherever a payment or intent amount is re-validated after creation, check what it is compared with. If it reads a mutable order field instead of a value stored on the payment object at creation (gateway metadata, a stored amount-at-creation), flag it and list the legitimate mutations between the two steps.

---

### Clear a charge-gating flag on every payment-completing path

**What shipped:** A flag that gates whether a reactivation charges is cleared only in the reactivation handler. Payments completed through update-payment-method or an invoice webhook leave it set, so a later cancel and reactivate within the already-paid period charges again.

**Detect by:** For each flag read before a charge or credit decision, enumerate every payment-completing path (synchronous checkout, update-payment-method, each webhook, admin action, cron) and confirm each clears the flag on success or routes through one shared clearer.

---

### Check the paid period before charging on reactivation

**What shipped:** A reactivation path charges the customer without checking whether the current paid period has ended, so reactivating before expiration charges twice for the same period.

**Detect by:** Find reactivate or renew paths that call the gateway; require an `expiration > now` (period already paid) branch that reactivates without charging.

---

### Read subscription state flags from the order that writes them

**What shipped:** A guard reads a decision flag (for example "replaced by another plan") from the subscription's original order, but the writer stores it on the most recent order, which is a renewal for any subscription that has renewed. The guard never sees it, and a subscription that should be blocked is reactivated and billed.

**Detect by:** For each state meta a guard reads, find where it is written and confirm the guard checks the same set of records (the parent order and every renewal), not only the original one.

---

### Run alternate checkout endpoints through the standard validation and login steps

**What shipped:** A custom REST endpoint for an express or card-only payment flow builds the order as an anonymous guest regardless of the registration or login fields the buyer filled in. It skips the normal checkout validation, user creation and auth-cookie steps, and ignores the 'guest checkout disabled' setting.

**Detect by:** For REST or AJAX controllers that create or capture orders outside the main checkout handler, confirm they call the same user-validation, registration, login and guest-checkout checks as the standard path. Diff the two paths step by step.

---

### Do not anchor recurring billing to an end-of-day access expiration

**What shipped:** Renewal charges are gated on `now >= expiration`, but expiration is normalized to `23:59:59`, so the charge cannot fire until the next day, and the next period is computed from the late fire time. Daily plans drift to every other day and renewal dates land a day late.

**Detect by:** Find renewal triggers comparing now to an access-expiration timestamp; flag expirations normalized to end of day used as a billing anchor, and next-date calculations based on the actual run time instead of a fixed billing anchor.

---

### Attach a payment method with the full billing address when the gateway needs it

**What shipped:** An update-payment-method flow creates the new payment method with only name and email in billing details, and the embedded payment form is configured to collect only country and postal code. Later off-session charges fail where a full address is required, and the server branch that would copy the address is dead because the client always posts a flag that skips it.

**Detect by:** Check client `createPaymentMethod` / `confirmPayment` calls include `billing_details.address` when the product needs it, check the payment form's address-collection setting, and confirm server branches gated on client-posted flags are reachable.

---

### Record price modifiers as order adjustments

**What shipped:** A custom checkout flow (renewal or upgrade) applies a discount by changing the cart price but writes no discount line or adjustment, so the order shows the full price and a lower total with no explanation.

**Detect by:** When a custom flow changes item prices, confirm a matching discount or adjustment record is written to the order. Compare order subtotal minus adjustments with the total in a test.

---

### Read the billing period from the product when no price option is chosen

**What shipped:** An upgrade or renewal path looks up the billing period by price-option ID and falls back to one year when no option ID is present, so a monthly single-price product gets a yearly expiration.

**Detect by:** In upgrade, renewal and expiration code, find lookups keyed by a price-option ID and confirm the fallback reads the product's own period settings instead of a hard-coded default.

---

### Exclude renewal orders from first-purchase logic

**What shipped:** Review-request or onboarding emails are sent for every completed order, including renewal orders that create a new order record. Customers who already reviewed or onboarded get the email again on each renewal.

**Detect by:** In logic triggered by purchases (emails, rewards, onboarding), confirm order queries exclude renewal or subscription-payment orders by their meta or type, and check whether the customer already completed the action.

---

### Set payment SDK flags only for the carts that need them

**What shipped:** A filter on the payment SDK's script query arguments re-adds parameters already set upstream and forces a subscription-only flag (such as `vault=true`) on every pass, enabling it on plain one-time carts and changing the checkout experience.

**Detect by:** Grep SDK query-arg and data-attribute filters for flags set unconditionally (`'vault' => true`, intent, commit). Confirm each is conditional on the cart contents or flow and that the filter does not duplicate values set elsewhere.

---

## Forms, settings and exports

### Keep form field names in sync with the keys the handler reads

**What shipped:** A refactored template or new front-end implementation renders a field under a new `name`, while the shared server-side processor still reads the old `$_POST` key. The value is always missing, so validation or the action silently does nothing. The same drift happens between camelCase keys in a JS AJAX payload and snake_case keys read in PHP, and when a bulk-action field is renamed without updating the handler. Within one codebase, a render path can name an input differently from the key the processor reads (for example a confirm-password field), so the action always fails, or a base field class assumes the submitted name equals the DOM id.

**Detect by:** When a form has several implementations (shortcode and block, legacy and new widget) or a JS payload feeds a PHP handler, diff every `name=` attribute or payload key against the `$_POST`/`$_GET`/`$request` keys the processor reads. Flag renames in a diff that touch only one side. Grep hardcoded field-name literals in render and processing code; every path should use the field object's name/id accessors, and subclasses whose submitted key differs from their DOM id must override the name accessor.

---

### Read a checkbox map by stored value, not by key presence

**What shipped:** A multi-checkbox setting is stored as a `key => '1'|'0'` map, so every key stays present after it is unchecked; a consumer that builds the enabled list with `array_keys( $option )` or `isset( $opts[ $k ] )` treats unchecked items as enabled. The same mistake appears when a writer always sets a flag key to `false` and a reader tests `isset( $errors['x']['critical'] )`, so every entry looks critical. On the save side, browsers omit unchecked checkboxes, so a handler that only updates `if ( isset( $_POST['x'] ) )` raises notices or keeps the old true value and the option can never be turned off.

**Detect by:** Grep for `array_keys( $opt )`, `isset( $opts[ $k ] )`, `array_key_exists(` or `in_array( $k, array_keys(` on values from `get_option()`/settings getters that back toggle or multicheck fields, and for `isset()` on keys whose writer can store `false`/`0`. Require filtering on the value (`array_filter`, `! empty()`, `'1' === $v`). For every `<input type="checkbox">`, confirm the save treats a missing key as off (`! empty( $_POST[...] )` then store false/delete) or the form emits a hidden off-value input first. Flag `(bool) $data['checkbox']` without an existence check.

---

### Treat a field absent from the request as unchanged in save handlers

**What shipped:** A metabox handler on `save_post` does `if ( isset( $_POST['field'] ) ) update_post_meta(...) else delete_post_meta(...)`, and its nonce guard is `isset( $nonce ) && ! wp_verify_nonce(...)`, which passes when the nonce is missing. Quick Edit, bulk edit, REST saves and `wp_update_post()` never post the metabox, so every such save silently turns the setting off. A settings sanitize callback that removes stored keys absent from the current request has the same effect: saving one settings section wipes fields registered in other sections.

**Detect by:** For every `save_post` / `save_post_{type}` / `edit_post` callback, confirm an early return when its own nonce field is missing (`! isset( $_POST[n] ) || ! wp_verify_nonce(...)`), on autosave/revision and for other post types, before any write. Flag `else { delete_post_meta(...) }` branches keyed only on `! isset( $_POST[...] )`. In `register_setting` sanitize callbacks, flag code that unsets stored keys not present in the input; remove a key only when submitted empty or no longer registered.

---

### Check validation errors before writing state or showing a generic error

**What shipped:** **(security)** A checkout start routine fires its validation hooks but never checks the collected error bag before continuing, so customer or session writes run even when validation refused the request. An unauthenticated visitor who knows a customer's email can change that customer's stored name or address. A sibling AJAX path throws a generic 'error processing' message before reading the error bag, which hides the real validation message.

**Detect by:** After validation hooks fire, confirm the code returns when the error collection is non-empty, before any customer, session or meta write and before any generic fallback error is built. Surface the specific errors to the client.

---

### Validate every value the save path writes

**What shipped:** **(security)** A multi-value field's validator does not inspect every value that is persisted. Format, URL or extension checks are nested inside `if ( required )`, so an optional field saves unvalidated values. Or the validator iterates one sub-array and indexes a sibling by the same keys while the saver iterates the sibling directly, so entries whose key is absent from the first array (or a request omitting the first array) are written without the URL/ownership check.

**Detect by:** For fields with separate `validate()` and `save()`/`sanitize()` methods, compare the loops: the validator must iterate exactly the collection the saver writes (same array, same keys). Flag validators wrapped wholesale in `if ( $this->required() )`; required-ness should gate only the emptiness check, never format or ownership checks. Test with a key present only in the saved array and with the field optional.

---

### Make every user-facing string translatable and load translations correctly

**What shipped:** Translation breaks in several ways: English connectors (`' by '`, `' on '`) or fallback labels are concatenated outside `__()`; fragments are concatenated instead of using `sprintf()` placeholders; plurals are fixed ('1 times') instead of `_n()`; `_x()` lacks a context; textdomains are missing or differ in case; `load_plugin_textdomain()` gets an absolute path instead of one relative to `WP_PLUGIN_DIR`; the loader is removed in a refactor; `__()` runs at include time or on `plugins_loaded`, triggering WordPress 6.7's `_load_textdomain_just_in_time` notice and caching wrong-language strings before multilingual plugins set the locale; a link string puts only the URL in a placeholder so translators can break the markup; a `wp_localize_script` key the JS reads is never passed, so the English fallback always ships.

**Detect by:** Grep templates for bare English literals concatenated into output. Check every `__()`/`_e()`/`_x()`/`_n()` call for the exact textdomain and `_x()` context. Confirm `load_plugin_textdomain()` runs on `init` with a relative path, and that no translated string or translatable option is evaluated at include time. Flag translatable strings with more than one `translators:` comment, and link strings that do not wrap the whole anchor in `%1$s...%2$s`. Compare JS reads of localized objects with the keys passed in PHP.

---

### Gate every entry point of a toggleable feature behind the same flag

**What shipped:** A setting enables or disables a feature, but the check is added only in the loader. Email tags, shortcodes, admin menu items, or REST routes registered in other files still run when the feature is off, leaving orphan UI or broken output.

**Detect by:** When a diff adds an enable/disable setting, grep for every registration point of the feature (`add_shortcode`, `register_rest_route`, `add_menu_page`, email-tag registration, `add_action`/`add_filter` calls) across all files and confirm each is gated by the same check.

---

### Make hidden inputs neither required nor submitted

**What shipped:** An input that stays in the DOM but is hidden carries a hardcoded `required` (and a `name`). The browser refuses to submit ('invalid form control ... is not focusable'), or the field leaks into submitted data. Examples: login fields on a hidden login form, inputs from an embedded secondary form, native selects hidden by an enhanced-select library, and fields whose visibility JS controls but that render `required` on load.

**Detect by:** Grep templates for `required` on inputs that can be hidden by layout, JS or an enhanced-select library. The attribute (and `name`, if the value must not submit) must depend on the same visibility condition, or be toggled by the JS that shows and hides the field.

---

### Merge stored nested settings over defaults recursively

**What shipped:** A settings getter merges stored settings over defaults with a shallow `array_merge()` or `wp_parse_args()`. When a release adds a key inside a nested group, every object saved earlier has that whole group replaced by its old stored sub-array, so the new nested default never applies and readers hit undefined keys. `array_replace_recursive( $defaults, $saved )` fixes it.

**Detect by:** Grep `array_merge(` with a defaults array, `wp_parse_args(` and `+ $defaults` where any default value is itself an array. Require `array_replace_recursive()` or an explicit per-group merge, especially for JSON or serialized settings blobs in options, meta or post content.

---

### Split composite id values before casting to int

**What shipped:** A dropdown submits composite values like `514_2` (object id plus sub-option id), and the save handler runs it through `absint()`, which yields `514` and silently discards the sub-id. Every saved record loses its variant, and a later null sub-id can trigger PHP 8 deprecations in string functions. The same loss happens when a comma-separated id list is passed through `intval()`. A sibling handler may also parse the value but assign it to a property that is never persisted.

**Detect by:** When a `<select>`/hidden input emits a composite value (`{$id}_{$sub}`, `id:sub`, `id|sub`, `1,2,3`), grep the save handler for `absint(`/`intval(`/`(int)` on that field; it must be split (`explode()`) and each part validated. Confirm add and edit handlers parse it identically and write each part to a real column.

---

### Remove stale defaults when a setting is deleted

**What shipped:** A setting is removed from the UI, but a helper still reads it with a non-empty default (`get_option( 'removed_key', 'full' )`). Fresh installs never have the option, so they always get the default, which here enables a payment method and requires fields that are no longer shown, blocking checkout.

**Detect by:** When a diff deletes a settings key, grep the codebase for every read of that key and its fallback value. A leftover non-empty default behaves as if the old setting were always on. Test on a fresh install with no saved options.

---

### Always include the saved value in a select built from a limited query

**What shipped:** A metabox or settings `<select>` builds its options from a query capped to the first N results and marks the saved value as selected. When the saved object is outside that page (or its label no longer resolves), no option matches, the field renders blank, and re-saving the screen submits an empty value that deletes the stored setting.

**Detect by:** For every `<select>` (including AJAX/enhanced selects) that renders a persisted value, find the options source. If it is limited (`get_posts`/`WP_Query` with `posts_per_page`/`number`, a helper with a default limit), confirm the saved id(s) are fetched by id and injected before rendering, and that an unresolvable stored value is preserved rather than replaced by the blank option.

---

### Compute list-table totals once with the same filters as the data query

**What shipped:** A `WP_List_Table` shows wrong totals: status or total counts ignore the active filter or search, or `$this->total_count` is overwritten by a second, filter-scoped query, so pagination and view counts disagree with the rows shown.

**Detect by:** In `WP_List_Table` subclasses, confirm `set_pagination_args()` and the total count are assigned once from a dedicated count query that applies the same `WHERE` clauses as the item query. Flag a second assignment inside `prepare_items()` or a method it calls.

---

### Filter in SQL, not PHP, when batch exports paginate

**What shipped:** A batch exporter's `get_total()` and `get_data()` query every row and filter (for example by country) in PHP. The step count is inflated, and each page keeps only part of the rows it fetched, so data is dropped on large stores. The same exporter hardcodes a status list instead of the plugin's shared, filterable status helper, and ignores partial refunds in its totals.

**Detect by:** In paginated exporters, confirm that `get_total()` and `get_data()` use the same `WHERE` clause and that no rows are discarded in PHP after `LIMIT`/`OFFSET`. Grep for hardcoded status arrays where a filterable helper exists. Check that financial totals subtract refunds.

---

### Build every CSV export row from one helper that matches the header columns

**What shipped:** An exporter builds row arrays separately in each filter branch. One branch omits a key and trailing columns that the header declares, so every value after it shifts one column left and the last columns come out empty.

**Detect by:** In CSV exporters, grep for more than one `$data[] = array(` / row literal. Each branch's key set must equal the header's keys in order. Prefer a single row-builder, and assert `array_keys( $row ) === array_keys( $columns )` in tests for every filter path.

---

### Apply create-time defaults only on create

**What shipped:** A shared create/update save handler assigns default derived values (rates, owner, status) on every save, so a later update by a lower-privileged owner resets values an admin customized after creation.

**Detect by:** In handlers serving both create and update (`save_post` with `$update`, `$is_new` flags, `wp_insert_post` vs `wp_update_post` branches), confirm defaults are written only on create or only when the stored value is absent. Flag `update_*_meta( ..., <default> )` executed unconditionally on update.

---

### Persist and render the saved order of sortable settings

**What shipped:** A sortable multi-check setting lets users drag to reorder and the front end honours the saved order, but the admin screen renders options from a hard-coded array, and saving without dragging overwrites the stored order. Unsetting keys absent from the submitted form also resets the order data.

**Detect by:** For sortable settings, confirm the render callback builds the list in the stored value's key order (appending new options) and the sanitize callback preserves order and keys not present in the submission.

---

### Re-emit the screen's query args in admin GET search forms

**What shipped:** A `WP_List_Table::search_box()` is rendered inside a `method="get"` form without hidden inputs for the screen's `page` (and `post_type`) args, so submitting a search drops them and WordPress returns 'Sorry, you are not allowed to access this page.'

**Detect by:** For every `search_box(` / custom `<form method="get">` on a plugin admin page, confirm hidden inputs re-emit every query arg the screen URL needs (`page`, `post_type`, `view`, `tab`). Flag GET forms on `admin.php?page=` screens with no `<input type="hidden" name="page"`.

---

### Set an async save's dirty baseline from the payload sent, not from live state

**What shipped:** A settings screen sends a field group only when it differs from a saved baseline, then on AJAX success sets the baseline from the current model. Edits made while the request was in flight are marked saved and never sent.

**Detect by:** In JS save handlers that compare against a `loaded*` / `original*` / `saved*` baseline, check what the success callback assigns: it must be the value captured before the request, never a fresh read of the model or form inside `.then` / `success`.

---

### Keep previously valid options in refactored option lists

**What shipped:** A refactor moves a frequency dropdown into a registry array and omits one value ('1 month'). Users who had saved that value can no longer see or keep it, and no error is raised.

**Detect by:** When an option list moves or is rewritten, diff old and new values and confirm every previously supported value remains, or that a migration maps saved values. Check that saved values not in the list are still displayed.

---

### Do not label historical report data only from the current registry

**What shipped:** A report enumerates the currently registered options (such as payment methods) to label and group stored rows, so rows recorded under a since-removed option vanish from historical totals.

**Detect by:** When removing an entry from a registry, search reports, exports and admin lists that iterate the registry to interpret stored values. Keep a legacy label or fall back to the raw stored value so historical rows still count.

---

### Take mode from the request instead of the global setting

**What shipped:** An AJAX handler serving one specific form calls a 'get current mode' helper, and that helper falls back to the site-wide setting because the form never posts its mode. When the site setting differs from the form that submitted, the server runs the wrong flow and returns a generic error, even though part of the operation already succeeded.

**Detect by:** Grep AJAX/form handlers that call mode or variant helpers which read only stored settings. The submitting form should post its mode explicitly (or the handler should pin it), and the helper should prefer request context over the global option when more than one mode can be active.

---

### Report effective settings values, not raw stored options

**What shipped:** A telemetry or reporting collector reads raw options. When a store never saved a default (relying on the 'first enabled' fallback), it reports an empty string instead of the value in use. A collector that iterates only registered settings drops settings that are registered conditionally, so a feature mode with a meaningful default is missing from the data.

**Detect by:** In telemetry, analytics and diagnostics code, flag direct option reads for settings with implicit defaults or runtime resolvers, and loops over registered settings only. Use the same resolver the runtime uses, with explicit fallbacks for conditionally registered settings.

---

### Add new control types to type-keyed cast lists

**What shipped:** A collector casts settings to int based on a whitelist of setting types (`checkbox`, `number`). A new boolean control type is not on the list, so its values come out empty instead of `0`/`1`.

**Detect by:** When a PR adds a settings control type, grep every switch or `in_array()` keyed on setting type (sanitizers, casts, telemetry, export/import) and confirm the new type is handled.

---

### Keep an admin notice's show-condition no broader than the control it points to

**What shipped:** An admin notice is shown based on one computed state, while the settings control its call-to-action tells the user to change is rendered under a different, narrower condition. Sites in the gap see a persistent notice pointing at a control that does not exist on their screen. A variant shows a non-dismissible notice to every user with a lower capability while its action link is only handled for `manage_options`, so lower-role users get a permanent notice whose link does nothing.

**Detect by:** For each admin notice whose call-to-action names a setting or action, diff the notice's show-condition (state checks and `current_user_can()`) against the field's registration/render condition and the action handler's capability check. Flag any notice that can display when the field is hidden or the handler would refuse the viewer.

---

### Keep a feature setting and its email's enabled state in sync

**What shipped:** Enabling a feature setting does not activate the email template row that the feature relies on, which already exists with a disabled status, so the feature's emails are never sent.

**Detect by:** When a feature has both a settings toggle and a stored email or template record with its own status, confirm that saving the setting updates the record, or that the email's enabled check reads the feature setting at runtime.

---

## Remote APIs and HTTP

### Validate remote URLs before fetching them (SSRF)

**What shipped:** **(security)** A fetch routine passes a stored or request-supplied URL straight to `wp_remote_get()` or `wp_remote_post()`, sometimes with `sslverify` disabled, and returns the response to the caller, so anyone can make the server request internal hosts. Indirect fetchers have the same issue, for example `wp_get_image_editor()` or download helpers given URLs from a remote response. `wp_http_validate_url()` alone does not reject every private range, such as link-local 169.254.0.0/16 and CGNAT 100.64.0.0/10. Guards that run `filter_var( $host, FILTER_VALIDATE_IP )` on a host from `wp_parse_url()` miss IPv6 literals, which keep their brackets (`[::1]`), so the value is treated as a hostname and the private-range check is skipped.

**Detect by:** Grep `wp_remote_get(`, `wp_remote_post(`, `wp_remote_request(`, `download_url(` and `wp_get_image_editor(` with a URL from options, meta, request input or a remote response. Require `wp_safe_remote_*` or `wp_http_validate_url()` plus an http/https scheme check, a host allowlist where possible, a resolved-IP check that blocks private, loopback and link-local ranges and fails closed on unresolvable hosts, and SSL verification left on. Strip brackets with `trim( $host, '[]' )` before IP validation, and test with `http://[::1]/`.

---

### Attach stored credentials only to allowlisted provider hosts

**What shipped:** **(security)** An API client stores an OAuth token as an `Authorization` header on a reusable request handler, and another method reuses it for an absolute URL taken from the request or from an option (a base-URL guard using `isset()` lets an empty string through). The token is delivered to any host a low-privilege user or option writer names, including internal hosts. Combined with `sslverify => false`, even legitimate requests are interceptable.

**Detect by:** Grep for `Authorization` / `Bearer` header construction and follow every `wp_remote_*` / `wp_safe_remote_*` call that sends it. Flag calls whose URL is not a constant provider base URL (from `$_POST`/`$_GET`, meta, options, or a response field). Require an HTTPS plus exact-host allowlist (`wp_parse_url( $url, PHP_URL_HOST )`) before attaching credentials, and `reject_unsafe_urls` where the URL is configurable. `wp_safe_remote_*` blocks internal IPs but does not stop exfiltration to a public attacker host.

---

### Do not disable TLS verification on outbound requests

**What shipped:** **(security)** API clients pass `'sslverify' => false` to `wp_remote_get()`/`wp_remote_post()` as a workaround for hosts with outdated CA bundles. That disables certificate validation, so a network-position attacker can intercept the request and the credentials or tokens it carries.

**Detect by:** Grep `'sslverify'\s*=>\s*false`, `CURLOPT_SSL_VERIFYPEER => false` and `https_ssl_verify` filters returning false, especially on requests carrying credentials or tokens. WordPress ships its own CA bundle, so require the flag to be removed.

---

### Check is_wp_error() before indexing an HTTP response

**What shipped:** An error handler receives the raw `wp_remote_get()` return and reads `$response['response']`. On a transport failure the return is a `WP_Error` object, so indexing it as an array is a fatal 'Cannot use object of type WP_Error as array', which hides the real connection error and breaks the recovery flow.

**Detect by:** Grep `wp_remote_(get|post|request|head)(` and `wp_safe_remote_*(` results and every function they are passed to. Before `$response['...']` or `json_decode( $response['body'] )`, the value must pass `is_wp_error()`; prefer `wp_remote_retrieve_*()` helpers. Pay special attention to error-handler helpers, which by construction receive the failure case.

---

### Require a positive success signal from state-changing remote calls

**What shipped:** A cancel/refund/delete routine treats the remote call as failed only when the response has one specific error shape (for example both an error code and a message). Timeouts returning `null`, non-2xx responses without a message, and other shapes fall through to success, so the local record is marked cancelled while the remote side keeps billing. Variants: `if ( $result )` on a function that returns an id or a truthy `WP_Error`; `! empty( $body['success'] )` accepting the string `"false"`; and a reconciliation job treating any error (auth, rate limit, 5xx) as 'record not found' and changing local state during an outage.

**Detect by:** Find remote calls that change state (cancel, refund, delete, capture, revoke). Flag success decided by absence of an error, `if ( ! is_wp_error( $r ) )` without checking `wp_remote_retrieve_response_code()`, truthiness checks on functions that can return `WP_Error`, and `! empty()` on remote boolean fields. Success must be a positive check on the documented success value; null, `WP_Error`, non-2xx and unparseable bodies take the failure path, and only a definitive not-found response may change local record state.

---

### Check fetch() status and the admin-ajax success flag before using a response

**What shipped:** Front-end code injects a `fetch()` response body into the UI without checking `response.ok`, so a 4xx/5xx error page renders as content or breaks JSON parsing. Separately, `wp_send_json_error()` still returns HTTP 200 with `{success:false,data:{message}}`; a client that treats any 200 as success, and reads `response.message` instead of `response.data.message`, shows a success toast for a refused save.

**Detect by:** Each `fetch(` / `await fetch` `.then( r => r.json() )` must first check `r.ok` or the status. For calls to admin-ajax handlers that can call `wp_send_json_error()`, check the client branches on `response.success === false` before the success path and reads `response.data.message`. Grep success notices inside `.then` / `.done` callbacks that never test `.success`.

---

### Back off on remote errors and stop retrying terminal failures

**What shipped:** A remote call (registration, verification or a cached fetch) runs on every `admin_init`, cron run or admin load and fails identically each time, because nothing records a terminal failure and the cache TTL ignores the response code. A persistent 401/403/429 then floods the remote service and the error log. Transient failures retry with no backoff, auth rejections are not paused like rate limits, a non-JSON response is classified as transient regardless of status so permanent 4xx errors retry forever, and a parser that reads only one documented response shape fails and retries on every page load.

**Detect by:** Grep remote calls hooked to `admin_init`, `init`, `wp_loaded` or cron, and `set_transient`/`update_option` around `wp_remote_*` calls. Errors must be classified: terminal (including 4xx even when the body is not JSON) stores a stop flag and short-circuits; transient gets exponential backoff via a timestamped option or a cooldown transient cleared on success. Confirm 401/403 pause the job as 429 does and that response parsing accepts every documented shape.

---

### Key cache freshness on expiry, not on an empty payload

**What shipped:** A cached-remote-data helper re-requests whenever the stored value is empty rather than when it has expired. An endpoint that legitimately returns nothing, or a site with no credential, then fires a doomed request on every call, adding latency to a hot path.

**Detect by:** In cached remote fetches, confirm the refresh condition checks a stored expiry timestamp or transient, not `empty( $data )`. Confirm the request is skipped entirely when a required credential (API key or token) is missing.

---

### Degrade gracefully when a third-party validation service is unavailable

**What shipped:** A tax-ID or address validation service returns a service-unavailable status, and the code cannot tell "service down" from "invalid input": it shows the raw upstream message and blocks checkout. A related variant: a marketing-list subscribe after a successful action throws on an API timeout, and the uncaught exception turns the main response into a 500.

**Detect by:** For each remote validation call in a checkout or form flow, check that unavailability statuses (5xx, 412, timeouts, `WP_Error`) are handled separately from a definitive invalid result and do not block the user (proceed, mark pending, re-validate asynchronously). Wrap optional side-effect calls in `try { } catch ( \Throwable $e )` and log, so they cannot fail the primary request.

---

### Do not mark a connection invalid on transient or permission API errors

**What shipped:** A remote-API error handler flags the stored connection as broken for every error passing a broad 'critical' check, including rate limits and missing-scope errors. The flag drives a reconnect prompt, so a working token is shown as broken and users are told to reconnect, which cannot fix a rate limit or grant a scope.

**Detect by:** Where an API error sets an `error`/`status`/`needs_reconnect` flag or deletes a token, list the error codes that reach it. HTTP 429 and vendor throttle codes, timeouts, 5xx and permission errors must not; only auth or token-invalid codes should. Check every write site.

---

### Do not hardcode the /wp-json/ REST path

**What shipped:** Client code builds REST URLs as a literal `/wp-json/...`. On plain-permalink sites that path 404s because the REST root is `/?rest_route=/`, and query arguments appended with `?` also break since the root already contains a query string.

**Detect by:** Grep JS and PHP for the literal `/wp-json/` and `'wp-json'` concatenation. Require `rest_url()` / `get_rest_url()` server-side and `wpApiSettings.root` or a localized root client-side, and join query args with `add_query_arg()` or the URL API rather than a literal `?`.

---

### Allow the host before switching an intentional off-site redirect to wp_safe_redirect()

**What shipped:** A redirect to an external payment or OAuth provider is switched to `wp_safe_redirect()`. The host is not in `allowed_redirect_hosts`, so the user is silently sent to the `admin_url()` fallback and never reaches the provider.

**Detect by:** For every `wp_safe_redirect()` or safe-redirect wrapper, check whether the target can be an external provider URL. If so, add the host through the `allowed_redirect_hosts` filter, or use `wp_redirect()` with a URL built only from trusted parts, followed by `exit`.

---

### Build idempotency keys from the occurrence, not only the entity id

**What shipped:** An outbound event or webhook client sets the idempotency key to a value fixed per entity (`'activated:' . $id`), or uses the same key for two different lifecycle events (cancel and expire both emitting `ended:<id>`). The receiving API treats the repeat as a retry and drops it, so a second activation or the expiry after a cancellation is never recorded.

**Detect by:** Grep `idempotency_key`, `Idempotency-Key` and `md5(`/`sha1(` key builders in event dispatchers. The key must include the event type and an occurrence id or timestamp, not just `$object->id`; static keys are fine only for true one-shot backfills. Check that sibling handlers emitting the same event name use distinct keys.

---

### Paginate remote list endpoints instead of trusting the first page

**What shipped:** A third-party REST list endpoint is requested once with the provider's default page size, and the first page is treated as the full set. Items past the default (often 30) never appear, and if the provider does not honour sort order the visible subset is arbitrary.

**Detect by:** Grep `wp_remote_get(`/SDK list calls against paginated APIs. Confirm an explicit `per_page`/`limit` and a loop until there is no next page (empty page, `Link: rel="next"`, `has_more`/cursor) with a sane upper bound, and client-side ordering when the API does not sort.

---

### Re-register a site URL with a remote service only from production

**What shipped:** A reconcile or key-rotation routine treats any difference between the current site URL and the URL stored at a remote service as a legitimate domain move, and re-registers. A production site cloned to staging, where hosts rewrite the domain, then moves the live registration to staging and breaks production webhooks. A related bug sends `site_url()` where `rest_url()` is built from `home_url()`.

**Detect by:** Grep remote registration and reconcile logic triggered by URL drift. Re-registration must be gated by a production-URL check (or an explicit admin action), and the registered URL must come from the same base WordPress uses for `rest_url()`/`home_url()`.

---

### Enforce the remote API's field length and charset before sending

**What shipped:** Payload fields built from customer or product data are sent to a third-party API without the provider's limits applied. Accented characters are rejected or mangled by an API that accepts a restricted charset, and a description longer than the provider's maximum makes every such transaction fail validation. A brand or merchant name taken from `get_bloginfo( 'name' )` is empty on sites with a blank Site Title, and the gateway's minimum-length validation rejects every order.

**Detect by:** Where a request for a remote API is built (SDK setters or array payloads to `wp_remote_post`), check every free-text field from user/product data against the provider's documented max length and charset. Truncation must be multibyte-safe (`mb_substr`), and normalization (`remove_accents()`, transliteration) must happen before sending. Require a non-empty fallback (for example the host from `wp_parse_url( home_url() )`) for user-editable settings sent to required fields.

---

### Send only documented fields to a payment API's address object

**What shipped:** A payment confirmation includes a `company` key inside `billing_details.address`. The gateway rejects unknown keys there, so payments fail or data is dropped. A guard existed for one extra field but not for the other.

**Detect by:** Compare arrays sent to gateway address objects such as `billing_details.address` with the documented schema (`line1`, `line2`, `city`, `state`, `postal_code`, `country`). Map other fields to their documented top-level keys or omit them.

---

### Guard optional properties on webhook payload objects

**What shipped:** A subscription-updated webhook handler reads `$event->object->plan->amount` unguarded, but the gateway only populates the top-level `plan` for single-item subscriptions; multi-item subscriptions send `null`, and every such event throws a warning or error.

**Detect by:** Grep webhook handlers for chained property reads (`->plan->`, `->price->`, `->latest_invoice->`) on payload objects; check the gateway's documentation for nullable fields and require `isset()` / null-safe access before use.

---

### Expand or list sub-resources a payment API no longer returns by default

**What shipped:** Code reads `$customer->subscriptions->data` on a gateway customer object retrieved without `expand`, but newer API versions stopped including that sub-list by default, so the property is always null and the tool fatals. In the same method a misspelled variable inside an `isset()` guard turns a check into a silent no-op.

**Detect by:** Grep for property chains into expandable sub-lists of retrieved gateway objects (`->subscriptions->data`, `->sources->data`) and require an explicit `expand` or a dedicated list call; check variables inside `isset()` / `empty()` are spelled like their assignments (static analysis flags undefined variables).

---

### Do not fire a blocking remote token fetch once per rendered button

**What shipped:** A purchase-button render path enqueues the gateway script with a force-load flag, and that flag also makes the page count as checkout, so a blocking server-side token request fires once per button on archive pages (N buttons, N round trips) even though the token is only used on the real checkout page.

**Detect by:** Find remote calls made during script registration or per-item rendering; confirm the gate uses the real page condition (not a force-load flag), and that the result is memoized in a static or request-level cache so it runs at most once per request.

---

### Do not rely on cookies from an admin-ajax request reaching a follow-up REST call

**What shipped:** After an AJAX add-to-cart, the front end fetches cart contents from a REST route, relying on a session cookie set during the AJAX request. On hosts with aggressive caching or cookie handling, the cookie does not reach the REST request and the cart comes back empty or 401. Client-side nonce expiry checks based on a timestamp in `sessionStorage` add false failures.

**Detect by:** For front-end flows that chain `admin-ajax.php` and REST requests, check that the second request does not depend on cookies set by the first. Return the needed data in the first response, or send `X-WP-Nonce` and handle 401/403 by refreshing. Flag client-side nonce validity checks; let the server decide.

---

### Request context=edit before reading content.raw and writing it back

**What shipped:** A read-modify-write of post content fetches a `wp/v2` post in the default `view` context, which returns only `content.rendered` and no `raw` key. A `content.raw || ''` fallback turns the missing field into an empty string, and the follow-up update overwrites the post content with it.

**Detect by:** Grep `.raw` reads (content, title, excerpt) on `wp/v2` responses and confirm the request carries `context=edit` (which needs an edit-capable nonce). Flag `?.raw || ''` fallbacks that feed a later POST/PUT of the same field.

---

### Ship a production endpoint as the default remote API base URL

**What shipped:** A new remote-API integration defines its default base URL as a local development host. Installed sites send every request to their own loopback, so the feature silently does nothing in production.

**Detect by:** Grep `define()` / `const` / default option values and `wp_remote_*()` targets for `localhost`, `127.0.0.1`, `.test`, `.local`, tunnel or staging hosts. A dev override belongs behind an `if ( ! defined( ... ) )` guard whose default is the production https URL.

---

## JavaScript and the block editor

### Declare every script that provides a global you use as a dependency

**What shipped:** A script uses a global (a select library, `jQuery.fn.dialog`, `$.fn.ajaxForm`, `$.fn.suggest`, `wp.media`, or a `@wordpress/*` package that webpack externalizes to `window.wp.*`) whose providing handle is not in its registered `$deps`, working only because another script happens to enqueue it. Script optimizers, reordering, or the other script being dropped produce `X is not defined` or a TypeError that aborts initialization so every later handler fails to bind. Mapping only `jQuery` to the external while code uses `$` throws `$ is not a function`. Related variants: reading another plugin's localized object on screens where it is not printed, reading a localized object at module scope when it was localized onto a handle you do not depend on, and using `wp.media` without `wp_enqueue_media()`.

**Detect by:** For each `wp_register_script` / `wp_enqueue_script`, list the globals and jQuery plugins the file uses and confirm each providing handle (`jquery-ui-dialog`, `jquery-form`, `suggest`, etc.) is in `$deps`. When externals or imports change, compare each bundle's `@wordpress/*` imports with the `wp-*` handles in its dependency array, or load the generated `*.asset.php` file. Confirm every global alias used in source (`$`, `jQuery`) maps to the external, for example with `ProvidePlugin`. Check `wp_enqueue_media()` accompanies `wp.media`; confirm `wp_localize_script` / `wp_add_inline_script` targets the handle that reads the data; guard optional plugin calls with `typeof $.fn.x === 'function'`.

---

### Check that a DOM lookup matched before chaining onto it

**What shipped:** A script reads `$('#field').val().trim()` or `document.querySelector(sel).offsetWidth` without checking that the element exists. Layouts that render different markup (block vs shortcode, a stale `?tab=` value that matches no element) throw `Cannot read properties of undefined` and stop the rest of the script.

**Detect by:** Grep `.val()`/`.value` chained into `.trim()`/`.toLowerCase()`, and property reads on the result of `querySelector`/`getElementById`/a selector built from a query string, with no length or null check first. Each lookup that can miss in another layout needs `if ( ! el ) return;`.

---

### Drop stale async responses and release UI locks on failure

**What shipped:** A JS handler fetches data for the selected inputs and applies the response when it arrives even if the selection changed meanwhile, so the form saves a result that no longer matches. A save lock or disabled state is also cleared only in the success callback, so a failed request leaves saving blocked.

**Detect by:** In `fetch` / `$.ajax` / `apiFetch` handlers, check that the response handler compares the request's inputs (or a request counter) with current state before applying the result, and that locks (`lockPostSaving`, `disabled`, spinners) are released in `finally` / `.always()`.

---

### Keep variables used by sibling callbacks in a shared scope

**What shipped:** A `const`/`let` declared inside an AJAX `.done`/`success` callback is referenced in the sibling `.fail` callback, which throws `ReferenceError` because block scope is not shared. The same happens when helper functions are declared inside an init closure but called from a function defined at outer scope, so the caller throws on first use and later work (for example loading the rest of a gallery) never runs.

**Detect by:** In `$.ajax({...}).done(...).fail(...)` chains, list `const`/`let` declarations in one callback body and grep the sibling callbacks for the same names. For any function declared at module or outer scope, confirm every helper it calls is declared in that scope or above, not inside another function's closure.

---

### Wrap top-level const, let and class in classic scripts

**What shipped:** Two separately enqueued non-module scripts each declare `const Core = window.Core;` at top level. Classic scripts share one global lexical scope, so the second throws `SyntaxError: Identifier 'Core' has already been declared` and none of it runs. Minified builds wrapped in an IIFE can hide the bug, so only unminified (`SCRIPT_DEBUG`) loads break.

**Detect by:** In JS enqueued with `wp_enqueue_script()` (not a module, not bundled into an IIFE), grep top-level `const `, `let ` and `class ` declarations. Require an IIFE or block wrapper, or properties on a `window` namespace object; compare the unminified source with the minified output's wrapper.

---

### Scope JS for repeatable widgets and shortcodes to each instance

**What shipped:** Scripts for a shortcode or widget update the DOM with `#form_<id>` selectors or a single `.find()` across the page, and renumber items across all instances at once. With two instances for the same item on one page, only one updates and indexes desync, so later actions affect the wrong item.

**Detect by:** For any shortcode, widget or block that can render more than once per page, grep its JS for `$( '#...' + id )`, `getElementById(` and page-wide counters over `$( '.class' )`. Require per-instance scoping (`.each()` over containers, `closest()`) and unique or attribute-based selectors.

---

### Give success and failure paths the same event payload shape

**What shipped:** A JS event is triggered with a structured payload on success (`{ response: { total: ... } }`) but the failure path passes the raw `jqXHR` object. Listeners that read `data.response.total` get `undefined` and take the wrong branch, for example hiding notices even though the recalculation failed.

**Detect by:** When a diff standardizes a custom event's payload, compare the object built on the success path with the one built on the failure path: same keys, with empty or null values where needed. Grep every listener of the event for nested property reads and confirm each property exists on both shapes.

---

### Return a JSON error that stops the client loop when a stepped AJAX job is refused

**What shipped:** A batch export/import AJAX handler answers a failed capability or nonce check with a bare `die`, `-1` or `wp_die()` string (HTTP 200), while the client step loop expects JSON. The loop reads the response as a step, computes the next step as `NaN`, and posts again forever; the failure handler only logs, so the button stays disabled with its spinner. A related variant returns failure through a helper that only sends on success, so admin-ajax ends with `0` and the error message is lost.

**Detect by:** In AJAX handlers that drive a step or poll loop, grep refusal branches for `die(`, `wp_die(`, `exit`, `echo -1`, `check_ajax_referer(` with default die, and helpers that only send on success. Each must return the JSON shape the client checks, such as `wp_send_json_error( $data, 403 )`. In the client, confirm a response without a valid step stops the loop and that `.fail()`/`catch` re-enables the control and shows the message.

---

### Recompute submit-button validity after every field change and never gate on a field that may be hidden

**What shipped:** A purchase button's enabled state is derived from a validity check that does not re-run, or does not reflect the field the user just fixed, so the button stays disabled until the user edits another field; other listeners on the same page can hide the bug in some configurations. A variant: a hosted payment form hides some fields (for example postal code) depending on card country, so that field's changed event never fires, its per-field validity flag stays false, and a button that requires every flag stays disabled forever for those customers.

**Detect by:** Find button-enable gates driven by `checkValidity()`, custom validators or per-field validity flags. Confirm they re-run on `input`/`change` for every relevant field and evaluate each input's current state. For each flag, check whether it is set only by an event an embedded third-party form may never emit; rely on the provider's overall validity event or treat hidden fields as valid. Test with optional listeners (taxes, coupons) both on and off.

---

### Validate the scheme and host of URLs read from the DOM before navigating

**What shipped:** **(security)** Admin JavaScript passes a URL from a `data-*` attribute, a localized config object or a return-URL parameter straight to `window.open()` / `window.location.href`. A `javascript:` URL runs script, and an attacker host becomes an open redirect. Server-side `esc_url()` on the attribute does not protect a value the DOM code later navigates to.

**Detect by:** Grep JS for `window.open(`, `location.href =`, `location.assign(`, `location.replace(` whose argument comes from `.attr('data-`, `dataset.`, `getAttribute(`, a localized object or a query parameter. Require `new URL(value)` with `protocol` in `['http:','https:']`, plus a host allowlist when the destination should be fixed.

---

### Use functional state updaters in async React callbacks

**What shipped:** An admin React list does an optimistic update and, in a separate in-flight request callback, calls `setList( listCapturedAtClickTime.filter( ... ) )`. When two operations overlap, the later callback writes back the stale array and silently reverts the other change; rapid checkbox selection loses selections the same way.

**Detect by:** Grep `set[A-Z]\w*\(` inside `.then(`, AJAX callbacks, `setTimeout` or `useCallback` bodies whose argument derives from a state variable in scope (`list.filter`, `[ ...list,`, `list.map`). Require `setX( prev => ... )` whenever the update depends on previous state and can run after another update.

---

### Support the iframed block editor: apiVersion 3, enqueue_block_assets and the canvas document

**What shipped:** Recent WordPress versions render the editor canvas in an iframe when blocks declare `apiVersion: 3`. A block registered below version 3 in JS or PHP forces the editor out of iframe mode. Styles or scripts the block preview needs that are enqueued only on `enqueue_block_editor_assets` load into the outer admin document, so the preview renders unstyled or broken; removing an `enqueue_block_assets` callback has the same effect. Editor-side JS that finds block content with `document.querySelector()` searches only the parent document and finds nothing inside the canvas.

**Detect by:** For each `registerBlockType(` / `register_block_type(` / `block.json`, check `apiVersion` is 3 in both JS and PHP. Grep `enqueue_block_editor_assets` callbacks for assets the rendered block needs; those belong on `enqueue_block_assets` (guarded with `is_admin()` if front-end loading is unwanted) or in block.json `editorStyle`/`style`/`viewScript`. Flag canvas CSS passed via `block_editor_settings_all` `styles[]`. In editor JS, grep `document.querySelector(` / `jQuery( document )` targeting block content or `.editor-styles-wrapper`; require the canvas document (`iframe[name="editor-canvas"]` contentDocument or the block ref's `ownerDocument`).

---

### Keep the old attribute schema and a migrate() in block deprecations

**What shipped:** A block is restructured and attributes are removed from `block.json`, while the new deprecation entry uses `attributes: metadata.attributes` and `save: () => null` with no `migrate`. Since the attributes were removed, the deprecation declares an empty schema; old blocks load as valid with empty attributes and the loss becomes permanent on the next save.

**Detect by:** When a diff changes a block's `save` or structure: diff `block.json` attributes and check whether any deprecation references them via `metadata`; confirm each `deprecated` entry hard-codes the old attribute schema and the old `save`; confirm a `migrate()` maps old attributes onto the new structure or inner blocks. Flag invalid `supports` keys not in the block.json schema.

---

### Never set a block's save to null

**What shipped:** A block registration sets `save: null`, which is not a valid value, so the block fails to register and stops working.

**Detect by:** In `registerBlockType()` calls, flag `save` set to `null`/`false`/`undefined`. Use a function returning `null` for dynamic blocks, or omit `save`.

---

### Guard register_block_type() against a missing block directory

**What shipped:** Block registration passes a computed absolute directory to `register_block_type()`. WordPress treats a string as a `block.json` directory only if that path exists; otherwise it treats it as a block name. When build assets are missing, the path is validated as a name, triggers `_doing_it_wrong`, and the block is not registered under its real name.

**Detect by:** Find `register_block_type( $path )` calls with a computed directory (under `build/` or `vendor/`). Require a `file_exists( trailingslashit( $path ) . 'block.json' )` guard, with a fallback to registering the literal lowercase `namespace/name` plus a `render_callback`.

---

### Import editor slot-fills from their current package

**What shipped:** A plugin adds a sidebar button with `PluginPostStatusInfo` from `wp.editPost`, which moved to `wp.editor` in WordPress 6.6. The old import emits deprecation warnings and will stop working.

**Detect by:** Grep for `wp.editPost.PluginPostStatusInfo`, `PluginSidebar`, `PluginMoreMenuItem` and other slot-fills imported from `@wordpress/edit-post`; on WordPress 6.6+ import them from `@wordpress/editor`, with a fallback if older versions are still supported.

---

### Do not lock movement on blocks users must move between columns

**What shipped:** Inner blocks are given a lock to make them 'moveable but not removable', but a `move` lock pins a block to its current parent. Users cannot drag it into another column of the layout.

**Detect by:** Grep block registration, templates and patterns for `lock: { move: ... }` and `templateLock` on blocks that users are expected to rearrange across containers. Protect required blocks some other way.

---

### Do not call stopImmediatePropagation() in capture-phase document listeners

**What shipped:** A document-level capture-phase click router claims certain clicks and calls `stopImmediatePropagation()` so a competing UI (such as a lightbox) does not open. On the document capture phase that cancels the event for every later listener on every element, so analytics click trackers and other plugins' handlers silently stop firing.

**Detect by:** Grep JS for `stopImmediatePropagation(` and `stopPropagation(` in listeners registered with `addEventListener( ..., true )` / `{ capture: true }` or on `document`/`window`/`body`, including jQuery delegated handlers on `document`. Prefer `preventDefault()` plus a marker on the event that the specific competing handler checks, or a narrower target.

---

### Scope gateway listeners to their own gateway

**What shipped:** One gateway's script binds global listeners on the checkout form and submit button and changes shared button state (`readonly`, a 'updating' data attribute) even when that gateway's element is absent or another gateway is selected. Checkout through the other gateway is blocked.

**Detect by:** In gateway-specific JS, flag listeners on shared form elements that do not first check that the gateway's container exists and that the gateway is selected. Listeners should no-op, or detach, when the gateway is switched away.

---

### Make loading-spinner state an explicit argument

**What shipped:** A shared form-update function is used both when re-rendering and while a submission is in flight. A single default for showing or hiding the spinner fits one path and breaks the other: the spinner sticks on re-render or disappears in the middle of a submit.

**Detect by:** In shared UI-update helpers called from both idle and submitting states, flag loading-state logic that infers context instead of taking it as a parameter. Exercise both call sites.

---

### Reset both result and error state when an async action starts

**What shipped:** A reducer's `*_START` case clears `error` but not the previous `result`, so the UI renders stale success state while the new request runs.

**Detect by:** In reducer diffs, confirm every pending/START case resets both the result and the error fields. Compare sibling START cases for asymmetry.

---

### Pass scalar IDs where a signature expects an ID

**What shipped:** A whole object is passed to a function whose signature is `(templateId, editor)`, so a URL becomes `/[object Object]`.

**Detect by:** Compare call-site arguments with the function definition. Flag any value interpolated into a URL or query string that could be an object, and check TypeScript/JSDoc types for the parameter.

---

### Select list-table check columns by class, not by tag

**What shipped:** Recent WordPress versions moved the list-table row header from the checkbox column to the primary column, so the checkbox cell is now a `td`. CSS and JS using `th.check-column`, and hand-built rows that emit `<th class="check-column">` with tag-qualified styles, stop matching. Bulk buttons never enable and row styling breaks.

**Detect by:** Grep CSS/JS for `th.check-column` and other tag-qualified `.check-column`/`.column-primary` selectors, and grep PHP for hand-emitted `<th class="check-column">`. Use class-only selectors scoped to `#the-list` so they match `th` and `td` and do not hit the select-all header cell.

---

### Use postMessage instead of parent.window access from media-modal iframes

**What shipped:** A custom media-upload tab inside a Thickbox or media-modal iframe returns the selected file by writing to `parent.window.<global>` and calling `parent.window.tb_remove()`. Newer WordPress and browser frame isolation make that throw `SecurityError`, so the insert button does nothing. The fix sends `parent.postMessage( payload, adminOrigin )` and the parent's `message` listener checks `event.origin`.

**Detect by:** Grep admin JS and inline scripts for `parent.window.`, `window.parent.`, `window.opener.` and `top.` property access from iframes. Replace with `postMessage` using an explicit target origin (never `'*'`), and confirm the receiving handler rejects any `event.origin` other than the site's.

---

### Toggle inert, aria-hidden and tabindex=-1 with state instead of hardcoding them

**What shipped:** An accessibility retrofit hardcodes state attributes in templates. `inert` with `aria-hidden="true"` written statically on a live container makes every control inside unclickable and unfocusable (`inert` is inherited and cannot be undone on a descendant). A hardcoded `tabindex="-1"` on a link assumes a sibling is always the tab stop, so in modes where that sibling is hidden nothing is keyboard-reachable. Attributes set once at init on dynamically cloned elements drift out of date the same way.

**Detect by:** Grep templates and JS for literal `inert`, `aria-hidden="true"` and `tabindex="-1"` on interactive elements or their containers. Each needs a condition tied to the state that justifies it (modal open, alternate tab stop visible, element cloned). Check every display mode where the alternate focus target is absent.

---

### Do not bind aria state to the initial prop on an uncontrolled input

**What shipped:** A toggle renders `<input type="checkbox" defaultChecked={checked} aria-checked={checked}>`. Because the input is uncontrolled, the attribute is not updated when the user toggles, so `aria-checked` stays at the initial value and screen readers announce the wrong state.

**Detect by:** In JSX, grep elements using `defaultChecked` / `defaultValue` together with `aria-checked` / `aria-pressed` / `aria-expanded` bound to a prop. Drop the redundant ARIA attribute on native inputs, or make the input controlled.

---

### Do not define React components inside another component's render body

**What shipped:** A child component is declared as a `const` inside its parent component. Every parent re-render creates a new component type, so React unmounts and remounts it, resetting its internal state and focus.

**Detect by:** In `.js`/`.jsx` files, grep `const [A-Z]\w* = (` or `function [A-Z]\w*(` inside another component's body that is then rendered as `<Name />`. Move it to module scope and pass state as props, unless it is only called as a plain function.

---

### Toggle a state class for rating widgets instead of showing hidden layers

**What shipped:** A star-rating widget reveals a hidden 'filled' layer with `.show()`/`.hide()` on hover and click. Hover and click handlers fight over the same elements, so the clicked star does not stay highlighted even though the right value is submitted.

**Detect by:** In rating and similar selection widgets, prefer setting a selected class or `aria-checked` on the chosen element and styling siblings via CSS. Flag `.show()`/`.hide()`/opacity toggling shared by hover and click handlers.

---

### Skip payment SDK updates when the total is zero

**What shipped:** A 100% discount brings the cart total to 0, and a listener calls `elements.update({ amount: 0 })`. A hosted payment element that requires `amount > 0` throws an integration error, which breaks checkout.

**Detect by:** Grep payment-SDK update or initialization calls (`elements.update(`, `.update({ amount`) that take a cart total, and confirm a guard for `amount > 0`. Zero-total and fully discounted carts must skip the SDK call and switch to a no-payment path.

---

### Do not wrap a hex CSS custom property in rgba()

**What shipped:** CSS uses `rgba( var(--color), 0.3 )` where the variable holds a hex color. That is invalid, so the whole declaration is dropped.

**Detect by:** Flag `rgba()`/`rgb()` whose first argument is a single `var()` unless the variable is known to hold comma-separated channels. Use `color-mix( in srgb, var(--x) 30%, transparent )` instead.

---

## PHP and WordPress API semantics

### Guard PHP 8 type-strict functions against null, arrays and false

**What shipped:** Values that can be `null`, `false`, arrays or the wrong scalar reach type-strict functions and fatal or emit deprecations on PHP 8.x. Common shapes: a `NULL` DB column passed to `strtolower()`/`json_decode()`/`trim()`; a request value sent as `field[]=x` passed to `sanitize_email()`, `hash_equals()` or `urldecode()`; `get_option()` returning `false` passed to `array_merge()`; a lookup returning `false` passed to `array_keys()` or read as an object; a non-200 remote response parsed to `null` and passed to `array_key_exists()`; `preg_replace()` returning `null` on malformed UTF-8; a filter callback with a non-nullable scalar parameter receiving `null` from another plugin; implicitly nullable typed parameters (`Foo $x = null`, deprecated on 8.4); undeclared dynamic properties (8.2); `${var}` interpolation (8.2); `FILTER_SANITIZE_STRING` (8.1); legacy `implode( $array, $glue )`; a required parameter after an optional one; stored data that changed from `stdClass` to array between versions.

**Detect by:** Grep for string functions (`strtolower`, `strlen`, `trim`, `str_replace`, `json_decode`) applied to DB, request or remote values without a cast or `?? ''`; array functions (`array_merge`, `array_keys`, `array_key_exists`, `count`, `foreach`) on values that can be `false`/`null`; request values used before `is_string()`/`is_array()` checks; `[A-Za-z\\]+\s+\$\w+\s*=\s*null` parameters without `?`; filter callbacks typed `function x( string $v )`; undeclared property writes; `FILTER_SANITIZE_STRING`; and remote response parsing without a `wp_remote_retrieve_response_code()` check. Normalize legacy stored shapes with a cast at the read boundary.

---

### Guard getters that return false or null before dereferencing them

**What shipped:** A repository getter that returns `false` or `null` on a miss is dereferenced right away: `$order = plugin_get_order( $id ); $order->gateway`. A webhook naming a deleted order, a blank key, or an all-digit key resolved through a by-key lookup triggers 'attempt to read property on bool' or a fatal `update() on false`. A variant guards the id but not the object. Another plucks keys from objects it already holds and re-fetches them through a lookup that can miss.

**Detect by:** Grep each getter documented to return `false`/`null` (`get_post()`, `get_user_by()`, `get_term()`, plugin `get_*()` lookups) where the next statement uses `->` with no `if ( ! $obj )` bail. Pay special attention to webhook/IPN handlers and bulk or retroactive sync loops. Flag a re-fetch of an object the code already has.

---

### Do not use empty() or truthiness on a value where zero or empty string is valid

**What shipped:** `empty()` (and JS truthiness) treats `0`, `'0'`, `0.0`, `''` and `false` as missing, so a valid array index `0`, a zero price index, a min/max of 0 or user id 0 in cron context is rejected or replaced with a fallback (for example the current user). A bare `array_filter( $info ) + $fallback` drops genuine zero ratings or counts and substitutes stale fallback values. An optional `$flag = null` parameter guarded with `empty()` makes omitted and explicit-false indistinguishable. Conversely, an 'inherit default' choice stored as `''` passes an `isset()` override check, so every object on the default overrides the global setting with an empty value.

**Detect by:** Grep for `empty( $...['..._id'] )`, `empty( $..._index )`, `empty( $key )`, `! $id`, `if ( $position )` and bare `array_filter( $x )` where the value is an index, offset, quantity, menu order, price, rating or user id that may legitimately be 0. Require `isset()`/`array_key_exists()`/`null ===`/`??` plus an explicit type/range check, and an `array_filter` callback that drops only `null` and `''`. Where a per-item value can override a global option, confirm the 'inherit' choice uses a non-empty sentinel (e.g. `'site_default'`) or the check compares against it; remember `get_post_meta( $id, $key, true )` returns `''` for a missing key.

---

### Do not use truthiness on WP return values that are never falsy

**What shipped:** **(security)** Code treats a truthy result as success or presence when the API never returns falsy: `wp_update_user()` returns a truthy `WP_Error` on failure, `wp_get_current_user()` always returns a `WP_User` (ID 0 for guests), and a JS `!array` check never fires for an empty array. A password-reset handler that checks `check_password_reset_key()` only against `false`, or skips it, accepts forged or expired keys because the function returns `WP_Error`, never `false`.

**Detect by:** Flag `if ( $result )`/`if ( ! $result )` and `false ===` checks after `wp_update_user`, `wp_insert_user`, `wp_insert_post( ..., true )`, `wp_remote_*`, `check_password_reset_key`, `wp_authenticate`, `wp_signon` and `media_handle_upload`; require `is_wp_error()`. Flag `$user &&` or `instanceof WP_User` as a logged-in check on `wp_get_current_user()`; require `->exists()` or `is_user_logged_in()`. In JS, require `arr.length === 0`. Confirm reset handlers verify the key server-side.

---

### Cast API and database values to the documented type before strict comparison

**What shipped:** Strict comparisons fail because PHP/WordPress APIs and the database return strings or `false`. `-1 === ini_get( 'memory_limit' )` never matches because `ini_get()` returns the string `'-1'`, so a queue relying on it stops silently, and `false !== ''` makes a 'no name' lookup look like a real name. Database values are strings, so strict `!==` against ints makes every row look different: duplicates are created, unchanged rows are rewritten and reported as updated, and already-imported remote ids are imported again on every cron run. A related loop `for ( $i = 0; $i <= $quantity; $i++ )` runs one extra time and creates a duplicate record.

**Detect by:** Grep `===`/`!==` and `in_array( ..., true )` between a literal (`-1`, `0`, `''`, `false`) or an int and the result of `ini_get`, `getenv`, `get_option`, `get_post_meta`, `$wpdb` results or decoded API ids. Check the documented return type and every sentinel (`false`, `null`, `''`, numeric string) and require explicit `(int)`/`(string)` casts on both sides, `empty()`, or the right literal. Grep `for` loops bounded by `<=` a count or quantity.

---

### Validate the shape of a filtered value before using it

**What shipped:** An `apply_filters()` result is used directly in `foreach`, array access or output with no type check, so one bad callback fatals the screen and other consumers (exports, background jobs) of the same value break too. Example: `plugins_api()` returns whatever the `plugins_api` filter returns (default `false`), and callers that check only `is_wp_error()` then dereference it, which fatals on PHP 8 and aborts a whole background loop.

**Detect by:** Grep `apply_filters(` results and functions documented to return `false|object|WP_Error` (such as `plugins_api()`) and require `is_array()` / `is_object()` checks before use; list every consumer of a new public filter, not only the screen in the diff.

---

### Validate id strings as all digits and non-zero before object lookups

**What shipped:** **(security)** Ids from shortcode attributes, requests or stored meta go through `absint()`/`intval()` and straight into lookups. `absint( '29 abc' )` is 29, so a stored value like `827-file.pdf` becomes attachment 827 and can be deleted by a cleanup routine. A non-numeric value becomes 0, and `get_post( 0 )` / `get_comment( 0 )` fall back to the global object, so the wrong object is used; `absint()` of an array is 1.

**Detect by:** Grep `absint(`/`intval(`/`(int)` on `$atts[...]`, request superglobals or `get_*_meta()` values feeding `get_post(`, `get_comment(`, `get_userdata(`, `wp_delete_attachment(`, `wp_delete_post(` or destructive queries. Require `ctype_digit( (string) $v )` (or `is_scalar` + strict numeric check) and `$id > 0`, and skip the call otherwise.

---

### Fully qualify global classes inside namespaced files

**What shipped:** Inside a namespaced file, an unqualified `catch ( Exception $e )` resolves to `Current\Ns\Exception`, which does not exist, so the defensive catch never matches and the error fatals; a `TypeError` is also not an `Exception` at all. The same resolution bites `X::clear()` after a string `class_exists( 'X' )` check (the string is global, the call is not), `new Vendor\Pkg\Cls()` without a leading backslash, and `catch` clauses in a vendor-prefixed (scoped) SDK that still name the original unprefixed exception class.

**Detect by:** In files with a `namespace` declaration, grep for `catch (`, `new `, `::` and `instanceof` with an unqualified or partially qualified class name and no matching `use` import; check that `class_exists( 'X' )` guards are followed by `\X::` calls; in scoped vendor code, confirm catch clauses use the prefixed names; prefer `\Throwable` for last-resort guards.

---

### Match static and instance method calls to their declarations

**What shipped:** An instance method is called statically (`Helper::method()`), which throws a fatal `Error` on PHP 8 (and breaks on PHP 7). The reverse also happens: a method declared `static` uses `$this` and fatals with 'Using $this when not in object context', or a static method on another class is called as `$this->method()`. These often hide in cron or background paths that tests do not hit.

**Detect by:** For each `ClassName::method()` call in the diff (excluding `self::`, `parent::`, `static::` inside the class), confirm the method is declared `static`. For methods changed to or from `static`, grep all callers and all `$this->` uses inside the method. Run PHPStan or an IDE inspection to surface mismatches; `grep -n '::' file | grep -v 'self::\|parent::\|static::'` lists candidates.

---

### Skip items with continue instead of leaving the loop

**What shipped:** A loop building API output uses `return` (or `break`) to skip an item with missing data, so every item after it loses its data or is never processed. In a gateway, a `break` inside a loop that creates one record per subscription keeps only the first record while the full cart is charged. Inside a `switch` nested in a loop, `continue` acts like `break` on the `switch` (PHP warns) and falls through to the rest of the loop body.

**Detect by:** In `foreach`/`while` loops over collections, flag `return` or `break` where the intent is to skip one item, and `break` with comments like 'only one supported' in per-item creation loops. Inside `switch` within a loop, require `continue 2`. Confirm per-order identifiers assigned in a per-item loop are scoped per iteration.

---

### Do not treat a false return from update_option() as a write failure

**What shipped:** `update_option()` (and `_set_cron_array()`, which wraps it) returns `false` both on failure and when the value did not change, including when an alternative backend saved it via `pre_` filters. Code that reports 'could not save' on `false` shows failures for writes that took effect. Conversely, code that clears a pending queue after `update_option()` without any check loses data when the write really failed.

**Detect by:** Grep `if ( ! update_option(`, `false === update_option(`, `false === _set_cron_array(` and `! wp_schedule_*_event(` used as error branches. Require a read-back (`get_option()`, `wp_get_scheduled_event()`) before reporting failure or discarding source data, and treat the return as 'changed', not 'succeeded'.

---

### Slash JSON before passing it to a write API that unslashes its input

**What shipped:** A `wp_json_encode()` string is passed straight to an API that runs `wp_unslash()` on its input: `update_metadata()` and the `update_*_meta()`/`add_*_meta()` wrappers, `wp_insert_post()`/`wp_update_post()`, or a query layer that unslashes on insert. The JSON escape backslashes are removed: an escaped quote or backslash makes the value fail to decode, and `é` becomes `u00e9`, which still decodes and silently corrupts text (`José` becomes `Josu00e9`).

**Detect by:** Grep for `wp_json_encode(`/`json_encode(` results passed without `wp_slash()` to `update_*_meta`, `update_metadata`, `add_*_meta`, `wp_insert_post`/`wp_update_post` (`post_content`, `post_excerpt`), or a custom data layer that unslashes. Require `wp_slash( wp_json_encode( ... ) )` or a store that does not unslash. Test the round trip with a value containing `"`, `\` and a non-ASCII character.

---

### Do not pass `true` as the fourth argument to update_*_meta()

**What shipped:** A meta save passes `true` as the fourth argument to `update_post_meta()`, as if it were a `$unique` flag. The fourth parameter is `$prev_value`, so WordPress only updates rows whose current value equals it; after the first save, edits silently never persist. Wrappers around meta updates carry the same bug.

**Detect by:** Grep `update_(post|user|term|comment|metadata)_meta\(` calls with four arguments, especially a literal `true`/`false`/`1` as the fourth: `update_\w+_meta\([^;]*,\s*(true|false|1)\s*\)`. `$unique` belongs only to `add_*_meta()`. Flag any fourth argument that is not a deliberate previous value, including through wrapper functions.

---

### Re-index after array_filter() or unset() before reading [0] or JSON-encoding a list

**What shipped:** `array_filter()`, `array_unique()`, `array_diff()` and `unset()` preserve keys. Code filters a list and then reads `$items[0]`, which no longer exists when the first entry was removed. A response builds a list, unsets one entry and JSON-encodes it; the non-sequential keys serialize as an object (`{"1":"a"}`) instead of an array, breaking consumers that expect a list.

**Detect by:** Grep `array_filter(`, `array_unique(`, `array_diff(` and `unset( $arr[` followed by `[0]`, indexed `for` loops, or `wp_json_encode` / `wp_send_json` / a REST response. Require `array_values()` around the result, or `reset()` for the first element.

---

### Keep sprintf() arguments in step with the format string's placeholders

**What shipped:** **(security)** A translated message is passed `<a>` and `</a>` arguments but has no `%s`, so the link never renders (extra args are silently discarded). Or a placeholder is removed from a URL format string but its argument stays, so later arguments shift into the wrong slots and a secret value ends up in a different query parameter.

**Detect by:** For every `sprintf(` / `printf(` / `wp_sprintf(` touched in a diff, count the placeholders and compare with the argument count; any edit to the format string must be matched in the argument list. PHPCS `WordPress.WP.I18n` catches only some mismatches in translated strings.

---

### Echo the return value of checked(), selected() and disabled() when called with false

**What shipped:** `checked( $a, $b, false )` (and `selected()`, `disabled()`, `readonly()`) returns the attribute string instead of printing it. A form field that calls it as a bare statement never shows the saved state, so the next save of the form silently clears the setting.

**Detect by:** Grep `(checked|selected|disabled|readonly)\([^;]*,\s*false\s*\)` and confirm each result is echoed or concatenated into the output. A bare statement `checked( ..., false );` is always a bug.

---

### Validate union-typed parameters with instanceof

**What shipped:** A constructor or callback accepts `int|object` (an ID or an already-loaded object) but checks only `is_numeric()`; any other value (string, wrong object, `null`, `false`) is assigned blindly and later property access fatals. The same class of bug appears when a host filter changes an argument from a string to an object between versions and the callback only checks truthiness, or compares the argument to a string literal that no longer matches.

**Detect by:** In functions taking `id|object`, confirm the non-numeric branch checks `instanceof ExpectedClass` and rejects everything else. For callbacks on filters whose argument type has changed across host versions, confirm each accepted type is handled explicitly (`is_string()`, `instanceof`) rather than by truthiness.

---

### Do not dispatch an id-or-name parameter on is_numeric()

**What shipped:** A function accepting either a numeric id or a name/slug/URL picks its branch with `is_numeric()`. A legitimate all-digit name is treated as an id, so the wrong row is acted on or deleted.

**Detect by:** Find functions whose parameter can be an id or a string key and that branch on `is_numeric()`, `ctype_digit()` or an int cast. Split them into explicit by-id and by-name entry points or take a typed argument.

---

### Merge defaults on read as well as on write

**What shipped:** A session or repository `get()` returns stored data as-is, while only `set()` merges defaults. Data written directly by an integration (for example an email only) comes back missing keys, and consumers that read those keys unguarded raise warnings.

**Detect by:** Grep `get()` methods that early-return raw stored arrays. Have `get()` and `set()` share one normalize step that merges defaults, nested arrays included, with `wp_parse_args()` or a recursive merge.

---

### Guard get_permalink() on a stored page id that may be deleted or unpublished

**What shipped:** A return/cancel URL is built as `trailingslashit( get_permalink( $page_id ) )` from a settings-stored page id. When the page is deleted or unpublished, `get_permalink()` returns `false`, `trailingslashit( false )` yields `/`, and the relative URL is sent to a payment API that requires an absolute URL, failing every checkout.

**Detect by:** Grep `trailingslashit( get_permalink(`, `add_query_arg( ..., get_permalink(` and `get_permalink( get_option(` / settings-stored page ids. Check the result for `false` (and `'publish' === get_post_status()`) and fall back to `home_url( '/' )`, especially for URLs sent to remote APIs.

---

### Build page URLs from the stored page id, not the global post

**What shipped:** A URL helper takes the URL of a configured page from the global `$post` when a conditional (`is_checkout()`) is true. During `admin-ajax.php` re-renders or secondary loops the global is some other post, so links point to that post's permalink.

**Detect by:** Grep URL helpers that use `get_permalink()` with no argument or that read `global $post`. Derive configured-page URLs from the stored page id option, since the global post is unreliable in AJAX, REST and nested loops.

---

### Use is_post_publicly_viewable() instead of comparing to 'publish'

**What shipped:** **(security)** Public visibility is decided by `'publish' === get_post_status()`. That rejects other public custom statuses and ignores whether the post type is publicly viewable, so private-type posts are exposed or legitimate public posts hidden.

**Detect by:** Grep `=== 'publish'`/`'publish' ===` in visibility decisions; require `is_post_publicly_viewable()` (WP 5.7+) or `is_post_status_viewable()` plus `is_post_type_viewable()`.

---

### Truncate user text on character boundaries, not byte or code-unit offsets

**What shipped:** A max-length or read-more setting cuts text with JavaScript `substring(0, n)` or PHP `substr()`. Emoji and other astral characters are two UTF-16 code units, and UTF-8 characters span multiple bytes, so the cut splits a character into a broken glyph or `?`, can produce empty output, and the visible length differs from the configured one.

**Detect by:** Grep PHP `substr(`, `strlen(`, `str_split(`, `wordwrap(` and JS `.substring(`, `.substr(`, `.slice(0,` and `.length` applied to user or API text with a length limit. PHP should use `mb_substr()`/`mb_strlen()` or `wp_trim_words()`/`wp_html_excerpt()`; JS should use `Array.from(str).slice(0, n).join('')`, `Intl.Segmenter`, or cut on a word boundary.

---

### Do not write escape sequences in single-quoted PHP strings

**What shipped:** Code joins values with `implode( ',\n', $list )` in single quotes, so stored data contains a literal backslash-n instead of a newline, and every consumer must handle the artifact. In regex literals the reverse happens: `'#^[A-Za-z]:[\\/]#'` in single quotes collapses `\\` to `\`, so PCRE sees a class containing only `/`, and backslash Windows paths bypass a path security check. Once bad rows are persisted, the fix must also normalize existing data.

**Detect by:** Grep single-quoted PHP literals containing `\n`, `\r`, `\t` passed to `implode`/`explode`/`str_replace`/`sprintf` or written to the DB; use `"\n"` or `PHP_EOL`. In `preg_*` patterns, check that intended literal backslashes are written as `\\\\` in single quotes and test with a backslash input. If historical rows exist, require read-side normalization or a migration.

---

### Use stacked case labels, never `case 'a' || 'b':`, in a switch

**What shipped:** A `switch` arm is written as `case 'pending' || 'processing':`. PHP evaluates the expression to boolean `true`, and because `switch` compares loosely, any non-empty string equals `true`, so every value not caught by an earlier arm falls into this branch and runs its side effect.

**Detect by:** Grep `case\s+[^:]*(\|\||&&|\bor\b|\band\b)[^:]*:` in PHP and `case .* \|\| ` in JS. Every hit is a bug; use stacked `case 'a': case 'b':` arms, `match`, or `in_array( $x, [...], true )`.

---

### Watch for casts that bind tighter than the comparison

**What shipped:** A check written as `(bool) 'refunded' === $order->status` parses as `((bool) 'refunded') === $status`, i.e. `true === $status`, so it is always false. The guard it was meant to provide (for example suppressing reminder emails for refunded records) never fires.

**Detect by:** Grep for `(bool)`, `(int)`, `(string)` casts applied to a string literal directly before `===`/`!==`/`==`. A cast on a literal in a comparison is almost always a precedence mistake; the intended code is usually `'refunded' === $status`.

---

### Assign instance properties before an admin action uses them

**What shipped:** An admin action method calls `wp_remote_post( $this->api_endpoint )`, but nothing assigns that property in this class or code path. The URL is empty and every request fails with 'A valid URL was not provided.'

**Detect by:** In gateway, retry and admin-action methods, grep for `$this->` properties used as URLs, keys or clients, and trace where each is assigned. A property set only in another subclass's constructor, or only on the checkout path, is empty here. Prefer a getter that computes the value.

---

### Refresh role objects and the current user after adding capabilities

**What shipped:** An installer grants capabilities with `$wp_roles->add_cap()`. That updates `WP_Roles::$roles` and the stored option but not `WP_Roles::$role_objects`, which `WP_User::get_role_caps()` reads, nor the current user's `allcaps`. For the rest of the request, including activation and upgrade, `current_user_can()` returns false for the new caps, even for administrators.

**Detect by:** Grep `->add_cap(`/`->remove_cap(` on a `WP_Roles` instance in activation, install or upgrade code. If the same request then checks those caps, require `get_role( $role )->add_cap()` or `wp_roles()->init_roles()`, and refresh the current user with `wp_get_current_user()->get_role_caps()`.

---

### Register custom post statuses that are queried or filtered

**What shipped:** A custom post type stores rows under custom `post_status` values that are never registered. Writes succeed, but `WP_Query` and the list table ignore unregistered statuses for status filters and counts, so filtering by status does nothing.

**Detect by:** Grep custom `post_status` literals written via `wp_insert_post`/`wp_update_post`/`$wpdb->update` or used in `WP_Query` args and list-table views. Confirm each has a matching `register_post_status()` on `init`, with `show_in_admin_status_list`/`show_in_admin_all_list` as needed.

---

### Remember delete_metadata() with $delete_all = true ignores the object id

**What shipped:** A meta wrapper passes a `$delete_all` argument through to `delete_metadata()`, documented as 'delete all values vs just the first'. WordPress reads `true` as 'ignore `$object_id` and delete this key from every object of this type', so a caller following the docblock wipes the key site-wide.

**Detect by:** Grep `delete_metadata(` with a fifth argument, and wrapper methods taking a `$delete_all`/`$all` parameter that pass it through. Flag any call where it can be `true` while a specific object id is expected, and docblocks that do not state the site-wide meaning.

---

### Pass an accepted field key to get_user_by()

**What shipped:** Code resolves users with `get_user_by( 'user_email', ... )` or `get_user_by( 'user_login', ... )`. The function accepts only `id`/`ID`, `slug`, `email` and `login`, so every lookup returns `false` and records fall back to no user.

**Detect by:** Grep `get_user_by( '` and flag any first argument other than `'id'`, `'ID'`, `'slug'`, `'email'`, `'login'`.

---

### Compute plugin_basename from the main plugin file

**What shipped:** `plugin_basename( __FILE__ )` is called from a file under `includes/`, so it returns `my-plugin/includes/functions.php`. That path never matches the active-plugins entry, so updater or registry code that compares basenames shows an 'update available' notice that can never be applied.

**Detect by:** Grep `plugin_basename( __FILE__ )`, `plugin_dir_path( __FILE__ )` and `plugins_url( ..., __FILE__ )` outside the root plugin file. Use a constant defined in the main file (`MY_PLUGIN_FILE`) instead.

---

### Constrain rewrite-rule captures to the expected character class

**What shipped:** `add_rewrite_rule()` captures a token with a greedy `(.*)` before an optional trailing slash. The slash and any extra path end up in the query var, so token lookups fail and arbitrary text reaches the handler.

**Detect by:** Grep `add_rewrite_rule()` / `rewrite_rules_array` regexes for `(.*)` or `(.+)` captures and replace them with a strict class such as `([a-f0-9]+)` or `([^/]+)`. When changing a rule, also update any flush or rule-exists check that looks for the old rule key.

---

### Warn when a helper receives a value outside its allowed set

**What shipped:** A helper accepts one of a fixed set of type strings and silently returns when given anything else, with no `_doing_it_wrong()` or logging. A call site passes a plausible but wrong string, and the output is dropped with no visible failure.

**Detect by:** Grep helpers that gate on an allowed-values constant or `in_array()` and check the rejection branch calls `_doing_it_wrong()` or logs. Separately grep call sites and diff the literal strings passed against the allowed set.

---

### Use a framework's save API instead of writing its meta directly

**What shipped:** An importer writes a page builder's data meta key directly with `update_post_meta()`, bypassing the builder's save pipeline, so derived state that only the pipeline regenerates (rendered `post_content`, CSS caches) goes stale.

**Detect by:** Flag `update_post_meta()`/`update_option()` on keys owned by another plugin or framework when that framework exposes a document or save API. Ask which derived data only that API regenerates.

---

### Check whether a third-party save API replaces or merges

**What shipped:** A small array such as `$document->save( [ 'settings' => [ ... ] ] )` is passed to a third-party save method that treats missing keys as deletions, wiping existing settings.

**Detect by:** For partial arrays passed to third-party `save()`/`update()` methods, read the library source to confirm merge semantics. If it replaces, read the current value, merge, and write the full structure.

---

### Interpret CLI exit codes by their documented meaning

**What shipped:** A wrapper treats any non-zero exit code as an error, but the command uses exit codes to report results (for example 'checks failing' or 'pending'), so the wrapper throws away the output it needed.

**Detect by:** Where code shells out (`exec()`, `proc_open()`, `WP_CLI::runcommand()`, subprocess helpers with raise-on-error), check the tool's documented exit codes and handle result-bearing codes explicitly instead of a blanket failure check.

---

### Construct a replacement PHPMailer with exceptions enabled

**What shipped:** A plugin swaps the global `$phpmailer` for its own subclass but constructs it with `new Subclass()` instead of `new Subclass( true )`. Without `$exceptions = true`, PHPMailer reports errors through return values, so `wp_mail()` never catches an exception, failures are swallowed, and `wp_mail_failed` never fires for loggers and retry handlers.

**Detect by:** Grep `new PHPMailer(` and `new <Class>(` where the class extends PHPMailer or is assigned to `$GLOBALS['phpmailer']`, and confirm the constructor gets `true`. When `wp_mail` is overridden, check failures still `do_action( 'wp_mail_failed', new WP_Error(...) )`.

---

### Read option labels from the current loop item

**What shipped:** A `<select>` built in a `foreach` prints a variable assigned outside the loop (or overwritten each iteration) instead of the current item's field, so every option shows the same label.

**Detect by:** In view files building `<option>` elements in loops, confirm the value and label reference the current iteration variable. Flag variables used in the loop body that are not derived from it.

---

## Install, upgrade, uninstall and multisite

### Run version-upgrade routines on a hook that fires outside wp-admin

**What shipped:** The DB or option migration routine is attached to `admin_init`, while new code immediately reads or writes the migrated schema. Sites updated via WP-CLI, or whose cron, REST or front-end traffic arrives before an admin page load, run new code against unmigrated data, for example inserts failing with `Unknown column`.

**Detect by:** Find the `version_compare()` / db-version upgrade dispatcher and check its hook; prefer `plugins_loaded` or `init` behind a version check. When a diff adds a column to an insert or update list, find where its `ALTER TABLE` runs; if only in admin, check every non-admin writer (WP-CLI, cron, background job queues, REST, webhooks) and require it to run the upgrade check first or keep the column out of the write until the upgrade is done.

---

### Advance the stored version to the current version after install or upgrade

**What shipped:** An upgrade routine compares a stored version option with `version_compare()` but writes a hard-coded old (or mismatched) version string at the end, or nothing on some exit path, so the stored version never matches the running one. Upgrade steps re-run on every load or later steps are skipped.

**Detect by:** In install/upgrade routines, grep `update_option( '*version*'` and flag literal version strings; the value must be the plugin's current version constant, or exactly the version each step migrated to. Confirm every exit path (fresh install, each step, the up-to-date early return) leaves the stored version correct, and that the routine is gated on a cheap compare before other work.

---

### Carry legacy schema changes into the new upgrade chain when replacing an installer

**What shipped:** A refactor replaces a legacy install/upgrade routine with a numbered-upgrade system and turns the old routine into a stub, but no numbered upgrade re-creates an index the old routine added. Sites that jump across that version never get the index, and a query runs a full table scan on every admin page. Upgrades that add an index or column with a bare `ALTER TABLE` also fail, and can stall the chain, on sites that already have it.

**Detect by:** When an installer is stubbed or moved, list every DDL change it applied and confirm each has an equivalent numbered upgrade, not only a correct fresh-install schema. In each upgrade that adds an index or column, require an existence check (`SHOW INDEX`, `SHOW COLUMNS` or `information_schema`) or `dbDelta()`.

---

### Lock DB upgrade routines that run DDL

**What shipped:** An upgrade routine runs `ALTER TABLE` without a lock. Opening several admin tabs right after an update fires concurrent requests that each run the same DDL, causing table locks and inconsistent upgrade state.

**Detect by:** For upgrade routines that run `ALTER TABLE` or long migrations, confirm a lock (an option added with `add_option()` or a transient with a timeout) is acquired first and released on completion or failure, and that the version is marked complete only after success.

---

### Keep uninstall and deactivation code self-contained and complete

**What shipped:** An uninstall handler calls a method on a global service object that is only created during normal bootstrap; uninstall runs in a stripped context, so it fatals and the plugin cannot be deleted. A deactivation hook that references a class extending a class from a parent plugin fatals when the parent is already inactive. Separately, tables added in later releases are missing from the uninstall `DROP TABLE` list, or `uninstall.php` is excluded from the release zip, so 'remove data' leaves tables behind and a reinstall resurrects old data. The same gap appears when a change adds a new option key but `uninstall.php` deletes options from an explicit list that does not include it, so the option survives a full uninstall even with data removal enabled.

**Detect by:** In `uninstall.php`, `register_uninstall_hook()` and `register_deactivation_hook()` callbacks, grep for `global $` plus `->` calls, `::instance()`/container lookups, and classes loaded only by the main bootstrap or a parent plugin; use core APIs (`delete_option`, `$wpdb`, `wp_clear_scheduled_hook`) and `class_exists()` guards. When a diff adds a literal option name (`update_option( '`, `add_option( '`, a new option constant), transient, cron hook or `CREATE TABLE`, open the uninstall cleanup; if it is list-based rather than prefix-based (`DELETE ... LIKE 'prefix_%'`), confirm the new item is listed. Confirm the build manifest ships `uninstall.php`.

---

### Check network activation, not just site activation, on multisite

**What shipped:** Plugin-presence or feature-gating logic calls `is_plugin_active()` or reads `get_option( 'active_plugins' )` alone. On multisite a network-activated plugin is listed in the `active_sitewide_plugins` site option, so the check reports a network-active plugin as inactive.

**Detect by:** Grep `is_plugin_active(` and `get_option( 'active_plugins' )`; on paths that can run on multisite, pair them with `is_plugin_active_for_network()` / `get_site_option( 'active_sitewide_plugins' )`. Both helpers live in `wp-admin/includes/plugin.php`, so front-end code needs a `function_exists` check or `require_once`.

---

### Check site membership after looking up a user by email on multisite

**What shipped:** **(security)** A helper resolves an account with `get_user_by( 'email', ... )` or `email_exists()` and then links records to it, verifies it or shows it in admin. Users are network-wide on multisite, so the lookup also returns accounts that are not members of the current site, and the site acts on a user with no role there.

**Detect by:** Grep `get_user_by( 'email'`, `get_user_by( 'login'`, `email_exists(`, `username_exists(` in code that links, claims, logs in or grants access. On multisite, require `is_user_member_of_blog( $user->ID )` or `get_users( array( 'blog_id' => get_current_blog_id(), ... ) )` before using the account.

---

### Ship runtime-required vendor and asset files in the package

**What shipped:** `.gitignore` or the release build's exclusion filter drops files the plugin needs at runtime (a Composer polyfill, a scoped library, an assets directory that PHP reads or that holds an enqueued script). Fresh checkouts or every built release then fatal on activation or ship broken assets.

**Detect by:** Diff `.gitignore`, `.distignore` and the rsync/zip filters against the paths that runtime `require`/`include`, `plugins_url()` and `wp_enqueue_*` calls reference. Broad `vendor/` or `assets/` exclusions need explicit exceptions for runtime files. Build the package and activate it from the zip.

---

### Run the PHP-version guard before loading the Composer autoloader

**What shipped:** A plugin requires its Composer autoloader before any PHP version check. Composer's generated `platform_check.php` throws when the plugin loads under an older PHP binary (for example a WP-CLI or cron job using a different PHP than the web server), crashing the process instead of showing a graceful notice.

**Detect by:** In the main plugin file, check that a `version_compare( PHP_VERSION, 'X', '<' )` bail with an admin notice runs before `require .../vendor/autoload.php` and before any file using newer syntax. Check `composer.json` for `"platform-check": false` when the plugin does its own version check.

---

### Give gating options a default on fresh installs

**What shipped:** A scheduled email is gated on an option that is never set on activation and has no UI, so it never runs on new installs and nothing reports why. The schedule also uses a `wp_schedule_event()` recurrence that does not match the configured interval (daily for a six-hour setting).

**Detect by:** For `get_option()` gates on features, confirm the option has an activation default or a setting that writes it. Compare `wp_schedule_event()` recurrence names with the configured frequency, and register custom intervals through `cron_schedules` where needed.

---

### Use a silent upgrader skin when installing plugins from AJAX or REST

**What shipped:** An AJAX 'install and activate' handler runs `new Plugin_Upgrader( new WP_Upgrader_Skin() )`. The default skin echoes progress HTML into the output before `wp_send_json_success()`, so the client's JSON parse fails and a successful install is reported as a failure.

**Detect by:** Grep `new Plugin_Upgrader(` / `new Theme_Upgrader(` reachable from `wp_ajax_*` or REST callbacks; require `WP_Ajax_Upgrader_Skin`, `Automatic_Upgrader_Skin` or a custom silent skin, or output buffering around `->install()`.

---

### Let a custom plugin updater attach under WP-CLI

**What shipped:** A self-hosted updater is instantiated only when `is_admin()` or `wp_doing_cron()` is true. Under WP-CLI there is no admin context and it is not cron, so the update-check filter is never hooked and `wp plugin update` never sees available updates.

**Detect by:** Grep updater bootstrap code for `is_admin()` / `wp_doing_cron()` gates; require that `defined( 'WP_CLI' ) && WP_CLI` is also allowed so the callback attaches to `pre_set_site_transient_update_plugins` and `plugins_api`.

---

### Key theme update data like themes, not like plugins

**What shipped:** A shared plugin/theme updater injects theme update data the plugin way. `update_themes` transient `response` entries are associative arrays, not objects, so an `is_object()`/`->new_version` check never matches. Keying the entry with `get_stylesheet()` targets the active child theme, so the notice shows on the child and updating replaces the child theme's directory.

**Detect by:** In updaters hooked to `pre_set_site_transient_update_themes` / `site_transient_update_themes`, check entries are built and read as arrays (`theme`, `new_version`, `url`, `package`), not `stdClass`. The key must be the registered theme slug or `get_template()`, never `get_stylesheet()` of the active theme.

---

## Back-compat and structure

### Guard functions and syntax newer than the declared minimum versions

**What shipped:** Code uses a WordPress function or feature newer than the plugin's `Requires at least` (for example `register_block_template()` from 6.7, or the `%i` identifier placeholder in `$wpdb->prepare()` from 6.2), which fatals or breaks queries on older supported versions. PHP syntax newer than `Requires PHP` (trailing commas in call or parameter lists) causes a parse error on activation.

**Detect by:** For each core function, hook or `prepare()` placeholder first used in a diff, check its `@since` against the plugin header's `Requires at least` and require a `function_exists()` or version guard if newer. Run `php -l` (or PHPCompatibility) at the minimum `Requires PHP` version on changed files.

---

### Guard calls into host and companion plugins, and make them only after the version gate passes

**What shipped:** Code calls functions or classes from a separately installed host or companion plugin without a `function_exists()`/`class_exists()` guard, so deactivating that plugin fatals the request. An add-on calls its host's registration API at file scope, outside the bootstrap function that checks the host's minimum version, so on older hosts the class does not exist and the site fatals. A destructive variant: a cleanup routine treats the missing dependency as 'record not found' and deletes stored data instead of bailing.

**Detect by:** For every call to a function or class not defined in the plugin or WP core, confirm a `function_exists()`/`class_exists()`/`defined()` guard on the same path, matching sibling call sites. In add-ons with a minimum-version gate, grep top-level (file-scope) calls to the dependency and require them inside a function hooked after the gate passes (for example on `plugins_loaded`). In prune or cleanup code, check that a missing dependency returns early instead of falling through to `delete_*_meta`/`delete_option`.

---

### Keep firing a released hook name when renaming it

**What shipped:** Renaming a `do_action` / `apply_filters` tag that has already shipped silently drops every external listener. A hook whose docblock has only the next-version `@since` placeholder is new this cycle and safe to rename; one with a released `@since` version must keep firing the old name (for example via `do_action_deprecated()` / `apply_filters_deprecated()`).

**Detect by:** In diffs renaming a hook tag, read its docblock `@since`; if a released version is present, require the old tag to keep firing; grep the codebase and known add-ons for `add_action` / `add_filter` on the old string to size the impact.

---

### Keep the payload of an existing public filter unchanged in a refactor

**What shipped:** A refactor keeps a filter's name but now passes an empty array instead of the full default set, and only merges the return value, so extensions that modified or removed defaults silently stop working.

**Detect by:** When a refactor touches `apply_filters()` for an existing hook, diff the value passed and how the return is consumed. Require the same shape, the same default contents, and honoring removals or edits; otherwise add a back-compat path and `_deprecated_hook()`.

---

### Spell string identifiers identically on every side

**What shipped:** A string enum or identifier differs between producer and consumer: `'block'` vs `'blocks'` across a getter, REST enum, `switch` and stored meta; a component returns an id with an extra underscore while other components use the derived spelling; the page localizes a nonce for action `my-admin` while the handler verifies `my_admin_nonce`, so every request fails.

**Detect by:** For each new string identifier, mode or nonce action, grep every occurrence (REST `enum`, `switch` cases, meta keys, whitelists, JS constants, `wp_create_nonce`/`check_ajax_referer` pairs) and confirm an exact match. Prefer a single constant over repeated literals.

---

### Read messages through the API that now writes them

**What shipped:** A consumer keeps reading a legacy session or option key after the producer moved to a new storage API, so the key is never populated and the check always fails. For example a success page reads `$session->get( 'legacy_message_key' )` while the code that sets the message now writes through a messages helper under a different key, so a successful action shows an error.

**Detect by:** When a change (or a dependency upgrade) changes where state is written, grep every reader of the old key. Each read must go through the new API, or through a version-aware fallback that checks both, never only the retired key.

---

### Require new or moved files from the bootstrap

**What shipped:** A change moves a feature into new files but the bootstrap never `require`s them. The code is valid but unreachable, so the feature (for example a set of admin bulk actions) disappears on every install.

**Detect by:** When a change adds or moves PHP files, confirm each one is loaded by the bootstrap, the autoloader map or a class-map entry. Check the built package too. A new file that no `require`, `include` or autoloader path reaches is dead code.

---

### Prefix and scope global asset handles, CSS classes and JS functions

**What shipped:** A plugin registers a common library under an unprefixed handle (for example a bare vendor name) on every admin screen. Whichever registration runs first wins, so another plugin using the same handle silently gets the wrong asset or none. The same collision happens with a bundled stylesheet that ships a global rule on a generic class such as `.animated`, which restyles other plugins' elements, and with a top-level JS function with a generic name that another plugin's script overwrites.

**Detect by:** Grep `wp_register_script`/`wp_register_style`/`wp_enqueue_script`/`wp_enqueue_style` for handles without the plugin prefix, especially when hooked unconditionally on `admin_enqueue_scripts` instead of gated on the plugin's own screens (`$hook_suffix` or `get_current_screen()`). Grep bundled CSS for unscoped rules on generic class names, and admin JS for top-level `function name()` declarations or `window.name =` assignments without a prefix or module wrapper.

---

### Replace deprecated host classes and removed helpers

**What shipped:** Payment code still builds a legacy payment object and calls helper functions the host plugin deprecated or removed. Each run emits deprecation notices, and logic that relies on the removed helpers stops working.

**Detect by:** Grep for legacy class instantiation and calls to functions the dependency has marked `_deprecated_function()` or removed in the minimum supported version. Every hit must move to the current API, or be guarded with `function_exists()` plus a fallback.

---

### Load admin-only class files lazily, not at bootstrap

**What shipped:** A `WP_List_Table` subclass file is required on every request, including the front end and `wp-login.php`. Its header requires `ABSPATH . 'wp-admin/includes/class-wp-list-table.php'`; on hosts with a non-standard core layout the path does not resolve and the whole site fatals, though the class is used on one admin screen.

**Detect by:** Grep the plugin's bootstrap include list for files that require `ABSPATH . 'wp-admin/includes/...'` or extend `WP_List_Table` or other admin-only classes. Confirm they load only inside an `is_admin()` branch or lazily right before instantiation. Flag any `wp-admin/` require reachable outside admin context.

---

### Check return types at every call site when consolidating logic into a shared builder

**What shipped:** A refactor moves per-call logic, such as clamping a value, into a shared builder. One call site always passed and received a scalar, but the shared path returns an array in its case, which flows into a function expecting a string or int and produces "Array to string conversion" plus an unclamped fallback.

**Detect by:** When several code paths are merged into one function, list each original call site's input and output types and diff them against the shared function's behaviour for that input. Add a test per call site, and watch for type-coercion warnings right after the change.

---

### Pin API response fields with a test so refactors cannot drop them

**What shipped:** A field in a remote API response (for example an upgrade notice in an update-check payload) disappears during a merge-conflict resolution or an unrelated refactor. Nothing errors. Clients simply stop receiving the data.

**Detect by:** When a change touches a response builder (REST controller, update-check endpoint), diff the payload keys before and after. Ask for a test that asserts each documented field is present.

---

### Namespace global resources in a package bundled by several plugins

**What shipped:** A shared library bundled into several plugins (often prefixed with php-scoper) registers the same global resource in each copy, and whichever copy loads first or last wins for all. Every copy hooks the same `wp_ajax_*` action and the first one calls `wp_send_json_error()` (which dies) for requests it does not own, losing the others' submissions. A static singleton ignores the consumer after the first call, so one plugin's data is stored under another's option. A shared `wp_localize_script()` handle and variable name lets the last plugin overwrite the rest.

**Detect by:** In a package meant to be bundled by multiple plugins, grep `add_action( 'wp_ajax_`, `register_rest_route(`, `wp_localize_script(` and `static $instance` for names that do not include the consumer's prefix. A shared handler must `return` without dying on requests it does not own, singletons must be keyed per consumer, and localized data must merge (for example via `wp_add_inline_script()`) rather than overwrite.

---

### Scope bundled Composer dependencies to survive older copies loaded by other plugins

**What shipped:** A plugin ships an unprefixed `vendor/` with `Composer\Autoload\ClassLoader`. When another plugin loads an older `ClassLoader` first, `class_exists` skips the bundled one, and the generated `autoload_real.php` calls a method the older class lacks (such as `setClassMapAuthoritative()`), fataling on update. It only happens with certain plugin combinations, so staging does not catch it.

**Detect by:** In a release build, check whether `vendor/composer/autoload_real.php` calls `ClassLoader` methods newer than the oldest Composer a co-installed plugin might ship (`setClassMapAuthoritative`, `setApcuPrefix`, `InstalledVersions`). Flag an unprefixed `vendor/` in a distributable plugin with no scoping step (PHP-Scoper, Strauss, Mozart) and no `method_exists` guard.

---

### Exclude host-provided global symbols from php-scoper prefixing

**What shipped:** A php-scoper-built plugin checks for a global class supplied at runtime by the host, an mu-plugin or another plugin via `class_exists()` / `method_exists()` or a static call. The scoper config excludes only WordPress core symbols, so the build rewrites the reference to the prefixed namespace, the check is always false, and the integration breaks only in production builds.

**Detect by:** When a diff adds `class_exists()` / `method_exists()` / `function_exists()` checks or static calls on a global symbol not from core and not bundled, confirm it is listed in the scoper config's `exclude-classes` / `exclude-functions` / `exclude-namespaces`. Inspect the built output, not the source.

---

## Tests

### Confirm a new test file is actually collected by the test runner

**What shipped:** A new test file does not match the suite's collection rule (for example `<directory prefix="tests-">` versus `suffix="Test.php"` in `phpunit.xml`), so it never runs and CI stays green. A new Jest test is added to a project with no test script or Jest config in CI. Conversely, a helper or fixture whose name matches the pattern runs as a test, and an `<exclude>` added to hide it can drop real coverage.

**Detect by:** For any added test file, read `phpunit.xml` / `phpunit.xml.dist` `<testsuite>` rules (`prefix=` / `suffix=` / `<file>`) or `package.json` / Jest config and the CI workflow, and confirm the file is collected; flag fixtures that match the pattern and new `<exclude>` entries.

---

### Restore superglobals, options and filters in tearDown, not inline

**What shipped:** Tests set `$_POST`/`$_GET`/`$_REQUEST` keys, add filters, change options or create fixtures, and restore them as the last statements of the test method or wipe a superglobal with `= array()`. A failed assertion or a `WPDieException` from `wp_send_json_*` skips the restore, leaking state into later tests whose failures are then misattributed. Blanket wipes clear keys other tests rely on, restoring `''` for a key that was absent changes `isset()` results, and clearing `$_POST` does not reset a nonce check that reads `$_REQUEST`.

**Detect by:** In test diffs, grep `$_POST[`, `$_GET[`, `$_REQUEST[`, `= array()` on superglobals, `update_option(`, `add_filter(`, and `remove_filter(` / `delete_option(` / `unset( $_GET` / cleanup helpers placed after an `assert*()` in the same method. Require capturing original values in `set_up()` and restoring them in `tear_down()` before `parent::tear_down()`, unsetting keys that were absent.

---

### Do not let test outcomes depend on the wall clock

**What shipped:** A test hardcodes a near-future date and asserts a status that the code derives from the current time; once that date passes, the test fails on every branch. Another computes its expected value from the real clock with month-end special cases that are wrong for some months, or assumes a 30-day month for a relative date, so it fails only on certain run dates.

**Detect by:** In new or changed tests, grep for date literals (`'20[0-9]{2}-[0-9]{2}-[0-9]{2}'`) on records whose status is derived from the current time (expiry, start, renewal, trial end). Require relative dates or an injected clock. Flag expected values computed from `time()`, `strtotime( '+1 month' )`, `date( 't' )` or `date( 'd' )` when the method under test accepts a timestamp, and add fixed-date cases for month-end, February and leap day.

---

### Do not let a masked PHP warning make a test pass

**What shipped:** A test asserts the opposite of the code's intent and stays green only because the mocked HTTP response omits a key, raising an `Undefined array key` warning that the test harness converts to an exception, which unwinds past the intended early return into a catch block. When the warning path is fixed, the test starts failing on its real assertion.

**Detect by:** In tests using mocked `wp_remote_*` responses, check that the mock includes every key the code reads (`response.code`, `response.message`, `body`); flag tests that assert the negation of an early-return branch they appear to exercise, and confirm the assertion holds with warnings not converted to exceptions.

---

### Do not assert count deltas on paginated responses

**What shipped:** A test asserts that a list grew by one, but the endpoint caps results at `per_page=100`, so once the fixture data exceeds the cap the count stops changing and the test fails intermittently.

**Detect by:** Flag tests that compare counts from paginated endpoints. Assert on the newest ID, the `X-WP-Total` header, or a filtered query instead.

---
