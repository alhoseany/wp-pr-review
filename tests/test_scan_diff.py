import json
import os

import pytest

import scan_diff as s

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _diff(path, added, start=1, context=()):
    body = [f" {c}" for c in context] + [f"+{a}" for a in added]
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -{start},0 +{start},{len(body)} @@\n" + "\n".join(body) + "\n")


def _rules(diff_text, **kw):
    return [(d["rule"], d["line"]) for d in s.scan(s.parse_diff(diff_text), **kw)["leads"]]


def test_parse_diff_tracks_new_side_line_numbers():
    text = ("diff --git a/a.php b/a.php\n--- a/a.php\n+++ b/a.php\n"
            "@@ -10,3 +20,4 @@\n ctx\n-old\n+new1\n+new2\n ctx2\n"
            "\\ No newline at end of file\n")
    lines = s.parse_diff(text)["a.php"]
    assert [(ln["line"], ln["text"], ln["added"]) for ln in lines] == [
        (20, "ctx", False), (21, "new1", True), (22, "new2", True), (23, "ctx2", False)]


def test_parse_diff_skips_deleted_files():
    text = "diff --git a/x.php b/x.php\n--- a/x.php\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-gone\n"
    assert s.parse_diff(text) == {}


@pytest.mark.parametrize("line,rule", [
    ("$wpdb->query( \"DELETE FROM t WHERE id = $id\" );", "sql-interpolation"),
    ("$wpdb->get_var( 'SELECT x FROM t WHERE id = ' . $id );", "sql-interpolation"),
    ("$id = $_POST['id'];", "request-input"),
    ("echo $name;", "unescaped-echo"),
    ("$v = unserialize( $raw );", "unserialize"),
    ("case 'a' || 'b':", "case-with-logical-operator"),
    ("if ( $token === $stored_token ) {", "secret-compared-with-equality"),
    ("add_rewrite_rule( '^x/(.*)/?', 'index.php?x=$matches[1]' );", "broad-rewrite-capture"),
    ("if ( false !== strpos( $_SERVER['REQUEST_URI'], 'wp-login' ) ) {", "request-uri-match"),
    ("if ( defined( 'DOING_CRON' ) ) { return; }", "doing-cron-gate"),
    ("$amount = (float) $_POST['amount'];", "float-cast-request-amount"),
    ("$q = new WP_Query( array( 'posts_per_page' => -1 ) );", "unbounded-query"),
    ("require_once 'includes/view.php';", "relative-include"),
    ("echo do_shortcode( '[x id=\"' . $id . '\"]' );", "do-shortcode-dynamic"),
    ("wp_enqueue_script( 'x', $src, array(), time() );", "asset-version-time"),
    ("$url = add_query_arg( 'done', 1 );", "add-query-arg-current-url"),
])
def test_line_rules_fire(line, rule):
    assert rule in [r for r, _ in _rules(_diff("inc/a.php", [line]))]


@pytest.mark.parametrize("line,rule", [
    ("$wpdb->query( $wpdb->prepare( \"DELETE FROM t WHERE id = %d\", $id ) );", "sql-interpolation"),
    ("$id = absint( $_POST['id'] );", "request-input"),
    ("$id = sanitize_text_field( wp_unslash( $_POST['id'] ) );", "request-input"),
    ("echo esc_html( $name );", "unescaped-echo"),
    ("$v = unserialize( $raw, array( 'allowed_classes' => false ) );", "unserialize"),
    ("if ( hash_equals( $stored_token, $token ) ) {", "secret-compared-with-equality"),
    ("if ( $token === '' ) {", "secret-compared-with-equality"),
    ("$url = add_query_arg( 'done', 1, admin_url( 'admin.php' ) );", "add-query-arg-current-url"),
    ("require_once __DIR__ . '/includes/view.php';", "relative-include"),
])
def test_line_rules_cleared_by_safe_shape(line, rule):
    assert rule not in [r for r, _ in _rules(_diff("inc/a.php", [line]))]


def test_rules_only_scan_added_lines():
    diff = _diff("inc/a.php", ["$ok = 1;"], context=["echo $name;"])
    assert _rules(diff) == []


def test_rules_respect_language():
    assert _rules(_diff("js/a.js", ["echo $name;"])) == []
    assert "fetch-without-status-check" in [
        r for r, _ in _rules(_diff("js/a.js", ["fetch( u ).then( ( r ) => r.json() );"]))]


@pytest.mark.parametrize("path", [
    "vendor/lib/a.php", "node_modules/x/a.js", "assets/app.min.js", "readme.txt"])
def test_skipped_paths(path):
    assert _rules(_diff(path, ["echo $name;"])) == []


def test_redirect_cleared_by_exit_on_next_lines():
    assert "redirect-without-exit" not in [
        r for r, _ in _rules(_diff("a.php", ["wp_safe_redirect( $u );", "exit;"]))]
    assert "redirect-without-exit" in [
        r for r, _ in _rules(_diff("a.php", ["wp_safe_redirect( $u );", "$x = 1;"]))]


def test_handler_rules_use_whole_file_when_repo_root_given(tmp_path):
    (tmp_path / "a.php").write_text(
        "<?php\nadd_action( 'wp_ajax_x', 'x' );\nfunction x() {\n"
        "check_ajax_referer( 'x' );\nif ( ! current_user_can( 'manage_options' ) ) return;\n}\n")
    diff = _diff("a.php", ["add_action( 'wp_ajax_x', 'x' );"], start=2)
    without = [r for r, _ in _rules(diff)]
    assert "handler-without-nonce" in without and "handler-without-capability" in without
    with_root = [r for r, _ in _rules(diff, repo_root=str(tmp_path))]
    assert "handler-without-nonce" not in with_root
    assert "handler-without-capability" not in with_root


def test_nopriv_handler_lead():
    rules = [r for r, _ in _rules(_diff("a.php", ["add_action( 'wp_ajax_nopriv_x', 'x' );"]))]
    assert "nopriv-handler" in rules


def test_query_in_loop_braced_and_braceless():
    braced = _diff("a.php", ["foreach ( $ids as $id ) {",
                             "    $m = get_post_meta( $id, 'k', true );", "}",
                             "$o = get_option( 'x' );"])
    leads = _rules(braced)
    assert ("query-in-loop", 2) in leads
    assert ("query-in-loop", 4) not in leads
    braceless = _diff("a.php", ["foreach ( $ids as $id )",
                                "    update_post_meta( $id, 'k', 1 );",
                                "$o = get_option( 'x' );"])
    leads = _rules(braceless)
    assert ("query-in-loop", 2) in leads
    assert ("query-in-loop", 3) not in leads


def test_query_in_loop_stops_at_hunk_gap():
    text = ("diff --git a/a.php b/a.php\n--- a/a.php\n+++ b/a.php\n"
            "@@ -1,0 +1,1 @@\n+foreach ( $ids as $id ) {\n"
            "@@ -40,0 +40,1 @@\n+$o = get_option( 'x' );\n")
    assert _rules(text) == []


def test_every_topic_resolves_in_this_corpus():
    headings = s.corpus_headings(SKILL_DIR)
    assert headings, "known-bug-patterns.md has no ### headings"
    missing = [r["id"] for r in s.RULES if r["topic"] and not s.related(r["topic"], headings)]
    assert missing == []


def test_leads_carry_related_patterns():
    headings = s.corpus_headings(SKILL_DIR)
    lead = s.scan(s.parse_diff(_diff("a.php", ["$v = unserialize( $raw );"])),
                  headings=headings)["leads"][0]
    assert lead["patterns"] and all(h in headings for h in lead["patterns"])


def test_main_json_from_diff_file(tmp_path, capsys):
    p = tmp_path / "c.diff"
    p.write_text(_diff("a.php", ["echo $name;"]))
    assert s.main(["--diff", str(p), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["files_scanned"] == 1
    assert out["leads"][0]["rule"] == "unescaped-echo"


def test_main_pr_uses_injected_run(capsys):
    calls = []

    def fake(args):
        calls.append(args)
        return _diff("a.php", ["echo $name;"])

    assert s.main(["--pr", "acme/my-plugin#5"], run=fake) == 0
    assert calls == [["pr", "diff", "5", "--repo", "acme/my-plugin"]]
    assert "unescaped-echo" in capsys.readouterr().out


def test_main_missing_file_is_io_error(tmp_path, capsys):
    assert s.main(["--diff", str(tmp_path / "nope.diff")]) == 1


def test_main_too_large_diff_suggests_local_diff(capsys):
    def fake(args):
        raise RuntimeError("gh pr diff failed: HTTP 406 PullRequest.diff too_large")

    assert s.main(["--pr", "acme/my-plugin#5"], run=fake) == 1
    assert "git -C <checkout> diff" in capsys.readouterr().err


@pytest.mark.parametrize("path", [
    "tests/stripe/CompletionRequest.php", "src/test/a.php", "tests/js/x.test.js",
    "src/FooTest.php", "js/__tests__/a.js"])
def test_test_files_skipped_unless_included(path):
    diff = _diff(path, ["echo $name;"]) if path.endswith(".php") else \
        _diff(path, ["fetch( u ).then( ( r ) => r.json() );"])
    result = s.scan(s.parse_diff(diff))
    assert result["leads"] == [] and result["tests_skipped"] == 1
    assert s.scan(s.parse_diff(diff), include_tests=True)["leads"]


def test_latest_is_not_a_test_path():
    assert not s.is_test_path("src/Latest.php")
    assert not s.is_test_path("includes/contest/a.php")
