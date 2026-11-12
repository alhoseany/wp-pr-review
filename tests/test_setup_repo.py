import pytest
import setup_repo as s


def test_plugin_from_branch_monorepo_prefix():
    assert s.parse_plugin_from_branch("my-plugin-wallet/issue/1303") == "my-plugin-wallet"

def test_plugin_from_branch_suffix_form():
    assert s.parse_plugin_from_branch("issue/123-my-plugin-wallet") == "my-plugin-wallet"

def test_plugin_from_branch_none():
    assert s.parse_plugin_from_branch("main") is None

def test_resolve_plugin_dir_exact():
    dirs = ["my-plugin-wallet", "my-other-plugin"]
    assert s.resolve_plugin_dir("my-plugin-wallet", dirs) == "my-plugin-wallet"

def test_resolve_plugin_dir_prefix_recovery(monkeypatch):
    monkeypatch.setenv("PLUGIN_DIR_PREFIXES", "acme-, my-plugin-")
    dirs = ["old-wallet-archive", "my-plugin-wallet"]
    assert s.resolve_plugin_dir("wallet", dirs) == "my-plugin-wallet"

def test_resolve_plugin_dir_no_default_prefixes(monkeypatch):
    monkeypatch.delenv("PLUGIN_DIR_PREFIXES", raising=False)
    dirs = ["old-wallet-archive", "my-plugin-wallet"]
    assert s.resolve_plugin_dir("wallet", dirs) == "old-wallet-archive"

def test_resolve_plugin_dir_no_match():
    assert s.resolve_plugin_dir("nope", ["my-plugin-wallet"]) is None

def test_filter_changed_files_monorepo():
    files = ["my-plugin-wallet/a.php", "my-other-plugin/b.php", "my-plugin-wallet/c.php"]
    assert s.filter_changed_files(files, "my-plugin-wallet") == [
        "my-plugin-wallet/a.php", "my-plugin-wallet/c.php"]

def test_filter_changed_files_no_plugin():
    files = ["a.php", "b.php"]
    assert s.filter_changed_files(files, None) == files

def test_checkout_invokes_git_checkout_B():
    calls = []
    def fake_run(args, cwd=None):
        calls.append(args)
        if args == ["rev-parse", "--verify", "--quiet", "issue/89"]:
            raise RuntimeError("no such branch")  # model "no local branch"
        return ""
    s.checkout_pr_branch("/repo", "issue/89", base="main", run=fake_run)
    assert ["status", "--porcelain"] in calls
    assert ["fetch", "origin"] in calls
    assert ["checkout", "-B", "issue/89", "origin/issue/89"] in calls

def test_checkout_fails_fast_on_dirty_tree():
    def fake_run(args, cwd=None):
        if args == ["status", "--porcelain"]:
            return " M includes/foo.php\n"
        return ""
    with pytest.raises(RuntimeError, match="dirty"):
        s.checkout_pr_branch("/repo", "issue/89", base="main", run=fake_run)

def test_checkout_fork_pr_fetches_pull_head_and_checks_out_fetch_head():
    calls = []
    def fake_run(args, cwd=None):
        calls.append(args)
        return ""
    s.checkout_pr_branch("/repo", "issue/89", base="main", pr_number=89, run=fake_run)
    assert ["fetch", "origin", "pull/89/head"] in calls
    assert ["checkout", "-B", "issue/89", "FETCH_HEAD"] in calls

def test_changed_files_diffs_against_created_local_branch():
    calls = []
    def fake_run(args, cwd=None):
        calls.append(args)
        return ""
    s.changed_files("/repo", base="main", branch="issue/89", run=fake_run)
    assert ["diff", "--name-only", "origin/main...issue/89"] in calls

def test_checkout_missing_origin_base_raises_diff_only_fallback():
    def fake_run(args, cwd=None):
        if args == ["rev-parse", "--verify", "--quiet", "origin/main"]:
            raise RuntimeError("git rev-parse --verify --quiet origin/main failed")
        return ""
    with pytest.raises(RuntimeError, match="DIFF-ONLY-FALLBACK"):
        s.checkout_pr_branch("/repo", "issue/89", base="main", pr_number=89, run=fake_run)

def test_checkout_local_ahead_branch_raises_local_work_guard_and_skips_checkout():
    calls = []
    def fake_run(args, cwd=None):
        calls.append(args)
        if args == ["rev-parse", "--verify", "--quiet", "issue/89"]:
            return "abc123\n"
        if len(args) == 3 and args[0] == "rev-list" and args[1] == "--count":
            return "3\n"
        return ""
    with pytest.raises(RuntimeError, match="LOCAL-WORK-GUARD"):
        s.checkout_pr_branch("/repo", "issue/89", base="main", pr_number=89, run=fake_run)
    assert not any(c[0] == "checkout" for c in calls)

def test_checkout_allow_branch_reset_skips_local_work_guard():
    calls = []
    def fake_run(args, cwd=None):
        calls.append(args)
        if args == ["rev-parse", "--verify", "--quiet", "issue/89"]:
            return "abc123\n"
        if len(args) == 3 and args[0] == "rev-list" and args[1] == "--count":
            return "3\n"
        return ""
    s.checkout_pr_branch("/repo", "issue/89", base="main", pr_number=89,
                         allow_branch_reset=True, run=fake_run)
    assert any(c[0] == "checkout" and c[1] == "-B" for c in calls)
