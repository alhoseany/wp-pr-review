import links


def test_line_anchor_single():
    assert links.line_anchor(100) == "#L100"

def test_line_anchor_range():
    assert links.line_anchor(100, 150) == "#L100-L150"

def test_line_anchor_none():
    assert links.line_anchor(None) == ""

def test_github_link_single_line():
    url = links.github_link("acme", "my-plugin", "issue/89",
                            "includes/class-foo.php", 42)
    assert url == ("https://github.com/acme/my-plugin/"
                   "blob/issue/89/includes/class-foo.php#L42")

def test_github_link_no_line():
    url = links.github_link("o", "r", "main", "a/b.php")
    assert url == "https://github.com/o/r/blob/main/a/b.php"

def test_editor_link_is_relative_with_anchor():
    # review.md at .pr-reviews/r/89/review.md ; file two trees up under the repo
    rel = links.editor_link(
        review_md=".pr-reviews/my-plugin/89/review.md",
        target_file="wp-content/plugins/my-plugin/includes/class-foo.php",
        line=42)
    assert rel == "../../../wp-content/plugins/my-plugin/includes/class-foo.php#L42"

def test_make_links_returns_all_three():
    out = links.make_links(
        owner="o", repo="r", branch="main",
        review_md=".pr-reviews/r/1/review.md",
        repo_root="wp-content/plugins/r",
        file="a.php",
        repo_path_in_branch="a.php",
        line=10, end_line=20)
    assert out["github"].endswith("/blob/main/a.php#L10-L20")
    assert out["editor"].endswith("a.php#L10-L20")
    assert "[Editor]" in out["formatted"] and "[GitHub]" in out["formatted"]


def test_github_link_slash_branch():
    url = links.github_link(
        "acme", "My-Plugin-Pro", "feature/2290",
        "src/REST/Controllers/Renewals/Validate.php", 96)
    assert url == ("https://github.com/acme/My-Plugin-Pro/"
                   "blob/feature/2290/src/REST/Controllers/Renewals/Validate.php#L96")


def test_editor_from_root_absolute_inputs():
    # Real-world case: both review_md and repo_root passed as absolute paths.
    review_md = "/private/tmp/ws/.pr-reviews/My-Plugin-Pro/2300/review.md"
    repo_root = "/private/tmp/ws/app/public/wp-content/plugins/my-plugin-pro"
    rel = links.editor_link_from_root(
        review_md=review_md, repo_root=repo_root,
        file="src/REST/Controllers/Renewals/Validate.php", line=96)
    assert rel.endswith(
        "src/REST/Controllers/Renewals/Validate.php#L96")
    assert not rel.startswith("/")
    assert "private/tmp" not in rel


def test_editor_from_root_mixed_inputs():
    # Absolute review_md, relative repo_root (and vice-versa) must give the
    # same correct relative result with no CWD leak.
    abs_review = "/private/tmp/ws/.pr-reviews/r/1/review.md"
    rel_root = "app/x"  # relative to CWD, which is not /private/tmp/ws
    rel = links.editor_link_from_root(
        review_md=abs_review, repo_root=rel_root, file="a.php", line=5)
    # Mixed bases resolve against the same absolute frame; no garbage CWD prefix.
    assert rel.endswith("a.php#L5")
    assert "private/tmp" not in rel
    assert not rel.startswith("/")


def test_acceptance_case_pr_2300():
    out = links.make_links(
        owner="acme", repo="My-Plugin-Pro",
        branch="feature/2290",
        review_md=".pr-reviews/My-Plugin-Pro/2300/review.md",
        repo_root="app/public/wp-content/plugins/my-plugin-pro",
        file="src/REST/Controllers/Renewals/Validate.php",
        repo_path_in_branch="src/REST/Controllers/Renewals/Validate.php",
        line=96)
    assert out["editor"] == (
        "../../../app/public/wp-content/plugins/my-plugin-pro/"
        "src/REST/Controllers/Renewals/Validate.php#L96")
    assert out["github"] == (
        "https://github.com/acme/My-Plugin-Pro/"
        "blob/feature/2290/src/REST/Controllers/Renewals/Validate.php#L96")
