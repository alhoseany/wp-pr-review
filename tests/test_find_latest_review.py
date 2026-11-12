import re
import find_latest_review


def test_single_round_no_suffix(tmp_path):
    """single round, no suffix: only pr/review.md exists → returns that path."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create .pr-reviews/<repo>/<pr>/review.md
    review_dir = base_dir / ".pr-reviews" / repo / pr
    review_dir.mkdir(parents=True)
    review_file = review_dir / "review.md"
    review_file.write_text("# Review")

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    assert result == str(review_file)


def test_numeric_greater_than_lexical(tmp_path):
    """numeric>lexical: 2300/, 2300-2/, 2300-10/ all with review.md → returns 2300-10/review.md (NOT 2300-2)."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create directories: 2300/, 2300-2/, 2300-10/ with review.md in each
    for suffix in ["", "-2", "-10"]:
        review_dir = base_dir / ".pr-reviews" / repo / (pr + suffix)
        review_dir.mkdir(parents=True)
        review_file = review_dir / "review.md"
        review_file.write_text("# Review")

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    expected = str(base_dir / ".pr-reviews" / repo / "2300-10" / "review.md")
    assert result == expected


def test_none_empty_directory(tmp_path):
    """none: empty .pr-reviews/<repo>/ (or absent) → returns None."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create empty .pr-reviews/<repo>/ directory (no matching dirs inside)
    (base_dir / ".pr-reviews" / repo).mkdir(parents=True)

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    assert result is None


def test_filter_sole_no_review_files(tmp_path):
    """filter-sole: dirs 2300/, 2300-2/ exist but NEITHER contains review.md → returns None (no crash, no pick)."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create directories without review.md
    for suffix in ["", "-2"]:
        review_dir = base_dir / ".pr-reviews" / repo / (pr + suffix)
        review_dir.mkdir(parents=True)
        # Don't create review.md

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    assert result is None


def test_prefix_collision(tmp_path):
    """prefix-collision: 2300/review.md and 23000/review.md both exist, query pr=2300 → returns the 2300 path only (regex anchored, 23000 excluded)."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create 2300/ with review.md
    review_dir_1 = base_dir / ".pr-reviews" / repo / "2300"
    review_dir_1.mkdir(parents=True)
    review_file_1 = review_dir_1 / "review.md"
    review_file_1.write_text("# Review 2300")

    # Create 23000/ with review.md
    review_dir_2 = base_dir / ".pr-reviews" / repo / "23000"
    review_dir_2.mkdir(parents=True)
    review_file_2 = review_dir_2 / "review.md"
    review_file_2.write_text("# Review 23000")

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    # Should return only the 2300 path, not 23000
    assert result == str(review_file_1)


def test_cli_contract_with_review(tmp_path, capsys):
    """CLI contract: when a review exists → printed path non-empty + no SystemExit/exit 0."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create review
    review_dir = base_dir / ".pr-reviews" / repo / pr
    review_dir.mkdir(parents=True)
    review_file = review_dir / "review.md"
    review_file.write_text("# Review")

    find_latest_review.main(argv=["--base-dir", str(base_dir), "--repo", repo, "--pr", pr])
    captured = capsys.readouterr()

    assert captured.out.strip() == str(review_file)


def test_cli_contract_without_review(tmp_path, capsys):
    """CLI contract: when none → capsys.readouterr().out.strip() == '' + exit 0."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create empty .pr-reviews directory (no matching reviews)
    (base_dir / ".pr-reviews" / repo).mkdir(parents=True)

    find_latest_review.main(argv=["--base-dir", str(base_dir), "--repo", repo, "--pr", pr])
    captured = capsys.readouterr()

    assert captured.out.strip() == ""


def test_bare_vs_suffix(tmp_path):
    """bare-vs-suffix: 2300/review.md and 2300-2/review.md → returns the 2300-2 path (bare round-1 must LOSE)."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create 2300/ with review.md
    review_dir_1 = base_dir / ".pr-reviews" / repo / "2300"
    review_dir_1.mkdir(parents=True)
    review_file_1 = review_dir_1 / "review.md"
    review_file_1.write_text("# Review")

    # Create 2300-2/ with review.md
    review_dir_2 = base_dir / ".pr-reviews" / repo / "2300-2"
    review_dir_2.mkdir(parents=True)
    review_file_2 = review_dir_2 / "review.md"
    review_file_2.write_text("# Review")

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    # Should return the 2300-2 path (higher round number)
    assert result == str(review_file_2)


def test_non_numeric_suffix(tmp_path):
    r"""non-numeric suffix: 2300/review.md and 2300-foo/review.md → returns the 2300 path (-foo excluded by -\d+)."""
    base_dir = tmp_path
    repo = "test-repo"
    pr = "2300"

    # Create 2300/ with review.md
    review_dir_1 = base_dir / ".pr-reviews" / repo / "2300"
    review_dir_1.mkdir(parents=True)
    review_file_1 = review_dir_1 / "review.md"
    review_file_1.write_text("# Review")

    # Create 2300-foo/ with review.md (non-numeric suffix, should be excluded)
    review_dir_2 = base_dir / ".pr-reviews" / repo / "2300-foo"
    review_dir_2.mkdir(parents=True)
    review_file_2 = review_dir_2 / "review.md"
    review_file_2.write_text("# Review")

    result = find_latest_review.latest_review(str(base_dir), repo, pr)
    # Should return the 2300 path (2300-foo excluded by pattern)
    assert result == str(review_file_1)
