import json
import pytest
import harvest_issues as h


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pr(
    number=1,
    merged_at="2026-06-10T12:00:00Z",
    issues=None,
    files=None,
    body="PR body",
    merge_commit_oid="abc123",
):
    """Build a minimal PR dict matching the gh pr list --json shape."""
    if issues is None:
        issues = [{"number": 42}]
    if files is None:
        files = [{"path": "src/foo.php"}]
    return {
        "number": number,
        "body": body,
        "mergedAt": merged_at,
        "mergeCommit": {"oid": merge_commit_oid},
        "closingIssuesReferences": issues,
        "files": files,
    }


def _issue_json(title="Issue title", body="Issue body"):
    return json.dumps({"title": title, "body": body})


# ---------------------------------------------------------------------------
# should_include
# ---------------------------------------------------------------------------

def test_should_include_ok():
    pr = _make_pr(merged_at="2026-06-10T12:00:00Z")
    ok, reason = h.should_include(pr, watermark="2026-06-09T00:00:00Z")
    assert ok is True
    assert reason == "ok"


def test_should_include_no_issue():
    pr = _make_pr(issues=[])
    ok, reason = h.should_include(pr, watermark=None)
    assert ok is False
    assert reason == "no_issue"


def test_should_include_stale():
    pr = _make_pr(merged_at="2026-06-05T00:00:00Z")
    ok, reason = h.should_include(pr, watermark="2026-06-05T00:00:00Z")
    assert ok is False
    assert reason == "stale"


def test_should_include_no_files():
    pr = _make_pr(files=[])
    ok, reason = h.should_include(pr, watermark=None)
    assert ok is False
    assert reason == "no_files"


def test_should_include_precedence():
    # no issue AND no files → no_issue wins
    pr_no_issue_no_files = _make_pr(issues=[], files=[])
    ok, reason = h.should_include(pr_no_issue_no_files, watermark=None)
    assert ok is False
    assert reason == "no_issue"

    # issue present BUT stale AND no files → stale wins over no_files
    pr_stale_no_files = _make_pr(
        issues=[{"number": 7}],
        files=[],
        merged_at="2026-06-01T00:00:00Z",
    )
    ok2, reason2 = h.should_include(pr_stale_no_files, watermark="2026-06-01T00:00:00Z")
    assert ok2 is False
    assert reason2 == "stale"


# ---------------------------------------------------------------------------
# build_record
# ---------------------------------------------------------------------------

def test_build_record_fetches_issue_via_gh():
    pr = _make_pr(
        number=10,
        issues=[{"number": 99}],
        files=[{"path": "a.php"}, {"path": "b.php"}],
        body="PR body text",
        merge_commit_oid="deadbeef",
    )

    def fake_run(args, check=True):
        if args[:2] == ["issue", "view"]:
            # args: ["issue", "view", "99", "--repo", "owner/repo", "--json", "title,body"]
            return json.dumps({"title": "Issue title from GH", "body": "Issue body from GH"})
        raise AssertionError(f"unexpected args: {args}")

    records = h.build_record(pr, owner="owner", repo="repo", run=fake_run)

    assert isinstance(records, list) and len(records) == 1
    record = records[0]
    assert record["pr"] == 10
    assert record["issue"] == 99
    assert record["issue_title"] == "Issue title from GH"
    assert record["issue_body"] == "Issue body from GH"
    assert record["pr_body"] == "PR body text"
    # pinpoint fields are NOT persisted (generalized-by-design)
    assert "fix_commit" not in record
    assert "changed_files" not in record
    # base-repo fetched (ref lacks a `repository` subfield)
    assert record["repo"] == "owner/repo"


def test_build_record_redacts_sensitive_links_and_emails():
    """A body or title carrying a private link (chat/helpdesk host, claude.ai
    session, GitHub private user-attachment) or an email address must come back
    redacted — nothing private or PII is stored, while enough surrounding text
    survives to distill a pattern."""
    sensitive = (
        "Repro from https://acme.slack.com/archives/C123/p456 and ticket "
        "https://secure.helpscout.net/conversation/789 plus "
        "https://acme.zendesk.com/agent/tickets/42 . Session https://claude.ai/chat/abc . "
        "Screenshot https://github.com/user-attachments/assets/deadbeef and "
        "https://private-user-images.githubusercontent.com/1/2.png . "
        "Contact jane.doe@example.com for details."
    )
    pr = _make_pr(number=11, issues=[{"number": 12}], files=[{"path": "a.php"}], body=sensitive)

    def fake_run(args, check=True):
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "Issue title", "body": sensitive})
        raise AssertionError(f"unexpected args: {args}")

    record = h.build_record(pr, owner="owner", repo="repo", run=fake_run)[0]

    for field in ("issue_body", "pr_body"):
        text = record[field]
        assert "slack.com" not in text
        assert "helpscout.net" not in text
        assert "zendesk.com" not in text
        assert "claude.ai" not in text
        assert "user-attachments" not in text
        assert "githubusercontent.com" not in text
        assert "jane.doe@example.com" not in text
        assert "[redacted]" in text
        # surrounding prose survives for pattern distillation
        assert "Repro from" in text or "Contact" in text


# ---------------------------------------------------------------------------
# gather
# ---------------------------------------------------------------------------

def test_gather_filters_and_builds():
    prs = [
        _make_pr(number=1, merged_at="2026-06-10T10:00:00Z"),         # ok
        _make_pr(number=2, issues=[], merged_at="2026-06-10T11:00:00Z"),  # no_issue
        _make_pr(number=3, files=[], merged_at="2026-06-10T12:00:00Z"),   # no_files
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    records, _raw_max, _complete = h.gather("owner", "repo", watermark=None, run=fake_run)
    assert len(records) == 1
    assert records[0]["pr"] == 1


def test_gather_watermark_excludes_stale():
    prs = [
        _make_pr(number=5, merged_at="2026-06-08T00:00:00Z"),  # stale
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        raise AssertionError(f"unexpected args: {args}")

    records, _raw_max, _complete = h.gather("owner", "repo", watermark="2026-06-08T00:00:00Z", run=fake_run)
    assert records == []


def test_gh_failure_raises():
    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            raise RuntimeError("gh pr list failed: 403")
        raise AssertionError(f"unexpected args: {args}")

    with pytest.raises(RuntimeError):
        h.gather("owner", "repo", watermark=None, run=fake_run)


# ---------------------------------------------------------------------------
# write_records / watermark
# ---------------------------------------------------------------------------

def test_write_records_to_staging_not_live_ref(tmp_path):
    records = [{"pr": 1, "issue": 42, "issue_title": "T", "issue_body": "B",
                "pr_body": "PB", "fix_commit": "abc", "changed_files": ["x.php"]}]
    out_file = tmp_path / "harvest-records.json"

    h.write_records(records, out_file)

    assert out_file.exists()
    loaded = json.loads(out_file.read_text())
    assert loaded == records

    # Must never have written the live reference file
    live_ref = tmp_path / "references" / "known-bug-patterns.md"
    assert not live_ref.exists()


def test_watermark_roundtrip(tmp_path):
    wm_file = tmp_path / "watermark"

    # Missing file → None
    assert h.read_watermark(wm_file) is None

    # Write then read back
    h.write_watermark(wm_file, "2026-06-16T00:00:00Z")
    assert h.read_watermark(wm_file) == "2026-06-16T00:00:00Z"


# ---------------------------------------------------------------------------
# record count guard
# ---------------------------------------------------------------------------

def test_record_count_matches():
    # 4 PRs: 2 includable, 1 no_issue, 1 no_files
    prs = [
        _make_pr(number=1, merged_at="2026-06-10T01:00:00Z"),
        _make_pr(number=2, merged_at="2026-06-10T02:00:00Z"),
        _make_pr(number=3, issues=[], merged_at="2026-06-10T03:00:00Z"),
        _make_pr(number=4, files=[], merged_at="2026-06-10T04:00:00Z"),
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    records, _raw_max, _complete = h.gather("owner", "repo", watermark=None, run=fake_run)
    assert len(records) == 2


# ---------------------------------------------------------------------------
# main() bumps watermark from raw list (DVW High)
# ---------------------------------------------------------------------------

def test_main_bumps_watermark_from_raw_list(tmp_path):
    """The watermark written must equal the newest mergedAt in the RAW gh
    pr list, even if that PR was SKIPPED (e.g. no files).  An older PR that
    IS included must NOT be used as the cutoff."""
    wm_file = tmp_path / "watermark"
    out_file = tmp_path / "records.json"

    older_included = _make_pr(
        number=1,
        merged_at="2026-06-09T00:00:00Z",
        files=[{"path": "x.php"}],
        issues=[{"number": 10}],
    )
    newer_skipped = _make_pr(
        number=2,
        merged_at="2026-06-11T00:00:00Z",  # newest but skipped (no files)
        files=[],
        issues=[{"number": 11}],
    )

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps([older_included, newer_skipped])
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    h.main(
        argv=[
            "--watermark-file", str(wm_file),
            "--out", str(out_file),
            "--repo", "owner/repo",
        ],
        run=fake_run,
    )

    written_wm = h.read_watermark(wm_file)
    assert written_wm == "2026-06-10T23:59:59Z", (
        f"Expected max(mergedAt from raw list, skipped PR) - 1s == "
        f"2026-06-10T23:59:59Z, got {written_wm!r}"
    )


# ---------------------------------------------------------------------------
# H-01 — RED tests for the windowed fetch design (order-independent, in gather())
# ---------------------------------------------------------------------------

def _filler_page(n, prefix=9000):
    """Build n minimal no-issue PR dicts (cheap filler for full-page fixtures)."""
    return [
        _make_pr(number=prefix + i, issues=[], merged_at="2026-01-01T00:00:00Z")
        for i in range(n)
    ]


def test_gather_search_query_shape_and_no_sort_token():
    """H-01 tests 1 & 4 (BUNDLED): the fetch must use `--search "is:merged
    merged:>WATERMARK"` at `--limit 1000` (no `--state merged`, no bare list),
    and NO issued query may contain a `sort:` token (order-independence —
    bundled here so the negative assertion is never vacuous)."""
    watermark = "2026-06-09T00:00:00Z"
    calls = []

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            calls.append(args)
            return json.dumps([])
        raise AssertionError(f"unexpected args: {args}")

    h.gather("owner", "repo", watermark=watermark, run=fake_run)

    assert calls, "expected at least one `pr list` query"
    first = calls[0]
    assert "--search" in first, "must use --search, not a bare `pr list --state merged`"
    search_val = first[first.index("--search") + 1]
    assert "is:merged" in search_val
    assert f"merged:>{watermark}" in search_val
    assert "--state" not in first, "must NOT pass --state merged"
    assert "--limit" in first
    assert first[first.index("--limit") + 1] == "1000"

    for call in calls:
        call_str = " ".join(call)
        assert "sort:" not in call_str, "no query may contain a sort: token (order-independence)"


def test_gather_full_page_triggers_calendar_slicing():
    """H-01 test 2: a 1000-row page must trigger calendar-slice sub-queries
    (`merged:<A>..<B>`), each driven to a short page (<1000 rows)."""
    full_page = _filler_page(1000)
    short_page = _filler_page(5, prefix=1)

    calls = []

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            calls.append(args)
            search_val = args[args.index("--search") + 1] if "--search" in args else None
            if search_val and ".." in search_val:
                return json.dumps(short_page)
            return json.dumps(full_page)
        raise AssertionError(f"unexpected args: {args}")

    h.gather("owner", "repo", watermark="2026-06-01T00:00:00Z", run=fake_run)

    slice_calls = [
        c for c in calls
        if "--search" in c and ".." in c[c.index("--search") + 1]
    ]
    assert slice_calls, "expected calendar-slice queries (merged:<A>..<B>) after a full 1000-row page"
    assert len(short_page) < 1000  # sanity: slice responses modeled as short pages


def test_gather_accumulates_and_dedupes_across_slices():
    """H-01 test 3: records from all queries/slices accumulate; a PR duplicated
    across the seam between adjacent slices is deduped by the pinned key."""
    filler = _filler_page(999)  # no-issue filler to keep the initial page at 1000 rows
    seam_pr = _make_pr(number=500, issues=[{"number": 77}], merged_at="2026-05-01T00:00:00Z")
    full_page = filler + [seam_pr]  # 1000 rows total

    new_pr = _make_pr(number=600, issues=[{"number": 88}], merged_at="2026-05-02T00:00:00Z")
    slice_page_a = [seam_pr, new_pr]  # seam PR duplicated here
    slice_page_b = [seam_pr]          # and again here

    state = {"slices": 0}

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            search_val = args[args.index("--search") + 1] if "--search" in args else None
            if search_val and ".." in search_val:
                state["slices"] += 1
                return json.dumps(slice_page_a if state["slices"] == 1 else slice_page_b)
            return json.dumps(full_page)
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    result = h.gather("owner", "repo", watermark="2026-04-01T00:00:00Z", run=fake_run)
    records = result[0] if isinstance(result, tuple) else result

    pr_numbers = [r["pr"] for r in records]
    assert 500 in pr_numbers and 600 in pr_numbers, "records must accumulate across all queries/slices"
    assert pr_numbers.count(500) == 1, "seam-overlap duplicate must be deduped by the pinned key"


def test_gather_returns_pinned_tuple():
    """H-01 test 5: gather() returns (records, raw_max_merged_at, complete)."""
    prs = [_make_pr(number=1, merged_at="2026-06-10T10:00:00Z")]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    result = h.gather("owner", "repo", watermark=None, run=fake_run)

    assert isinstance(result, tuple) and len(result) == 3, (
        "gather() must return a 3-tuple (records, raw_max_merged_at, complete)"
    )
    records, raw_max_merged_at, complete = result
    assert isinstance(records, list)
    assert raw_max_merged_at == "2026-06-10T10:00:00Z"
    assert isinstance(complete, bool)


def test_gather_first_run_plain_is_merged_no_qualifier():
    """H-01 test 6: watermark=None → the issued search is plain `is:merged`,
    with NO `merged:` qualifier."""
    calls = []

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            calls.append(args)
            return json.dumps([])
        raise AssertionError(f"unexpected args: {args}")

    h.gather("owner", "repo", watermark=None, run=fake_run)

    assert calls, "expected at least one `pr list` query"
    first = calls[0]
    assert "--search" in first
    search_val = first[first.index("--search") + 1]
    assert search_val.strip() == "is:merged", (
        f"first run must query plain is:merged with no merged: qualifier, got {search_val!r}"
    )


def test_gather_day_slice_full_page_halves_further():
    """H-01 test 7: a day-slice returning 1000 rows must itself be halved into
    sub-slices that short-page; their records accumulate into the result."""
    top_full = _filler_page(1000, prefix=8000)        # initial merged:> page (full)
    day_slice_full = _filler_page(1000, prefix=7000)  # one day-slice still full
    half_a = [_make_pr(number=701, issues=[{"number": 1}], merged_at="2026-05-10T00:00:00Z")]
    half_b = [_make_pr(number=702, issues=[{"number": 2}], merged_at="2026-05-11T00:00:00Z")]

    state = {"slice_calls": 0}

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            search_val = args[args.index("--search") + 1] if "--search" in args else None
            if search_val and ".." in search_val:
                state["slice_calls"] += 1
                if state["slice_calls"] == 1:
                    return json.dumps(day_slice_full)  # day-slice: still full → must halve
                elif state["slice_calls"] == 2:
                    return json.dumps(half_a)
                else:
                    return json.dumps(half_b)
            return json.dumps(top_full)
        if args[:2] == ["issue", "view"]:
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    result = h.gather("owner", "repo", watermark="2026-05-01T00:00:00Z", run=fake_run)
    records = result[0] if isinstance(result, tuple) else result

    pr_numbers = {r["pr"] for r in records}
    assert {701, 702}.issubset(pr_numbers), (
        "records from the halved sub-slices of a still-full day-slice must accumulate"
    )


def test_gather_first_run_full_page_uses_createdat_floor():
    """H-01 test 8: watermark=None + a 1000-row page for the plain `is:merged`
    query must fetch the repo's createdAt (`gh repo view <owner>/<repo> --json
    createdAt`) as the range floor, then issue year-granularity slices."""
    full_page = _filler_page(1000, prefix=6000)
    short_page = _filler_page(5, prefix=1)

    calls = []

    def fake_run(args, check=True):
        calls.append(args)
        if args[:2] == ["repo", "view"]:
            return json.dumps({"createdAt": "2020-01-01T00:00:00Z"})
        if args[:2] == ["pr", "list"]:
            search_val = args[args.index("--search") + 1] if "--search" in args else None
            if search_val and ".." in search_val:
                return json.dumps(short_page)
            return json.dumps(full_page)
        raise AssertionError(f"unexpected args: {args}")

    h.gather("owner", "repo", watermark=None, run=fake_run)

    repo_view_calls = [c for c in calls if c[:2] == ["repo", "view"]]
    assert repo_view_calls, "first-run full page must fetch repo createdAt as the range floor"

    slice_calls = [
        c for c in calls
        if c[:2] == ["pr", "list"] and "--search" in c and ".." in c[c.index("--search") + 1]
    ]
    assert slice_calls, "year-granularity slices must be issued from the createdAt floor"


# ---------------------------------------------------------------------------
# H-02 — RED tests for the global watermark rule
# ---------------------------------------------------------------------------

def test_main_watermark_all_short_paged_max_minus_one_second(tmp_path):
    """H-02 rule 1: when all windows/slices short-page, the watermark written
    is max(mergedAt over fetched set) minus 1 second, in second-precision
    UTC `YYYY-MM-DDTHH:MM:SSZ` (no microseconds)."""
    wm_file = tmp_path / "watermark"
    out_file = tmp_path / "records.json"

    prs = [
        _make_pr(number=1, issues=[], merged_at="2026-06-10T10:00:00Z"),
        _make_pr(number=2, issues=[], merged_at="2026-06-10T11:00:00Z"),
        _make_pr(number=3, issues=[], merged_at="2026-06-10T12:00:05Z"),
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        raise AssertionError(f"unexpected args: {args}")

    h.main(
        argv=["--watermark-file", str(wm_file), "--out", str(out_file), "--repo", "owner/repo"],
        run=fake_run,
    )

    written = h.read_watermark(wm_file)
    assert written == "2026-06-10T12:00:04Z", (
        f"expected max(mergedAt) - 1s == 2026-06-10T12:00:04Z, got {written!r}"
    )


def test_main_watermark_untouched_when_window_unresolved(tmp_path):
    """H-02 rule 2: if any window/slice is still full (unresolved) — or the
    run crashes mid-way — the watermark file must be left exactly as it was;
    this is a global rule (one unresolved slice freezes the whole run)."""
    wm_file = tmp_path / "watermark"
    out_file = tmp_path / "records.json"
    wm_file.write_text("2026-01-01T00:00:00Z")

    full_page = [
        _make_pr(number=1000 + i, issues=[], merged_at=f"2026-06-{(i % 28) + 1:02d}T00:00:00Z")
        for i in range(1000)
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(full_page)
        raise AssertionError(f"unexpected args: {args}")

    h.main(
        argv=["--watermark-file", str(wm_file), "--out", str(out_file), "--repo", "owner/repo"],
        run=fake_run,
    )

    assert h.read_watermark(wm_file) == "2026-01-01T00:00:00Z", (
        "a still-full (unresolved) window must leave the watermark file untouched"
    )


def test_main_watermark_never_written_older_than_stored(tmp_path):
    """H-02 rule 3: monotonic — never write a watermark older than the value
    already stored, even if this run's computed cutoff is older."""
    wm_file = tmp_path / "watermark"
    out_file = tmp_path / "records.json"
    wm_file.write_text("2026-07-01T00:00:00Z")  # newer than anything this run fetches

    prs = [_make_pr(number=1, issues=[], merged_at="2026-06-10T12:00:00Z")]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        raise AssertionError(f"unexpected args: {args}")

    h.main(
        argv=["--watermark-file", str(wm_file), "--out", str(out_file), "--repo", "owner/repo"],
        run=fake_run,
    )

    assert h.read_watermark(wm_file) == "2026-07-01T00:00:00Z", (
        "watermark must never regress to an older value"
    )


def test_main_degenerate_one_second_slice_still_full_warns_and_untouched(tmp_path, capsys):
    """H-02 rule 4: a slice halved down to a 1-second span that STILL returns
    a full page is a degenerate case — the run must warn loudly and leave the
    watermark untouched (global freeze), never silently drop data."""
    wm_file = tmp_path / "watermark"
    out_file = tmp_path / "records.json"
    wm_file.write_text("2026-01-01T00:00:00Z")

    full_page = [
        _make_pr(number=2000 + i, issues=[], merged_at="2026-06-15T00:00:00Z")
        for i in range(1000)
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(full_page)
        raise AssertionError(f"unexpected args: {args}")

    h.main(
        argv=["--watermark-file", str(wm_file), "--out", str(out_file), "--repo", "owner/repo"],
        run=fake_run,
    )

    captured = capsys.readouterr()
    assert "warn" in (captured.out + captured.err).lower(), (
        "a degenerate 1-second-slice-still-full case must warn loudly"
    )
    assert h.read_watermark(wm_file) == "2026-01-01T00:00:00Z", (
        "watermark must be left untouched for the run when a slice degenerates"
    )


def test_gather_empty_fetched_set_no_crash():
    """H-02 rule 5: an empty fetched set must not crash (no `max([])`), and
    reports `raw_max_merged_at = None` rather than advancing the watermark."""
    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps([])
        raise AssertionError(f"unexpected args: {args}")

    records, raw_max_merged_at, complete = h.gather("owner", "repo", watermark=None, run=fake_run)

    assert records == []
    assert raw_max_merged_at is None


def test_gather_none_merged_at_excluded_from_max():
    """H-02 rule 6: PRs with `mergedAt: None` must be excluded from the max
    computation — the max is the newest REAL timestamp, not None."""
    prs = [
        _make_pr(number=1, issues=[], merged_at="2026-06-10T10:00:00Z"),
        _make_pr(number=2, issues=[], merged_at=None),
    ]

    def fake_run(args, check=True):
        if args[:2] == ["pr", "list"]:
            return json.dumps(prs)
        raise AssertionError(f"unexpected args: {args}")

    records, raw_max_merged_at, complete = h.gather("owner", "repo", watermark=None, run=fake_run)

    assert raw_max_merged_at == "2026-06-10T10:00:00Z"


# ---------------------------------------------------------------------------
# H-03 — RED tests for append + dedupe survival in write_records
# ---------------------------------------------------------------------------

def test_write_records_zero_new_content_equal(tmp_path):
    """H-03: a 0-new run must leave the existing records file content-equal
    (compared as parsed JSON, not bytes) — never truncated to `[]`."""
    out_file = tmp_path / "records.json"
    existing = [{
        "pr": 1, "issue": 42, "repo": "owner/repo",
        "issue_title": "T", "issue_body": "B",
        "pr_body": "PB", "fix_commit": "abc", "changed_files": ["x.php"],
    }]
    out_file.write_text(json.dumps(existing))

    h.write_records([], out_file)

    loaded = json.loads(out_file.read_text())
    assert loaded == existing, "0-new run must leave existing records file content-equal, not truncate to []"


def test_write_records_appends_new(tmp_path):
    """H-03: new records APPEND to the existing file rather than replacing it."""
    out_file = tmp_path / "records.json"
    a = {
        "pr": 1, "issue": 42, "repo": "owner/repo",
        "issue_title": "A", "issue_body": "AB",
        "pr_body": "APB", "fix_commit": "aaa", "changed_files": ["a.php"],
    }
    b = {
        "pr": 2, "issue": 7, "repo": "owner/repo",
        "issue_title": "B", "issue_body": "BB",
        "pr_body": "BPB", "fix_commit": "bbb", "changed_files": ["b.php"],
    }
    out_file.write_text(json.dumps([a]))

    h.write_records([b], out_file)

    loaded = json.loads(out_file.read_text())
    keys = {(r.get("repo"), r["pr"], r["issue"]) for r in loaded}
    assert keys == {("owner/repo", 1, 42), ("owner/repo", 2, 7)}, (
        "new record must APPEND to existing, not replace"
    )


def test_write_records_dedupe_no_duplicate(tmp_path):
    """H-03: a record whose key already exists must NOT be re-added, while
    other pre-existing records survive the write."""
    out_file = tmp_path / "records.json"
    other = {
        "pr": 2, "issue": 7, "repo": "owner/repo",
        "issue_title": "Other", "issue_body": "B2",
        "pr_body": "PB2", "fix_commit": "def", "changed_files": ["y.php"],
    }
    existing = {
        "pr": 1, "issue": 42, "repo": "owner/repo",
        "issue_title": "Old", "issue_body": "B",
        "pr_body": "PB", "fix_commit": "abc", "changed_files": ["x.php"],
    }
    out_file.write_text(json.dumps([other, existing]))

    dup = {**existing, "issue_title": "New title but same key"}
    h.write_records([dup], out_file)

    loaded = json.loads(out_file.read_text())
    assert len(loaded) == 2, "duplicate key must not be re-added, and other record must survive"
    keys = {(r.get("repo"), r["pr"], r["issue"]) for r in loaded}
    assert keys == {("owner/repo", 2, 7), ("owner/repo", 1, 42)}


def test_write_records_returns_delta(tmp_path):
    """H-03: write_records() RETURNS the count of NEW (post-dedupe) records
    added, not the total or None."""
    out_file = tmp_path / "records.json"
    existing = {
        "pr": 1, "issue": 42, "repo": "owner/repo",
        "issue_title": "T", "issue_body": "B",
        "pr_body": "PB", "fix_commit": "abc", "changed_files": ["x.php"],
    }
    out_file.write_text(json.dumps([existing]))

    new_b = {
        "pr": 2, "issue": 7, "repo": "owner/repo",
        "issue_title": "B", "issue_body": "BB",
        "pr_body": "BPB", "fix_commit": "bbb", "changed_files": ["b.php"],
    }
    dup_of_existing = dict(existing)

    delta = h.write_records([new_b, dup_of_existing], out_file)

    assert delta == 1, "delta must equal the number of NEW post-dedupe records added"


# ---------------------------------------------------------------------------
# H-04 — RED tests for multi-issue / foreign-repo / base-fallback records
# ---------------------------------------------------------------------------

def test_build_record_multiple_issues_returns_list():
    """H-04 test 1: a PR with 2 closing issues must produce 2 records."""
    pr = _make_pr(
        number=5,
        issues=[{"number": 10}, {"number": 20}],
        files=[{"path": "a.php"}],
    )

    def fake_run(args, check=True):
        if args[:2] == ["issue", "view"]:
            issue_num = args[2]
            return json.dumps({"title": f"Issue {issue_num}", "body": f"Body {issue_num}"})
        raise AssertionError(f"unexpected args: {args}")

    records = h.build_record(pr, owner="owner", repo="repo", run=fake_run)

    assert isinstance(records, list), "build_record must return a List[dict], one per closing issue"
    assert len(records) == 2
    assert {r["issue"] for r in records} == {10, 20}


def test_build_record_foreign_repo_issue_fetched_from_own_repo():
    """H-04 test 2: a closing ref with a foreign `repository{name, owner{login}}`
    must be fetched via `gh issue view --repo <owner>/<name>` (that repo), and
    the record's `repo` key reflects the foreign repo."""
    pr = _make_pr(
        number=6,
        issues=[{"number": 55, "repository": {"name": "foo", "owner": {"login": "bar"}}}],
        files=[{"path": "a.php"}],
    )

    def fake_run(args, check=True):
        if args[:2] == ["issue", "view"]:
            assert args[:3] == ["issue", "view", "55"]
            assert "--repo" in args
            assert args[args.index("--repo") + 1] == "bar/foo", (
                "foreign closing ref must be fetched from its OWN repo, not the base repo"
            )
            return json.dumps({"title": "FT", "body": "FB"})
        raise AssertionError(f"unexpected args: {args}")

    result = h.build_record(pr, owner="owner", repo="repo", run=fake_run)
    record = result[0] if isinstance(result, list) else result

    assert record.get("repo") == "bar/foo"


def test_build_record_base_repo_fallback_when_no_repository_subfield():
    """H-04 test 3: a closing ref WITHOUT a `repository` subfield (the shape
    `_make_pr` already builds) must fall back to the base owner/repo, and the
    record's `repo` key reflects that base repo."""
    pr = _make_pr(
        number=7,
        issues=[{"number": 33}],  # no `repository` subfield
        files=[{"path": "a.php"}],
    )

    def fake_run(args, check=True):
        if args[:2] == ["issue", "view"]:
            assert args[:3] == ["issue", "view", "33"]
            assert args[args.index("--repo") + 1] == "owner/repo"
            return json.dumps({"title": "T", "body": "B"})
        raise AssertionError(f"unexpected args: {args}")

    result = h.build_record(pr, owner="owner", repo="repo", run=fake_run)
    record = result[0] if isinstance(result, list) else result

    assert record.get("repo") == "owner/repo"


def test_should_include_zero_closing_refs_skipped():
    """H-04 test 4 — regression guard (documented RED-gate exception: this
    already passes under current code). 0 closing refs must remain skipped
    as `(False, "no_issue")`, preserved once build_record grows multi-issue
    support."""
    pr = _make_pr(issues=[])
    ok, reason = h.should_include(pr, watermark=None)
    assert ok is False
    assert reason == "no_issue"


# ---------------------------------------------------------------------------
# H-05 — RED test for the None-safe stale check
# ---------------------------------------------------------------------------

def test_should_include_none_merged_at_with_watermark_is_included():
    """H-05: `mergedAt` PRESENT-but-`None` under a TRUTHY watermark must be
    INCLUDED (non-stale) with no TypeError — None bypasses the compare."""
    pr = _make_pr(merged_at=None, issues=[{"number": 9}], files=[{"path": "z.php"}])

    ok, reason = h.should_include(pr, watermark="2026-06-01T00:00:00Z")

    assert ok is True
    assert reason == "ok"


# ---------------------------------------------------------------------------
# Org-wide repo listing
# ---------------------------------------------------------------------------

def test_list_org_repos_sorts_dedupes_and_paginates():
    """The batch harvest must see every repo, not gh repo list's first page."""
    calls = []

    def fake_run(args, check=True):
        calls.append(args)
        return "\n".join([
            "acme/beta-plugin-addon",
            "acme/Beta-Plugin",
            "acme/beta-plugin-addon",
            "",
            "not-a-repo",
            '"acme/alpha-plugin"',
        ])

    repos = h.list_org_repos("acme", run=fake_run)

    assert repos == [
        "acme/alpha-plugin",
        "acme/Beta-Plugin",
        "acme/beta-plugin-addon",
    ]
    assert calls == [[
        "api", "--paginate", "--method", "GET",
        "orgs/acme/repos?per_page=100&type=all",
        "--jq", ".[].full_name",
    ]]


def test_list_org_repos_rejects_a_repo_ref():
    with pytest.raises(ValueError):
        h.list_org_repos("acme/my-plugin", run=lambda *a, **k: "")


def test_main_list_org_prints_repos_and_does_not_harvest(capsys):
    def fake_run(args, check=True):
        assert args[0] == "api"
        return "acme/zzz\nacme/aaa\n"

    h.main(argv=["--list-org", "acme"], run=fake_run)

    out, err = capsys.readouterr()
    assert err == ""
    assert out == "acme/aaa\nacme/zzz\n"


def test_run_harvest_requires_org_or_repos():
    """run-harvest.sh has no default org: no HARVEST_ORG and no args -> exit 2."""
    import os
    import subprocess
    from pathlib import Path
    script = Path(__file__).resolve().parent.parent / "scripts" / "run-harvest.sh"
    env = {k: v for k, v in os.environ.items() if k != "HARVEST_ORG"}
    proc = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert proc.returncode == 2
    assert "HARVEST_ORG" in proc.stderr


def test_main_requires_repo_without_list_org(capsys):
    with pytest.raises(SystemExit) as exc:
        h.main(argv=[], run=lambda *a, **k: "")
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--repo owner/repo is required" in err


# ---------------------------------------------------------------------------
# Signals harvest — fix PRs with no closing issue, acted-on review threads
# ---------------------------------------------------------------------------

def _comment(login="alice", typename="User", body="Looks wrong."):
    return {"author": {"login": login, "__typename": typename}, "body": body}


def _thread(tid="T1", outdated=True, resolved=False, path="src/a/b.php", comments=None):
    comments = comments if comments is not None else [_comment()]
    return {"id": tid, "isOutdated": outdated, "isResolved": resolved, "path": path,
            "comments": {"totalCount": len(comments), "nodes": comments}}


def _gql_pr(number=1, title="Fix rounding", merged_at="2026-06-10T12:00:00Z",
            updated_at=None, closing=0, files=("src/x.php",), threads=(), more_threads=None):
    return {
        "number": number, "title": title, "body": "PR body mail me at a@b.com",
        "mergedAt": merged_at, "updatedAt": updated_at or merged_at,
        "closingIssuesReferences": {"totalCount": closing},
        "files": {"totalCount": len(files), "nodes": [{"path": f} for f in files]},
        "reviewThreads": {"totalCount": len(threads),
                          "pageInfo": {"hasNextPage": more_threads is not None,
                                       "endCursor": "TC1" if more_threads else None},
                          "nodes": list(threads)},
    }


def _gql_page(prs, has_next=False, cursor=None):
    return json.dumps({"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}, "nodes": prs}}}})


def test_parse_claude_marker_with_models():
    body = ("Null deref here.\n\n<sub>🤖 Drafted with Claude Code · Models: Sonnet 5.5, "
            "Opus 5.5 · 3 Claude subagents</sub>")
    tags = h.parse_claude_marker(body)
    assert tags == {"claude_drafted": True, "claude_models": ["Sonnet 5.5", "Opus 5.5"],
                    "claude_subagents": 3}


def test_parse_claude_marker_bare_and_absent():
    assert h.parse_claude_marker("x <sub>🤖 Drafted with Claude Code</sub>") == {
        "claude_drafted": True, "claude_models": [], "claude_subagents": None}
    assert h.parse_claude_marker("plain")["claude_drafted"] is False
    assert h.parse_claude_marker(None)["claude_drafted"] is False


def test_classify_author_kinds(monkeypatch):
    monkeypatch.delenv("HARVEST_AI_REVIEWERS", raising=False)
    monkeypatch.delenv("HARVEST_CI_BOTS", raising=False)
    assert h.classify_author({"login": "cursor", "__typename": "Bot"})["bot_kind"] == "ai_reviewer"
    assert h.classify_author({"login": "coderabbitai[bot]", "__typename": "Bot"})["bot_kind"] == "ai_reviewer"
    assert h.classify_author({"login": "github-actions", "__typename": "Bot"})["bot_kind"] == "ci"
    assert h.classify_author({"login": "newthing[bot]", "__typename": "Bot"})["bot_kind"] == "bot"
    human = h.classify_author({"login": "alice", "__typename": "User"})
    assert human == {"author": "alice", "author_type": "User", "bot_kind": None}
    assert h.classify_author(None)["author"] == "ghost"


def test_classify_author_env_overrides(monkeypatch):
    monkeypatch.delenv("HARVEST_AI_REVIEWERS", raising=False)
    monkeypatch.delenv("HARVEST_CI_BOTS", raising=False)
    assert h.classify_author({"login": "acme-reviewer", "__typename": "User"})["bot_kind"] is None
    monkeypatch.setenv("HARVEST_AI_REVIEWERS", "acme-reviewer, Other-AI")
    monkeypatch.setenv("HARVEST_CI_BOTS", "acme-ci")
    assert h.classify_author({"login": "acme-reviewer", "__typename": "User"})["bot_kind"] == "ai_reviewer"
    assert h.classify_author({"login": "other-ai[bot]", "__typename": "Bot"})["bot_kind"] == "ai_reviewer"
    assert h.classify_author({"login": "acme-ci", "__typename": "User"})["bot_kind"] == "ci"


def test_redact_env_extra_patterns(monkeypatch):
    monkeypatch.delenv("HARVEST_REDACT_PATTERNS", raising=False)
    text = "See https://tickets.acme.test/t/1 now"
    assert h._redact(text) == text
    monkeypatch.setenv("HARVEST_REDACT_PATTERNS", r"https?://tickets\.acme\.test\S*")
    assert h._redact(text) == "See [redacted] now"


def test_fix_pr_record_qualifies_only_without_closing_issue():
    rec = h.build_fix_pr_record(_gql_pr(files=("a/b.php", "c.js", "d.php")), "o", "r")
    assert rec["kind"] == "fix_pr" and rec["revert"] is False
    assert rec["file_exts"] == [".js", ".php"] and rec["files_changed"] == 3
    assert "a/b.php" not in json.dumps(rec), "file paths must not be stored"
    assert "a@b.com" not in rec["pr_body"]
    assert h.build_fix_pr_record(_gql_pr(closing=1), "o", "r") is None
    assert h.build_fix_pr_record(_gql_pr(title="Add feature"), "o", "r") is None
    assert h.build_fix_pr_record(_gql_pr(files=()), "o", "r") is None
    assert h.build_fix_pr_record(_gql_pr(title="Revert \"Add feature\""), "o", "r")["revert"] is True
    assert h.build_fix_pr_record(_gql_pr(title="Prefix fixture loader"), "o", "r") is None


def test_thread_records_keep_acted_on_and_tag_claude():
    claude = _comment(body="Missing nonce.\n<sub>🤖 Drafted with Claude Code · Models: Opus 5.5 · 2 Claude subagents</sub>")
    pr = _gql_pr(title="Add export", threads=[
        _thread("T1", outdated=True, comments=[claude, _comment("bob", body="Fixed")]),
        _thread("T2", outdated=False, resolved=True,
                comments=[_comment("seer-by-sentry", "Bot", "**Bug:** off by one")]),
        _thread("T3", outdated=False, resolved=False),
    ])
    recs = h.build_thread_records(pr, "o", "r")
    assert [r["thread"] for r in recs] == ["T1", "T2"], "untouched threads are dropped"
    t1, t2 = recs
    assert t1["claude_drafted"] is True and t1["claude_models"] == ["Opus 5.5"]
    assert t1["reply_count"] == 1 and t1["comments"][1]["author"] == "bob"
    assert t1["file_ext"] == ".php" and "src/a/b.php" not in json.dumps(t1)
    assert t2["bot_kind"] == "ai_reviewer" and t2["author_type"] == "Bot"
    assert t2["claude_drafted"] is False


def test_gather_signals_stops_at_watermark_and_pages():
    wm = "2026-06-05T00:00:00Z"
    page1 = [_gql_pr(1, merged_at="2026-06-10T00:00:00Z", threads=[_thread("A")])]
    page2 = [
        # updated after the watermark but merged before it: skipped, keep paging
        _gql_pr(2, merged_at="2026-06-01T00:00:00Z", updated_at="2026-06-09T00:00:00Z"),
        _gql_pr(3, merged_at="2026-06-04T00:00:00Z", updated_at="2026-06-04T00:00:00Z"),
    ]
    page3_calls = []

    def fake_run(args, check=True):
        assert args[:2] == ["api", "graphql"]
        if "cursor=C1" in args:
            return _gql_page(page2, has_next=True, cursor="C2")
        if "cursor=C2" in args:
            page3_calls.append(args)
            return _gql_page([])
        return _gql_page(page1, has_next=True, cursor="C1")

    recs, raw_max, complete = h.gather_signals("o", "r", wm, run=fake_run)
    assert complete is True
    assert not page3_calls, "paging must stop at the first PR updated at/before the watermark"
    assert {(r["kind"], r["pr"]) for r in recs} == {("fix_pr", 1), ("review_thread", 1)}
    assert raw_max == "2026-06-10T00:00:00Z"


def test_gather_signals_fetches_remaining_threads():
    pr = _gql_pr(1, title="Add thing", threads=[_thread("A")], more_threads=True)
    calls = []

    def fake_run(args, check=True):
        if any(a.startswith("number=") for a in args):
            calls.append(args)
            return json.dumps({"data": {"repository": {"pullRequest": {"reviewThreads": {
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "nodes": [_thread("B", outdated=False, resolved=True)]}}}}})
        return _gql_page([pr])

    recs, _max, _complete = h.gather_signals("o", "r", None, run=fake_run)
    assert len(calls) == 1 and "cursor=TC1" in calls[0]
    assert [r["thread"] for r in recs] == ["A", "B"]


def test_gather_signals_graphql_errors_mark_incomplete():
    def fake_run(args, check=True):
        return json.dumps({"errors": [{"message": "boom"}], "data": None})

    recs, raw_max, complete = h.gather_signals("o", "r", None, run=fake_run)
    assert (recs, raw_max, complete) == ([], None, False)


def test_main_signals_mode_writes_own_store_and_watermark(tmp_path, capsys):
    pr = _gql_pr(7, merged_at="2026-06-10T12:00:00Z", threads=[_thread("A")])

    def fake_run(args, check=True):
        return _gql_page([pr])

    wm, out = tmp_path / "swm", tmp_path / "signals.json"
    argv = ["--signals", "--repo", "o/r", "--watermark-file", str(wm), "--out", str(out)]
    h.main(argv, run=fake_run)
    assert "records_written=2" in capsys.readouterr().out
    assert wm.read_text() == "2026-06-10T11:59:59Z"
    h.main(argv, run=fake_run)
    assert "records_written=0" in capsys.readouterr().out
    assert len(json.loads(out.read_text())) == 2
