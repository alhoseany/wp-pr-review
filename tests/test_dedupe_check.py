"""Duplicate-finding gate tests: offline, the gh seam is a local fake."""

import copy
import json

import pytest

import dedupe_check as dedupe


def valid_finding(**overrides):
    finding = {
        "id": "F-1",
        "path": "src/app/checkout.php",
        "line": 42,
        "severity": "CRITICAL",
        "problem": "Discount is applied twice on split carts.",
        "what_where": "apply_discount() at checkout.php:42 loops per line item.",
        "customer_impact": "Customers are overcharged at checkout.",
        "fix": "Guard the discount so it applies once per cart.",
        "verified": "Two-pass source trace; unit repro added.",
    }
    finding.update(overrides)
    return finding


def valid_doc(**overrides):
    doc = {"repo": "acme/my-plugin", "pr": 2521, "findings": [valid_finding()]}
    doc.update(copy.deepcopy(overrides))
    return doc


PATH = "src/app/checkout.php"
URL = "https://github.com/acme/my-plugin/pull/2521#discussion_r111"

SAME_TEXT = (
    "Heads up: the discount gets applied twice on split carts because "
    "apply_discount loops per line item."
)


def existing(**overrides):
    """Return one normalized existing-comment record."""
    rec = {
        "source": "inline",
        "id": 111,
        "author": "alice",
        "url": URL,
        "body": "Unrelated remark about whitespace in the docblock.",
        "path": PATH,
        "line": None,
        "original_line": None,
    }
    rec.update(overrides)
    return rec


def fetcher(*records):
    """Return a ``(repo, pr)`` fetch seam yielding ``records``."""
    return lambda repo, pr: list(records)


def write_doc(tmp_path, doc):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def cli(tmp_path, doc, *records, extra=()):
    argv = [write_doc(tmp_path, doc), *extra]
    import io

    buf = io.StringIO()
    rc = dedupe.main(argv, fetch=fetcher(*records), out=buf)
    return rc, buf.getvalue()


def only(report):
    assert len(report.results) == 1
    return report.results[0]


# --- matcher ---------------------------------------------------------------


def test_same_line_match():
    report = dedupe.check(valid_doc(), [existing(line=42)])
    res = only(report)
    assert res.status == "unacknowledged"
    assert [c.author for c in res.candidates] == ["alice"]
    assert any("same line 42" in r for r in res.candidates[0].reasons)
    assert report.exit_code == 3


def test_nearby_line_match_uses_original_line_and_window():
    # line is None (outdated); original_line is 3 away from 42.
    rec = existing(line=None, original_line=45)
    res = only(dedupe.check(valid_doc(), [rec], window=5))
    assert any("nearby line" in r for r in res.candidates[0].reasons)
    # A smaller window drops the match.
    assert only(dedupe.check(valid_doc(), [rec], window=2)).candidates == []
    # The window edge is inclusive.
    assert only(dedupe.check(valid_doc(), [existing(line=47)], window=5)).candidates


def test_other_path_same_line_is_not_a_location_match():
    rec = existing(path="src/app/other.php", line=42)
    assert only(dedupe.check(valid_doc(), [rec])).candidates == []


def test_text_only_match_on_conversation_comment():
    rec = existing(source="conversation", path=None, body=SAME_TEXT, author="bot[bot]")
    res = only(dedupe.check(valid_doc(), [rec]))
    cand = res.candidates[0]
    assert cand.author == "bot[bot]"
    assert cand.source == "conversation"
    assert cand.score >= dedupe.DEFAULT_THRESHOLD
    assert cand.reasons == [f"text similarity {cand.score:.2f}"]


def test_text_match_respects_threshold():
    rec = existing(source="conversation", path=None, body=SAME_TEXT)
    assert only(dedupe.check(valid_doc(), [rec], threshold=0.99)).candidates == []


def test_no_match():
    rec = existing(
        source="review",
        path=None,
        body="Looks good overall, thanks for the cleanup of the readme.",
    )
    report = dedupe.check(valid_doc(), [rec, existing(line=300)])
    assert only(report).candidates == []
    assert only(report).status == "clean"
    assert report.exit_code == 0


def test_attribution_trailer_alone_does_not_match():
    trailer = "Co-Authored-By: someone <noreply@example.com>"
    rec = existing(path=None, source="review", body=trailer)
    assert only(dedupe.check(valid_doc(), [rec])).candidates == []


# --- acknowledgement ---------------------------------------------------------


def _doc_with_ack(ack, **finding_overrides):
    return valid_doc(findings=[valid_finding(dedupe=ack, **finding_overrides)])


def test_ack_new_and_dropped_suppress_failure():
    for status in ("new", "dropped"):
        report = dedupe.check(_doc_with_ack({"status": status}), [existing(line=42)])
        assert only(report).status == "acknowledged"
        assert only(report).candidates  # still listed
        assert report.exit_code == 0


def test_ack_reference_needs_known_url_and_citation():
    ack = {"status": "reference", "url": URL}
    cited = {"what_where": f"Already raised in {URL}; no new comment."}
    ok = dedupe.check(_doc_with_ack(ack, **cited), [existing(line=42)])
    assert ok.exit_code == 0

    # Finding text does not cite the url.
    bad = dedupe.check(_doc_with_ack(ack), [existing(line=42)])
    assert bad.exit_code == 3
    assert any("does not cite" in p for p in only(bad).problems)

    # The url is not an existing comment on the PR.
    ack2 = {"status": "reference", "url": "https://github.com/x/y/pull/1#r9"}
    unknown = dedupe.check(
        _doc_with_ack(ack2, what_where="See https://github.com/x/y/pull/1#r9 here."),
        [existing(line=42)],
    )
    assert unknown.exit_code == 3
    assert any("not an existing comment" in p for p in only(unknown).problems)


def test_ack_reference_url_cited_only_in_a_local_field_is_not_a_citation():
    ack = {"status": "reference", "url": URL}
    local_only = {"fix": f"Already raised in {URL}.", "verified": f"See {URL}."}
    report = dedupe.check(_doc_with_ack(ack, **local_only), [existing(line=42)])
    assert report.exit_code == 3
    assert any("does not cite" in p for p in only(report).problems)


def test_ack_without_candidates_is_clean():
    report = dedupe.check(_doc_with_ack({"status": "new"}), [])
    assert only(report).status == "clean"


# --- CLI -----------------------------------------------------------------


def test_cli_exit_0_when_no_candidates(tmp_path):
    rc, out = cli(tmp_path, valid_doc())
    assert rc == 0
    assert "OK: no unacknowledged duplicate candidates." in out


def test_cli_exit_3_and_report_contents(tmp_path):
    rc, out = cli(tmp_path, valid_doc(), existing(line=42, author="alice"))
    assert rc == 3
    assert "F-1" in out and "@alice" in out and URL in out
    assert "score=" in out and "same line 42" in out
    assert "UNACKNOWLEDGED" in out


def test_cli_ack_suppresses_exit_3(tmp_path):
    doc = _doc_with_ack({"status": "new", "note": "checked by hand"})
    rc, out = cli(tmp_path, doc, existing(line=42))
    assert rc == 0
    assert "ack: new - checked by hand" in out


def test_cli_json_output_and_options(tmp_path):
    out_path = tmp_path / "report.json"
    rc, _ = cli(
        tmp_path,
        valid_doc(),
        existing(line=60),
        extra=["--json", str(out_path), "--window", "20", "--threshold", "0.5"],
    )
    assert rc == 3
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["exit_code"] == 3
    assert data["window"] == 20 and data["threshold"] == 0.5
    assert data["findings"][0]["candidates"][0]["author"] == "alice"


def test_cli_fetch_failure_is_exit_2(tmp_path, capsys):
    def boom(repo, pr):
        raise dedupe.DedupeError("gh down")

    rc = dedupe.main([write_doc(tmp_path, valid_doc())], fetch=boom)
    assert rc == 2
    assert "gh down" in capsys.readouterr().err


def test_cli_invalid_doc_and_bad_ack_are_exit_2(tmp_path, capsys):
    rc, _ = cli(tmp_path, _doc_with_ack({"status": "maybe"}))
    assert rc == 2
    assert "dedupe.status" in capsys.readouterr().err


def test_cli_bad_options_exit_2(tmp_path):
    rc, _ = cli(tmp_path, valid_doc(), extra=["--threshold", "2"])
    assert rc == 2


# --- fetching ---------------------------------------------------------------


def test_fetch_existing_normalizes_three_endpoints():
    calls = []
    raw = {
        "repos/o/r/pulls/7/comments": [
            {
                "id": 1,
                "user": {"login": "carol"},
                "html_url": "u1",
                "body": "inline",
                "path": "a.php",
                "line": 3,
                "original_line": 2,
            }
        ],
        "repos/o/r/pulls/7/reviews": [
            {"id": 2, "user": {"login": "dave"}, "html_url": "u2", "body": "rev"},
            {"id": 3, "user": {"login": "eve"}, "html_url": "u3", "body": "  "},
        ],
        "repos/o/r/issues/7/comments": [
            {"id": 4, "user": None, "html_url": "u4", "body": "conv"}
        ],
    }

    def get(endpoint):
        calls.append(endpoint)
        return raw[endpoint]

    recs = dedupe.fetch_existing("o/r", 7, get=get)
    assert sorted(calls) == sorted(raw)
    assert [(r["source"], r["author"], r["url"]) for r in recs] == [
        ("inline", "carol", "u1"),
        ("review", "dave", "u2"),
        ("conversation", "", "u4"),
    ]
    assert recs[0]["original_line"] == 2


def test_parse_pages_accepts_merged_and_concatenated_arrays():
    assert dedupe._parse_pages('[{"a":1},{"a":2}]') == [{"a": 1}, {"a": 2}]
    assert dedupe._parse_pages('[{"a":1}]\n[{"a":2}]') == [{"a": 1}, {"a": 2}]
    assert dedupe._parse_pages("") == []


def test_default_getter_is_a_paginated_get_only(monkeypatch):
    seen = []

    class Proc:
        returncode = 0
        stdout = "[]"
        stderr = ""

    monkeypatch.setattr(dedupe.subprocess, "run", lambda args, **kw: seen.append(args) or Proc())
    assert dedupe.fetch_existing("o/r", 7) == []
    assert len(seen) == 3
    for args in seen:
        assert args[:4] == ["gh", "api", "--method", "GET"]
        assert "--paginate" in args
        assert not {"POST", "PATCH", "PUT", "DELETE"} & set(args)


def test_default_getter_failure_raises_dedupe_error(monkeypatch):
    class Proc:
        returncode = 1
        stdout = ""
        stderr = "HTTP 500"

    monkeypatch.setattr(dedupe.subprocess, "run", lambda args, **kw: Proc())
    with pytest.raises(dedupe.DedupeError, match="HTTP 500"):
        dedupe.fetch_existing("o/r", 7)


# --- validation -------------------------------------------------------------


@pytest.mark.parametrize("doc,fragment", [
    ([], "JSON object"),
    ({"repo": "nope", "pr": 1, "findings": []}, '"repo"'),
    ({"repo": "o/r", "pr": 0, "findings": []}, '"pr"'),
    ({"repo": "o/r", "pr": 1}, '"findings"'),
    ({"repo": "o/r", "pr": 1, "findings": [{"id": "F-1", "path": "a", "problem": "p", "line": 0}]},
     "line"),
])
def test_validate_rejects(doc, fragment):
    assert any(fragment in e for e in dedupe.validate(doc))


def test_validate_accepts_minimal_doc():
    assert dedupe.validate(valid_doc()) == []
