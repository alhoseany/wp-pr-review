import json
import pytest
import collect_pr as c


@pytest.mark.parametrize("ref,expected", [
    ("https://github.com/acme/my-plugin/pull/89",
     ("acme", "my-plugin", 89)),
    ("github.com/o/r/pull/7", ("o", "r", 7)),
    ("acme/my-plugin#89", ("acme", "my-plugin", 89)),
    ("o/r/pull/12", ("o", "r", 12)),
])
def test_parse_pr_ref_valid(ref, expected):
    assert c.parse_pr_ref(ref) == expected


def test_parse_pr_ref_invalid():
    with pytest.raises(ValueError):
        c.parse_pr_ref("not-a-pr")


def test_collect_assembles_sections_via_injected_run():
    # Fake gh: returns canned JSON keyed by the --json fields requested.
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            data = {
                "number,title,author,body,state,baseRefName,headRefName,labels,additions,deletions,files,url,headRepository,headRepositoryOwner,isCrossRepository,headRefOid,mergeable,mergeStateStatus":
                    {"number": 89, "title": "T", "headRefName": "issue/89",
                     "baseRefName": "main", "files": [{"path": "a.php"}]},
                "comments": {"comments": [{"body": "hi"}]},
                "reviews": {"reviews": [{"state": "APPROVED"}]},
            }
            return json.dumps(data[field])
        if args[:2] == ["pr", "checks"]:
            return "build\tpass\t1m\thttp://x"
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("acme", "my-plugin", 89, run=fake_run)
    assert out["metadata"]["title"] == "T"
    assert out["comments"][0]["body"] == "hi"
    assert out["reviews"][0]["state"] == "APPROVED"
    assert out["ci"]["raw"].startswith("build")
    assert out["files"] == [{"path": "a.php"}]


def test_collect_ci_failing_checks_still_captured():
    # `gh pr checks` exits non-zero when checks fail/pending; collect must
    # request check=False and keep the stdout — not swallow it as "".
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["pr", "checks"]:
            assert check is False
            return "build\tfail\t1m\thttp://x"
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("o", "r", 1, run=fake_run)
    assert out["ci"]["raw"].startswith("build\tfail")


# ---------------------------------------------------------------------------
# Phase A: failing tests (test-first — functions not implemented yet)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("conclusion", [
    "FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED",
])
def test_classify_blocking(conclusion):
    result = c.classify(conclusion, "COMPLETED")
    assert result == "blocking"


@pytest.mark.parametrize("status", ["IN_PROGRESS", "QUEUED", "PENDING"])
def test_classify_pending(status):
    result = c.classify(None, status)
    assert result == "pending"


def test_classify_unknown():
    result = c.classify(None, "COMPLETED")
    assert result == "unknown"


@pytest.mark.parametrize("conclusion", ["NEUTRAL", "SKIPPED", "EXPECTED"])
def test_classify_advisory(conclusion):
    result = c.classify(conclusion, "COMPLETED")
    assert result == "advisory"


def test_classify_passing():
    result = c.classify("SUCCESS", "COMPLETED")
    assert result == "passing"


def test_normalize_checkrun():
    entry = {
        "__typename": "CheckRun",
        "name": "build",
        "conclusion": "SUCCESS",
        "status": "COMPLETED",
        "detailsUrl": "https://example.com/run/1",
    }
    result = c.normalize_check(entry)
    assert result["name"] == "build"
    assert result["conclusion"] == "SUCCESS"
    assert result["status"] == "COMPLETED"
    assert result["url"] == "https://example.com/run/1"
    assert result["category"] == "passing"


@pytest.mark.parametrize("state", ["failure", "error"])
def test_normalize_statuscontext_failure(state):
    entry = {
        "__typename": "StatusContext",
        "context": "ci/test",
        "state": state,
        "targetUrl": "https://example.com/status/1",
    }
    result = c.normalize_check(entry)
    assert result["conclusion"] == "FAILURE"
    assert result["category"] == "blocking"
    assert result["name"] == "ci/test"
    assert result["url"] == "https://example.com/status/1"


def test_normalize_statuscontext_pending():
    entry = {
        "__typename": "StatusContext",
        "context": "ci/test",
        "state": "pending",
        "targetUrl": "https://example.com/status/2",
    }
    result = c.normalize_check(entry)
    assert result["category"] == "pending"


def _make_fake_run_with_rollup(rollup_entries):
    """Return a fake_run that serves both legacy fields and statusCheckRollup."""
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            if field == "statusCheckRollup":
                return json.dumps({"statusCheckRollup": rollup_entries})
            return json.dumps({field: []})
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")
    return fake_run


def test_collect_populates_ci_checks():
    rollup = [
        {
            "__typename": "CheckRun",
            "name": "lint",
            "conclusion": "FAILURE",
            "status": "COMPLETED",
            "detailsUrl": "https://example.com/run/lint",
        },
        {
            "__typename": "CheckRun",
            "name": "unit",
            "conclusion": "SUCCESS",
            "status": "COMPLETED",
            "detailsUrl": "https://example.com/run/unit",
        },
    ]
    fake_run = _make_fake_run_with_rollup(rollup)
    out = c.collect("o", "r", 1, run=fake_run)
    checks = out["ci"]["checks"]
    assert isinstance(checks, list)
    assert len(checks) == 2
    categories = {ch["name"]: ch["category"] for ch in checks}
    assert categories["lint"] == "blocking"
    assert categories["unit"] == "passing"
    # raw must still be present
    assert "raw" in out["ci"]


def test_collect_empty_rollup():
    fake_run = _make_fake_run_with_rollup([])
    out = c.collect("o", "r", 1, run=fake_run)
    assert out["ci"]["checks"] == []


def test_collect_mixed_only_failing_blocking():
    rollup = [
        {
            "__typename": "CheckRun",
            "name": "build",
            "conclusion": "FAILURE",
            "status": "COMPLETED",
            "detailsUrl": "https://example.com/run/build",
        },
        {
            "__typename": "CheckRun",
            "name": "unit-1",
            "conclusion": "SUCCESS",
            "status": "COMPLETED",
            "detailsUrl": "https://example.com/run/unit-1",
        },
        {
            "__typename": "CheckRun",
            "name": "unit-2",
            "conclusion": "SUCCESS",
            "status": "COMPLETED",
            "detailsUrl": "https://example.com/run/unit-2",
        },
    ]
    fake_run = _make_fake_run_with_rollup(rollup)
    out = c.collect("o", "r", 1, run=fake_run)
    blocking = [ch for ch in out["ci"]["checks"] if ch["category"] == "blocking"]
    assert len(blocking) == 1
    assert blocking[0]["name"] == "build"


# ---------------------------------------------------------------------------
# Phase A: failing tests for review_threads (test-first, RED)
# ---------------------------------------------------------------------------

def _make_fake_run_with_threads(thread_nodes):
    """Return a fake_run that serves metadata + reviewThreads graphql."""
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            # Mimic the GraphQL response shape for review threads.
            return json.dumps({
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": thread_nodes
                            }
                        }
                    }
                }
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")
    return fake_run


def test_review_threads_happy_shape():
    """Test: graphql JSON → review_threads with parsed shape + run invocation."""
    thread_nodes = [
        {
            "isResolved": False,
            "comments": {
                "nodes": [
                    {
                        "path": "src/main.py",
                        "line": 42,
                        "originalLine": 40,
                        "body": "Nice catch!",
                        "author": {"login": "alice"}
                    }
                ]
            }
        }
    ]
    run_calls = []

    def tracking_fake_run(args, check=True):
        run_calls.append(args)
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({
                "data": {
                    "repository": {
                        "pullRequest": {"reviewThreads": {"nodes": thread_nodes}}
                    }
                }
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("myowner", "myrepo", 99, run=tracking_fake_run)

    assert "review_threads" in out
    threads = out["review_threads"]
    assert len(threads) == 1
    assert threads[0]["path"] == "src/main.py"
    assert threads[0]["line"] == 42
    assert threads[0]["body"] == "Nice catch!"
    assert threads[0]["author"] == "alice"
    assert threads[0]["isResolved"] is False

    # Also assert the helper called run with correct graphql args
    graphql_calls = [call for call in run_calls if call[:2] == ["api", "graphql"]]
    assert len(graphql_calls) > 0, "run should be called with ['api', 'graphql', ...]"
    graphql_call = graphql_calls[0]
    call_str = " ".join(graphql_call)
    assert "myowner" in call_str, "owner param should be in graphql call"
    assert "myrepo" in call_str, "repo param should be in graphql call"
    assert "99" in call_str, "number param should be in graphql call"
    assert "reviewThreads" in call_str, "query should contain reviewThreads"


def test_review_threads_fallback_runtime_error():
    """Test: fake run raises RuntimeError → review_threads == []."""
    def error_fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            raise RuntimeError("graphql failed")
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("o", "r", 1, run=error_fake_run)
    assert out["review_threads"] == []
    assert out["threads_error"]
    assert out["partial"] is True


def test_review_threads_regression_existing_keys():
    """Test: existing keys unchanged when review_threads added."""
    thread_nodes = []
    fake_run = _make_fake_run_with_threads(thread_nodes)

    out = c.collect("o", "r", 1, run=fake_run)

    assert "metadata" in out
    assert "comments" in out
    assert "reviews" in out
    assert "ci" in out
    assert "files" in out
    assert "review_threads" in out


def test_review_threads_null_line_fallback():
    """Test: line=null → parsed dict uses originalLine value."""
    thread_nodes = [
        {
            "isResolved": False,
            "comments": {
                "nodes": [
                    {
                        "path": "src/app.js",
                        "line": None,
                        "originalLine": 55,
                        "body": "Consider refactor",
                        "author": {"login": "bob"}
                    }
                ]
            }
        }
    ]
    fake_run = _make_fake_run_with_threads(thread_nodes)
    out = c.collect("o", "r", 1, run=fake_run)

    threads = out["review_threads"]
    assert len(threads) == 1
    assert threads[0]["line"] == 55  # Should use originalLine


def test_review_threads_data_null():
    """Test: graphql returns data:null + errors → defensive errors-array layer
    raises inside _fetch_review_threads, so review_threads == [] AND the
    collect() handler sets threads_error + partial."""
    def null_data_fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({
                "data": None,
                "errors": [{"message": "something went wrong"}]
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("o", "r", 1, run=null_data_fake_run)
    assert out["review_threads"] == []
    assert out["threads_error"]
    assert out["partial"] is True


def test_review_threads_resolved_mix():
    """Test: mixed isResolved true/false → both captured with correct flags."""
    thread_nodes = [
        {
            "isResolved": False,
            "comments": {
                "nodes": [
                    {
                        "path": "src/one.py",
                        "line": 10,
                        "originalLine": 10,
                        "body": "unresolved comment",
                        "author": {"login": "alice"}
                    }
                ]
            }
        },
        {
            "isResolved": True,
            "comments": {
                "nodes": [
                    {
                        "path": "src/two.py",
                        "line": 20,
                        "originalLine": 20,
                        "body": "resolved comment",
                        "author": {"login": "bob"}
                    }
                ]
            }
        }
    ]
    fake_run = _make_fake_run_with_threads(thread_nodes)
    out = c.collect("o", "r", 1, run=fake_run)

    threads = out["review_threads"]
    assert len(threads) == 2
    assert threads[0]["isResolved"] is False
    assert threads[1]["isResolved"] is True


def test_review_threads_empty_comments_skipped():
    """Test: thread with empty comments.nodes skipped; valid thread captured."""
    thread_nodes = [
        {
            "isResolved": False,
            "comments": {"nodes": []}  # Empty — should be skipped
        },
        {
            "isResolved": False,
            "comments": {
                "nodes": [
                    {
                        "path": "src/valid.py",
                        "line": 30,
                        "originalLine": 30,
                        "body": "valid comment",
                        "author": {"login": "charlie"}
                    }
                ]
            }
        }
    ]
    fake_run = _make_fake_run_with_threads(thread_nodes)
    out = c.collect("o", "r", 1, run=fake_run)

    threads = out["review_threads"]
    assert len(threads) == 1, "empty-comments thread should be skipped"
    assert threads[0]["path"] == "src/valid.py"
    assert threads[0]["body"] == "valid comment"


# ---------------------------------------------------------------------------
# F-03 / F-04 / F-06 Phase 1: failing tests (test-first, RED — impl absent)
# ---------------------------------------------------------------------------

def test_collect_metadata_requests_head_repo_fields():
    """F-03: metadata request must include the head-repo fields."""
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                assert "headRepository" in field
                assert "headRepositoryOwner" in field
                assert "isCrossRepository" in field
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({
                "data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": []}}}}
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    c.collect("o", "r", 1, run=fake_run)
    # Direct assert on METADATA_FIELDS itself — a pure output-passthrough
    # assertion would be vacuous since collect() returns whatever the fake feeds it.
    assert "headRepository" in c.METADATA_FIELDS
    assert "headRepositoryOwner" in c.METADATA_FIELDS
    assert "isCrossRepository" in c.METADATA_FIELDS


def test_collect_metadata_requests_head_ref_oid():
    """F-04: metadata request must include headRefOid."""
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                assert "headRefOid" in field
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({
                "data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": []}}}}
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    c.collect("o", "r", 1, run=fake_run)
    # Direct assert on METADATA_FIELDS itself — see note above.
    assert "headRefOid" in c.METADATA_FIELDS


def test_metadata_fields_include_merge_state():
    """The verdict rule needs conflicts and behind-base, so fetch both."""
    assert "mergeable" in c.METADATA_FIELDS
    assert "mergeStateStatus" in c.METADATA_FIELDS


def test_collect_ci_error_sets_partial():
    """F-06: statusCheckRollup exception -> top-level ci_error + partial=True,
    NOT a silent checks=[] with no error key."""
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            if field == "statusCheckRollup":
                raise RuntimeError("rollup boom")
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({
                "data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": []}}}}
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("o", "r", 1, run=fake_run)
    assert out["ci_error"]
    assert out["partial"] is True
    assert out["ci"]["checks"] == []


def test_collect_threads_error_sets_partial():
    """F-06: review-threads exception -> top-level threads_error + partial=True."""
    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            raise RuntimeError("threads boom")
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("o", "r", 1, run=fake_run)
    assert out["threads_error"]
    assert out["partial"] is True
    assert out["review_threads"] == []


def test_collect_clean_run_no_error_keys():
    """F-06 regression guard: fully-served clean run -> no ci_error/threads_error,
    no partial. `pr checks` returning empty stdout stays a non-error empty ci.raw.
    This is the sole Phase-1 test that legitimately passes from the start."""
    rollup = [{
        "__typename": "CheckRun",
        "name": "build",
        "conclusion": "SUCCESS",
        "status": "COMPLETED",
        "detailsUrl": "https://example.com/run/build",
    }]
    thread_nodes = [{
        "isResolved": False,
        "comments": {"nodes": [{
            "path": "src/main.py", "line": 10, "originalLine": 10,
            "body": "looks good", "author": {"login": "alice"},
        }]},
    }]

    def fake_run(args, check=True):
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": []})
            if field == "statusCheckRollup":
                return json.dumps({"statusCheckRollup": rollup})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({
                "data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": thread_nodes}}}}
            })
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")

    out = c.collect("o", "r", 1, run=fake_run)
    assert "ci_error" not in out
    assert "threads_error" not in out
    assert not out.get("partial")


# ---------------------------------------------------------------------------
# Test steps, full threads, own activity, head re-fetch
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body,heading,steps", [
    ("## Summary\nFixes x.\n\n## Testing Instructions\n1. Go to Settings\n2. Click Save\n\n## Notes\nnone",
     "Testing Instructions", ["Go to Settings", "Click Save"]),
    ("**How to test:**\n- [ ] Open the cart\n- [x] Apply a code\n\n**Changelog**\n- fix",
     "How to test:", ["Open the cart", "Apply a code"]),
    ("Steps to reproduce:\n* add item\n* checkout\n", "Steps to reproduce", ["add item", "checkout"]),
    ("### QA\nLoad the page and confirm the notice is gone.\n",
     "QA", ["Load the page and confirm the notice is gone."]),
    ("## Testing\n### Setup\n- install\n### Steps\n- run\n## Other\n- no",
     "Testing", ["install", "run"]),
])
def test_parse_test_steps(body, heading, steps):
    assert c.parse_test_steps(body) == {"heading": heading, "steps": steps}


@pytest.mark.parametrize("body", [
    None, "", "Just a fix.\n- one\n- two",
    "## Testing Instructions\n<!-- describe how to test -->\n\n## Notes\nx",
])
def test_parse_test_steps_absent(body):
    assert c.parse_test_steps(body) == {"heading": "", "steps": []}


def test_review_threads_carry_replies():
    nodes = [{
        "id": "T1", "isResolved": True, "isOutdated": False,
        "comments": {"nodes": [
            {"databaseId": 10, "url": "u10", "path": "a.php", "line": 5, "originalLine": 5,
             "body": "bug here", "createdAt": "2026-01-01T00:00:00Z",
             "author": {"login": "rev"}, "replyTo": None},
            {"databaseId": 11, "url": "u11", "path": "a.php", "line": None, "originalLine": 5,
             "body": "fixed in abc", "createdAt": "2026-01-02T00:00:00Z",
             "author": {"login": "dev"}, "replyTo": {"databaseId": 10}},
        ]},
    }]
    t = c.collect("o", "r", 1, run=_make_fake_run_with_threads(nodes))["review_threads"][0]
    assert (t["author"], t["body"], t["thread_id"], t["isResolved"]) == ("rev", "bug here", "T1", True)
    assert [(x["id"], x["in_reply_to_id"], x["author"], x["line"]) for x in t["comments"]] == [
        (10, None, "rev", 5), (11, 10, "dev", 5)]


def test_graphql_query_requests_all_thread_comments():
    calls = []
    fake = _make_fake_run_with_threads([])

    def tracking(args, check=True):
        calls.append(args)
        return fake(args, check)

    c.collect("o", "r", 1, run=tracking)
    query = " ".join(next(a for a in calls if a[:2] == ["api", "graphql"]))
    assert "comments(first:100)" in query and "replyTo{databaseId}" in query


def _fake_with_viewer(login, body="", comments=(), reviews=(), thread_nodes=()):
    def fake_run(args, check=True):
        if args[:2] == ["api", "user"]:
            return login + "\n"
        if "--json" in args:
            field = args[args.index("--json") + 1]
            if field.startswith("number,"):
                return json.dumps({"number": 1, "files": [], "body": body})
            if field == "comments":
                return json.dumps({"comments": list(comments)})
            if field == "reviews":
                return json.dumps({"reviews": list(reviews)})
            return json.dumps({field: []})
        if args[:2] == ["api", "graphql"]:
            return json.dumps({"data": {"repository": {"pullRequest": {
                "reviewThreads": {"nodes": list(thread_nodes)}}}}})
        if args[:2] == ["pr", "checks"]:
            return ""
        raise AssertionError(f"unexpected gh args: {args}")
    return fake_run


def test_collect_own_activity_and_test_steps():
    thread = {"id": "T", "isResolved": False, "comments": {"nodes": [
        {"databaseId": 1, "path": "a.php", "line": 2, "body": "mine", "author": {"login": "me"}},
        {"databaseId": 2, "path": "a.php", "line": 2, "body": "theirs", "author": {"login": "dev"},
         "replyTo": {"databaseId": 1}},
    ]}}
    out = c.collect("o", "r", 1, run=_fake_with_viewer(
        "me", body="## How to test\n1. do it",
        comments=[{"author": {"login": "me"}, "body": "c1"}, {"author": {"login": "x"}, "body": "c2"}],
        reviews=[{"author": {"login": "me"}, "state": "COMMENTED"}],
        thread_nodes=[thread]))
    assert out["test_steps"] == {"heading": "How to test", "steps": ["do it"]}
    own = out["own"]
    assert own["login"] == "me"
    assert [x["body"] for x in own["comments"]] == ["c1"]
    assert [x["state"] for x in own["reviews"]] == ["COMMENTED"]
    assert [x["id"] for x in own["review_comments"]] == [1]
    assert "viewer_error" not in out and not out.get("partial")


def test_collect_viewer_failure_is_non_fatal():
    out = c.collect("o", "r", 1, run=_make_fake_run_with_threads([]))
    assert out["own"] is None
    assert "viewer_error" in out
    assert not out.get("partial")


def test_head_state_fetches_only_head_fields():
    calls = []

    def fake(args, check=True):
        calls.append(args)
        return json.dumps({"headRefOid": "b" * 40, "mergeable": "MERGEABLE",
                           "mergeStateStatus": "CLEAN"})

    assert c.head_state("o", "r", 3, run=fake)["headRefOid"] == "b" * 40
    assert calls == [["pr", "view", "3", "--repo", "o/r", "--json",
                      "headRefOid,mergeable,mergeStateStatus"]]
