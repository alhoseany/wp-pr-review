"""Tests for scripts/render_review.py (findings.json -> local review.md)."""

import copy
import json
import os
import re

import pytest

import render_review as review_md

_SKILL_TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "references", "review-template.md")


def valid_finding(**overrides):
    finding = {
        "id": "F-1",
        "path": "src/app/checkout.php",
        "line": 42,
        "anchor": "line 42",
        "side": "RIGHT",
        "severity": "CRITICAL",
        "origin": "review",
        "likelihood": "High",
        "dimensions": {
            "UX": "checkout blocks",
            "Functional": "order not created",
            "Data": "cart persists stale",
            "Security": "none",
        },
        "problem": "Discount is applied twice on split carts.",
        "what_where": "apply_discount() at checkout.php:42 loops per line item.",
        "customer_impact": "Customers are overcharged at checkout.",
        "fix": "Guard the discount so it applies once per cart.",
        "verified": "Two-pass source trace; unit repro added.",
    }
    finding.update(overrides)
    return finding


@pytest.fixture
def env(tmp_path):
    """A checkout with one source file plus a minimal skill references dir."""
    repo_root = tmp_path / "checkout"
    (repo_root / "src" / "app").mkdir(parents=True)
    source = "\n".join(f"line {n}" for n in range(1, 61)) + "\n"
    (repo_root / "src" / "app" / "checkout.php").write_text(source)
    skill = tmp_path / "skill" / "references"
    skill.mkdir(parents=True)
    (skill / "verification-pitfalls.md").write_text(
        "# Verification Pitfalls\n\n_Version: 33 patterns · cross-ref: x._\n")
    (skill / "known-bug-patterns.md").write_text(
        "# Known\n\n## Authorization and nonces\n\n"
        "### Verify a nonce in every state-changing AJAX and admin handler\n")
    return {"repo_root": str(repo_root), "skill_dir": str(tmp_path / "skill"),
            "base": str(tmp_path / "project")}


def finding(**overrides):
    base = valid_finding(
        detection="traced apply_discount() into the per-line loop at checkout.php:42",
        documented_intent="None — checked docblock + adjacent comments at checkout.php:42.",
        verdict="confirmed",
        severity="MAJOR",
        likelihood="High",
    )
    base.update(overrides)
    return base


def pr_json(**meta):
    metadata = {
        "number": 2521, "title": "Fix split-cart discounts", "author": {"login": "dev"},
        "state": "OPEN", "headRefName": "fix/discount", "baseRefName": "main",
        "headRefOid": "a" * 40, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
    }
    metadata.update(meta)
    return {"metadata": metadata, "ci": {"checks": [
        {"name": "phpunit", "category": "passing"}]}}


def report(**overrides):
    rep = {
        "summary": "The PR applies discounts per cart. One finding.",
        "questions": ["Claim vs diff → matches (checkout.php:42)"],
        "recommendations": ["Guard the discount."],
        "scenarios": [{"title": "Split cart", "setup": "Two items",
                       "steps": ["Add both", "Apply code"], "expected": "One discount",
                       "edge_cases": ["Zero-price item"]}],
        "compliance": {
            "scaling_triggers": "Correctness, Data",
            "security_checklist": "N/A: PR touches no vuln-close",
            "known_bug_patterns_sections": ["Authorization and nonces"],
            "known_bug_patterns_matches": {},
            "pitfalls_per_finding": {"F-1": [12, 26]},
            "pre_verdict_checklist": [f"item {n} — N/A: no sink" for n in range(1, 9)],
            "input_sink": "N/A: diff adds no request input",
            "stored_consumer": "N/A: diff persists nothing",
            "flag_matrix": "N/A: no charge-gating state",
            "tests_run": "phpunit @ aaaa — 10 pass / 0 fail / 0 skip",
            "live_probes": "none — all findings static",
        },
    }
    rep.update(overrides)
    return rep


def doc(findings=None, **overrides):
    d = {"repo": "acme/my-plugin", "pr": 2521, "head": "a" * 40, "head_at_emit": "a" * 40,
         "findings": [finding()] if findings is None else findings, "report": report()}
    d.update(copy.deepcopy(overrides))
    return d


def render(d, env, pj=None, **kw):
    out = os.path.join(env["base"], ".pr-reviews", "my-plugin", "2521", "review.md")
    return review_md.render(d, pj or pr_json(), review_md=out, repo_root=env["repo_root"],
                            skill_dir=env["skill_dir"], date="2026-11-12", **kw)


def errors_of(d, env, pj=None, **kw):
    with pytest.raises(review_md.RenderError) as info:
        render(d, env, pj, **kw)
    return info.value.errors


# --- happy path ------------------------------------------------------------

def test_renders_header_and_request_changes_for_major(env):
    text = render(doc(), env)
    assert text.startswith("# PR Review: Fix split-cart discounts\n\n- **Repo:** acme/my-plugin")
    assert "- **Branch:** fix/discount → main" in text
    assert "- **Author/State:** dev / OPEN" in text
    assert "- **CI:** passing" in text
    assert "- **Recommendation:** Request changes — F-1 (MAJOR)" in text


def test_finding_block_has_links_evidence_intent_and_table(env):
    text = render(doc(), env)
    assert "#### 🟠 MAJOR — Discount is applied twice on split carts." in text
    assert ("[GitHub](https://github.com/acme/my-plugin/blob/fix/discount/"
            "src/app/checkout.php#L42)") in text
    assert "../../../../checkout/src/app/checkout.php#L42" in text
    assert "```php\nline 41\nline 42\nline 43\n```" in text
    assert "- **Documented intent:** None — checked" in text
    assert "| Severity | Impact |" in text
    assert "- **Verification:** ✓ confirmed — Two-pass source trace" in text


def test_fields_are_loose_list_items(env):
    findings_part = render(doc(), env).split("## Findings")[1]
    assert "- **Detection:**" in findings_part
    findings_only = findings_part.split("## Recommendations")[0]
    assert not re.search(r"^- \*\*[A-Z][a-z ]+:\*\*.*\n- \*\*", findings_only, re.MULTILINE)


def test_evidence_uses_end_line_and_caps_at_eight_lines(env):
    text = render(doc([finding(line=10, end_line=30, anchor="line 10")]), env)
    block = text.split("```php\n")[1].split("\n```")[0].splitlines()
    assert block[0] == "line 10" and len(block) == 8


def test_findings_sorted_by_severity_and_grouped_by_part(env):
    fs = [finding(id="F-1", severity="MINOR", likelihood="Low", part="Data"),
          finding(id="F-2", severity="CRITICAL", part="Security"),
          finding(id="F-3", severity="INFO", likelihood="N/A")]
    d = doc(fs)
    d["report"]["compliance"]["pitfalls_per_finding"] = {"F-1": [1], "F-2": [2], "F-3": [3]}
    text = render(d, env)
    # Parts appear in the order of their most severe finding.
    assert text.index("### Part: Security") < text.index("### Part: Data")
    assert text.index("⚪ INFO") < text.index("### Part: Data")  # unparted first
    assert "- **Likelihood:**" not in text.split("⚪ INFO —")[1].split("####")[0]


def test_counts_use_two_axes_on_downgrade(env):
    d = doc([finding(severity="MINOR", original_severity="MAJOR", verdict="partial",
                     likelihood="Low")])
    d["report"]["verified_out"] = [{"title": "nonce gap", "severity": "INFO",
                                    "reason": "handler only redirects (pitfall 17)"}]
    text = render(d, env)
    assert "| 🟠 MAJOR | 1 | 0 | 0 | 0 |" in text
    assert "| 🟡 MINOR | 0 | 0 | 1 | 0 |" in text
    assert "| ⚪ INFO | 1 | 0 | 0 | 1 |" in text
    assert "⚠ partially valid (severity MAJOR→MINOR)" in text
    assert "## Verified-out (false positives)" in text


def test_compliance_trace_quotes_version_line_and_pitfalls(env):
    text = render(doc(), env)
    assert 'version line quoted: "_Version: 33 patterns · cross-ref: x._"' in text
    assert "pitfalls checked per finding: F-1→#12,#26" in text
    assert "  8. item 8 — N/A: no sink" in text
    assert "- Head: " + "a" * 40 + " / " + "a" * 40 + " — same" in text


def test_multiline_matrix_is_a_separate_block(env):
    d = doc()
    d["report"]["compliance"]["input_sink"] = "| key | sink |\n|---|---|\n| id | DB |"
    text = render(d, env)
    assert "- Input → sink matrix:\n\n| key | sink |" in text


def test_no_test_steps_line_and_fresh_omits_delta(env):
    d = doc()
    d["report"]["previous_delta"] = ["F-1 persisting"]
    assert "No documented test steps." in render(d, env)
    assert "## Previous review delta" in render(d, env)
    assert "## Previous review delta" not in render(d, env, fresh=True)


def test_output_headings_match_skill_template(env):
    if not os.path.isfile(_SKILL_TEMPLATE):
        pytest.skip("skill template not present")
    template = open(_SKILL_TEMPLATE, encoding="utf-8").read()
    wanted = {re.split(r"\s{2,}|\s+\(", h)[0].strip()
              for h in re.findall(r"^## (.+)$", template, re.MULTILINE)}
    d = doc()
    d["report"].update(previous_delta=["x"], cross_issue=["x"], runtime_unverified=["x"],
                       verified_out=[{"title": "t", "severity": "INFO", "reason": "r"}])
    got = set(re.split(r"\s+\(", h)[0] for h in re.findall(r"^## (.+)$", render(d, env), re.MULTILINE))
    assert wanted <= got, wanted - got


# --- recommendation rule ---------------------------------------------------

@pytest.mark.parametrize("meta,ci,expect", [
    ({}, None, None),
    ({"mergeable": "CONFLICTING"}, None, "not mergeable"),
    ({"mergeStateStatus": "BEHIND"}, None, "behind its base"),
    ({"mergeable": "UNKNOWN"}, None, "mergeability unknown"),
    ({}, {"checks": [{"name": "lint", "category": "blocking"}]}, "failing CI check: lint"),
    ({}, "error", "CI status unavailable"),
])
def test_recommendation_blockers(meta, ci, expect):
    pj = pr_json(**meta)
    if ci == "error":
        pj["ci_error"] = "boom"
    elif ci:
        pj["ci"] = ci
    verdict, reasons = review_md.recommendation(
        {"findings": [finding(severity="MINOR")]}, pj)
    if expect is None:
        assert (verdict, reasons) == ("Approve", [])
    else:
        assert verdict == "Request changes" and any(expect in r for r in reasons)


def test_payment_tag_blocks_at_any_severity():
    verdict, _ = review_md.recommendation(
        {"findings": [finding(severity="INFO", tags=["payment"])]}, pr_json())
    assert verdict == "Request changes"


def test_ci_line_names_failing_checks():
    pj = pr_json()
    pj["ci"] = {"checks": [{"name": "lint", "category": "blocking"},
                           {"name": "e2e", "category": "pending"}]}
    assert review_md.ci_summary(pj)[0] == "FAILING: lint"


# --- validation ------------------------------------------------------------

def test_major_without_documented_intent_is_refused(env):
    errs = errors_of(doc([finding(documented_intent="")]), env)
    assert any("documented_intent" in e for e in errs)


def test_refuted_finding_is_refused(env):
    errs = errors_of(doc([finding(verdict="refuted")]), env)
    assert any("verified_out" in e for e in errs)


def test_unreadable_evidence_is_refused(env):
    errs = errors_of(doc([finding(path="src/missing.php")]), env)
    assert any("Evidence snippet" in e for e in errs)


def test_head_moved_needs_delta_note(env):
    d = doc(head_at_emit="b" * 40)
    assert any("head moved" in e for e in errors_of(d, env))
    d["report"]["head_delta_note"] = "delta re-reviewed at 10:02"
    assert "— moved: delta re-reviewed at 10:02" in render(d, env)


def test_compliance_lines_and_checklist_must_be_filled(env):
    d = doc()
    d["report"]["compliance"]["input_sink"] = ""
    d["report"]["compliance"]["pre_verdict_checklist"] = ["only one"]
    errs = errors_of(d, env)
    assert any("compliance.input_sink" in e for e in errs)
    assert any("exactly 8" in e for e in errs)


def test_unknown_bug_pattern_heading_is_refused(env):
    d = doc()
    d["report"]["compliance"]["known_bug_patterns_matches"] = {"Made up heading": "F-1"}
    assert any("Made up heading" in e for e in errors_of(d, env))


def test_stated_recommendation_must_match_rule(env):
    assert any("blocker rule gives" in e
               for e in errors_of(doc(recommendation="Approve"), env))


def test_rereview_requires_delta(env):
    assert any("previous_delta" in e for e in errors_of(doc(), env, rereview=True))
    render(doc(), env, rereview=True, fresh=True)  # fresh needs none


def test_missing_report_object_is_refused(env):
    d = doc()
    del d["report"]
    d["findings"][0]["detection"] = ""
    errs = errors_of(d, env)
    assert errs[0] == "report: required object (summary, questions, compliance, ...)"
    assert any("detection" in e for e in errs)  # findings are still checked


# --- paths and CLI ---------------------------------------------------------

def test_next_review_path_counts_rounds(tmp_path):
    base = str(tmp_path)
    first = review_md.next_review_path(base, "my-plugin", 7)
    assert first.endswith(os.path.join("my-plugin", "7", "review.md"))
    os.makedirs(os.path.dirname(first))
    open(first, "w").close()
    assert review_md.next_review_path(base, "my-plugin", 7).endswith(
        os.path.join("7-2", "review.md"))
    assert review_md.latest_prior_exists(base, "my-plugin", 7,
                                         review_md.next_review_path(base, "my-plugin", 7))


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


def test_cli_writes_review_and_prints_recommendation(env, tmp_path, capsys):
    rc = review_md.main([_write(tmp_path, "f.json", doc()),
                         "--pr-json", _write(tmp_path, "pr.json", pr_json()),
                         "--repo-root", env["repo_root"], "--base-dir", env["base"],
                         "--skill-dir", env["skill_dir"], "--date", "2026-11-12"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["recommendation"] == "Request changes"
    assert os.path.isfile(result["review_md"])


def test_cli_refuses_and_writes_nothing(env, tmp_path, capsys):
    out = str(tmp_path / "review.md")
    rc = review_md.main([_write(tmp_path, "f.json", doc([finding(documented_intent="")])),
                         "--pr-json", _write(tmp_path, "pr.json", pr_json()),
                         "--repo-root", env["repo_root"], "--out", out,
                         "--skill-dir", env["skill_dir"]])
    assert rc == 2 and not os.path.exists(out)
    assert "documented_intent" in capsys.readouterr().err


def test_cli_checks_document_envelope(env, tmp_path, capsys):
    rc = review_md.main([_write(tmp_path, "f.json", doc(repo="no-slash")),
                         "--pr-json", _write(tmp_path, "pr.json", pr_json()),
                         "--repo-root", env["repo_root"], "--out", str(tmp_path / "r.md"),
                         "--skill-dir", env["skill_dir"], "--check"])
    assert rc == 2 and "repo: must be" in capsys.readouterr().err


def test_cli_verdict_needs_no_report_or_checkout(tmp_path, capsys):
    bare = {"repo": "acme/my-plugin", "pr": 2521,
            "findings": [finding(severity="MINOR"), finding(id="F-2", severity="MAJOR")]}
    rc = review_md.main([_write(tmp_path, "f.json", bare),
                         "--pr-json", _write(tmp_path, "pr.json", pr_json()), "--verdict"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["recommendation"] == "Request changes"
    assert result["reasons"] == ["F-2 (MAJOR)"]
    assert not list(tmp_path.glob("**/*.md"))


def test_cli_verdict_approve_and_merge_state(tmp_path, capsys):
    bare = {"repo": "acme/my-plugin", "pr": 2521, "findings": [finding(severity="MINOR")]}
    f = _write(tmp_path, "f.json", bare)
    assert review_md.main([f, "--pr-json", _write(tmp_path, "a.json", pr_json()), "--verdict"]) == 0
    assert json.loads(capsys.readouterr().out)["recommendation"] == "Approve"
    behind = _write(tmp_path, "b.json", pr_json(mergeStateStatus="BEHIND"))
    assert review_md.main([f, "--pr-json", behind, "--verdict"]) == 0
    assert "behind its base branch" in json.loads(capsys.readouterr().out)["reasons"]


def test_cli_verdict_rejects_malformed_findings(tmp_path, capsys):
    rc = review_md.main([_write(tmp_path, "f.json", {"findings": ["x"]}),
                         "--pr-json", _write(tmp_path, "pr.json", pr_json()), "--verdict"])
    assert rc == 2


def test_cli_render_still_requires_repo_root(tmp_path):
    with pytest.raises(SystemExit):
        review_md.main([_write(tmp_path, "f.json", doc()),
                        "--pr-json", _write(tmp_path, "pr.json", pr_json())])


def test_summary_may_be_a_list_of_paragraphs(env):
    rep = report()
    rep["summary"] = ["First paragraph.", "Second paragraph."]
    text = render(doc(report=rep), env)
    assert "First paragraph.\n\nSecond paragraph." in text


def _red_sonar():
    pj = pr_json()
    pj["ci"]["checks"] = [
        {"name": "build", "category": "passing"},
        {"name": "SonarCloud Code Analysis", "category": "blocking"},
    ]
    return pj


def test_ci_advisory_waives_a_named_failing_check(env):
    waiver = [{"name": "SonarCloud Code Analysis", "reason": "team policy: coverage gate optional"}]
    d = doc([finding(severity="MINOR")], ci_advisory=waiver)
    verdict, reasons = review_md.recommendation(d, _red_sonar())
    assert (verdict, reasons) == ("Approve", [])
    text, blocking, _ = review_md.ci_summary(_red_sonar(), review_md.ci_waivers(d))
    assert blocking == []
    assert "SonarCloud Code Analysis (team policy: coverage gate optional)" in text
    text = render(d, env, _red_sonar())
    assert "non-blocking by team policy" in text
    assert "- **CI:** no blocking failures (1 failed check non-blocking by team policy: " in text


def test_ci_advisory_without_waiver_still_blocks():
    verdict, reasons = review_md.recommendation(doc([finding(severity="MINOR")]), _red_sonar())
    assert verdict == "Request changes"
    assert reasons == ["failing CI check: SonarCloud Code Analysis"]


@pytest.mark.parametrize("waiver,fragment", [
    ([{"name": "SonarCloud Code Analysis"}], "team-policy reason"),
    ([{"name": "build", "reason": "x"}], "not a failing check"),
    ({"name": "x"}, "must be a list"),
])
def test_ci_advisory_validation(env, waiver, fragment):
    d = doc([finding(severity="MINOR")], ci_advisory=waiver)
    with pytest.raises(review_md.RenderError) as info:
        render(d, env, _red_sonar())
    assert any(fragment in e for e in info.value.errors)


# --- author test steps ------------------------------------------------------

def _pr_with_steps(*steps):
    pj = pr_json()
    pj["test_steps"] = {"heading": "Testing", "steps": list(steps)}
    return pj


def test_collected_steps_must_all_be_accounted_for(env):
    errs = errors_of(doc(), env, _pr_with_steps("Buy it", "Refund it"))
    assert any("author step(s) [1, 2] not accounted for" in e for e in errs)


def test_steps_render_by_status_with_author_text(env):
    d = doc()
    d["report"]["test_steps"] = [
        {"steps": [1], "status": "passed", "note": "one order on the local site"},
        {"steps": [2, 3], "status": "not_run", "note": "needs a live gateway"},
        {"text": "Replayed the webhook", "status": "passed", "note": "no second order"}]
    text = render(d, env, _pr_with_steps("Buy it", "Refund it", "Void\n  it"))
    ran = text.split("## Verified by running the PR's test steps")[1].split("## ")[0]
    assert "**Step 1** — passed: one order on the local site" in ran
    assert "  - Step 1: Buy it" in ran
    assert "**Own step:** Replayed the webhook — passed" in ran
    assert "Refund it" not in ran
    unverified = text.split("## Runtime-unverified")[1]
    assert "**Steps 2, 3** — not run: needs a live gateway" in unverified
    assert "  - Step 3: Void it" in unverified


def test_no_step_run_says_so_and_keeps_runtime_unverified(env):
    d = doc()
    d["report"]["test_steps"] = [{"steps": [1], "status": "not_run", "note": "no site"}]
    d["report"]["runtime_unverified"] = ["Overlay timing"]
    text = render(d, env, _pr_with_steps("Buy it"))
    assert "None of the documented test steps were run; see Runtime-unverified." in text
    unverified = text.split("## Runtime-unverified")[1]
    assert "**Step 1** — not run: no site" in unverified and "- Overlay timing" in unverified


@pytest.mark.parametrize("item,needle", [
    ("Ran step 1", "must be {steps"),
    ({"steps": [4], "status": "passed", "note": "x"}, "no author step 4"),
    ({"steps": [1], "status": "done", "note": "x"}, ".status: must be one of"),
    ({"steps": [1], "status": "passed"}, ".note: required"),
    ({"steps": [1], "text": "x", "status": "passed", "note": "x"}, "exactly one of"),
    ({"steps": [1], "status": "failed", "note": "x"}, "a failed step needs the id"),
])
def test_bad_test_step_entries_are_refused(env, item, needle):
    d = doc()
    d["report"]["test_steps"] = [item]
    assert any(needle in e for e in errors_of(d, env, _pr_with_steps("Buy it")))


def test_step_listed_twice_is_refused(env):
    d = doc()
    d["report"]["test_steps"] = [{"steps": [1], "status": "passed", "note": "x"},
                                 {"steps": [1], "status": "not_run", "note": "y"}]
    assert any("already listed" in e for e in errors_of(d, env, _pr_with_steps("Buy it")))


def test_failed_step_names_its_finding(env):
    d = doc()
    d["report"]["test_steps"] = [{"steps": [1], "status": "failed", "note": "two orders",
                                  "finding": "F-1"}]
    text = render(d, env, _pr_with_steps("Buy it"))
    assert "**Step 1** — FAILED (F-1): two orders" in text


# --- line numbers ------------------------------------------------------------

def test_anchor_must_be_on_the_cited_line(env):
    errs = errors_of(doc([finding(anchor="line 40")]), env)
    assert any("'line 40' is not on src/app/checkout.php:42; it is at line(s) [40]" in e
               for e in errs)
    assert any(".anchor: required" in e for e in errors_of(doc([finding(anchor="")]), env))


def test_anchor_may_sit_anywhere_in_the_range(env):
    render(doc([finding(line=40, end_line=44, anchor="line 43")]), env)


def test_text_citation_past_end_of_file_is_refused(env):
    d = doc()
    d["report"]["questions"] = ["Is it guarded? → yes (checkout.php:61)"]
    assert any("cites checkout.php:61 but src/app/checkout.php has 60 lines" in e
               for e in errors_of(d, env))


def test_text_citation_of_missing_or_ambiguous_file_is_refused(env):
    other = os.path.join(env["repo_root"], "src", "admin")
    os.makedirs(other)
    open(os.path.join(other, "checkout.php"), "w").write("x\n")
    d = doc()
    d["report"]["summary"] = "See Gone.php:3 and checkout.php:1."
    errs = errors_of(d, env)
    assert any("cites Gone.php:3: no such file" in e for e in errs)
    assert any("cites checkout.php:1: ambiguous" in e for e in errs)
    pj = pr_json()
    pj["files"] = [{"path": "src/app/checkout.php"}]
    assert not any("ambiguous" in e for e in errors_of(d, env, pj))


def test_urls_and_other_refs_are_not_citations(env):
    d = doc()
    d["report"]["summary"] = ("Base had it at checkout.php@main:900; see "
                              "https://example.test/checkout.php:900 too.")
    render(d, env)


def test_cli_lists_cited_code(env, tmp_path, capsys):
    rc = review_md.main([_write(tmp_path, "f.json", doc()),
                         "--pr-json", _write(tmp_path, "pr.json", pr_json()),
                         "--repo-root", env["repo_root"], "--base-dir", env["base"],
                         "--skill-dir", env["skill_dir"], "--check"])
    assert rc == 0
    assert "checkout.php:42 -> src/app/checkout.php:42: line 42" in capsys.readouterr().err


def test_fresh_review_is_marked_in_the_header(env):
    assert "- **Mode:** fresh review; earlier rounds were not read" in render(doc(), env, fresh=True)
    assert "**Mode:**" not in render(doc(), env)
