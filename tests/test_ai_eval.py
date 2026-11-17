import copy

from exposureiq.ai import evaluate


def test_packaged_fixtures_normal_and_wrong_models_have_known_answers():
    result = evaluate.run_evaluation()
    assert result["passed"] and result["passed_rows"] == 22
    summaries = [row for row in result["rows"] if row["kind"] == "summary"]
    assert len(summaries) == 16
    assert all(row["facts_match"] and row["display_high_coverage"] for row in summaries)
    assert all(row["raw_accepted"] for row in summaries if row["provider"] == "fake")
    assert all(not row["raw_accepted"] and row["source"] == "template" and row["rejected"]
               for row in summaries if row["provider"] == "wrong fake")
    assert all(row["calls"] == 0 and row["source"] == "policy" for row in result["rows"] if row["kind"] == "policy")
    assert "not evidence" in evaluate.evaluation_table(result)


def test_evaluation_is_reproducible_and_never_instantiates_real_provider(monkeypatch):
    from exposureiq.ai import provider

    monkeypatch.setattr(provider, "OpenAIProvider", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("No real model in evaluation")))
    assert evaluate.run_evaluation() == evaluate.run_evaluation()


def test_expected_fixture_facts_are_independent_of_code(monkeypatch):
    fixtures = copy.deepcopy(evaluate.load_cases())
    fixtures["cases"][0]["expected"]["score"] = 999
    monkeypatch.setattr(evaluate, "load_cases", lambda: fixtures)
    result = evaluate.run_evaluation()
    assert not result["passed"]
    assert all(not row["facts_match"] and not row["passed"] for row in result["rows"][:2])


def test_coverage_and_json_repair_failures_are_measured_before_fallback():
    rows = evaluate.run_evaluation()["rows"]
    omitted = next(row for row in rows if row["case"] == "high-rule-coverage" and row["provider"] == "wrong fake")
    assert not omitted["raw_high_coverage"] and omitted["display_high_coverage"]
    assert any("omitted" in item["reason"] for item in omitted["rejected"])
    malformed = next(row for row in rows if row["case"] == "passive-unknown" and row["provider"] == "wrong fake")
    assert malformed["calls"] == 2 and malformed["display_verified"] == "6/6"


def test_fixture_digest_budgets_and_hostile_raw_data_exclusion():
    result = evaluate.run_evaluation()
    for row in result["rows"]:
        assert row["digest_tokens_estimate"] <= (3000 if row["case"] == "mixed-history" else 600)
    fixtures = evaluate.load_cases()
    from exposureiq.insight.digest import scan_digest

    digest = scan_digest(fixtures["scans"]["hostile"])
    assert digest["hostile_text_seen"]
    assert "ignored-demo-text" not in str(digest) and "ignore previous instructions" not in str(digest)
