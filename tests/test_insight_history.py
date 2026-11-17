import copy

import pytest

from exposureiq import storage
from exposureiq.ai.sanitize import estimated_tokens
from exposureiq.history import confined_scan_path, domain_history, list_domains, sparkline
from exposureiq.insight.history_digest import build_history_layers, finding_lists, history_digest
from exposureiq.insight.verdict import ABSOLUTE_THRESHOLD, RELATIVE_THRESHOLD, history_verdict, movement


@pytest.mark.parametrize("before,after,expected", [
    (0, .49, 0), (0, .5, 1), (1, .5, -1), (10, 10.99, 0), (10, 11, 1), (10, 9, -1),
    (100, 109.9, 0), (100, 110, 1),
])
def test_named_verdict_thresholds(before, after, expected):
    assert ABSOLUTE_THRESHOLD == .5 and RELATIVE_THRESHOLD == .10
    assert movement(before, after) == expected


@pytest.mark.parametrize("sequence,expected", [
    ([[], []], "stable"), ([['high'], []], "improving"), ([[], ['high']], "worse"),
    ([['high'], [], ['high']], "mixed"), ([['high']], "not_enough_data"),
])
def test_code_owned_verdict(sequence, expected, ai_scan_factory):
    scans = [ai_scan_factory(i, rules=[("https.cert_expired", severity) for severity in severities])
             for i, severities in enumerate(sequence)]
    assert history_verdict(scans)["value"] == expected


def test_all_layers_and_persistent_fixed_new_regression_lists(ai_scan_factory):
    persistent = ("headers.missing_csp", "medium")
    fixed = ("https.cert_expired", "high")
    regression = ("ports.database_exposed", "high")
    new = ("ports.ssh_exposed", "low")
    rules = [[persistent, fixed, regression], [persistent], [persistent], [persistent, regression, new]]
    scans = [ai_scan_factory(i, rules=r) for i, r in enumerate(rules)]
    layers = build_history_layers(scans)
    assert len(layers["L1"]) == 4 and len(layers["L2"]) == 3 and len(layers["L3"]) == 4
    lists = layers["lists"]
    assert [i["rule"] for i in lists["still_unfixed"]] == [persistent[0]]
    assert [i["rule"] for i in lists["fixed"]] == [fixed[0]]
    assert [i["rule"] for i in lists["new_recently"]] == [new[0]]
    assert [i["rule"] for i in lists["regressions"]] == [regression[0]]
    assert all(i["ref"].startswith("L:") for items in lists.values() for i in items)
    assert layers["L4"]["latest"] == layers["L1"][-1]
    assert estimated_tokens(layers["L4"]) <= 3000


def test_ids_are_not_history_identity_and_missing_host_is_not_a_fix(ai_scan_factory):
    scans = [ai_scan_factory(i) for i in range(3)]
    scans[-1]["assets"][0]["findings"][0]["id"] = "F-0042"
    assert len(finding_lists(scans)["still_unfixed"]) == 2
    scans[1]["assets"][0]["host"] = "retired.example.com"
    scans[2]["assets"][0]["host"] = "retired.example.com"
    assert not finding_lists(scans)["fixed"]


def test_passive_scans_are_skipped_and_not_treated_as_fixes(ai_scan_factory):
    scans = [ai_scan_factory(), ai_scan_factory(1, passive=True), ai_scan_factory(2)]
    result = build_history_layers(scans)["L4"]
    assert result["header"]["compared"] == 2
    assert result["verdict"]["value"] == "stable"
    assert len(result["transitions"]) == 1
    assert len(result["still_unfixed"]) == 2 and not result["fixed"]
    assert any("Skipped 1 passive" in n for n in result["notes"])


@pytest.mark.parametrize("count", [50, 100, 400])
def test_history_hard_budget_and_whole_date_span(count, ai_scan_factory):
    scans = [ai_scan_factory(i, rules=[("ports.database_exposed", "high")] if i % 5 else []) for i in range(count)]
    result = build_history_layers(scans)["L4"]
    assert estimated_tokens(result) <= 3000
    assert result["header"]["scans"] == count
    assert result["timeline"][0][0].split("/")[0] == "2026-01-01"
    assert result["timeline"][-1][0].split("/")[-1] == scans[-1]["started_at"][:10]
    assert len(result["transitions"]) == 5
    if count > 50:
        assert sum(r[6] for r in result["timeline"]) == count


def test_confined_history_and_demo_files(tmp_path, ai_scan_factory):
    root = tmp_path / "results"
    storage.save_scan(ai_scan_factory(), str(root / "example.com" / "one.json"))
    storage.save_scan(ai_scan_factory(1), str(root / "example.com" / "two.json"))
    demo = ai_scan_factory(2)
    demo["scan_id"] = "DEMO-HISTORY-03"
    storage.save_scan(demo, str(root / "example.com" / "demo_history_03.json"))
    assert len(domain_history("example.com", root)) == 2
    assert history_digest("example.com", root)["header"]["scans"] == 2
    assert list_domains(root)[0]["scans"] == 3
    assert confined_scan_path("example.com/one.json", root).parent == root / "example.com"
    for path in ("../secret.json", "/etc/secret.json", "example.com/one.txt"):
        with pytest.raises(ValueError):
            confined_scan_path(path, root)
    outside = tmp_path / "outside.json"
    storage.save_scan(ai_scan_factory(), str(outside))
    (root / "linked.json").symlink_to(outside)
    with pytest.raises(ValueError):
        confined_scan_path("linked.json", root)
    assert len(domain_history("example.com", root)) == 2


def test_bad_domain_and_empty_history(ai_scan_factory, tmp_path):
    with pytest.raises(ValueError):
        history_digest("example.com", tmp_path)
    with pytest.raises(ValueError):
        build_history_layers([])
    with pytest.raises(ValueError):
        finding_lists([ai_scan_factory()], window=1)
    assert len(sparkline(list(range(100)))) == 48
    assert sparkline([1, 1]) == "▁▁"
