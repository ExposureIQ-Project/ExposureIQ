"""Tests for the report model (Stage 4).

All data comes from the checked-in example scan or from copies of it. Nothing
here touches the network, the results folder, or the clock.
"""

import copy
import json
from pathlib import Path

from exposureiq import storage
from exposureiq.report.model import build_report

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-02T12:00:00Z"


def example_scan():
    return storage.load_scan(str(EXAMPLE))


def test_demo_summary_never_claims_real_scoped_checks_ran():
    scan = example_scan()
    scan["scan_id"] = "DEMO-" + scan["scan_id"]
    report = build_report(scan, generated_at=FIXED_TIME)
    summary = " ".join(report["executive_summary"])
    assert report["demo"] and "not a real assessment" in summary
    assert "simulated evidence" in summary
    assert "hosts that were in scope" not in summary
    real_summary = build_report(example_scan(), generated_at=FIXED_TIME)["executive_summary"]
    assert "hosts that were in scope" in " ".join(real_summary)


def test_counts_findings_and_risk():
    report = build_report(example_scan(), generated_at=FIXED_TIME)

    assert report["target"] == "example.com"
    assert report["counts"] == {
        "assets": 2,
        "ips": 2,
        "ports": 1,
        "technologies": 2,
        "findings": 2,
    }
    assert report["severity"] == {"high": 1, "medium": 1, "low": 0, "total": 2}
    assert report["risk"]["level"] == "high"
    assert report["risk"]["label"] == "High risk"
    assert [finding["title"] for finding in report["findings"]] == [
        "Certificate has expired",
        "Missing Content-Security-Policy header",
    ]
    assert report["generated_label"] == "02 Nov 2026, 12:00 UTC"


def test_findings_are_sorted_high_then_medium():
    scan = example_scan()
    scan["assets"][0]["findings"].append({
        "id": "F-0099",
        "rule": "headers.weak_hsts",
        "check": "security_headers",
        "severity": "medium",
        "title": "Weak HSTS",
        "detail": "Short max-age",
        "recommendation": "Increase max-age",
    })
    report = build_report(scan, generated_at=FIXED_TIME)

    severities = [finding["severity"] for finding in report["findings"]]
    assert severities == ["high", "medium", "medium"]


def test_executive_summary_mentions_target_and_change():
    scan = example_scan()
    diff = {
        "old": {"scan_id": "old", "started_at": "2026-10-01T10:00:00Z"},
        "new": {"scan_id": "new", "started_at": "2026-10-29T10:00:00Z"},
        "notes": [],
        "summary": {
            "headline": "1 thing got worse",
            "counts": {"total": 1, "worse": 1, "better": 0, "neutral": 0},
            "highlights": ["staging.example.com: new host discovered"],
            "lines": ["staging.example.com: new host discovered"],
        },
    }
    report = build_report(scan, diff=diff, generated_at=FIXED_TIME)

    text = " ".join(report["executive_summary"])
    assert "ExposureIQ assessed example.com" in text
    assert "The scan recorded 1 high-severity issue" in text
    assert "1 thing got worse" in text
    assert "staging.example.com" in text
    assert report["diff_summary"]["headline"] == "1 thing got worse"


def test_disabled_comparison_is_not_described_as_missing_history():
    report = build_report(example_scan(), comparison_enabled=False, generated_at=FIXED_TIME)
    summary = " ".join(report["executive_summary"])
    assert report["comparison_enabled"] is False
    assert "Change comparisons were disabled" in summary
    assert "no earlier saved scan" not in summary and "Run another scan" not in summary


def test_no_findings_is_clear_not_a_claim_of_safety():
    scan = example_scan()
    for asset in scan["assets"]:
        asset["findings"] = []
    report = build_report(scan, generated_at=FIXED_TIME)

    assert report["severity"] == {"high": 0, "medium": 0, "low": 0, "total": 0}
    assert report["risk"]["level"] == "none"
    assert report["risk"]["label"] == "No findings"
    assert "No findings were recorded" in " ".join(report["executive_summary"])


def test_history_points_are_sorted_deduplicated_and_stop_at_selected_scan():
    current = example_scan()
    older = copy.deepcopy(current)
    older["scan_id"] = "older"
    older["started_at"] = "2026-10-01T10:00:00Z"
    older["assets"] = [older["assets"][0]]
    newest = copy.deepcopy(current)
    newest["scan_id"] = "newest"
    newest["started_at"] = "2026-10-29T10:00:00Z"

    report = build_report(
        current,
        history=[newest, current, older, older],
        generated_at=FIXED_TIME,
    )

    assert [point["started_at"] for point in report["history"]] == [
        "2026-10-01T10:00:00Z",
        "2026-10-13T20:15:00Z",
    ]
    assert [point["assets"] for point in report["history"]] == [1, 2]


def test_history_labels_include_time_when_a_day_repeats():
    current = example_scan()
    current["scan_id"] = "a"
    current["started_at"] = "2026-10-29T18:00:00Z"
    other = copy.deepcopy(current)
    other["scan_id"] = "b"
    other["started_at"] = "2026-10-29T10:00:00Z"

    report = build_report(current, history=[current, other], generated_at=FIXED_TIME)

    labels = [point["label"] for point in report["history"]]
    assert labels == ["29 Oct 10:00", "29 Oct 18:00"]


def test_asset_inventory_sorts_findings_first():
    scan = example_scan()
    report = build_report(scan, generated_at=FIXED_TIME)

    assert [asset["host"] for asset in report["assets"]] == [
        "api.example.com",
        "dev.example.com",
    ]
    assert report["assets"][0]["findings"] == 2
    assert report["assets"][0]["highest"] == "high"
    assert report["assets"][1]["findings"] == 0
    assert report["assets"][1]["highest_label"] == "—"


def test_schema_0_1_scan_without_optional_fields(tmp_path):
    scan = example_scan()
    scan["schema_version"] = "0.1"
    for asset in scan["assets"]:
        asset.pop("technologies", None)
        asset.pop("findings", None)
    path = tmp_path / "old.json"
    path.write_text(json.dumps(scan), encoding="utf-8")

    report = build_report(storage.load_scan(str(path)), generated_at=FIXED_TIME)

    assert report["schema_version"] == "0.1"
    assert report["counts"]["findings"] == 0
    assert report["counts"]["technologies"] == 0
    assert report["risk"]["label"] == "No findings"


def test_custom_title_is_used_by_renderers():
    report = build_report(
        example_scan(), title="Board briefing", generated_at=FIXED_TIME
    )

    assert report["title"] == "Board briefing"


def test_report_is_plain_data_and_does_not_mutate_scan():
    scan = example_scan()
    before = json.dumps(scan, sort_keys=True)
    report = build_report(scan, generated_at=FIXED_TIME)

    assert json.dumps(scan, sort_keys=True) == before
    assert isinstance(report, dict)
    assert json.dumps(report)  # renderer-ready and serialisable
