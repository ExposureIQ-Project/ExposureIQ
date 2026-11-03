"""Tests for the self-contained HTML report."""

import json
from pathlib import Path

from exposureiq import storage
from exposureiq.report.html import render_html
from exposureiq.report.model import build_report

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-02T12:00:00Z"


def example_scan():
    return storage.load_scan(str(EXAMPLE))


def test_html_has_every_required_section():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    page = render_html(report)

    assert page.startswith("<!DOCTYPE html>")
    for text in (
        "Executive summary",
        "Findings",
        "What changed",
        "Findings by severity",
        "Assets over time",
        "Asset inventory",
        "Methodology and scope",
        "Confidential",
    ):
        assert text in page
    assert "badge-high" in page
    assert "badge-medium" in page
    assert "<svg" in page
    assert "example.com" in page


def test_html_escapes_scan_text():
    scan = example_scan()
    scan["assets"][0]["findings"][0]["title"] = '<script>alert("x")</script>'
    scan["assets"][0]["findings"][0]["detail"] = "<img src=x onerror=alert(1)>"
    report = build_report(scan, generated_at=FIXED_TIME)
    page = render_html(report)

    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert "<img src=x" not in page
    assert "&lt;img" in page


def test_html_shows_change_summary_and_lines():
    report = build_report(
        example_scan(),
        diff={
            "old": {"scan_id": "old", "started_at": "2026-10-01T10:00:00Z"},
            "new": {"scan_id": "new", "started_at": "2026-10-29T10:00:00Z"},
            "notes": ["1 removal is not confirmed yet."],
            "summary": {
                "headline": "1 thing got worse",
                "counts": {"total": 1, "worse": 1, "better": 0, "neutral": 0},
                "highlights": ["staging.example.com: new host discovered"],
                "lines": ["staging.example.com: new host discovered"],
            },
        },
        generated_at=FIXED_TIME,
    )
    page = render_html(report)

    assert "1 thing got worse" in page
    assert "staging.example.com: new host discovered" in page
    assert "Highlights" in page
    assert "All changes" in page
    assert "1 removal is not confirmed yet." in page


def test_html_without_diff_explains_why():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    page = render_html(report)

    assert "No earlier saved scan was found." in page


def test_html_is_self_contained_and_has_no_javascript():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    page = render_html(report)

    assert "<script" not in page.lower()
    assert "src=\"http" not in page
    assert "href=\"http" not in page
    assert "fonts.googleapis" not in page


def test_html_renders_empty_scan_without_error():
    scan = example_scan()
    scan["assets"] = []
    report = build_report(scan, generated_at=FIXED_TIME)
    page = render_html(report)

    assert "No hosts were saved in this scan." in page
    assert "No findings were recorded." in page


def test_html_does_not_mutate_the_report():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    before = json.dumps(report, sort_keys=True)
    render_html(report)
    assert json.dumps(report, sort_keys=True) == before
