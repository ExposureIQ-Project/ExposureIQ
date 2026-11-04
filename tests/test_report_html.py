"""Tests for the self-contained HTML report."""

import json
import base64
import hashlib
import socket
from html.parser import HTMLParser
from pathlib import Path

import pytest

from exposureiq import storage
from exposureiq.report.html import render_html
from exposureiq.report.interactive import SCRIPT
from exposureiq.report.model import build_report

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-02T12:00:00Z"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("HTML tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


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


def test_html_is_self_contained_and_only_allows_its_fixed_script(portal_html):
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    page = render_html(report)

    assert portal_html(page).scripts == [SCRIPT]
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in page
    assert "connect-src 'none'" in page
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


def test_html_has_accessible_section_navigation_and_charts_after_overview():
    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids, self.anchors = [], []

        def handle_starttag(self, tag, attributes):
            attributes = dict(attributes)
            if "id" in attributes:
                self.ids.append(attributes["id"])
            if tag == "a":
                self.anchors.append(attributes["href"])

    page = render_html(build_report(example_scan(), generated_at=FIXED_TIME))
    parser = Links()
    parser.feed(page)
    assert len(parser.ids) == len(set(parser.ids))
    assert len(parser.anchors) == 9  # Navigation plus both charts' one scan node.
    assert all(anchor.startswith("#") and anchor[1:] in parser.ids for anchor in parser.anchors)
    assert 'aria-label="Report sections"' in page
    assert "Skip to report" in page
    assert page.index('id="exposure"') < page.index('id="findings"')


def test_html_animations_are_responsive_reduced_motion_safe_and_print_safe():
    page = render_html(build_report(example_scan(), generated_at=FIXED_TIME))
    for css in (
        "scroll-behavior: smooth", "@keyframes panel-enter", "@keyframes trend-draw",
        "@keyframes segment-enter", "@media screen and (max-width: 760px)",
        "@media (prefers-reduced-motion: reduce)", "animation: none !important",
        "scroll-behavior: auto !important", "@media print", "overflow-x: auto",
    ):
        assert css in page
    assert 'class="donut-segment"' in page
    assert 'class="trend-line" pathLength="1"' in page
    assert ".report-topbar, .skip-link { display: none; }" in page
    assert "Content-Security-Policy" in page
    assert "default-src 'none'" in page
    assert "url(http" not in page.lower()


def test_html_escapes_user_title_navigation_target_and_recommendations():
    scan = example_scan()
    scan["target"] = '<img src=x onerror="alert(1)">'
    scan["assets"][0]["findings"][0]["recommendation"] = '<svg onload="alert(2)"></svg>'
    page = render_html(build_report(scan, title='</title><script>alert(3)</script>', generated_at=FIXED_TIME))
    assert "<img src=x" not in page
    assert "<svg onload" not in page
    assert "<script>" not in page
    assert "&lt;img" in page
    assert "&lt;svg onload" in page
    assert "&lt;/title&gt;" in page
