"""Tests for the dependency-free PDF writer."""

import re
from pathlib import Path

from exposureiq import storage
from exposureiq.report.model import build_report
from exposureiq.report.pdf import render_pdf

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-02T12:00:00Z"


def example_scan():
    return storage.load_scan(str(EXAMPLE))


def page_count(data: bytes) -> int:
    match = re.search(rb"/Type /Pages .*?/Count (\d+)", data, re.S)
    assert match, "PDF has no page count"
    return int(match.group(1))


def test_pdf_is_a_real_multipage_document():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    data = render_pdf(report)

    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in data
    assert b"/BaseFont /Helvetica" in data
    assert b"/BaseFont /Helvetica-Bold" in data
    assert b"ExposureIQ" in data
    assert b"Findings" in data
    assert page_count(data) >= 6


def test_pdf_with_many_findings_paginates():
    scan = example_scan()
    findings = scan["assets"][0]["findings"]
    for index in range(60):
        finding = dict(findings[0])
        finding["id"] = f"F-{1000 + index:04d}"
        finding["title"] = f"Repeated finding {index}"
        finding["detail"] = "A deliberately long detail line that wraps in the table."
        findings.append(finding)
    report = build_report(scan, generated_at=FIXED_TIME)
    data = render_pdf(report)

    assert page_count(data) > 8
    assert b"Repeated finding 59" in data


def test_pdf_handles_an_empty_scan():
    scan = example_scan()
    scan["assets"] = []
    report = build_report(scan, generated_at=FIXED_TIME)
    data = render_pdf(report)

    assert data.startswith(b"%PDF-1.4")
    assert b"No hosts were saved in this scan." in data
    assert b"No findings were recorded." in data
    assert page_count(data) >= 6


def test_pdf_rejects_non_dictionary():
    try:
        render_pdf([])
    except ValueError as error:
        assert "dictionary" in str(error)
    else:
        raise AssertionError("render_pdf should reject a list")
