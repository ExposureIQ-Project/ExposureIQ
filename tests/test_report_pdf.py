"""Tests for the dependency-free PDF writer."""

import re
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from exposureiq import storage
from exposureiq.report.model import build_report
from exposureiq.report.pdf import BOTTOM, MARGIN, ReportPdf, measure, render_pdf

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-02T12:00:00Z"
LONG_HOST = ".".join(["w" * 63] * 3 + ["example", "com"])


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("PDF tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def example_scan():
    return storage.load_scan(str(EXAMPLE))


def page_count(data: bytes) -> int:
    match = re.search(rb"/Type /Pages .*?/Count (\d+)", data, re.S)
    assert match, "PDF has no page count"
    return int(match.group(1))


def record_text(writer, monkeypatch):
    calls = []
    original = writer.text

    def record(x, top, value, size=10, bold=False, *args, **kwargs):
        calls.append((x, top, value, size, bold))
        original(x, top, value, size, bold, *args, **kwargs)

    monkeypatch.setattr(writer, "text", record)
    return calls


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


@pytest.mark.parametrize("start", [200, BOTTOM - 50])
@pytest.mark.parametrize("with_endpoint", [False, True])
def test_finding_wraps_the_asset_and_sizes_the_row(monkeypatch, start, with_endpoint):
    writer = ReportPdf({})
    writer.new_page()
    writer.y = start
    calls = record_text(writer, monkeypatch)
    finding = {
        "id": "F-0001", "severity": "high", "host": LONG_HOST,
        "title": "Missing header", "detail": "Saved sample evidence.",
        "recommendation": "Set the header.", "rule": "missing_csp",
    }
    endpoint = "2001:db8:1234:5678:1234:5678:1234:5678:65535"
    if with_endpoint:
        finding.update(ip=endpoint.rsplit(":", 1)[0], port=65535)
    widths = (52, 94, 206, 159)
    writer._finding_row(finding, widths, 1)

    asset_x = MARGIN + widths[0] + 4
    host_calls = [call for call in calls if call[0] == asset_x and call[3] == 8.5]
    endpoint_calls = [call for call in calls
                      if call[0] == asset_x and call[3] == 7 and not call[4]]
    assert len(host_calls) > 1
    assert "".join(call[2] for call in host_calls) == LONG_HOST
    for _, top, value, size, bold in host_calls + endpoint_calls:
        assert measure(value, size, bold) <= widths[1] - 8
        assert top + 4 < writer.y <= BOTTOM
    if with_endpoint:
        assert "".join(call[2] for call in endpoint_calls) == endpoint
        assert endpoint_calls[0][1] > host_calls[-1][1]
    else:
        assert not endpoint_calls
    assert len(writer.doc.pages) == (2 if start > BOTTOM - 100 else 1)
    if len(writer.doc.pages) == 2:
        assert b"FINDING AND EVIDENCE" in writer.doc.to_bytes()


def test_inventory_wraps_using_the_font_it_draws(monkeypatch):
    writer = ReportPdf({"assets": [{
        "host": LONG_HOST, "ips": ["192.0.2.1"], "ports": ["443/tcp"],
        "technologies": ["ExampleServer"], "findings": 1, "highest_label": "High",
    }]})
    calls = record_text(writer, monkeypatch)
    writer.inventory()

    host_calls = [call for call in calls if call[0] == MARGIN + 4 and call[3] == 7.5]
    assert len(host_calls) > 1
    assert "".join(call[2] for call in host_calls) == LONG_HOST
    for _, top, value, size, bold in host_calls:
        assert bold
        assert measure(value, size, bold) <= 118 - 8
        assert top + 4 < writer.y <= BOTTOM


def test_inventory_paginates_long_hosts_and_repeats_the_header(monkeypatch):
    writer = ReportPdf({"assets": [{"host": LONG_HOST}] * 10})
    calls = record_text(writer, monkeypatch)
    writer.inventory()

    assert len(writer.doc.pages) > 1
    headers = [call for call in calls if call[2] == "HOST"]
    assert len(headers) == len(writer.doc.pages)
    assert all(call[1] + 4 < BOTTOM for call in calls if call[3] == 7.5)


def test_pdf_fonts_have_explicit_unicode_maps_for_copying():
    data = render_pdf(build_report(example_scan(), generated_at=FIXED_TIME))
    references = re.findall(rb"/ToUnicode (\d+) 0 R", data)
    assert len(references) == 2
    assert references[0] == references[1]
    cmap = re.search(
        rb"\n" + references[0] + rb" 0 obj\n<< /Length (\d+) >>\nstream\n(.*?)\nendstream",
        data, re.S,
    )
    assert cmap
    assert int(cmap[1]) == len(cmap[2])
    assert b"/CMapType 2" in cmap[2]
    for code, character in ((0x20, " "), (0x28, "("), (0x5C, "\\"), (0x80, "€"),
                            (0x93, "“"), (0x94, "”"), (0x96, "–"), (0xE9, "é")):
        assert f"<{code:02X}> <{ord(character):04X}>".encode("ascii") in cmap[2]
    for count, entries in re.findall(rb"(\d+) beginbfchar\n(.*?)\nendbfchar", cmap[2], re.S):
        assert 0 < int(count) <= 100
        assert len(entries.splitlines()) == int(count)
    assert b"/Encrypt" not in data
    assert b"/Subtype /Image" not in data


def test_wrapped_host_keeps_its_full_copyable_value():
    scan = example_scan()
    scan["assets"] = [scan["assets"][0]]
    scan["assets"][0]["host"] = LONG_HOST
    data = render_pdf(build_report(scan, generated_at=FIXED_TIME))

    encoded = ("\ufeff" + LONG_HOST).encode("utf-16-be").hex().upper().encode("ascii")
    assert data.count(b"/ActualText <" + encoded + b">") >= 2


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="optional PDF text reader is not installed")
def test_text_reader_can_copy_the_full_host_and_punctuation(tmp_path):
    scan = example_scan()
    scan["assets"] = [scan["assets"][0]]
    scan["assets"][0]["host"] = LONG_HOST
    title = "Café – “sample”"
    detail = "Saved evidence (sample) \\ path."
    scan["assets"][0]["findings"][0].update(title=title, detail=detail)
    path = tmp_path / "copyable.pdf"
    path.write_bytes(render_pdf(build_report(scan, generated_at=FIXED_TIME)))

    result = subprocess.run(
        ["pdftotext", "-enc", "UTF-8", str(path), "-"],
        capture_output=True, text=True, check=True,
    )
    assert not result.stderr
    assert result.stdout.count(LONG_HOST) >= 2
    assert title in result.stdout
    assert detail in result.stdout
