"""Offline tests for editable Word reports, using only the saved example scan."""

import json
import socket
import zipfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

import pytest
from docx import Document
from docx.oxml.ns import qn

from exposureiq import storage
from exposureiq.report import branding
from exposureiq.report.docx import render_docx
from exposureiq.report.model import build_report

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-04T12:00:00Z"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("DOCX tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    assert attempts == []


def example_scan():
    return storage.load_scan(str(EXAMPLE))


def document_text(document):
    return "\n".join(element.text or "" for element in document.element.iter(qn("w:t")))


def all_tables(container):
    for table in container.tables:
        yield table
        for row in table.rows:
            for cell in row.cells:
                yield from all_tables(cell)


def test_docx_is_a_readable_word_document_with_valid_xml():
    data = render_docx(build_report(example_scan(), generated_at=FIXED_TIME))
    document = Document(BytesIO(data))
    assert document.tables
    with zipfile.ZipFile(BytesIO(data)) as archive:
        assert {"[Content_Types].xml", "word/document.xml", "word/styles.xml"} <= set(archive.namelist())
        for name in archive.namelist():
            if name.endswith((".xml", ".rels")):
                ElementTree.fromstring(archive.read(name))
            if name.endswith(".rels"):
                assert b'TargetMode="External"' not in archive.read(name)
        assert not any("vba" in name.lower() for name in archive.namelist())


def test_docx_contains_all_sections_evidence_and_recommendations():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    text = document_text(Document(BytesIO(render_docx(report))))
    for value in (
        "Executive summary", "Findings", "What changed", "Exposure at a glance",
        "Findings by severity", "Assets over time", "Findings over time", "Chart data", "Asset inventory",
        "Methodology and scope", "Point-in-time assessment", report["target"], report["scan_id"],
    ):
        assert value in text
    for finding in report["findings"]:
        for key in ("id", "host", "title", "detail", "rule", "recommendation"):
            assert finding[key] in text
    for asset in report["assets"]:
        for value in [asset["host"], *asset["ips"], *asset["ports"], *asset["technologies"]]:
            assert value in text


def test_docx_findings_keep_severity_order_and_shared_colors():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    document = Document(BytesIO(render_docx(report)))
    table = next(table for table in document.tables if table.rows[0].cells[0].text == "Severity / ID")
    assert [row.cells[0].text.splitlines()[1] for row in table.rows[1:]] == [
        finding["id"] for finding in report["findings"]
    ]
    for row, finding in zip(table.rows[1:], report["findings"]):
        fills = row.cells[0]._tc.get_or_add_tcPr().findall(qn("w:shd"))
        assert len(fills) == 1
        assert fills[0].get(qn("w:fill")) == branding.SEVERITY_COLORS[finding["severity"]].lstrip("#")
    data_tables = [table for table in all_tables(document) if table.rows[0].cells[0].text in {
        "Severity / ID", "Severity", "Host", "Field", "Scan time",
    }]
    assert len(data_tables) == 5
    for table in data_tables:
        assert table.rows[0]._tr.get_or_add_trPr().find(qn("w:tblHeader")) is not None
        for row in table.rows:
            assert row._tr.get_or_add_trPr().find(qn("w:cantSplit")) is not None
        header_fill = table.rows[0].cells[0]._tc.get_or_add_tcPr().find(qn("w:shd"))
        assert header_fill.get(qn("w:fill")) == branding.TABLE_HEADER.lstrip("#")
    assert str(document.styles["Heading 1"].font.color.rgb) == branding.PRINT_ACCENT_TEXT.lstrip("#")
    assert str(document.styles["Subtitle"].font.color.rgb) == branding.PRINT_ACCENT_TEXT.lstrip("#")
    for border in document.styles["Title"].element.iter(qn("w:bottom")):
        assert border.get(qn("w:color")) == branding.LINE.lstrip("#")
        assert border.get(qn("w:themeColor")) is None


def test_docx_has_branded_header_confidential_footer_and_page_numbers():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    document = Document(BytesIO(render_docx(report)))
    section = document.sections[0]
    assert "ExposureIQ" in section.header.paragraphs[0].text
    assert report["target"] in section.header.paragraphs[0].text
    assert "Confidential" in section.footer.paragraphs[0].text
    page = section.footer.paragraphs[0]._p.find(qn("w:fldSimple"))
    assert page.get(qn("w:instr")) == "PAGE"
    assert section.different_first_page_header_footer
    assert not section.first_page_header.paragraphs[0].text
    assert "CONFIDENTIAL" in section.first_page_footer.paragraphs[0].text
    assert document.core_properties.title == report["title"]


def test_docx_has_pdf_style_dark_cover_with_editable_summary_and_cards():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    document = Document(BytesIO(render_docx(report)))
    cover = document.tables[0].rows[0].cells[0]
    properties = cover._tc.get_or_add_tcPr()
    assert properties.find(qn("w:shd")).get(qn("w:fill")) == branding.DARK.lstrip("#")
    border = properties.find(qn("w:tcBorders")).find(qn("w:left"))
    assert border.get(qn("w:color")) == branding.TEAL.lstrip("#")
    cover_text = "\n".join(element.text or "" for element in cover._tc.iter(qn("w:t")))
    assert report["target"] in cover_text and report["scan_id"] in cover_text
    assert all(text in cover_text for text in report["executive_summary"])
    cards = cover.tables[-1]
    for cell, name in zip(cards.rows[0].cells[::2], ("high", "medium", "low", "total")):
        assert cell.paragraphs[0].text == str(report["severity"][name])
        color = branding.TEAL if name == "total" else branding.SEVERITY_COLORS[name]
        assert str(cell.paragraphs[0].runs[0].font.color.rgb) == color.lstrip("#")
    assert document.sections[0].page_width.mm == pytest.approx(210, abs=.02)
    assert document.sections[0].page_height.mm == pytest.approx(297, abs=.02)
    assert document.styles["Normal"].font.name == "Arial"


def test_docx_starts_sections_on_new_pages_with_branded_rules():
    document = Document(BytesIO(render_docx(build_report(example_scan(), generated_at=FIXED_TIME))))
    kickers = [paragraph for paragraph in document.paragraphs if paragraph.style.name == "Report Kicker"]
    assert [paragraph.text for paragraph in kickers] == [
        "04 / RESULTS", "05 / CHANGE", "06 / CHARTS", "07 / INVENTORY", "08 / CONTEXT", "APPENDIX / HISTORY",
    ]
    assert all(paragraph.paragraph_format.page_break_before for paragraph in kickers)
    headings = [paragraph for paragraph in document.paragraphs if paragraph.style.name == "Heading 1"]
    assert len(headings) == len(kickers)
    for heading in headings:
        border = heading._p.get_or_add_pPr().find(qn("w:pBdr")).find(qn("w:bottom"))
        assert border.get(qn("w:color")) == branding.TEAL.lstrip("#")
        assert heading.style.paragraph_format.keep_with_next


def test_docx_embeds_three_native_charts_rather_than_chart_screenshots():
    data = render_docx(build_report(example_scan(), generated_at=FIXED_TIME))
    with zipfile.ZipFile(BytesIO(data)) as archive:
        charts = [name for name in archive.namelist() if name.startswith("word/charts/") and name.endswith(".xml")]
        workbooks = [name for name in archive.namelist() if name.startswith("word/embeddings/")]
        images = [archive.read(name) for name in archive.namelist() if name.startswith("word/media/")]
        assert len(charts) == len(workbooks) == 3
        assert all(name.endswith(".xlsx") for name in workbooks)
        assert images == [branding.logo_png()]
    document = Document(BytesIO(data))
    titles = [element.get("descr") for element in document.element.iter(qn("wp:docPr"))]
    for title in ("Findings by severity", "Assets over time", "Findings over time"):
        assert any(title in description and "editable" in description for description in titles)


def test_docx_preserves_very_long_evidence_as_editable_text():
    scan = example_scan()
    detail = "\n".join(f"Saved evidence line {index}: example.com" for index in range(250))
    scan["assets"][0]["findings"][0]["detail"] = detail
    report = build_report(scan, generated_at=FIXED_TIME)
    document = Document(BytesIO(render_docx(report)))
    table = next(table for table in document.tables if table.rows[0].cells[0].text == "Severity / ID")
    assert detail in "\n".join(row.cells[2].text for row in table.rows[1:])


def test_docx_treats_html_unicode_and_invalid_xml_characters_as_text():
    scan = example_scan()
    scan["assets"][0]["findings"][0]["detail"] = '<script>alert("x")</script> Café & فريق\x00'
    report = build_report(scan, generated_at=FIXED_TIME)
    data = render_docx(report)
    text = document_text(Document(BytesIO(data)))
    assert '<script>alert("x")</script> Café & فريق\ufffd' in text
    with zipfile.ZipFile(BytesIO(data)) as archive:
        xml = archive.read("word/document.xml")
        assert b"<script>" not in xml
        assert b"&lt;script&gt;" in xml
        ElementTree.fromstring(xml)


def test_docx_handles_an_empty_scan():
    scan = example_scan()
    scan["assets"] = []
    text = document_text(Document(BytesIO(render_docx(build_report(scan, generated_at=FIXED_TIME)))))
    assert "No hosts were saved in this scan." in text
    assert "No findings were recorded." in text
    assert "No findings\nrecorded" in text
    assert "No earlier saved scan was found." in text


def test_docx_includes_all_changes_and_confirmation_notes():
    lines = [f"host-{index}.example.com: new host discovered" for index in range(45)]
    report = build_report(example_scan(), diff={
        "old": {"scan_id": "old", "started_at": "2026-10-01T12:00:00Z"},
        "new": {"scan_id": "new", "started_at": "2026-10-13T20:15:00Z"},
        "notes": ["1 removal is not confirmed yet."],
        "summary": {"headline": "45 things got worse", "counts": {"worse": 45},
                    "highlights": lines[:2], "lines": lines},
    }, generated_at=FIXED_TIME)
    text = document_text(Document(BytesIO(render_docx(report))))
    assert "45 things got worse" in text
    assert "1 removal is not confirmed yet." in text
    assert all(line in text for line in lines)
    assert "Compared scan old" in text


def test_docx_history_tables_use_the_shared_model():
    scan = example_scan()
    old = deepcopy(scan)
    old.update(scan_id="old", started_at="2026-10-01T12:00:00Z")
    old["assets"] = []
    report = build_report(scan, history=[old], generated_at=FIXED_TIME)
    document = Document(BytesIO(render_docx(report)))
    history = next(table for table in document.tables if table.rows[0].cells[0].text == "Scan time")
    assert [int(row.cells[1].text) for row in history.rows[1:]] == [0, len(scan["assets"])]


def test_docx_does_not_mutate_the_report():
    report = build_report(example_scan(), generated_at=FIXED_TIME)
    before = json.dumps(report, sort_keys=True)
    render_docx(report)
    assert json.dumps(report, sort_keys=True) == before


@pytest.mark.parametrize("invalid", [None, [], "report"])
def test_docx_rejects_non_dictionary_input(invalid):
    with pytest.raises(ValueError, match="dictionary"):
        render_docx(invalid)
