"""Native Word charts and embedded workbooks, tested without Office or network."""

import re
import socket
import zipfile
from copy import deepcopy
from io import BytesIO
from xml.etree import ElementTree

import pytest
from docx import Document
from docx.oxml.ns import qn

from exposureiq.demo_data import build_demo_scans
from exposureiq.report import branding
from exposureiq.report.docx import render_docx
from exposureiq.report.model import build_report
from exposureiq.report.word_charts import add_severity_chart, add_trend_chart

NS = {
    "c": "http://schemas.openxmlformats.org/drawingml/2006/chart",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    "ct": "http://schemas.openxmlformats.org/package/2006/content-types",
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("Word charts must never use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    assert attempts == []


@pytest.fixture
def points():
    return [
        {"scan_id": "first", "started_at": "2026-10-01T10:00:00Z", "label": "01 Oct",
         "assets": 4, "findings": 6, "high": 3},
        {"scan_id": "second", "started_at": "2026-10-02T10:00:00Z", "label": "02 Oct",
         "assets": 5, "findings": 3, "high": 1},
    ]


def save_document(document):
    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def chart_parts(data):
    with zipfile.ZipFile(BytesIO(data)) as archive:
        return [ElementTree.fromstring(archive.read(name)) for name in sorted(archive.namelist())
                if re.fullmatch(r"word/charts/chart\d+\.xml", name)]


def workbook_rows(data, index):
    with zipfile.ZipFile(BytesIO(data)) as archive:
        blob = archive.read(f"word/embeddings/chart-data-{index}.xlsx")
    with zipfile.ZipFile(BytesIO(blob)) as archive:
        sheet = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    return [[cell.find("s:is/s:t", NS).text or "" if cell.get("t") == "inlineStr"
             else int(cell.find("s:v", NS).text) for cell in row.findall("s:c", NS)]
            for row in sheet.findall("s:sheetData/s:row", NS)]


def cached_values(chart, path):
    return [point.find("c:v", NS).text for point in chart.findall(path + "/c:pt", NS)]


def test_three_native_charts_have_valid_parts_and_internal_edit_data_workbooks(points):
    document = Document()
    add_severity_chart(document.add_paragraph(), {"high": 3, "medium": 2, "low": 1})
    add_trend_chart(document.add_paragraph(), points)
    add_trend_chart(document.add_paragraph(), points, metric="findings")
    data = save_document(document)
    with zipfile.ZipFile(BytesIO(data)) as archive:
        types = ElementTree.fromstring(archive.read("[Content_Types].xml"))
        chart_types = [node for node in types.findall("ct:Override", NS)
                       if node.get("PartName", "").startswith("/word/charts/")]
        assert len(chart_types) == 3
        assert all(node.get("ContentType").endswith("drawingml.chart+xml") for node in chart_types)
        document_rels = ElementTree.fromstring(archive.read("word/_rels/document.xml.rels"))
        links = [node for node in document_rels if node.get("Type").endswith("/chart")]
        assert len(links) == 3
        for index in range(1, 4):
            chart = ElementTree.fromstring(archive.read(f"word/charts/chart{index}.xml"))
            relationship = chart.find("c:externalData", NS).get(qn("r:id"))
            rels = ElementTree.fromstring(archive.read(f"word/charts/_rels/chart{index}.xml.rels"))
            link = next(node for node in rels if node.get("Id") == relationship)
            assert link.get("Type").endswith("/package")
            assert link.get("Target") == f"../embeddings/chart-data-{index}.xlsx"
            assert chart.find("c:externalData/c:autoUpdate", NS).get("val") == "0"
            with zipfile.ZipFile(BytesIO(archive.read(f"word/embeddings/chart-data-{index}.xlsx"))) as workbook:
                for name in workbook.namelist():
                    if name.endswith((".xml", ".rels")):
                        root = ElementTree.fromstring(workbook.read(name))
                        if name.endswith(".rels"):
                            assert all(node.get("TargetMode") != "External" for node in root)
                assert not any("vba" in name.lower() or "external" in name.lower() for name in workbook.namelist())
        for name in archive.namelist():
            if name.endswith((".xml", ".rels")):
                root = ElementTree.fromstring(archive.read(name))
                if name.endswith(".rels"):
                    assert all(node.get("TargetMode") != "External" for node in root)
        assert not any("vba" in name.lower() for name in archive.namelist())


def test_chart_caches_and_editable_workbooks_contain_the_same_exact_data(points):
    document = Document()
    add_severity_chart(document.add_paragraph(), {"high": 3, "medium": 2, "low": 1})
    add_trend_chart(document.add_paragraph(), points)
    add_trend_chart(document.add_paragraph(), points, metric="findings")
    data = save_document(document)
    for index, chart in enumerate(chart_parts(data), 1):
        rows = workbook_rows(data, index)
        series = chart.findall("c:chart/c:plotArea/*/c:ser", NS)
        for column, item in enumerate(series, 1):
            assert cached_values(item, "c:cat/c:strRef/c:strCache") == [row[0] for row in rows[1:]]
            assert cached_values(item, "c:val/c:numRef/c:numCache") == [str(row[column]) for row in rows[1:]]
            assert cached_values(item, "c:tx/c:strRef/c:strCache") == [rows[0][column]]
            assert item.find("c:val/c:numRef/c:f", NS).text == f"Data!${chr(65 + column)}$2:${chr(65 + column)}${len(rows)}"
        if index > 1:
            assert [row[-2:] for row in rows[1:]] == [[point["scan_id"], point["started_at"]] for point in points]


def test_native_charts_share_pdf_colors_and_dashed_high_series(points):
    document = Document()
    add_severity_chart(document.add_paragraph(), {"high": 3, "medium": 2, "low": 1})
    add_trend_chart(document.add_paragraph(), points)
    add_trend_chart(document.add_paragraph(), points, metric="findings")
    donut, assets, findings = chart_parts(save_document(document))
    colors = [node.get("val") for node in donut.findall(".//c:dPt/c:spPr/a:solidFill/a:srgbClr", NS)]
    assert colors == [branding.SEVERITY_COLORS[name].lstrip("#") for name in ("high", "medium", "low")]
    assert donut.find(".//c:holeSize", NS).get("val") == "65"
    assert donut.find("c:chart/c:title", NS) is None
    assert assets.find(".//c:ser/c:spPr/a:ln/a:solidFill/a:srgbClr", NS).get("val") == branding.TEAL.lstrip("#")
    lines = findings.findall(".//c:ser/c:spPr/a:ln", NS)
    assert [line.find("a:solidFill/a:srgbClr", NS).get("val") for line in lines] == [
        branding.INDIGO.lstrip("#"), branding.HIGH.lstrip("#"),
    ]
    assert [line.find("a:prstDash", NS).get("val") for line in lines] == ["solid", "dash"]
    assert all(node.get("val") == "0" for node in findings.findall(".//c:smooth", NS))


@pytest.mark.parametrize("maximum,ceiling", [(0, 4), (1, 4), (4, 4), (5, 8), (9, 12), (1000, 1000)])
def test_axes_start_at_zero_with_whole_number_grid_units(points, maximum, ceiling):
    points[0]["assets"], points[1]["assets"] = 0, maximum
    document = Document()
    add_trend_chart(document.add_paragraph(), points)
    chart = chart_parts(save_document(document))[0]
    axis = chart.find(".//c:valAx", NS)
    assert axis.find("c:scaling/c:min", NS).get("val") == "0"
    assert axis.find("c:scaling/c:max", NS).get("val") == str(ceiling)
    assert axis.find("c:majorUnit", NS).get("val") == str(ceiling // 4)


def test_zero_findings_donut_keeps_real_zeroes_without_placeholder_findings():
    document = Document()
    add_severity_chart(document.add_paragraph(), {})
    data = save_document(document)
    chart = chart_parts(data)[0]
    assert cached_values(chart, ".//c:ser/c:val/c:numRef/c:numCache") == ["0", "0", "0"]
    assert workbook_rows(data, 1)[1:] == [["High", 0], ["Medium", 0], ["Low", 0]]


@pytest.mark.parametrize("metric", ["assets", "findings"])
def test_single_scan_is_centered_without_inventing_extra_snapshots(points, metric):
    document = Document()
    add_trend_chart(document.add_paragraph(), points[:1], metric=metric)
    data = save_document(document)
    chart = chart_parts(data)[0]
    assert chart.find(".//c:valAx/c:crossBetween", NS).get("val") == "between"
    assert all(node.get("val") == "1" for node in chart.findall(".//c:ptCount", NS))
    assert len(workbook_rows(data, 1)) == 2


def test_long_history_keeps_every_point_and_limits_date_label_frequency(points):
    points = [dict(points[0], scan_id=f"scan-{index}", label=f"Date {index}", assets=index)
              for index in range(17)]
    document = Document()
    add_trend_chart(document.add_paragraph(), points)
    data = save_document(document)
    chart = chart_parts(data)[0]
    assert cached_values(chart, ".//c:ser/c:val/c:numRef/c:numCache") == [str(index) for index in range(17)]
    assert len(workbook_rows(data, 1)) == 18
    assert chart.find(".//c:catAx/c:tickLblSkip", NS).get("val") == "3"


def test_empty_history_is_an_honest_text_placeholder():
    document = Document()
    paragraph = document.add_paragraph()
    add_trend_chart(paragraph, [])
    assert paragraph.text == "No scan history yet."
    assert not chart_parts(save_document(document))


def test_untrusted_labels_and_workbook_strings_are_literal_text_not_formulas(points):
    text = '=HYPERLINK("https://example.com", "Café & فريق")\x00'
    points[0].update(label=text, scan_id=text, started_at=text)
    document = Document()
    add_trend_chart(document.add_paragraph(), points)
    data = save_document(document)
    expected = text.replace("\x00", "\ufffd")
    rows = workbook_rows(data, 1)
    assert rows[1][0] == rows[1][-1] == rows[1][-2] == expected
    chart = chart_parts(data)[0]
    assert cached_values(chart, ".//c:ser/c:cat/c:strRef/c:strCache")[0] == expected
    with zipfile.ZipFile(BytesIO(data)) as archive:
        with zipfile.ZipFile(BytesIO(archive.read("word/embeddings/chart-data-1.xlsx"))) as workbook:
            worksheet = ElementTree.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
            assert worksheet.findall(".//s:f", NS) == []
            assert worksheet.findall(".//s:hyperlink", NS) == []


def test_chart_drawing_ids_are_unique_even_with_an_existing_logo(points):
    document = Document()
    document.add_paragraph().add_run().add_picture(BytesIO(branding.logo_png()))
    for _ in range(3):
        add_trend_chart(document.add_paragraph(), points)
    ids = [node.get("id") for node in document.element.iter(qn("wp:docPr"))]
    assert len(ids) == len(set(ids)) == 4
    assert len(chart_parts(save_document(document))) == 3


def test_chart_generation_does_not_mutate_input_or_randomize_embedded_workbooks(points):
    counts = {"high": 3, "medium": 2, "low": 1}
    before = deepcopy((points, counts))
    workbooks = []
    for _ in range(2):
        document = Document()
        add_severity_chart(document.add_paragraph(), counts)
        add_trend_chart(document.add_paragraph(), points)
        with zipfile.ZipFile(BytesIO(save_document(document))) as archive:
            workbooks.append([archive.read(f"word/embeddings/chart-data-{index}.xlsx") for index in (1, 2)])
    assert (points, counts) == before
    assert workbooks[0] == workbooks[1]


@pytest.mark.parametrize("number", [1, 3, 4, 10])
def test_report_charts_and_workbooks_never_use_later_snapshots(number):
    scans = build_demo_scans()
    report = build_report(scans[number - 1], history=scans, generated_at="2026-11-04T12:00:00Z")
    data = render_docx(report)
    _, assets, findings = chart_parts(data)
    for index, chart, metric in ((2, assets, "assets"), (3, findings, "findings")):
        series = chart.findall(".//c:ser", NS)
        assert cached_values(series[0], "c:val/c:numRef/c:numCache") == [
            str(point[metric]) for point in report["history"]
        ]
        rows = workbook_rows(data, index)
        assert [row[-2] for row in rows[1:]] == [scan["scan_id"] for scan in scans[:number]]
        assert not any(scan["scan_id"] in str(rows) for scan in scans[number:])
    assert cached_values(findings.findall(".//c:ser", NS)[1], "c:val/c:numRef/c:numCache") == [
        str(point["high"]) for point in report["history"]
    ]


@pytest.mark.parametrize("value", [-1, True, 1.5, "3", None])
@pytest.mark.parametrize("metric", ["severity", "assets", "findings", "high"])
def test_invalid_counts_fail_before_attaching_any_chart(points, metric, value):
    document = Document()
    with pytest.raises(ValueError, match="non-negative integers"):
        if metric == "severity":
            add_severity_chart(document.add_paragraph(), {"high": value})
        else:
            points[0][metric] = value
            add_trend_chart(document.add_paragraph(), points,
                            metric="assets" if metric == "assets" else "findings")
    assert not chart_parts(save_document(document))


@pytest.mark.parametrize("value", [0, -1, True, "65", None, float("nan"), float("inf")])
@pytest.mark.parametrize("dimension", ["width", "height"])
def test_invalid_chart_dimensions_are_rejected(dimension, value):
    document = Document()
    with pytest.raises(ValueError, match="positive, finite"):
        add_severity_chart(document.add_paragraph(), {}, **{dimension: value})
    assert not chart_parts(save_document(document))


def test_unknown_metric_is_an_input_error(points):
    with pytest.raises(ValueError, match="metric"):
        add_trend_chart(Document().add_paragraph(), points, metric="ports")
