"""Editable Word charts with embedded data, generated entirely in memory.

OOXML is the zipped XML format used by Word and Excel. A native chart needs a
chart part, cached values for readers, and an embedded workbook for Edit Data.
All three contain the same presentation data. Nothing is downloaded or linked
externally, and worksheet strings are never interpreted as formulas.
"""

from __future__ import annotations

import math
import re
import zipfile
from io import BytesIO

from docx.opc.constants import CONTENT_TYPE, RELATIONSHIP_TYPE
from docx.opc.packuri import PackURI
from docx.opc.part import Part
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm
from lxml import etree

from exposureiq.report import branding

CHART_NS = "http://schemas.openxmlformats.org/drawingml/2006/chart"
SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_INVALID_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _text(value) -> str:
    return _INVALID_XML.sub("\ufffd", "" if value is None else str(value))


def _element(parent, tag: str, text=None, **attributes):
    element = OxmlElement(tag)
    for key, value in attributes.items():
        element.set(key, str(value))
    if text is not None:
        element.text = _text(text)
    parent.append(element)
    return element


def _xml(element) -> bytes:
    return etree.tostring(element, encoding="UTF-8", xml_declaration=True, standalone=True)


def _count(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("chart counts must be non-negative integers")
    return value


def _fill(parent, color: str) -> None:
    _element(_element(parent, "a:solidFill"), "a:srgbClr", val=color.lstrip("#"))


def _line(parent, color: str, *, width: int = 19050, dashed: bool = False) -> None:
    line = _element(parent, "a:ln", w=width)
    _fill(line, color)
    _element(line, "a:prstDash", val="dash" if dashed else "solid")


def _font(parent, size: int = 800) -> None:
    text = _element(parent, "c:txPr")
    _element(text, "a:bodyPr")
    _element(text, "a:lstStyle")
    paragraph = _element(text, "a:p")
    properties = _element(paragraph, "a:pPr")
    run = _element(properties, "a:defRPr", sz=size)
    _fill(run, branding.PRINT_SECONDARY)
    _element(run, "a:latin", typeface="Arial")
    _element(paragraph, "a:endParaRPr", lang="en-US", sz=size)


def _reference(parent, kind: str, formula: str, values: list) -> None:
    reference = _element(parent, f"c:{kind}Ref")
    _element(reference, "c:f", formula)
    cache = _element(reference, f"c:{kind}Cache")
    if kind == "num":
        _element(cache, "c:formatCode", "0")
    _element(cache, "c:ptCount", val=len(values))
    for index, value in enumerate(values):
        _element(_element(cache, "c:pt", idx=index), "c:v", value)


def _series(parent, index: int, name: str, categories: list, values: list,
            color: str, *, line: bool = False, dashed: bool = False):
    series = _element(parent, "c:ser")
    _element(series, "c:idx", val=index)
    _element(series, "c:order", val=index)
    column = chr(ord("B") + index)
    _reference(_element(series, "c:tx"), "str", f"Data!${column}$1", [name])
    shape = _element(series, "c:spPr")
    if line:
        _line(shape, color, width=25400, dashed=dashed)
        marker = _element(series, "c:marker")
        _element(marker, "c:symbol", val="none" if dashed else "circle")
        if not dashed:
            _element(marker, "c:size", val=5)
            marker_shape = _element(marker, "c:spPr")
            _fill(marker_shape, branding.PRINT_PAGE)
            _line(marker_shape, color)
    else:
        _fill(shape, color)
    last = len(categories) + 1
    _reference(_element(series, "c:cat"), "str", f"Data!$A$2:$A${last}", categories)
    _reference(_element(series, "c:val"), "num", f"Data!${column}$2:${column}${last}", values)
    if line:
        _element(series, "c:smooth", val=0)
    return series


def _axes(plot, count: int, maximum: int) -> None:
    category = _element(plot, "c:catAx")
    _element(category, "c:axId", val=501)
    _element(_element(category, "c:scaling"), "c:orientation", val="minMax")
    _element(category, "c:delete", val=0)
    _element(category, "c:axPos", val="b")
    _element(category, "c:majorTickMark", val="none")
    _element(category, "c:minorTickMark", val="none")
    _element(category, "c:tickLblPos", val="nextTo")
    _line(_element(category, "c:spPr"), branding.LINE, width=6350)
    _font(category, 750)
    _element(category, "c:crossAx", val=502)
    _element(category, "c:crosses", val="autoZero")
    _element(category, "c:auto", val=1)
    _element(category, "c:lblAlgn", val="ctr")
    _element(category, "c:lblOffset", val=100)
    _element(category, "c:tickLblSkip", val=max(1, (count + 7) // 8))
    _element(category, "c:noMultiLvlLbl", val=1)

    value = _element(plot, "c:valAx")
    _element(value, "c:axId", val=502)
    scaling = _element(value, "c:scaling")
    _element(scaling, "c:orientation", val="minMax")
    _element(scaling, "c:max", val=maximum)
    _element(scaling, "c:min", val=0)
    _element(value, "c:delete", val=0)
    _element(value, "c:axPos", val="l")
    grid = _element(value, "c:majorGridlines")
    _line(_element(grid, "c:spPr"), branding.LINE, width=6350)
    _element(value, "c:numFmt", formatCode="0", sourceLinked=0)
    _element(value, "c:majorTickMark", val="none")
    _element(value, "c:minorTickMark", val="none")
    _element(value, "c:tickLblPos", val="nextTo")
    _element(_element(_element(value, "c:spPr"), "a:ln"), "a:noFill")
    _font(value, 750)
    _element(value, "c:crossAx", val=501)
    _element(value, "c:crosses", val="autoZero")
    _element(value, "c:crossBetween", val="between" if count == 1 else "midCat")
    _element(value, "c:majorUnit", val=maximum // 4)


def _chart(categories: list, series: list[dict], *, doughnut: bool = False):
    root = OxmlElement("c:chartSpace")
    _element(root, "c:date1904", val=0)
    _element(root, "c:lang", val="en-US")
    _element(root, "c:roundedCorners", val=0)
    chart = _element(root, "c:chart")
    _element(chart, "c:autoTitleDeleted", val=1)
    plot = _element(chart, "c:plotArea")
    _element(plot, "c:layout")
    kind = _element(plot, "c:doughnutChart" if doughnut else "c:lineChart")
    if not doughnut:
        _element(kind, "c:grouping", val="standard")
    _element(kind, "c:varyColors", val=int(doughnut))
    for index, item in enumerate(series):
        element = _series(kind, index, item["name"], categories, item["values"], item["color"],
                          line=not doughnut, dashed=item.get("dashed", False))
        if doughnut:
            # Point colours are explicit, not the reader's Office theme colours.
            before = element.find(qn("c:cat"))
            for point, name in enumerate(("high", "medium", "low")):
                properties = OxmlElement("c:dPt")
                _element(properties, "c:idx", val=point)
                shape = _element(properties, "c:spPr")
                _fill(shape, branding.SEVERITY_COLORS[name])
                _element(_element(shape, "a:ln"), "a:noFill")
                before.addprevious(properties)
    if doughnut:
        _element(kind, "c:firstSliceAng", val=270)
        _element(kind, "c:holeSize", val=65)
    else:
        _element(kind, "c:marker", val=1)
        _element(kind, "c:smooth", val=0)
        for number in (501, 502):
            _element(kind, "c:axId", val=number)
        maximum = max((value for item in series for value in item["values"]), default=0)
        _axes(plot, len(categories), max(1, (maximum + 3) // 4) * 4)
        if len(series) > 1:
            legend = _element(chart, "c:legend")
            _element(legend, "c:legendPos", val="b")
            _element(legend, "c:layout")
            _element(legend, "c:overlay", val=0)
            _font(legend)
    _element(chart, "c:plotVisOnly", val=1)
    _element(chart, "c:dispBlanksAs", val="zero")
    _element(chart, "c:showDLblsOverMax", val=0)
    shape = _element(root, "c:spPr")
    _fill(shape, branding.PRINT_PAGE)
    _element(_element(shape, "a:ln"), "a:noFill")
    _font(root)
    return root


def _sheet(parent, tag: str, text=None, **attributes):
    element = etree.SubElement(parent, f"{{{SHEET_NS}}}{tag}",
                               **{key: str(value) for key, value in attributes.items()})
    if text is not None:
        element.text = _text(text)
    return element


def _workbook(headers: list[str], rows: list[list]) -> bytes:
    """A small, standards-based XLSX. Every string cell is literal inline text."""
    workbook = etree.Element(f"{{{SHEET_NS}}}workbook", nsmap={None: SHEET_NS, "r": OFFICE_REL_NS})
    sheet = _sheet(_sheet(workbook, "sheets"), "sheet", name="Data", sheetId=1)
    sheet.set(f"{{{OFFICE_REL_NS}}}id", "rId1")
    worksheet = etree.Element(f"{{{SHEET_NS}}}worksheet", nsmap={None: SHEET_NS})
    columns = _sheet(worksheet, "cols")
    for index in range(1, len(headers) + 1):
        _sheet(columns, "col", min=index, max=index, width=24, customWidth=1)
    data = _sheet(worksheet, "sheetData")
    for number, values in enumerate([headers, *rows], 1):
        row = _sheet(data, "row", r=number)
        for index, value in enumerate(values):
            cell = _sheet(row, "c", r=f"{chr(ord('A') + index)}{number}")
            if isinstance(value, int) and not isinstance(value, bool):
                _sheet(cell, "v", value)
            else:
                cell.set("t", "inlineStr")
                text = _sheet(_sheet(cell, "is"), "t", value)
                text.set(qn("xml:space"), "preserve")

    def relationships(target: str, kind: str):
        root = etree.Element(f"{{{REL_NS}}}Relationships", nsmap={None: REL_NS})
        etree.SubElement(root, f"{{{REL_NS}}}Relationship", Id="rId1",
                         Type=OFFICE_REL_NS + "/" + kind, Target=target)
        return root

    types = etree.Element(f"{{{TYPES_NS}}}Types", nsmap={None: TYPES_NS})
    for extension, content in (("rels", "application/vnd.openxmlformats-package.relationships+xml"),
                               ("xml", "application/xml")):
        etree.SubElement(types, f"{{{TYPES_NS}}}Default", Extension=extension, ContentType=content)
    spreadsheet_type = "application/vnd.openxmlformats-officedocument.spreadsheetml."
    for part, content in (("/xl/workbook.xml", spreadsheet_type + "sheet.main+xml"),
                          ("/xl/worksheets/sheet1.xml", spreadsheet_type + "worksheet+xml")):
        etree.SubElement(types, f"{{{TYPES_NS}}}Override", PartName=part, ContentType=content)
    files = {
        "[Content_Types].xml": types,
        "_rels/.rels": relationships("xl/workbook.xml", "officeDocument"),
        "xl/workbook.xml": workbook,
        "xl/_rels/workbook.xml.rels": relationships("worksheets/sheet1.xml", "worksheet"),
        "xl/worksheets/sheet1.xml": worksheet,
    }
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, element in files.items():
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, _xml(element))
    return buffer.getvalue()


def _attach(paragraph, chart, headers: list[str], rows: list[list], title: str,
            width: float, height: float) -> None:
    if any(isinstance(value, bool) or not isinstance(value, (int, float))
           or not math.isfinite(value) or value <= 0 for value in (width, height)):
        raise ValueError("chart dimensions must be positive, finite numbers")
    document = paragraph.part
    package = document.package
    names = {str(part.partname) for part in package.iter_parts()}
    index = 1
    while (f"/word/charts/chart{index}.xml" in names
           or f"/word/embeddings/chart-data-{index}.xlsx" in names):
        index += 1
    workbook = Part(PackURI(f"/word/embeddings/chart-data-{index}.xlsx"), WORKBOOK_TYPE,
                    _workbook(headers, rows), package)
    chart_part = Part(PackURI(f"/word/charts/chart{index}.xml"), CONTENT_TYPE.DML_CHART,
                      package=package)
    relation = chart_part.relate_to(workbook, RELATIONSHIP_TYPE.PACKAGE)
    external = _element(chart, "c:externalData")
    external.set(qn("r:id"), relation)
    _element(external, "c:autoUpdate", val=0)
    chart_part._blob = _xml(chart)
    relationship = document.relate_to(chart_part, RELATIONSHIP_TYPE.CHART)
    inline = OxmlElement("wp:inline")
    for edge in ("T", "B", "L", "R"):
        inline.set("dist" + edge, "0")
    _element(inline, "wp:extent", cx=int(Mm(width)), cy=int(Mm(height)))
    _element(inline, "wp:docPr", id=document.next_id, name=title,
             descr=title + "; editable chart with embedded data")
    locks = _element(inline, "wp:cNvGraphicFramePr")
    _element(locks, "a:graphicFrameLocks", noChangeAspect=1)
    graphic = _element(_element(inline, "a:graphic"), "a:graphicData", uri=CHART_NS)
    reference = _element(graphic, "c:chart")
    reference.set(qn("r:id"), relationship)
    paragraph.add_run()._r.add_drawing(inline)


def add_severity_chart(paragraph, counts: dict, *, width: float = 65, height: float = 60) -> None:
    """An editable donut with the shared HIGH/MEDIUM/LOW colours."""
    names = ("high", "medium", "low")
    categories = [branding.SEVERITY_LABELS[name] for name in names]
    values = [_count(counts.get(name, 0)) for name in names]
    series = [{"name": "Findings", "values": values, "color": branding.TEAL}]
    _attach(paragraph, _chart(categories, series, doughnut=True), ["Severity", "Findings"],
            [[name, value] for name, value in zip(categories, values)],
            "Findings by severity", width, height)


def add_trend_chart(paragraph, points: list[dict], *, metric: str = "assets",
                    width: float = 174, height: float = 54) -> None:
    """Use exactly the supplied history; the report model has already bounded it."""
    if metric not in ("assets", "findings"):
        raise ValueError("chart metric must be assets or findings")
    if not points:
        paragraph.add_run("No scan history yet.")
        return
    categories = [_text(point.get("label") or point.get("date") or "?") for point in points]
    series = [{"name": "Hosts" if metric == "assets" else "All findings",
               "values": [_count(point.get(metric, 0)) for point in points],
               "color": branding.TEAL if metric == "assets" else branding.INDIGO}]
    if metric == "findings":
        series.append({"name": "High severity", "values": [_count(point.get("high", 0)) for point in points],
                       "color": branding.HIGH, "dashed": True})
    headers = ["Scan date", *(item["name"] for item in series), "Scan ID", "UTC timestamp"]
    rows = [[category, *(item["values"][index] for item in series),
             _text(point.get("scan_id")), _text(point.get("started_at"))]
            for index, (category, point) in enumerate(zip(categories, points))]
    title = "Assets over time" if metric == "assets" else "Findings over time"
    _attach(paragraph, _chart(categories, series), headers, rows, title, width, height)
