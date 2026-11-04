"""Render the shared report model as an editable, offline Word document.

The PDF-style cover, white body pages, tables, and native charts all stay
editable. Chart workbooks are embedded, not remotely linked. No scan text
becomes markup, a formula, a link, a macro, or an external resource.
"""

from __future__ import annotations

import re
from io import BytesIO

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_ROW_HEIGHT_RULE, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor

from exposureiq.report import branding
from exposureiq.report.model import format_time
from exposureiq.report.word_charts import add_severity_chart, add_trend_chart

_INVALID_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
_CONTENT_WIDTH = 174


def _text(value) -> str:
    """Replace characters Word's XML cannot store, without changing the model."""
    return _INVALID_XML.sub("\ufffd", "" if value is None else str(value))


def _color(value: str) -> RGBColor:
    return RGBColor.from_string(value.lstrip("#"))


def _shade(properties, color: str) -> None:
    previous = properties.find(qn("w:shd"))
    if previous is not None:
        properties.remove(previous)
    fill = OxmlElement("w:shd")
    fill.set(qn("w:fill"), color.lstrip("#"))
    properties.append(fill)


def _logo(paragraph, width: float) -> None:
    picture = paragraph.add_run().add_picture(BytesIO(branding.logo_png()), width=Mm(width))
    picture._inline.docPr.set("descr", "ExposureIQ scan aperture icon")
    picture._inline.docPr.set("name", "ExposureIQ logo")


def _borders(properties, tag: str, edges: dict) -> None:
    previous = properties.find(qn(tag))
    if previous is not None:
        properties.remove(previous)
    borders = OxmlElement(tag)
    for edge, value in edges.items():
        border = OxmlElement(f"w:{edge}")
        border.set(qn("w:val"), "single" if value else "nil")
        if value:
            color, size = value
            border.set(qn("w:color"), color.lstrip("#"))
            border.set(qn("w:sz"), str(size))
        borders.append(border)
    properties.append(borders)


def _margins(cell, *, top: int = 80, left: int = 100, bottom: int = 80, right: int = 100) -> None:
    properties = cell._tc.get_or_add_tcPr()
    previous = properties.find(qn("w:tcMar"))
    if previous is not None:
        properties.remove(previous)
    margins = OxmlElement("w:tcMar")
    for edge, value in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        margin = OxmlElement(f"w:{edge}")
        margin.set(qn("w:w"), str(value))
        margin.set(qn("w:type"), "dxa")
        margins.append(margin)
    properties.append(margins)


def _format(paragraph, *, size: float = 10, color: str = branding.DARK,
            bold: bool = False, before: float = 0, after: float = 6, keep: bool = False) -> None:
    layout = paragraph.paragraph_format
    layout.space_before, layout.space_after = Pt(before), Pt(after)
    layout.line_spacing = 1.1
    layout.keep_with_next = keep
    layout.widow_control = True
    for run in paragraph.runs:
        run.font.name = "Arial"
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = _color(color)


def _paragraph(container, text, **style):
    paragraph = container.add_paragraph(_text(text))
    _format(paragraph, **style)
    return paragraph


def _layout_table(container, widths: tuple):
    """A borderless layout made of ordinary, editable Word cells."""
    if hasattr(container, "_tc"):
        table = container.add_table(rows=1, cols=len(widths))
        # Word requires an empty paragraph after a nested table. Keep it small.
        trailing = container.paragraphs[-1]
        _format(trailing, size=1, after=0)
        trailing.paragraph_format.line_spacing = Pt(1)
    else:
        table = container.add_table(rows=1, cols=len(widths))
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    width = table._tbl.tblPr.find(qn("w:tblW"))
    width.set(qn("w:type"), "dxa")
    width.set(qn("w:w"), str(Mm(sum(widths)).twips))
    _borders(table._tbl.tblPr, "w:tblBorders", {
        edge: None for edge in ("top", "left", "bottom", "right", "insideH", "insideV")
    })
    for column, width in zip(table.columns, widths):
        column.width = Mm(width)
    for cell, width in zip(table.rows[0].cells, widths):
        cell.width = Mm(width)
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
        _margins(cell, top=0, left=0, bottom=0, right=0)
    return table


def _table(document, headers: tuple, rows: list, widths: tuple | None = None):
    """Repeat dark headers, band rows, and avoid splitting ordinary rows."""
    widths = widths or tuple(_CONTENT_WIDTH / len(headers) for _ in headers)
    table = _layout_table(document, widths)
    _borders(table._tbl.tblPr, "w:tblBorders", {
        "top": None, "left": None, "right": None, "insideV": None,
        "bottom": (branding.LINE, 4), "insideH": (branding.LINE, 4),
    })
    repeat = OxmlElement("w:tblHeader")
    table.rows[0]._tr.get_or_add_trPr().append(repeat)

    for index, values in enumerate([headers, *rows]):
        row = table.rows[0] if index == 0 else table.add_row()
        row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        cells = row.cells
        for cell, value, width in zip(cells, values, widths):
            cell.width = Mm(width)
            cell.text = _text(value)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
            _margins(cell)
            _shade(cell._tc.get_or_add_tcPr(), branding.TABLE_HEADER if index == 0 else
                   branding.PRINT_SURFACE if index % 2 else branding.PRINT_PAGE)
            for paragraph in cell.paragraphs:
                _format(paragraph, size=8.5, after=2, keep=index == 0, bold=index == 0,
                        color=branding.TEXT_PRIMARY if index == 0 else branding.DARK)
    _paragraph(document, "", size=1, after=0)
    return table


def _cards(container, values: tuple, *, width: float = _CONTENT_WIDTH,
           background: str = branding.PRINT_PAGE) -> None:
    card_width = (width - (len(values) - 1) * 3) / len(values)
    widths = tuple(value for index in range(len(values))
                   for value in ((card_width, 3) if index < len(values) - 1 else (card_width,)))
    table = _layout_table(container, widths)
    table.rows[0].height, table.rows[0].height_rule = Mm(23), WD_ROW_HEIGHT_RULE.AT_LEAST
    for index, cell in enumerate(table.rows[0].cells):
        _shade(cell._tc.get_or_add_tcPr(), background)
        if index % 2:
            _format(cell.paragraphs[0], size=1, after=0)
            continue
        label, count, color = values[index // 2]
        _shade(cell._tc.get_or_add_tcPr(), branding.INNER_SURFACE)
        _borders(cell._tc.get_or_add_tcPr(), "w:tcBorders", {"left": (color, 24)})
        _margins(cell, top=120, left=140, bottom=120, right=100)
        cell.paragraphs[0].add_run(_text(count))
        _format(cell.paragraphs[0], size=23, color=color, bold=True, after=3, keep=True)
        _paragraph(cell, label.upper(), size=7, color=branding.TEXT_SUBTLE, bold=True, after=0)


def _section(document, title: str, kicker: str, lede: str | None = None) -> None:
    label = document.add_paragraph(kicker.upper(), "Report Kicker")
    label.paragraph_format.page_break_before = True
    heading = document.add_heading(title, 1)
    _borders(heading._p.get_or_add_pPr(), "w:pBdr", {"bottom": (branding.TEAL, 12)})
    if lede:
        document.add_paragraph(_text(lede), "Report Lede")


def _callout(document, text: str) -> None:
    paragraph = _paragraph(document, text, size=9.5, color=branding.PRINT_SECONDARY,
                           before=8, after=12)
    paragraph.paragraph_format.left_indent = Mm(5)
    paragraph.paragraph_format.right_indent = Mm(4)
    _shade(paragraph._p.get_or_add_pPr(), branding.PRINT_SURFACE)
    _borders(paragraph._p.get_or_add_pPr(), "w:pBdr", {"left": (branding.TEAL, 24)})


def _setup(document, report: dict) -> None:
    section = document.sections[0]
    section.page_width, section.page_height = Mm(210), Mm(297)
    section.top_margin = section.bottom_margin = Mm(18)
    section.left_margin = section.right_margin = Mm(18)
    section.header_distance = section.footer_distance = Mm(8)
    section.different_first_page_header_footer = True
    normal = document.styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10)
    normal.font.color.rgb = _color(branding.DARK)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.1
    normal.paragraph_format.widow_control = True
    for name, size in (("Title", 30), ("Subtitle", 12), ("Heading 1", 21), ("Heading 2", 13)):
        style = document.styles[name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.color.rgb = _color(branding.PRINT_ACCENT_TEXT)
        style.font.bold = name != "Subtitle"
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.space_before = Pt(8 if name == "Heading 2" else 0)
        style.paragraph_format.space_after = Pt(5 if name == "Heading 2" else 10)
    document.styles["Subtitle"].font.italic = False
    for name, size, bold, after in (("Report Kicker", 8, True, 4), ("Report Lede", 9.5, False, 10)):
        style = document.styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
        style.base_style = normal
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.bold = bold
        style.font.color.rgb = _color(branding.PRINT_ACCENT_TEXT if bold else branding.PRINT_MUTED)
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.space_after = Pt(after)
    # The bundled Word template otherwise leaves a blue theme-coloured rule.
    for border in document.styles["Title"].element.iter(qn("w:bottom")):
        border.set(qn("w:color"), branding.LINE.lstrip("#"))
        border.attrib.pop(qn("w:themeColor"), None)

    header = section.header.paragraphs[0]
    document.styles["Header"].paragraph_format.tab_stops.clear_all()
    header.paragraph_format.tab_stops.add_tab_stop(Mm(_CONTENT_WIDTH), WD_TAB_ALIGNMENT.RIGHT)
    header.paragraph_format.space_after = Pt(4)
    _borders(header._p.get_or_add_pPr(), "w:pBdr", {"bottom": (branding.LINE, 4)})
    _logo(header, 7)
    run = header.add_run(" Exposure")
    run.font.size = Pt(11)
    run.bold = True
    run.font.color.rgb = _color(branding.DARK)
    run = header.add_run("IQ")
    run.font.size = Pt(11)
    run.bold = True
    run.font.color.rgb = _color(branding.PRINT_ACCENT_TEXT)
    run = header.add_run(_text(f"\t{report['target']}"))
    run.font.size = Pt(8)
    run.font.color.rgb = _color(branding.PRINT_MUTED)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = footer.add_run(_text(f"Confidential · {report['target']} · {report['scan_id']}  |  Page "))
    run.font.size = Pt(8)
    run.font.color.rgb = _color(branding.PRINT_MUTED)
    page = OxmlElement("w:fldSimple")
    page.set(qn("w:instr"), "PAGE")
    number = footer.add_run("1")
    number.font.size = Pt(8)
    number.font.color.rgb = _color(branding.PRINT_MUTED)
    page.append(number._r)
    footer._p.append(page)
    first_footer = section.first_page_footer.paragraphs[0]
    first_footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    first_footer.add_run(_text(f"CONFIDENTIAL · Prepared for the owner of {report['target']}"))
    _format(first_footer, size=7.5, color=branding.PRINT_MUTED, after=0)
    document.core_properties.author = "ExposureIQ"
    document.core_properties.title = _text(report["title"])
    document.core_properties.subject = _text(f"Attack surface assessment of {report['target']}")


def _cover(document, report: dict) -> None:
    panel = _layout_table(document, (_CONTENT_WIDTH,))
    panel.rows[0].height, panel.rows[0].height_rule = Mm(236), WD_ROW_HEIGHT_RULE.AT_LEAST
    cover = panel.rows[0].cells[0]
    _shade(cover._tc.get_or_add_tcPr(), branding.DARK)
    _borders(cover._tc.get_or_add_tcPr(), "w:tcBorders", {"left": (branding.TEAL, 36)})
    _margins(cover, top=560, left=680, bottom=450, right=680)
    brand = cover.paragraphs[0]
    _logo(brand, 16)
    run = brand.add_run(" Exposure")
    run.bold = True
    run.font.size = Pt(24)
    run.font.color.rgb = _color(branding.TEXT_PRIMARY)
    run = brand.add_run("IQ")
    run.bold = True
    run.font.size = Pt(24)
    run.font.color.rgb = _color(branding.TEAL)
    brand.paragraph_format.space_after = Pt(3)
    _paragraph(cover, "ATTACK SURFACE MANAGEMENT", size=7.5,
               color=branding.TEXT_SUBTLE, after=34)
    _paragraph(cover, _text(report["title"]).upper(), size=8.5, color=branding.TEAL,
               bold=True, after=9, keep=True)
    _paragraph(cover, report["target"], size=32, color=branding.TEXT_PRIMARY,
               bold=True, after=8, keep=True)
    _paragraph(cover, f"Scan {report['scan_id']}", size=9, color=branding.TEXT_SUBTLE, after=3)
    _paragraph(cover, report["started_label"], size=9, color=branding.TEXT_SUBTLE, after=14)
    risk = _layout_table(cover, (44,))
    cell = risk.rows[0].cells[0]
    _shade(cell._tc.get_or_add_tcPr(), report["risk"]["color"])
    _margins(cell, top=70, bottom=70)
    cell.paragraphs[0].add_run(_text(report["risk"]["label"].upper()))
    cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
    _format(cell.paragraphs[0], size=8, bold=True, after=0)
    _paragraph(cover, "Executive summary", size=9, color=branding.TEAL,
               bold=True, before=17, after=9, keep=True)
    for text in report["executive_summary"]:
        _paragraph(cover, text, size=9.5, color=branding.TEXT_SECONDARY, after=7)
    _paragraph(cover, "", size=1, after=12)
    counts = report["severity"]
    _cards(cover, tuple(("Total findings" if name == "total" else f"{name} severity",
                         counts.get(name, 0), branding.TEAL if name == "total" else branding.SEVERITY_COLORS[name])
                        for name in ("high", "medium", "low", "total")),
           width=150, background=branding.DARK)
    caption = _paragraph(document, f"Generated {report['generated_label']}", size=7.5,
                         color=branding.PRINT_MUTED, before=6, after=0)
    caption.alignment = WD_ALIGN_PARAGRAPH.RIGHT


def _cell_content(cell, parts: tuple) -> None:
    cell.text = ""
    for index, (text, size, bold, color) in enumerate(parts):
        paragraph = cell.paragraphs[0] if index == 0 else cell.add_paragraph()
        paragraph.add_run(_text(text))
        _format(paragraph, size=size, bold=bold, color=color, after=4,
                keep=index < len(parts) - 1)


def _findings(document, report: dict) -> None:
    _section(document, "Findings", "04 / Results",
             "Ordered by severity, then by asset. Each row names the evidence ExposureIQ "
             "collected and the recommended next step.")
    if not report["findings"]:
        _callout(document, "No findings were recorded. This is not proof that the target is secure.")
        return
    rows = []
    for finding in report["findings"]:
        endpoint = str(finding.get("ip") or "")
        if endpoint and finding.get("port"):
            endpoint += f":{finding['port']}"
        rows.append((
            f"{branding.SEVERITY_LABELS[finding['severity']]}\n{finding.get('id') or ''}",
            f"{finding.get('host') or ''}" + (f"\n{endpoint}" if endpoint else ""),
            f"{finding.get('title') or ''}\n\n{finding.get('detail') or ''}\n\n"
            f"Rule: {finding.get('rule') or ''}",
            finding.get("recommendation") or "",
        ))
    table = _table(document, ("Severity / ID", "Asset", "Finding and evidence", "Recommendation"),
                   rows, (24, 36, 66, 48))
    for row, finding in zip(table.rows[1:], report["findings"]):
        _shade(row.cells[0]._tc.get_or_add_tcPr(), branding.SEVERITY_COLORS[finding["severity"]])
        _cell_content(row.cells[0], (
            (branding.SEVERITY_LABELS[finding["severity"]], 8, True, branding.DARK),
            (finding.get("id") or "", 7, False, branding.PRINT_SECONDARY),
        ))
        endpoint = str(finding.get("ip") or "")
        if endpoint and finding.get("port"):
            endpoint += f":{finding['port']}"
        _cell_content(row.cells[1], (
            (finding.get("host") or "", 8.5, True, branding.DARK),
            (endpoint, 7.5, False, branding.PRINT_MUTED),
        ))
        _cell_content(row.cells[2], (
            (finding.get("title") or "", 9, True, branding.DARK),
            (finding.get("detail") or "", 8.5, False, branding.PRINT_SECONDARY),
            (f"Rule: {finding.get('rule') or ''}", 7, False, branding.PRINT_MUTED),
        ))
        _cell_content(row.cells[3], (
            (finding.get("recommendation") or "", 8.5, False, branding.PRINT_SECONDARY),
        ))


def _changes(document, report: dict) -> None:
    _section(document, "What changed", "05 / Change",
             "Security-relevant differences between saved scans. Removals need agreement "
             "from two included snapshots; future scans cannot confirm earlier changes.")
    diff, summary = report.get("diff"), report.get("diff_summary") or {}
    if not diff:
        _callout(document,
            "Change comparisons were disabled for this export. Enable comparisons when exporting to see what changed."
            if not report.get("comparison_enabled", True) else
            "No earlier saved scan was found. This report describes the current exposure only."
        )
        return
    document.add_heading("Overall change since baseline", 2)
    document.add_paragraph(_text(summary.get("headline") or "Saved scan changes compared"))
    counts = summary.get("counts") or {}
    _cards(document, (("Worse", counts.get("worse", 0), branding.HIGH),
                      ("Better", counts.get("better", 0), branding.GREEN),
                      ("Neutral", counts.get("neutral", 0), branding.SLATE)))
    _paragraph(document, "", size=1, after=6)
    for title, lines in (("Highlights", summary.get("highlights")),
                         ("All changes", summary.get("lines")), ("Notes", diff.get("notes"))):
        if lines:
            document.add_heading(title, 2)
            for line in lines:
                document.add_paragraph(_text(line), "List Bullet")
    old, new = diff.get("old") or {}, diff.get("new") or {}
    document.add_paragraph(_text(f"Compared scan {old.get('scan_id')} ({old.get('started_at')}) "
                                f"with {new.get('scan_id')} ({new.get('started_at')})."))
    steps = diff.get("history") or []
    if steps:
        document.add_heading("Scan-by-scan history", 2)
        document.add_paragraph("Overall counts above are net changes. These steps retain temporary issues "
                               "and fixes through the selected scan; later scans are not included.")
        rows = []
        for step in steps:
            previous, current = step.get("old") or {}, step.get("new") or {}
            counts = (step.get("summary") or {}).get("counts") or {}
            rows.append((f"{previous.get('scan_id')} → {current.get('scan_id')}",
                         *(counts.get(name, 0) for name in ("worse", "better", "neutral"))))
        _table(document, ("From / to", "Worse", "Better", "Neutral"), rows, (102, 24, 24, 24))
        for step in steps:
            previous, current = step.get("old") or {}, step.get("new") or {}
            summary = step.get("summary") or {}
            document.add_heading(_text(f"{previous.get('scan_id')} → {current.get('scan_id')}"), 2)
            document.add_paragraph(_text(f"{format_time(previous.get('started_at'))} → "
                                        f"{format_time(current.get('started_at'))}"))
            document.add_paragraph(_text(summary.get("headline") or "No changes"))
            for line in summary.get("lines") or []:
                document.add_paragraph(_text(line), "List Bullet")
            for note in step.get("notes") or []:
                document.add_paragraph(_text(f"Note: {note}"))


def _overview(document, report: dict) -> None:
    _section(document, "Exposure at a glance", "06 / Charts",
             "The severity mix shows where attention is needed. The trends show how hosts "
             "and findings changed from the first saved scan through this scan.")
    document.add_heading("Findings by severity", 2)
    overview = _layout_table(document, (74, 100))
    left = overview.rows[0].cells[0]
    counts = report["severity"]
    if not counts.get("total"):
        notice = left.paragraphs[0]
        notice.add_run("No findings\nrecorded")
        notice.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _format(notice, size=12, color=branding.PRINT_MUTED, before=45, after=0)
        donut = left.add_paragraph()
    else:
        donut = left.paragraphs[0]
    donut.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _format(donut, size=1, after=0)
    add_severity_chart(donut, counts, height=60 if counts.get("total") else 30)
    legend = overview.rows[0].cells[1]
    legend.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    legend.paragraphs[0].add_run(_text(counts.get("total", 0)))
    _format(legend.paragraphs[0], size=24, bold=True, after=2, keep=True)
    _paragraph(legend, "TOTAL FINDINGS", size=8, color=branding.PRINT_MUTED,
               bold=True, after=7, keep=True)
    _table(legend, ("Severity", "Findings", "Share"), [
        (row["label"], row["count"], f"{row['percent']}%") for row in report["severity_rows"]
    ], (42, 28, 30))
    for metric, title in (("assets", "Assets over time"), ("findings", "Findings over time")):
        document.add_heading(title, 2)
        chart = document.add_paragraph()
        _format(chart, size=1, after=2)
        chart.paragraph_format.keep_together = True
        add_trend_chart(chart, report.get("history") or [], metric=metric)
    _paragraph(document, "Charts end at this scan. To edit a chart, right-click it and choose Edit Data.",
               size=8, color=branding.PRINT_MUTED, after=0)


def _chart_data(document, report: dict) -> None:
    _section(document, "Chart data", "Appendix / History",
             "Editable values behind the charts, from the first saved snapshot through this scan. "
             "Later snapshots are never included.")
    history = report.get("history") or []
    if history:
        _table(document, ("Scan time", "Hosts", "Findings", "High severity", "Medium", "Low", "Open ports"), [
            (f"Scan {point.get('number', index)} · {point.get('scan_id', '')}\n"
             f"{format_time(point.get('started_at'))}", point["assets"], point["findings"], point["high"],
              point.get("medium", 0), point.get("low", 0), point.get("ports", 0))
            for index, point in enumerate(history, 1)
        ], (52, 18, 20, 21, 21, 21, 21))
    else:
        _callout(document, "No scan history yet.")


def _inventory(document, report: dict) -> None:
    _section(document, "Asset inventory", "07 / Inventory",
             "Every host saved in this scan, including assets with no findings.")
    if not report["assets"]:
        document.add_paragraph("No hosts were saved in this scan.")
        return
    _table(document, ("Host", "IP addresses", "Open ports", "Technologies", "Findings"), [
        (asset["host"], "\n".join(asset["ips"]) or "—",
         "\n".join(asset["ports"]) or "none recorded",
         "\n".join(asset["technologies"]) or "none detected",
         f"{asset['findings']} {asset['highest_label'] if asset['findings'] else ''}".strip())
        for asset in report["assets"]
    ], (40, 34, 36, 40, 24))


def _methodology(document, report: dict) -> None:
    _section(document, "Methodology and scope", "08 / Context")
    document.add_heading("What ExposureIQ checked", 2)
    for text in (
        "Passive subdomain discovery and DNS resolution (A and AAAA records).",
        "Front-page HTTP response: security headers and technology hints.",
        "HTTPS certificate: expiry, hostname coverage, and trust chain.",
        "Top-100 TCP ports on authorized IPv4 addresses, then offline risky-service rules.",
    ):
        document.add_paragraph(text, "List Bullet")
    document.add_heading("Scope and safety", 2)
    scope = ("DEMO: all hosts, ports, certificates and findings are simulated. No discovery, DNS, "
             "HTTP, TLS or port probes were sent. No exploitation was attempted."
             if report.get("demo") else
        "Active probes (HTTP, TLS, and ports) require authorized scope. Other hosts are "
        "discovered passively and skipped. ExposureIQ does not exploit a service, brute "
        "force a login, or crawl beyond the front page. Exporting this report sends no traffic."
    )
    document.add_paragraph(scope)
    document.add_heading("Severity levels", 2)
    for name, detail in report["severity_help"].items():
        document.add_paragraph(_text(f"{branding.SEVERITY_LABELS[name]}: {detail}"), "List Bullet")
    document.add_heading("About this report", 2)
    _table(document, ("Field", "Value"), [
        ("Target", report["target"]), ("Scan ID", report["scan_id"]),
        ("Scan started", report["started_label"]), ("Report generated", report["generated_label"]),
        ("Schema version", report["schema_version"]),
        ("ExposureIQ version", report.get("tool_version") or "0.1.0"),
    ])
    document.add_paragraph(
        "Point-in-time assessment. A clean result is not proof that the target is secure, "
        "and a finding is not proof of exploitability. Re-scan regularly and review changes."
    )


def render_docx(report: dict) -> bytes:
    """Return a complete DOCX file in memory; never read or write scan files."""
    if not isinstance(report, dict):
        raise ValueError("report must be a dictionary")
    document = Document()
    _setup(document, report)
    for section in (_cover, _findings, _changes, _overview, _inventory, _methodology, _chart_data):
        section(document, report)
    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()
