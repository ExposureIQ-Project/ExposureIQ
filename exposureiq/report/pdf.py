"""A tiny, dependency-free PDF writer for ExposureIQ reports.

The project does not require WeasyPrint, ReportLab, or a headless browser. This
module writes a normal PDF 1.4 file with the built-in Helvetica fonts, vector
charts, coloured tables, and page numbers. It is intentionally small: it only
implements the operators this report needs.
"""

from __future__ import annotations

import math

from exposureiq.report import branding
from exposureiq.report.branding import hex_to_rgb as _rgb

PAGE_WIDTH = 595.276
PAGE_HEIGHT = 841.89
MARGIN = 42.0
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN
BOTTOM = PAGE_HEIGHT - 54

# Helvetica and Helvetica-Bold advance widths for ASCII 32..126 (units / 1000).
_REGULAR_WIDTHS = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
    278, 278, 584, 584, 584, 556, 1015,
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667,
    778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
    278, 278, 278, 469, 556, 333,
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556,
    556, 333, 500, 278, 556, 500, 722, 500, 500, 500,
    334, 260, 334, 584,
)
_BOLD_WIDTHS = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
    333, 333, 584, 584, 584, 611, 975,
    722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667,
    778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
    333, 278, 333, 584, 556, 333,
    556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611,
    611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
    389, 280, 389, 584,
)


def _clean(text) -> str:
    """Keep text inside WinAnsi so the built-in fonts can draw it."""
    text = "" if text is None else str(text)
    text = text.replace("\r", " ").replace("\n", " ")
    return text.encode("cp1252", "replace").decode("cp1252")


def _escape(text: str) -> str:
    return _clean(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def measure(text: str, size: float, bold: bool = False) -> float:
    widths = _BOLD_WIDTHS if bold else _REGULAR_WIDTHS
    total = 0
    for character in _clean(text):
        code = ord(character)
        total += widths[code - 32] if 32 <= code <= 126 else 556
    return total * size / 1000


def wrap(text, width: float, size: float, bold: bool = False) -> list[str]:
    """Wrap one paragraph to ``width`` points, breaking very long words."""
    lines = []
    for paragraph in _clean(text).split("\n"):
        words = paragraph.split()
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if measure(candidate, size, bold) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while measure(word, size, bold) > width and len(word) > 1:
                cut = len(word)
                while cut > 1 and measure(word[:cut], size, bold) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines or [""]


class PdfDocument:
    """Collect page content streams and serialise them as PDF 1.4."""

    def __init__(self):
        self.pages: list[list[str]] = []

    def add_page(self) -> list[str]:
        content: list[str] = []
        self.pages.append(content)
        return content

    def to_bytes(self) -> bytes:
        if not self.pages:
            self.add_page()
        objects: list[str | None] = [None]  # object 0 is the free entry

        def add(value: str) -> int:
            objects.append(value)
            return len(objects) - 1

        catalog = add("<< /Type /Catalog /Pages 2 0 R >>")
        pages_id = add("")  # filled after the page objects exist
        font_regular = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                           "/Encoding /WinAnsiEncoding >>")
        font_bold = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                        "/Encoding /WinAnsiEncoding >>")

        page_ids = []
        for content in self.pages:
            stream = "\n".join(content).encode("cp1252", "replace")
            content_id = add(f"<< /Length {len(stream)} >>\nstream\n"
                             f"{stream.decode('cp1252')}\nendstream")
            page_id = add(
                f"<< /Type /Page /Parent {pages_id} 0 R "
                f"/MediaBox [0 0 {PAGE_WIDTH:.3f} {PAGE_HEIGHT:.3f}] "
                f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            )
            page_ids.append(page_id)

        objects[pages_id] = (
            f"<< /Type /Pages /Kids [{' '.join(f'{page} 0 R' for page in page_ids)}] "
            f"/Count {len(page_ids)} >>"
        )

        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, value in enumerate(objects[1:], start=1):
            offsets.append(len(output))
            output += f"{number} 0 obj\n{value}\nendobj\n".encode("cp1252", "replace")

        xref = len(output)
        output += f"xref\n0 {len(objects)}\n".encode("ascii")
        output += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            output += f"{offset:010d} 00000 n \n".encode("ascii")
        output += (
            f"trailer\n<< /Size {len(objects)} /Root {catalog} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
        return bytes(output)


class ReportPdf:
    """Lay out one report model on A4 pages."""

    def __init__(self, report: dict):
        if not isinstance(report, dict):
            raise ValueError("report must be a dictionary")
        self.report = report
        self.doc = PdfDocument()
        self.content: list[str] = []
        self.y = MARGIN  # distance from the top of the page to the next baseline

    # ------------------------------------------------------------------ text
    def _op(self, value: str) -> None:
        self.content.append(value)

    def text(self, x: float, top: float, value, size: float = 10, bold: bool = False,
             color: str = branding.DARK, align: str = "left", width: float | None = None) -> None:
        value = _clean(value)
        if align != "left" and width is not None:
            used = measure(value, size, bold)
            x = x + width - used if align == "right" else x + (width - used) / 2
        red, green, blue = _rgb(color)
        self._op(
            f"BT /{'F2' if bold else 'F1'} {size:.2f} Tf "
            f"{red:.3f} {green:.3f} {blue:.3f} rg "
            f"{x:.2f} {PAGE_HEIGHT - top:.2f} Td ({_escape(value)}) Tj ET"
        )

    def wrapped(self, value, x: float = MARGIN, width: float = CONTENT_WIDTH,
                size: float = 9.5, leading: float = 13, color: str = branding.PRINT_SECONDARY,
                bold: bool = False) -> None:
        for line in wrap(value, width, size, bold):
            self.text(x, self.y, line, size, bold, color)
            self.y += leading

    def rect(self, x: float, top: float, width: float, height: float, color: str) -> None:
        red, green, blue = _rgb(color)
        self._op(f"{red:.3f} {green:.3f} {blue:.3f} rg "
                 f"{x:.2f} {PAGE_HEIGHT - top - height:.2f} {width:.2f} {height:.2f} re f")

    def line(self, x1: float, top1: float, x2: float, top2: float,
             color: str = branding.LINE, thickness: float = 0.8) -> None:
        red, green, blue = _rgb(color)
        self._op(f"{red:.3f} {green:.3f} {blue:.3f} RG {thickness:.2f} w "
                 f"{x1:.2f} {PAGE_HEIGHT - top1:.2f} m "
                 f"{x2:.2f} {PAGE_HEIGHT - top2:.2f} l S")

    # ----------------------------------------------------------------- pages
    def new_page(self, header: bool = True) -> None:
        self.content = self.doc.add_page()
        if header:
            self._logo(MARGIN, 24, 20)
            self.text(MARGIN + 26, 39, "Exposure", 11, True, branding.DARK)
            self.text(MARGIN + 26 + measure("Exposure", 11, True), 39, "IQ", 11, True,
                      branding.PRINT_ACCENT_TEXT)
            self.text(MARGIN, 39, self.report.get("target", ""), 8, False,
                      branding.PRINT_MUTED, align="right", width=CONTENT_WIDTH)
            self.line(MARGIN, 50, PAGE_WIDTH - MARGIN, 50, branding.LINE, 0.8)
            self.y = 76
        else:
            self.y = 0

    def ensure(self, height: float, header: bool = True) -> None:
        if self.y + height > BOTTOM:
            self.new_page(header=header)

    def heading(self, title: str, kicker: str | None = None) -> None:
        if kicker:
            self.text(MARGIN, self.y, kicker.upper(), 8, True, branding.PRINT_ACCENT_TEXT)
            self.y += 16
        self.text(MARGIN, self.y, title, 20, True, branding.DARK)
        self.y += 14
        self.rect(MARGIN, self.y, 46, 3, branding.TEAL)
        self.y += 14

    def lede(self, text: str) -> None:
        self.wrapped(text, size=9.5, leading=13.5, color=branding.PRINT_MUTED)
        self.y += 10

    def subheading(self, text: str) -> None:
        self.ensure(34)
        self.text(MARGIN, self.y, text.upper(), 8.5, True, branding.PRINT_SECONDARY)
        self.y += 15

    def bullet(self, text: str, color: str = branding.PRINT_SECONDARY, size: float = 9) -> None:
        lines = wrap(text, CONTENT_WIDTH - 14, size)
        self.ensure(len(lines) * 12 + 4)
        self.text(MARGIN, self.y, "\u2022", size + 1, True, branding.PRINT_ACCENT_TEXT)
        for line in lines:
            self.text(MARGIN + 12, self.y, line, size, False, color)
            self.y += 12

    # ------------------------------------------------------------------ logo
    def _logo(self, x: float, top: float, size: float) -> None:
        scale = size / branding.LOGO_SIZE

        def point(px: float, py: float) -> str:
            return f"{x + px * scale:.2f} {PAGE_HEIGHT - top - py * scale:.2f}"

        self._op("q")
        radius, edge = branding.LOGO_RADIUS, branding.LOGO_SIZE
        bend = radius * .5522847498
        self._op(f"{_fmt_rgb(branding.PAGE_BACKGROUND)} rg {point(radius, 0)} m {point(edge - radius, 0)} l")
        self._op(f"{point(edge - radius + bend, 0)} {point(edge, radius - bend)} {point(edge, radius)} c")
        self._op(f"{point(edge, edge - radius)} l")
        self._op(f"{point(edge, edge - radius + bend)} {point(edge - radius + bend, edge)} {point(edge - radius, edge)} c")
        self._op(f"{point(radius, edge)} l")
        self._op(f"{point(radius - bend, edge)} {point(0, edge - radius + bend)} {point(0, edge - radius)} c")
        self._op(f"{point(0, radius)} l {point(0, radius - bend)} {point(radius - bend, 0)} {point(radius, 0)} c h f")
        self._op(f"{_fmt_rgb(branding.TEAL)} RG 2 J 0 j {branding.LOGO_FRAME_WIDTH * scale:.2f} w")
        for frame in branding.LOGO_FRAMES:
            for index, (px, py) in enumerate(frame):
                self._op(f"{point(px, py)} {'m' if index == 0 else 'l'}")
            self._op("S")
        self._op(f"{branding.LOGO_CROSSBAR_WIDTH * scale:.2f} w")
        for index, (px, py) in enumerate(branding.LOGO_CROSSBAR):
            self._op(f"{point(px, py)} {'m' if index == 0 else 'l'}")
        self._op("S")
        cx, cy, radius = branding.LOGO_DOT
        self._circle(x + cx * scale, top + cy * scale, radius * scale, branding.TEAL)
        self._op("Q")

    def _circle(self, cx: float, top: float, radius: float, color: str) -> None:
        red, green, blue = _rgb(color)
        k = 0.5523 * radius
        y = PAGE_HEIGHT - top
        self._op(
            f"{red:.3f} {green:.3f} {blue:.3f} rg "
            f"{cx + radius:.2f} {y:.2f} m "
            f"{cx + radius:.2f} {y + k:.2f} {cx + k:.2f} {y + radius:.2f} {cx:.2f} {y + radius:.2f} c "
            f"{cx - k:.2f} {y + radius:.2f} {cx - radius:.2f} {y + k:.2f} {cx - radius:.2f} {y:.2f} c "
            f"{cx - radius:.2f} {y - k:.2f} {cx - k:.2f} {y - radius:.2f} {cx:.2f} {y - radius:.2f} c "
            f"{cx + k:.2f} {y - radius:.2f} {cx + radius:.2f} {y - k:.2f} {cx + radius:.2f} {y:.2f} c f"
        )

    # ----------------------------------------------------------------- cover
    def cover(self) -> None:
        self.new_page(header=False)
        report = self.report
        self.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, branding.DARK)
        self.rect(0, 0, 9, PAGE_HEIGHT, branding.TEAL)
        self._logo(MARGIN, 52, 46)
        self.text(MARGIN + 56, 74, "Exposure", 18, True, branding.TEXT_PRIMARY)
        self.text(MARGIN + 56 + measure("Exposure", 18, True), 74, "IQ", 18, True,
                  branding.TEAL)
        self.text(MARGIN + 56, 89, "ATTACK SURFACE MANAGEMENT", 7, False, branding.TEXT_SUBTLE)

        self.text(MARGIN, 165, (report.get("title") or "Security Assessment Report").upper(),
                  8.5, True, branding.TEAL)
        self.text(MARGIN, 205, report.get("target", ""), 34, True, branding.TEXT_PRIMARY)
        self.text(MARGIN, 232, f"Scan {report.get('scan_id', '')}  \u00b7  "
                  f"{report.get('started_label', '')}", 9, False, branding.TEXT_SUBTLE)

        risk = report.get("risk") or {}
        self.rect(MARGIN, 250, 104, 20, risk.get("color", branding.TEAL))
        self.text(MARGIN, 264, risk.get("label", "").upper(), 8, True, branding.DARK,
                  align="center", width=104)

        self.text(MARGIN, 304, "EXECUTIVE SUMMARY", 8.5, True, branding.TEAL)
        self.y = 320
        for paragraph in report.get("executive_summary") or []:
            self.wrapped(paragraph, width=CONTENT_WIDTH - 16, size=9.5, leading=13.5,
                         color=branding.TEXT_SECONDARY)
            self.y += 5

        counts = report.get("severity") or {}
        cards = (
            ("high", counts.get("high", 0), branding.SEVERITY_COLORS["high"]),
            ("medium", counts.get("medium", 0), branding.SEVERITY_COLORS["medium"]),
            ("low", counts.get("low", 0), branding.SEVERITY_COLORS["low"]),
            ("total", counts.get("total", 0), branding.TEAL),
        )
        gap = 10
        width = (CONTENT_WIDTH - gap * 3) / 4
        top = max(610, self.y + 16)
        for index, (name, value, color) in enumerate(cards):
            x = MARGIN + index * (width + gap)
            self.rect(x, top, width, 64, branding.INNER_SURFACE)
            self.rect(x, top, 3, 64, color)
            self.text(x + 12, top + 30, str(value), 24, True, color)
            label = "TOTAL FINDINGS" if name == "total" else f"{name.upper()} SEVERITY"
            self.text(x + 12, top + 47, label, 6.5, True, branding.TEXT_SUBTLE)

        self.line(MARGIN, 792, PAGE_WIDTH - MARGIN, 792, branding.LINE, 0.8)
        self.text(MARGIN, 806, "CONFIDENTIAL  \u00b7  Prepared for the owner of "
                  f"{report.get('target', '')}", 7, False, branding.MUTED)
        self.text(MARGIN, 806, f"Generated {report.get('generated_label', '')}", 7,
                  False, branding.MUTED, align="right", width=CONTENT_WIDTH)

    # -------------------------------------------------------------- findings
    def findings(self) -> None:
        self.new_page()
        self.heading("Findings", "04 / Results")
        self.lede("Ordered by severity, then by asset. Each row names the evidence "
                  "ExposureIQ collected and the recommended next step.")
        findings = self.report.get("findings") or []
        if not findings:
            self._empty_box("No findings were recorded. The checks that ran did not see "
                            "a problem; this is not proof that the target is secure.")
            return
        widths = (52, 94, 206, 159)
        self._table_header(("Severity", "Asset", "Finding and evidence", "Recommendation"),
                           widths)
        for index, finding in enumerate(findings):
            self._finding_row(finding, widths, index)

    def _table_header(self, headers: tuple, widths: tuple) -> None:
        height = 22
        self.rect(MARGIN, self.y, CONTENT_WIDTH, height, branding.TABLE_HEADER)
        x = MARGIN
        for header, width in zip(headers, widths):
            self.text(x + 4, self.y + 14, header.upper(), 7, True, branding.TEXT_PRIMARY)
            x += width
        self.y += height

    def _finding_row(self, finding: dict, widths: tuple, index: int) -> None:
        x_sev, x_asset, x_find, x_rec = (
            MARGIN, MARGIN + widths[0], MARGIN + widths[0] + widths[1],
            MARGIN + sum(widths[:3]))
        title_lines = wrap(finding.get("title") or "", widths[2] - 10, 8.5, True)
        detail_lines = wrap(finding.get("detail") or "", widths[2] - 10, 8)
        rec_lines = wrap(finding.get("recommendation") or "", widths[3] - 10, 8)
        # Keep one table row on one page. Real findings are short; this guard
        # stops a pathological detail from spilling over the page footer.
        if len(title_lines) > 4:
            title_lines = title_lines[:3] + ["... (truncated)"]
        if len(detail_lines) > 14:
            detail_lines = detail_lines[:13] + ["... (truncated)"]
        if len(rec_lines) > 10:
            rec_lines = rec_lines[:9] + ["... (truncated)"]
        title_h = len(title_lines) * 9.5
        detail_h = len(detail_lines) * 9.5
        row_height = max(11 + title_h + detail_h + 12, 11 + len(rec_lines) * 9.5 + 8, 36)

        if self.y + row_height > BOTTOM:
            self.new_page()
            self._table_header(("Severity", "Asset", "Finding and evidence", "Recommendation"),
                               widths)
        if index % 2 == 1:
            self.rect(MARGIN, self.y, CONTENT_WIDTH, row_height, branding.PRINT_SURFACE)

        severity = finding.get("severity", "low")
        color = branding.SEVERITY_COLORS.get(severity, branding.SEVERITY_COLORS["low"])
        label = branding.SEVERITY_LABELS.get(severity, severity.title()).upper()
        self.rect(x_sev + 4, self.y + 7, 42, 13, color)
        self.text(x_sev + 4, self.y + 17, label, 6.2, True, branding.DARK,
                  align="center", width=42)
        self.text(x_sev + 4, self.y + 31, finding.get("id") or "", 6.5, False,
                  branding.PRINT_MUTED)

        self.text(x_asset + 4, self.y + 15, finding.get("host") or "", 8.5, True,
                  branding.DARK)
        endpoint = ""
        if finding.get("ip"):
            endpoint = finding["ip"] + (f":{finding['port']}" if finding.get("port") else "")
        if endpoint:
            self.text(x_asset + 4, self.y + 26, endpoint, 7, False, branding.PRINT_MUTED)

        cursor = self.y + 12
        for line in title_lines:
            self.text(x_find + 4, cursor, line, 8.5, True, branding.DARK)
            cursor += 9.5
        for line in detail_lines:
            self.text(x_find + 4, cursor, line, 8, False, branding.PRINT_SECONDARY)
            cursor += 9.5
        self.text(x_find + 4, cursor + 1, finding.get("rule") or "", 6.5, False,
                  branding.PRINT_MUTED)

        cursor = self.y + 12
        for line in rec_lines:
            self.text(x_rec + 4, cursor, line, 8, False, branding.PRINT_SECONDARY)
            cursor += 9.5

        self.y += row_height
        self.line(MARGIN, self.y, PAGE_WIDTH - MARGIN, self.y, branding.LINE, 0.5)

    def _empty_box(self, text: str) -> None:
        lines = wrap(text, CONTENT_WIDTH - 28, 9.5)
        height = max(44, len(lines) * 13 + 24)
        self.ensure(height)
        self.rect(MARGIN, self.y, CONTENT_WIDTH, height, branding.PRINT_SURFACE)
        self.rect(MARGIN, self.y, 4, height, branding.TEAL)
        cursor = self.y + 18
        for line in lines:
            self.text(MARGIN + 16, cursor, line, 9.5, False, branding.PRINT_SECONDARY)
            cursor += 13
        self.y += height + 10

    # ----------------------------------------------------------- what changed
    def what_changed(self) -> None:
        self.new_page()
        self.heading("What changed", "05 / Change")
        self.lede("Security-relevant differences between saved scans. Removals are "
                  "only called confirmed when a later scan agrees.")
        diff = self.report.get("diff")
        if not diff:
            message = ("Change comparisons were disabled for this export. Enable comparisons "
                       "when exporting to see what changed." if not self.report.get("comparison_enabled", True) else
                       "No earlier saved scan was found. This report describes the "
                       "current exposure only. Run another scan of the same target and "
                       "generate the report again to see what changed.")
            self._empty_box(message)
            return

        summary = self.report.get("diff_summary") or {}
        self.subheading("Overall change since baseline")
        headline = summary.get("headline") or "Saved scan changes compared"
        self.text(MARGIN, self.y + 6, headline, 15, True, branding.DARK)
        self.y += 26

        counts = summary.get("counts") or {}
        labels = (("worse", counts.get("worse", 0), branding.SEVERITY_COLORS["high"]),
                  ("better", counts.get("better", 0), branding.GREEN),
                  ("neutral", counts.get("neutral", 0), branding.SLATE))
        gap = 10
        width = (CONTENT_WIDTH - gap * 2) / 3
        for index, (name, value, color) in enumerate(labels):
            x = MARGIN + index * (width + gap)
            self.rect(x, self.y, width, 50, branding.INNER_SURFACE)
            self.rect(x, self.y, 3, 50, color)
            self.text(x + 12, self.y + 24, str(value), 19, True, color)
            self.text(x + 12, self.y + 39, name.upper(), 7, True, branding.MUTED)
        self.y += 64

        highlights = summary.get("highlights") or []
        if highlights:
            self.subheading("Highlights")
            for item in highlights:
                self.bullet(item, color=branding.DARK, size=9)
            self.y += 4

        lines = summary.get("lines") or []
        if lines:
            self.subheading("All changes")
            for item in lines:
                self.bullet(item, size=8.5)
            self.y += 4

        notes = diff.get("notes") or []
        if notes:
            self.subheading("Notes")
            for note in notes:
                self.bullet(note, size=8.5, color=branding.PRINT_MUTED)

        old = diff.get("old") or {}
        new = diff.get("new") or {}
        self.y += 4
        self.wrapped(f"Compared scan {old.get('scan_id', '?')} ({old.get('started_at', '?')}) "
                     f"with {new.get('scan_id', '?')} ({new.get('started_at', '?')}).",
                      size=8, color=branding.PRINT_MUTED)
        steps = diff.get("history") or []
        if steps:
            self.y += 8
            self.subheading("Scan-by-scan history")
            self.wrapped("Overall counts above are net changes. These steps retain temporary "
                         "issues and fixes through the selected scan, without later snapshots.",
                         size=8.5, color=branding.PRINT_MUTED)
            for step in steps:
                old, new = step.get("old") or {}, step.get("new") or {}
                summary = step.get("summary") or {}
                self.y += 8
                self.ensure(68)
                self.subheading(f"{old.get('scan_id', '?')} -> {new.get('scan_id', '?')}")
                self.wrapped(f"{old.get('started_at', '?')} -> {new.get('started_at', '?')}",
                             size=8, color=branding.PRINT_MUTED)
                self.wrapped(summary.get("headline") or "No changes", size=9)
                for line in summary.get("lines") or []:
                    self.bullet(line, size=8.5)
                for note in step.get("notes") or []:
                    self.bullet(f"Note: {note}", size=8, color=branding.PRINT_MUTED)

    # ---------------------------------------------------------------- charts
    def charts(self) -> None:
        self.new_page()
        self.heading("Exposure at a glance", "06 / Charts")
        self.lede("The severity mix shows where attention is needed. The trend shows how "
                  "hosts and findings changed from the first saved scan through this scan.")
        counts = self.report.get("severity") or {}
        self._donut(MARGIN + 90, 250, 66, 22, counts)

        legend_x = MARGIN + 210
        self.text(legend_x, 200, "FINDINGS BY SEVERITY", 8, True, branding.PRINT_SECONDARY)
        cursor = 224
        total = counts.get("total") or 0
        for name in ("high", "medium", "low"):
            value = counts.get(name, 0)
            color = branding.SEVERITY_COLORS[name]
            self.rect(legend_x, cursor - 8, 9, 9, color)
            self.text(legend_x + 16, cursor, branding.SEVERITY_LABELS[name], 9, False,
                      branding.DARK)
            percent = round(value * 100 / total) if total else 0
            finding_word = "finding" if value == 1 else "findings"
            self.text(legend_x + 16, cursor + 14, f"{value} {finding_word} \u00b7 {percent}%",
                      8, False, branding.PRINT_MUTED)
            cursor += 34

        self._line_chart(self.report.get("history") or [], MARGIN, 350, CONTENT_WIDTH, 155)
        self._line_chart(self.report.get("history") or [], MARGIN, 560, CONTENT_WIDTH, 155,
                         metric="findings")
        self.text(MARGIN, 755, f"{len(self.report.get('history') or [])} saved scan(s) through "
                  "the selected scan. No later snapshots are included.", 8, False, branding.PRINT_MUTED)

    def _donut(self, cx: float, top: float, radius: float, thickness: float,
               counts: dict) -> None:
        total = counts.get("total") or 0
        # Background ring.
        self._ring(cx, top, radius, thickness, branding.LINE, 0.0, 360.0)
        start = 0.0
        for name in ("high", "medium", "low"):
            value = counts.get(name, 0)
            if not value or not total:
                continue
            sweep = 360.0 * value / total
            self._ring(cx, top, radius, thickness, branding.SEVERITY_COLORS[name],
                       start, start + sweep)
            start += sweep
        self.text(cx, top + 3, str(total), 26, True, branding.DARK, align="center", width=0)
        self.text(cx, top + 18, "FINDINGS", 7, True, branding.PRINT_MUTED, align="center", width=0)

    def _ring(self, cx: float, top: float, radius: float, thickness: float, color: str,
              start: float, end: float) -> None:
        red, green, blue = _rgb(color)
        steps = max(2, int(abs(end - start) / 3))
        self._op(f"{red:.3f} {green:.3f} {blue:.3f} RG {thickness:.2f} w 1 J")
        first = True
        for index in range(steps + 1):
            angle = math.radians(start + (end - start) * index / steps)
            x = cx + radius * math.sin(angle)
            y = PAGE_HEIGHT - top - radius * math.cos(angle)
            self._op(f"{x:.2f} {y:.2f} {'m' if first else 'l'}")
            first = False
        self._op("S")

    def _line_chart(self, points: list, x: float, top: float, width: float,
                     height: float, *, metric: str = "assets") -> None:
        left, right, bottom = 34, 10, 26
        plot_width = width - left - right
        plot_height = height - bottom - 10
        values = [int(point.get(metric) or 0) for point in points]
        maximum = max(values) if values else 0
        maximum = max(1, math.ceil(maximum / 4)) * 4

        self.text(x + left, top - 2, "FINDINGS OVER TIME" if metric == "findings" else "ASSETS OVER TIME",
                  8, True, branding.PRINT_SECONDARY)
        if metric == "findings":
            self.rect(x + width - 178, top - 9, 12, 2, branding.INDIGO)
            self.text(x + width - 160, top - 2, "All findings", 7, False, branding.PRINT_SECONDARY)
            self.rect(x + width - 97, top - 9, 12, 2, branding.HIGH)
            self.text(x + width - 79, top - 2, "High (dashed)", 7, False, branding.PRINT_SECONDARY)
        for step in range(5):
            value = maximum * step / 4
            line_top = top + 16 + plot_height - plot_height * step / 4
            self.line(x + left, line_top, x + left + plot_width, line_top,
                      branding.LINE, 0.6)
            self.text(x + left - 6, line_top + 3, f"{value:.0f}", 7, False,
                      branding.PRINT_MUTED, align="right", width=0)

        if not points:
            self.text(x + left + plot_width / 2, top + 70, "No scan history yet", 9, False,
                      branding.PRINT_MUTED, align="center", width=0)
            return

        count = len(points)
        if count == 1:
            xs = [x + left + plot_width / 2]
        else:
            xs = [x + left + plot_width * index / (count - 1) for index in range(count)]
        ys = [top + 16 + plot_height - plot_height * value / maximum for value in values]

        color = branding.INDIGO if metric == "findings" else branding.TEAL

        def series(positions: list, color: str, dashed: bool = False):
            self._op(f"q {_fmt_rgb(color)} RG 2.2 w 1 J " + ("[4 3] 0 d" if dashed else "[] 0 d"))
            for index, (px, py) in enumerate(zip(xs, positions)):
                self._op(f"{px:.2f} {PAGE_HEIGHT - py:.2f} {'m' if index == 0 else 'l'}")
            self._op("S Q")

        series(ys, color)
        if metric == "findings":
            high_ys = [top + 16 + plot_height - plot_height * int(point.get("high") or 0) / maximum
                       for point in points]
            series(high_ys, branding.HIGH, dashed=True)
        for px, py in zip(xs, ys):
            self._circle(px, py, 3.2, branding.PRINT_SURFACE)
            self._ring(px, py, 3.2, 1.4, color, 0, 360)

        step = max(1, math.ceil(count / 8))
        for index, (px, point) in enumerate(zip(xs, points)):
            if index % step == 0 or index == count - 1:
                self.text(px, top + 16 + plot_height + 16, point.get("label") or "?", 7,
                          False, branding.PRINT_MUTED, align="center", width=0)
        self.text(x + left + plot_width / 2, top + height + 12, "SCAN DATE", 7, True,
                  branding.PRINT_MUTED, align="center", width=0)

    # ------------------------------------------------------------- inventory
    def inventory(self) -> None:
        self.new_page()
        self.heading("Asset inventory", "07 / Inventory")
        self.lede("What the scan found, including hosts with no recorded findings.")
        assets = self.report.get("assets") or []
        if not assets:
            self._empty_box("No hosts were saved in this scan.")
            return
        widths = (118, 118, 112, 104, 59)
        self._table_header(("Host", "IP addresses", "Open ports", "Technologies", "Findings"),
                           widths)
        for index, asset in enumerate(assets):
            finding_count = asset.get("findings", 0)
            highest = asset.get("highest_label") or ""
            finding_label = str(finding_count) if not finding_count else f"{finding_count} {highest}"
            values = (
                asset.get("host") or "",
                "\n".join(asset.get("ips") or []) or "\u2014",
                "\n".join(asset.get("ports") or []) or "none recorded",
                "\n".join(asset.get("technologies") or []) or "none detected",
                finding_label.strip(),
            )
            wrapped = [wrap(value, width - 8, 7.5) for value, width in zip(values, widths)]
            row_height = max(len(lines) for lines in wrapped) * 9.5 + 12
            if self.y + row_height > BOTTOM:
                self.new_page()
                self._table_header(("Host", "IP addresses", "Open ports", "Technologies",
                                    "Findings"), widths)
            if index % 2 == 1:
                self.rect(MARGIN, self.y, CONTENT_WIDTH, row_height, branding.PRINT_SURFACE)
            x = MARGIN
            for column, (lines, width) in enumerate(zip(wrapped, widths)):
                for line_index, line in enumerate(lines):
                    self.text(x + 4, self.y + 13 + line_index * 9.5, line, 7.5,
                              column == 0, branding.DARK if column == 0 else branding.PRINT_SECONDARY)
                x += width
            self.y += row_height
            self.line(MARGIN, self.y, PAGE_WIDTH - MARGIN, self.y, branding.LINE, 0.5)

    # ----------------------------------------------------------- methodology
    def methodology(self) -> None:
        self.new_page()
        self.heading("Methodology and scope", "08 / About")
        self.subheading("What ExposureIQ checked")
        for item in (
            "Passive subdomain discovery and DNS resolution (A and AAAA records).",
            "Front-page HTTP response: security headers and technology hints.",
            "HTTPS certificate: expiry, hostname coverage, and trust chain.",
            "Top-100 TCP ports on authorized IPv4 addresses, then offline risky-service rules.",
        ):
            self.bullet(item)

        self.subheading("Scope and safety")
        scope = ("DEMO: all hosts, ports, certificates and findings are simulated. No discovery, DNS, "
                 "HTTP, TLS or port probes were sent. No exploitation was attempted."
                 if self.report.get("demo") else
                     "Active probes (HTTP, TLS, and ports) were sent only to hosts "
                      "authorized in scope.txt. Other hosts were discovered passively and "
                      "skipped. ExposureIQ does not exploit a service, brute force a login, "
                      "or crawl beyond the front page. A finding is evidence, not proof of "
                      "a vulnerability.")
        self.wrapped(scope, size=9, leading=13)
        self.y += 8

        self.subheading("Severity levels")
        for name in ("high", "medium", "low"):
            color = branding.SEVERITY_COLORS[name]
            label = branding.SEVERITY_LABELS[name].upper()
            self.ensure(20)
            self.rect(MARGIN, self.y - 8, 46, 12, color)
            self.text(MARGIN, self.y + 1, label, 6.5, True, branding.DARK, align="center",
                      width=46)
            self.text(MARGIN + 54, self.y, self.report["severity_help"][name], 8.5,
                      False, branding.PRINT_SECONDARY)
            self.y += 20
        self.y += 6

        self.subheading("About this report")
        details = (
            ("Target", self.report.get("target", "")),
            ("Scan ID", self.report.get("scan_id", "")),
            ("Scan started", self.report.get("started_label", "")),
            ("Report generated", self.report.get("generated_label", "")),
            ("Schema version", self.report.get("schema_version", "")),
            ("ExposureIQ version", self.report.get("tool_version") or "0.1.0"),
        )
        for label, value in details:
            self.ensure(18)
            self.text(MARGIN, self.y, label, 8.5, True, branding.PRINT_SECONDARY)
            self.text(MARGIN + 120, self.y, value, 8.5, False, branding.DARK)
            self.y += 16

        self.y += 10
        self.ensure(84)
        box_top = self.y
        self.rect(MARGIN, box_top, CONTENT_WIDTH, 76, branding.PRINT_SURFACE)
        self.rect(MARGIN, box_top, 4, 76, branding.AMBER)
        self.text(MARGIN + 14, box_top + 18, "POINT-IN-TIME ASSESSMENT", 8, True,
                  branding.PRINT_ACCENT_TEXT)
        self.y = box_top + 30
        self.wrapped("This report describes the state seen during one scan. A clean "
                     "result is not proof that the target is secure, and a finding is not "
                     "proof of exploitability. Re-scan regularly and review changes.",
                     x=MARGIN + 14, width=CONTENT_WIDTH - 28, size=8.5, leading=12,
                     color=branding.PRINT_SECONDARY)
        self.y = box_top + 84

    # ---------------------------------------------------------------- finish
    def footer(self) -> None:
        total = len(self.doc.pages)
        for index, page in enumerate(self.doc.pages):
            if index == 0:
                continue
            self.content = page
            self.line(MARGIN, PAGE_HEIGHT - 40, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 40,
                      branding.LINE, 0.6)
            self.text(MARGIN, PAGE_HEIGHT - 28,
                      "ExposureIQ  \u00b7  Confidential  \u00b7  "
                      f"{self.report.get('target', '')}", 7, False, branding.PRINT_MUTED)
            self.text(MARGIN, PAGE_HEIGHT - 28, f"Page {index + 1} of {total}", 7, False,
                      branding.PRINT_MUTED, align="right", width=CONTENT_WIDTH)

    def build(self) -> bytes:
        self.cover()
        self.findings()
        self.what_changed()
        self.charts()
        self.inventory()
        self.methodology()
        self.footer()
        return self.doc.to_bytes()


def _fmt_rgb(color: str) -> str:
    red, green, blue = _rgb(color)
    return f"{red:.3f} {green:.3f} {blue:.3f}"


def render_pdf(report: dict) -> bytes:
    """Return a complete PDF file for one report model."""
    return ReportPdf(report).build()
