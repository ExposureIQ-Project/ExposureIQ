"""One palette for ExposureIQ's terminal, TUI, HTML, PDF, and SVG charts.

The logo is embedded as a small inline SVG instead of a file path, which keeps
the HTML report portable and the PDF independent of the repository layout.
"""

import re
import struct
import zlib
from functools import lru_cache

# Backgrounds and surfaces.
PAGE_BACKGROUND = "#0D141B"
GRADIENT_END = "#081116"
PANEL = "#0B1424"
INNER_SURFACE = "#111E2B"
TABLE_HEADER = "#1C303A"
HIGHLIGHT = "#203857"
FOOTER = "#182639"

# Brand accents.
TEAL = "#38E1C3"
BUTTON_FILL = "#20C9B3"
BUTTON_TEXT = "#09201E"
GLOW = "#20D4B7"
INDIGO = "#9297FF"

# Text on dark surfaces.
TEXT_PRIMARY = "#F1F6F3"
TEXT_SECONDARY = "#BED0CA"
TEXT_SUBTLE = "#A7B5BC"
MUTED = "#9BAEB0"
HINT = "#84949B"
TEXT_FAINT = "#7E9B94"
TEXT_DISABLED = "#78918E"

# Borders and dividers.
LINE = "#30514D"
BORDER_SOFT = "#365752"
DIVIDER = "#314247"
BORDER_MUTED = "#28403D"

# TUI design details; keep the existing report colours unchanged.
TUI_TABLE_HEADER = "#20323C"
TUI_BODY_TEXT = "#E6F0ED"
TUI_BREADCRUMB = "#819A97"
TUI_TAB_INACTIVE = "#9AABA9"
TUI_FOOTNOTE = "#89A39D"
TUI_LABEL = "#90A7A1"
TUI_KEY_HINT = "#ADC0BD"
TUI_PANEL_BORDER = "#304845"
TUI_TAB_DIVIDER = "#34494C"
TUI_ROW_DIVIDER = "#2B3E43"
TUI_DETAIL_DIVIDER = "#343E5C"
TUI_HIGH = "#FF7379"
DEMO_BACKGROUND = "#392D22"
DEMO_BORDER = "#8D6A35"
HIGH_BACKGROUND = "#3A222A"
MEDIUM_BACKGROUND = "#382E22"
LOW_BACKGROUND = "#1D2B3C"

# Keep the existing names available without maintaining another palette.
DARK = PAGE_BACKGROUND
SLATE = TEXT_SECONDARY
PAPER = INNER_SURFACE
WHITE = TEXT_PRIMARY
GREEN = TEAL

# White body pages remain unpainted in the PDF for printing. Use dark palette
# text on those pages; the bright accents belong in graphics and dark headers.
PRINT_PAGE = "#FFFFFF"
PRINT_SURFACE = TEXT_PRIMARY
PRINT_SECONDARY = DIVIDER
PRINT_MUTED = BORDER_SOFT
PRINT_ACCENT_TEXT = LINE

# Severity colours are intentionally different from the brand accents so a
# reader never confuses "high risk" with "ExposureIQ teal".
HIGH = "#FF6268"
AMBER = "#FFBB54"
LOW = "#83BBFF"
SEVERITY_COLORS = {
    "high": HIGH,
    "medium": AMBER,
    "low": LOW,
    "none": TEAL,
}

SEVERITY_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Clear",
}


def hex_to_rgb(value: str) -> tuple[float, float, float]:
    """Convert a six-digit hex colour to the PDF's 0–1 RGB channels."""
    if not isinstance(value, str) or re.fullmatch(r"#[0-9a-fA-F]{6}", value) is None:
        raise ValueError("colour must be a six-digit hex value")
    return tuple(int(value[index:index + 2], 16) / 255 for index in (1, 3, 5))


def css_rgba(value: str, opacity: float) -> str:
    """Reuse a palette colour in CSS without duplicating its RGB channels."""
    red, green, blue = (round(channel * 255) for channel in hex_to_rgb(value))
    return f"rgba({red}, {green}, {blue}, {opacity:g})"


# A system font stack: no web fonts, so the HTML works offline and in print.
FONT_STACK = (
    'Inter, "Segoe UI", Roboto, "Helvetica Neue", Arial, '
    '"Noto Sans", sans-serif'
)
MONO_STACK = '"SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace'

# The scan aperture mark from assets/branding/icon.svg. Shared geometry keeps
# HTML, the vector PDF, and the DOCX's embedded PNG on the same current brand.
LOGO_SIZE = 107
LOGO_RADIUS = 18
LOGO_FRAMES = (
    ((10, 34), (10, 10), (34, 10)),
    ((73, 10), (97, 10), (97, 34)),
    ((97, 73), (97, 97), (73, 97)),
    ((34, 97), (10, 97), (10, 73)),
)
LOGO_FRAME_WIDTH = 5
LOGO_CROSSBAR = ((30, 53.5), (77, 53.5))
LOGO_CROSSBAR_WIDTH = 3
LOGO_DOT = (53.5, 53.5, 9)

LOGO_SVG = (
    f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {LOGO_SIZE} {LOGO_SIZE}" '
    'role="img" aria-label="ExposureIQ scan aperture icon">'
    f'<rect width="{LOGO_SIZE}" height="{LOGO_SIZE}" rx="{LOGO_RADIUS}" fill="{PAGE_BACKGROUND}"/>'
    f'<g fill="none" stroke="{TEAL}" stroke-linecap="square" stroke-linejoin="miter">'
    '<path d="M10 34V10h24 M73 10h24v24 M97 73v24H73 M34 97H10V73" stroke-width="5"/>'
    '<path d="M30 53.5h47" stroke-width="3"/></g>'
    f'<circle cx="53.5" cy="53.5" r="9" fill="{TEAL}"/>'
    "</svg>"
)


@lru_cache(maxsize=4)
def logo_png(size: int = 214) -> bytes:
    """A small embedded Word-compatible icon, drawn without image dependencies."""
    if isinstance(size, bool) or not isinstance(size, int) or not 16 <= size <= 1024:
        raise ValueError("logo size must be an integer from 16 to 1024")
    dark = bytes(round(channel * 255) for channel in hex_to_rgb(PAGE_BACKGROUND))
    teal = bytes(round(channel * 255) for channel in hex_to_rgb(TEAL))
    segments = [(start, end, LOGO_FRAME_WIDTH / 2)
                for frame in LOGO_FRAMES for start, end in zip(frame, frame[1:])]
    segments.append((*LOGO_CROSSBAR, LOGO_CROSSBAR_WIDTH / 2))
    rows = bytearray()
    for row in range(size):
        rows.append(0)  # PNG's unfiltered scanline marker.
        y = (row + .5) * LOGO_SIZE / size
        for column in range(size):
            x = (column + .5) * LOGO_SIZE / size
            corner_x = min(max(x, LOGO_RADIUS), LOGO_SIZE - LOGO_RADIUS)
            corner_y = min(max(y, LOGO_RADIUS), LOGO_SIZE - LOGO_RADIUS)
            if (x - corner_x) ** 2 + (y - corner_y) ** 2 > LOGO_RADIUS ** 2:
                rows.extend(b"\x00\x00\x00\x00")
                continue
            cx, cy, radius = LOGO_DOT
            marked = (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2 or any(
                min(start[0], end[0]) - half <= x <= max(start[0], end[0]) + half
                and min(start[1], end[1]) - half <= y <= max(start[1], end[1]) + half
                for start, end, half in segments
            )
            rows.extend((teal if marked else dark) + b"\xff")

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data)))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b""))
