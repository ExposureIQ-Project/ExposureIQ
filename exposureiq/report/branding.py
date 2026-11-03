"""One palette for ExposureIQ's terminal, TUI, HTML, PDF, and SVG charts.

The logo is embedded as a small inline SVG instead of a file path, which keeps
the HTML report portable and the PDF independent of the repository layout.
"""

import re

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

# Clean drawing extracted from assets/branding/icon.svg. The metadata block of
# the original file is provenance data and is not needed in a report.
LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" '
    'role="img" aria-label="ExposureIQ logo">'
    f'<path fill="{TEAL}" fill-rule="evenodd" '
    'd="M200 80 L40 410 L360 410 Z M200 192 L118 352 L282 352 Z"/>'
    f'<polygon fill="{INDIGO}" points="250,80 292,80 452,410 410,410"/>'
    f'<circle fill="{TEXT_PRIMARY}" cx="200" cy="300" r="30"/>'
    "</svg>"
)

# Shapes used by the PDF writer. Coordinates are in the 512 x 512 view box.
LOGO_TRIANGLES = (
    ((200, 80), (40, 410), (360, 410)),
    ((200, 192), (118, 352), (282, 352)),
)
LOGO_PARALLELOGRAM = ((250, 80), (292, 80), (452, 410), (410, 410))
LOGO_DOT = (200, 300, 30)
