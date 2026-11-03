"""One place for the ExposureIQ report look: colours, fonts, and the logo.

Both renderers (HTML and PDF) read this module, so a brand change happens once.
The logo is embedded as a small inline SVG instead of a file path, which keeps
the HTML report portable and the PDF independent of the repository layout.
"""

# Core brand palette (shared with the terminal output in exposureiq/output.py).
TEAL = "#16B8A6"
INDIGO = "#7C83FD"
AMBER = "#F59E0B"
DARK = "#111827"
SLATE = "#475569"
MUTED = "#64748B"
LINE = "#E2E8F0"
PAPER = "#F8FAFC"
WHITE = "#FFFFFF"
GREEN = "#16A34A"

# Severity colours are intentionally different from the brand accents so a
# reader never confuses "high risk" with "ExposureIQ teal".
SEVERITY_COLORS = {
    "high": "#DC2626",
    "medium": "#F59E0B",
    "low": "#2563EB",
    "none": TEAL,
}

SEVERITY_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Clear",
}

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
    '<path fill="#16B8A6" fill-rule="evenodd" '
    'd="M200 80 L40 410 L360 410 Z M200 192 L118 352 L282 352 Z"/>'
    '<polygon fill="#7C83FD" points="250,80 292,80 452,410 410,410"/>'
    '<circle fill="#F4F7FA" cx="200" cy="300" r="30"/>'
    "</svg>"
)

# Shapes used by the PDF writer. Coordinates are in the 512 x 512 view box.
LOGO_TRIANGLES = (
    ((200, 80), (40, 410), (360, 410)),
    ((200, 192), (118, 352), (282, 352)),
)
LOGO_PARALLELOGRAM = ((250, 80), (292, 80), (452, 410), (410, 410))
LOGO_DOT = (200, 300, 30)
