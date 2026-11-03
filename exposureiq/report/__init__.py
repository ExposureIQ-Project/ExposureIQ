"""Stage 4: turn a saved scan into a professional HTML and PDF report.

The package is deliberately dependency-free. It reads the same JSON snapshot
that the scanner writes (schema 0.1/0.2), uses the Stage 3 diff summary for the
"What changed" section, and renders self-contained HTML plus a small, portable
PDF. Nothing here sends traffic or changes a scan.
"""

from exposureiq.report.model import build_report
from exposureiq.report.render import generate_report

__all__ = ["build_report", "generate_report"]
