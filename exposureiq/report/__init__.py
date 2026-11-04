"""Stage 4: saved-scan documents and an offline HTML domain workspace.

HTML and PDF need no rendering dependencies; DOCX uses python-docx. The package
reads the same JSON snapshots that the scanner writes (schema 0.1/0.2), uses the
Stage 3 diff summary for "What changed", and renders self-contained HTML with
separately bounded scan views, plus a small, portable
PDF or editable DOCX. Nothing here sends traffic or changes a scan.
"""

from exposureiq.report.model import build_report
from exposureiq.report.render import generate_report

__all__ = ["build_report", "generate_report"]
