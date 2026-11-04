"""Load a saved scan, build the report model, and write HTML/PDF/DOCX files.

This is the only module in ``exposureiq.report`` that touches the filesystem.
It reuses ``storage.load_scan`` (so the same validation applies) and the Stage 3
diff pipeline (so "What changed" matches ``exposureiq diff``).
"""

from __future__ import annotations

import re
from pathlib import Path

from exposureiq import storage
from exposureiq.paths import domain_directory
from exposureiq.report.domain import build_domain_report
from exposureiq.report.html import render_domain_html
from exposureiq.report.model import build_report
from exposureiq.report.pdf import render_pdf

DEFAULT_REPORT_DIR = Path("report")
FORMATS = ("html", "pdf", "docx", "both")
_EXTENSIONS = {".html": "html", ".htm": "html", ".pdf": "pdf", ".docx": "docx"}


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("exposureiq") or "0.1.0"
    except Exception:
        return "0.1.0"


def _load_source(source: str, results_dir: str | Path) -> tuple[dict, Path | None]:
    """Return (validated scan, path). A path may also be a bare domain name."""
    text = str(source or "").strip()
    if not text:
        raise ValueError("A scan file or domain is required.")

    path = Path(text)
    if path.is_file() or text.lower().endswith(".json"):
        if not path.is_file():
            raise ValueError(f"Scan file not found: {path}")
        return storage.load_scan(str(path)), path

    if "/" in text or "\\" in text:
        raise ValueError(f"Scan file not found: {path}")

    from exposureiq.diffing import pipeline
    from exposureiq.discovery.subdomains import normalize_domain

    domain = normalize_domain(text)
    entries = pipeline.find_domain_scans(domain, results_dir)
    if not entries:
        raise ValueError(
            f"No saved scans for {domain} in {results_dir}. "
            f"Run: exposureiq scan {domain}"
        )
    newest = entries[-1]
    return newest["scan"], Path(newest["path"])


def _build_diff(scan: dict, *, compare: str | None, include_diff: bool,
                history: list[dict]) -> dict | None:
    if not include_diff:
        if compare:
            raise ValueError("--compare cannot be combined with --no-diff.")
        return None
    from exposureiq.diffing import pipeline

    baseline = storage.load_scan(str(compare)) if compare else None
    try:
        return pipeline.build_history_diff(scan, history, baseline=baseline)
    except ValueError as error:
        raise ValueError(f"Cannot compare scan history: {error}") from error


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "report"


def _resolve_format(output: str | None, requested: str | None) -> str:
    if requested is not None:
        if requested not in FORMATS:
            raise ValueError(f"format must be one of: {', '.join(FORMATS)}")
        return requested
    if output:
        suffix = Path(output).suffix.lower()
        if suffix in _EXTENSIONS:
            return _EXTENSIONS[suffix]
    return "both"


def _output_paths(output: str | None, fmt: str, target: str, scan_id: str) -> dict[str, Path]:
    stem = _safe_name(f"{target}_{scan_id}")
    path = Path(output) if output else DEFAULT_REPORT_DIR
    file_format = _EXTENSIONS.get(path.suffix.lower()) if output else None
    folder = domain_directory(path, target) if file_format is None else None
    selected = ("html", "pdf") if fmt == "both" else (fmt,)
    return {
        name: (path if name == file_format else path.with_suffix(f".{name}"))
        if file_format else folder / ("index.html" if name == "html" else f"{stem}.{name}")
        for name in selected
    }


def generate_report(source: str, *, output: str | None = None, format: str | None = None,
                    compare: str | None = None, results_dir: str | Path = "results",
                    include_diff: bool = True, title: str | None = None,
                    generated_at: str | None = None) -> dict:
    """Generate a domain HTML dashboard and/or selected-scan PDF/DOCX files.

    ``source`` is a saved JSON file or a domain with saved scans. ``output`` may
    be an ``.html``/``.pdf``/``.docx`` file or a directory. ``format`` overrides the
    extension guess. ``compare`` selects an explicit older scan for the change
    section; otherwise the earliest compatible saved scan is the baseline.
    Each detail view's comparison and charts stop at its scan. The HTML home
    lists every saved snapshot for the domain, newest first, with separate
    real/demo histories. Directory outputs are grouped by domain.
    ``both`` keeps its original meaning: HTML and PDF, without DOCX.
    """
    from exposureiq.diffing import pipeline

    scan, source_path = _load_source(source, results_dir)
    available = [entry["scan"] for entry in pipeline.find_domain_scans(scan["target"], results_dir)]
    history = pipeline.scan_history(scan, available)
    diff = _build_diff(scan, compare=compare, include_diff=include_diff,
                       history=history)

    report = build_report(scan, diff=diff, history=history,
                           generated_at=generated_at, title=title,
                           comparison_enabled=include_diff)
    report["tool_version"] = _version()

    fmt = _resolve_format(output, format)
    paths = _output_paths(output, fmt, report["target"], report["scan_id"])
    html_path, pdf_path, docx_path = (paths.get(name) for name in ("html", "pdf", "docx"))

    domain = None
    if html_path is not None:
        domain = build_domain_report(scan, available, report, include_diff=include_diff)
        page = render_domain_html(domain)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(page, encoding="utf-8")
    if pdf_path is not None:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        pdf_path.write_bytes(render_pdf(report))
    if docx_path is not None:
        # Keep HTML and the default PDF usable before dependencies are upgraded.
        try:
            from exposureiq.report.docx import render_docx
        except ImportError as error:
            raise ImportError(
                "DOCX export requires python-docx. Install dependencies with: "
                "python -m pip install -e ."
            ) from error
        document = render_docx(report)
        docx_path.parent.mkdir(parents=True, exist_ok=True)
        docx_path.write_bytes(document)

    return {
        "report": report,
        "html": str(html_path) if html_path is not None else None,
        "pdf": str(pdf_path) if pdf_path is not None else None,
        "docx": str(docx_path) if docx_path is not None else None,
        "source": str(source_path) if source_path is not None else None,
        "diff": diff,
        "domain": domain,
    }
