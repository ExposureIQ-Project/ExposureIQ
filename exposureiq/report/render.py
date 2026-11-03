"""Load a saved scan, build the report model, and write HTML/PDF files.

This is the only module in ``exposureiq.report`` that touches the filesystem.
It reuses ``storage.load_scan`` (so the same validation applies) and the Stage 3
diff pipeline (so "What changed" matches ``exposureiq diff``).
"""

from __future__ import annotations

import re
from pathlib import Path

from exposureiq import storage
from exposureiq.report.html import render_html
from exposureiq.report.model import build_report
from exposureiq.report.pdf import render_pdf

DEFAULT_REPORT_DIR = Path("report")
FORMATS = ("html", "pdf", "both")


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("exposureiq") or "0.1.0"
    except Exception:
        return "0.1.0"


def _scan_key(scan: dict) -> tuple:
    return (str(scan.get("scan_id") or ""), str(scan.get("started_at") or ""))


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


def _is_demo(scan: dict) -> bool:
    return str(scan.get("scan_id") or "").startswith("DEMO-")


def _history_for(scan: dict, results_dir: str | Path) -> list[dict]:
    from exposureiq.diffing import pipeline

    target = str(scan.get("target") or "")
    entries = pipeline.find_domain_scans(target, results_dir) if target else []
    # Never mix fake demo snapshots into a real report (or the other way round).
    current_demo = _is_demo(scan)
    scans = [entry["scan"] for entry in entries if _is_demo(entry["scan"]) == current_demo]
    if not any(_scan_key(item) == _scan_key(scan) for item in scans):
        scans.append(scan)
    return scans


def _previous_scans(scan: dict, history: list[dict]) -> tuple[dict | None, dict | None]:
    """Return (previous, before_previous) for the current scan, oldest first."""
    ordered = sorted(history, key=lambda item: (
        str(item.get("started_at") or ""), str(item.get("scan_id") or "")))
    key = _scan_key(scan)
    index = next((position for position, item in enumerate(ordered)
                  if _scan_key(item) == key), None)
    if index is None:
        current_time = str(scan.get("started_at") or "")
        earlier = [item for item in ordered
                   if str(item.get("started_at") or "") < current_time]
        if not earlier:
            return None, None
        return earlier[-1], (earlier[-2] if len(earlier) >= 2 else None)
    previous = ordered[index - 1] if index > 0 else None
    before = ordered[index - 2] if index >= 2 else None
    return previous, before


def _build_diff(scan: dict, *, compare: str | None, include_diff: bool,
                results_dir: str | Path, history: list[dict]) -> dict | None:
    if not include_diff:
        if compare:
            raise ValueError("--compare cannot be combined with --no-diff.")
        return None
    from exposureiq.diffing import pipeline

    if compare:
        old = storage.load_scan(str(compare))
        try:
            return pipeline.build_diff(old, scan)
        except ValueError as error:
            raise ValueError(f"Cannot compare the two scans: {error}") from error

    previous, before = _previous_scans(scan, history)
    if previous is None:
        return None
    try:
        return pipeline.build_diff(previous, scan, before_old=before)
    except ValueError as error:
        raise ValueError(f"Cannot compare with the previous scan: {error}") from error


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "report"


def _resolve_format(output: str | None, requested: str | None) -> str:
    if requested is not None:
        if requested not in FORMATS:
            raise ValueError(f"format must be one of: {', '.join(FORMATS)}")
        return requested
    if output:
        suffix = Path(output).suffix.lower()
        if suffix in (".html", ".htm"):
            return "html"
        if suffix == ".pdf":
            return "pdf"
    return "both"


def _output_paths(output: str | None, fmt: str, target: str, scan_id: str) -> tuple[Path | None, Path | None]:
    stem = _safe_name(f"{target}_{scan_id}")
    if output:
        path = Path(output)
        suffix = path.suffix.lower()
        if suffix in (".html", ".htm"):
            html_path, pdf_path = path, path.with_suffix(".pdf")
        elif suffix == ".pdf":
            html_path, pdf_path = path.with_suffix(".html"), path
        else:
            html_path, pdf_path = path / f"{stem}.html", path / f"{stem}.pdf"
    else:
        html_path = DEFAULT_REPORT_DIR / f"{stem}.html"
        pdf_path = DEFAULT_REPORT_DIR / f"{stem}.pdf"

    if fmt == "html":
        pdf_path = None
    elif fmt == "pdf":
        html_path = None
    return html_path, pdf_path


def generate_report(source: str, *, output: str | None = None, format: str | None = None,
                    compare: str | None = None, results_dir: str | Path = "results",
                    include_diff: bool = True, title: str | None = None,
                    generated_at: str | None = None) -> dict:
    """Generate one report and return the paths plus the report model.

    ``source`` is a saved JSON file or a domain with saved scans. ``output`` may
    be an ``.html``/``.pdf`` file or a directory. ``format`` overrides the
    extension guess. ``compare`` selects an explicit older scan for the change
    section; otherwise the previous saved scan for the same target is used.
    """
    scan, source_path = _load_source(source, results_dir)
    history = _history_for(scan, results_dir)
    diff = _build_diff(scan, compare=compare, include_diff=include_diff,
                       results_dir=results_dir, history=history)

    report = build_report(scan, diff=diff, history=history,
                          generated_at=generated_at, title=title)
    report["tool_version"] = _version()

    fmt = _resolve_format(output, format)
    html_path, pdf_path = _output_paths(output, fmt, report["target"], report["scan_id"])

    if html_path is not None:
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(report), encoding="utf-8")
    if pdf_path is not None:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        pdf_path.write_bytes(render_pdf(report))

    return {
        "report": report,
        "html": str(html_path) if html_path is not None else None,
        "pdf": str(pdf_path) if pdf_path is not None else None,
        "source": str(source_path) if source_path is not None else None,
        "diff": diff,
    }
