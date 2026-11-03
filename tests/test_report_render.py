"""Tests for report loading, history, diff wiring, and file output."""

import copy
import json
from pathlib import Path

import pytest

from exposureiq import storage
from exposureiq.cli import main
from exposureiq.report.render import generate_report

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
FIXED_TIME = "2026-11-02T12:00:00Z"


def example_scan():
    return storage.load_scan(str(EXAMPLE))


def write_scan(directory: Path, scan: dict) -> Path:
    path = directory / f"{scan['scan_id']}.json"
    storage.save_scan(scan, str(path))
    return path


def history_directory(tmp_path: Path) -> Path:
    results = tmp_path / "results"
    results.mkdir()

    old = copy.deepcopy(example_scan())
    old["scan_id"] = "2026-10-01T10-00-00Z"
    old["started_at"] = "2026-10-01T10:00:00Z"
    old["assets"] = [copy.deepcopy(old["assets"][0])]
    old["assets"][0]["findings"] = []
    old["assets"][0]["ips"][0]["open_ports"] = []
    write_scan(results, old)

    middle = example_scan()
    middle["scan_id"] = "2026-10-15T10-00-00Z"
    middle["started_at"] = "2026-10-15T10:00:00Z"
    write_scan(results, middle)

    new = example_scan()
    new["scan_id"] = "2026-10-29T10-00-00Z"
    new["started_at"] = "2026-10-29T10:00:00Z"
    new["assets"].append({
        "host": "staging.example.com",
        "ips": [{"ip": "203.0.113.30", "open_ports": []}],
        "technologies": [],
        "findings": [],
    })
    write_scan(results, new)
    return results


def test_generate_html_only(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = generate_report(
        str(EXAMPLE),
        output=str(tmp_path / "report.html"),
        format="html",
        results_dir=str(empty),
        generated_at=FIXED_TIME,
    )

    assert result["html"] == str(tmp_path / "report.html")
    assert result["pdf"] is None
    assert result["diff"] is None
    assert Path(result["html"]).is_file()
    assert "example.com" in Path(result["html"]).read_text(encoding="utf-8")


def test_output_extension_infers_a_single_format(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = generate_report(
        str(EXAMPLE),
        output=str(tmp_path / "report.pdf"),
        results_dir=str(empty),
        generated_at=FIXED_TIME,
    )

    assert result["pdf"] == str(tmp_path / "report.pdf")
    assert result["html"] is None
    assert Path(result["pdf"]).read_bytes().startswith(b"%PDF-1.4")
    assert not (tmp_path / "report.html").exists()


def test_directory_output_uses_target_and_scan_id(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = generate_report(
        str(EXAMPLE),
        output=str(tmp_path / "out"),
        format="both",
        results_dir=str(empty),
        generated_at=FIXED_TIME,
    )

    assert Path(result["html"]).name == "example.com_2026-10-13T20-15-00Z.html"
    assert Path(result["pdf"]).name == "example.com_2026-10-13T20-15-00Z.pdf"
    assert Path(result["html"]).is_file()
    assert Path(result["pdf"]).is_file()


def test_domain_source_uses_newest_scan_and_previous_diff(tmp_path):
    results = history_directory(tmp_path)
    result = generate_report(
        "example.com",
        output=str(tmp_path / "report.html"),
        format="html",
        results_dir=str(results),
        generated_at=FIXED_TIME,
    )

    report = result["report"]
    assert report["scan_id"] == "2026-10-29T10-00-00Z"
    assert result["diff"] is not None
    assert result["diff"]["summary"]["counts"]["worse"] == 1
    assert "new host discovered" in result["diff"]["summary"]["headline"] or \
        "new host discovered" in " ".join(result["diff"]["summary"]["lines"])
    assert len(report["history"]) == 3
    assert "staging.example.com" in Path(result["html"]).read_text(encoding="utf-8")


def test_no_diff_skips_history_comparison(tmp_path):
    results = history_directory(tmp_path)
    result = generate_report(
        "example.com",
        output=str(tmp_path / "report.html"),
        format="html",
        results_dir=str(results),
        include_diff=False,
        generated_at=FIXED_TIME,
    )

    assert result["diff"] is None
    assert result["report"]["diff_summary"] is None


def test_explicit_compare_file(tmp_path):
    results = history_directory(tmp_path)
    old_path = results / "2026-10-01T10-00-00Z.json"
    result = generate_report(
        str(results / "2026-10-29T10-00-00Z.json"),
        output=str(tmp_path / "report.html"),
        format="html",
        compare=str(old_path),
        results_dir=str(results),
        generated_at=FIXED_TIME,
    )

    assert result["diff"] is not None
    assert result["diff"]["old"]["scan_id"] == "2026-10-01T10-00-00Z"
    assert result["diff"]["new"]["scan_id"] == "2026-10-29T10-00-00Z"


def test_demo_history_is_not_mixed_into_a_real_report(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    demo = example_scan()
    demo["scan_id"] = "DEMO-2026-10-01T10-00-00Z"
    demo["started_at"] = "2026-10-01T10:00:00Z"
    write_scan(results, demo)

    result = generate_report(
        str(EXAMPLE),
        output=str(tmp_path / "report.html"),
        format="html",
        results_dir=str(results),
        generated_at=FIXED_TIME,
    )

    assert len(result["report"]["history"]) == 1
    assert result["report"]["history"][0]["started_at"] == "2026-10-13T20:15:00Z"
    assert result["diff"] is None


def test_missing_source_and_bad_format_raise_value_error(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        generate_report(str(tmp_path / "missing.json"))

    with pytest.raises(ValueError, match="format"):
        generate_report(str(EXAMPLE), format="docx", output=str(tmp_path / "x"))


def test_compare_with_no_diff_is_rejected(tmp_path):
    results = history_directory(tmp_path)
    with pytest.raises(ValueError, match="no-diff"):
        generate_report(
            "example.com",
            results_dir=str(results),
            compare=str(results / "2026-10-01T10-00-00Z.json"),
            include_diff=False,
        )


def test_cli_report_returns_zero_and_writes_file(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    target = tmp_path / "cli-report.html"
    code = main([
        "report", str(EXAMPLE),
        "-o", str(target),
        "--format", "html",
        "--results-dir", str(empty),
    ])

    assert code == 0
    assert target.is_file()


def test_cli_report_bad_source_returns_two(tmp_path):
    code = main(["report", str(tmp_path / "missing.json")])
    assert code == 2


def test_demo_scan_automatically_writes_pdf_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    code = main(["scan", "example.com", "--demo", "--plain"])

    assert code == 0
    pdfs = sorted((tmp_path / "report").glob("*.pdf"))
    assert len(pdfs) == 1
    assert pdfs[0].read_bytes().startswith(b"%PDF-1.4")
    assert list((tmp_path / "results").glob("*.json"))


def test_scan_no_report_flag_skips_pdf(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    code = main(["scan", "example.com", "--demo", "--plain", "--no-report"])

    assert code == 0
    assert not (tmp_path / "report").exists()


def test_report_model_is_json_serialisable(tmp_path):
    result = generate_report(
        str(EXAMPLE),
        output=str(tmp_path / "report.html"),
        format="html",
        results_dir=str(tmp_path / "empty"),
        generated_at=FIXED_TIME,
    )
    encoded = json.dumps(result["report"])
    assert "example.com" in encoded
