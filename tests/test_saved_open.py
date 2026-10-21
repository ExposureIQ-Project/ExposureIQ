"""Saved-scan preview, --open, and the home/results navigation screens.

Headless Textual with fake jobs. No network, Subfinder, Nmap, HTTP or TLS.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Static

from exposureiq import cli, storage
from exposureiq.discovery import scope
from exposureiq.fingerprint.severity import build_findings
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.confirm_scope import ScopeConfirmation
from exposureiq.tui.saved import display_time, list_saved, result_from_snapshot
from exposureiq.tui.scan import PHASES


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("saved-preview tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    assert attempts == []


def text(widget):
    rendered = widget.render()
    return rendered.plain if isinstance(rendered, Text) else str(rendered)


def make_scan(path: Path, target="example.com", started="2026-10-21T08:00:00Z", demo=False):
    findings = build_findings([{"rule": "headers.missing_csp", "detail": "Saved fake evidence."}])
    assets = [
        {"host": target, "ips": [{"ip": "192.0.2.10", "open_ports": [
            {"port": 443, "protocol": "tcp", "service": "https"},
        ]}], "technologies": [{"name": "nginx", "version": "1.18.0", "source": "Saved fake header"}],
         "findings": findings},
    ]
    snapshot = storage.build_scan(target, assets, started_at=started)
    if demo:
        snapshot["scan_id"] = f"DEMO-{snapshot['scan_id']}"
    storage.save_scan(snapshot, str(path))
    return path


def fake_result(target="example.com", started="2026-10-21T09:30:00Z"):
    return {
        "target": target, "demo": False, "names": [], "assets": [], "elapsed": 0.2,
        "saved_to": "results/example.json", "started_at": started,
        "phase_states": dict.fromkeys(PHASES, "done"), "phase_counts": dict.fromkeys(PHASES, 0),
        "phase_times": dict.fromkeys(PHASES, 0.1), "warnings": [], "host_states": {},
        "skipped_hosts": [], "skipped_ips": [], "skipped_scope_ips": [], "skipped_ipv6_ips": [],
        "port_rows": [], "return_code": 0, "mode": "passive",
        "mode_detail": "Passive only: fake.",
    }


def home_app(tmp_path, **kwargs):
    args = cli.build_parser().parse_args([])
    kwargs.setdefault("results_dir", str(tmp_path / "results"))
    return ExposureIQApp(args, home=True, **kwargs)


def test_saved_snapshot_becomes_a_read_only_result(tmp_path):
    path = make_scan(tmp_path / "saved.json")
    snapshot = storage.load_scan(str(path))
    result = result_from_snapshot(snapshot, path)
    assert result["target"] == "example.com"
    assert result["mode"] == "preview" and "read-only" in result["mode_detail"]
    assert result["started_time"] == "2026-10-21 08:00 UTC"
    assert result["port_rows"] == [("192.0.2.10", [{"port": 443, "protocol": "tcp", "service": "https"}])]
    assert result["assets"][0]["findings"][0]["rule"] == "headers.missing_csp"
    assert ("Scan time", "2026-10-21 08:00 UTC") in result["summary_rows"]
    assert display_time("2026-10-21T08:00:00Z") == "2026-10-21 08:00 UTC"
    assert display_time(None) == "unknown time"


def test_saved_list_is_newest_first_and_marks_unreadable_files(tmp_path):
    first = make_scan(tmp_path / "old.json", target="old.example.com", started="2026-10-20T08:00:00Z")
    second = make_scan(tmp_path / "new.json", target="new.example.com", started="2026-10-21T08:00:00Z")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    os.utime(first, (time.time() - 500, time.time() - 500))
    os.utime(second, (time.time() - 100, time.time() - 100))
    os.utime(broken, (time.time(), time.time()))

    entries = list_saved(tmp_path)
    assert [entry["name"] for entry in entries] == ["broken.json", "new.json", "old.json"]
    assert entries[0]["target"] == "unreadable" and entries[0]["error"]
    assert entries[1]["target"] == "new.example.com"


def test_cli_open_and_alias_print_a_read_only_preview(tmp_path, capsys):
    path = make_scan(tmp_path / "saved.json")
    assert cli.main(["--open", str(path)]) == 0
    printed = capsys.readouterr().out
    assert "Saved scan: example.com" in printed and "read-only preview" in printed
    assert "2026-10-21 08:00 UTC" in printed and "Missing content security policy" in printed

    assert cli.main(["--op", str(path)]) == 0
    assert "Saved scan: example.com" in capsys.readouterr().out


def test_cli_open_missing_or_broken_file_is_a_clean_error(tmp_path, capsys):
    assert cli.main(["--open", str(tmp_path / "missing.json")]) == 1
    assert "Could not open" in capsys.readouterr().out

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli.main(["--open", str(broken)]) == 1
    captured = capsys.readouterr()
    assert "Could not open" in captured.out and "Traceback" not in captured.out + captured.err


def test_bare_command_opens_home_only_in_a_terminal(monkeypatch, capsys):
    from exposureiq.tui import app as app_module

    seen = {}

    class FakeApp:
        def __init__(self, args, **kwargs):
            seen.update(kwargs)

        def run(self):
            return 0

    monkeypatch.setattr(app_module, "ExposureIQApp", FakeApp)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    assert cli.main([]) == 0
    assert seen["home"] is True and "open_file" not in seen

    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
    assert cli.main([]) == 2
    assert "usage: exposureiq" in capsys.readouterr().out


def test_open_flag_uses_the_tui_when_stdout_is_a_terminal(monkeypatch, tmp_path):
    from exposureiq.tui import app as app_module

    path = make_scan(tmp_path / "saved.json")
    seen = {}

    class FakeApp:
        def __init__(self, args, **kwargs):
            seen.update(kwargs)

        def run(self):
            return 0

    monkeypatch.setattr(app_module, "ExposureIQApp", FakeApp)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    assert cli.main(["--open", str(path)]) == 0
    assert seen["open_file"] == str(path)


def test_open_without_a_file_opens_the_results_browser(monkeypatch, capsys):
    from exposureiq.tui import app as app_module

    seen = {}

    class FakeApp:
        def __init__(self, args, **kwargs):
            seen.update(kwargs)

        def run(self):
            return 0

    monkeypatch.setattr(app_module, "ExposureIQApp", FakeApp)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    assert cli.main(["--open"]) == 0
    assert seen["home"] is True and seen["browser"] is True
    seen.clear()
    assert cli.main(["--op"]) == 0
    assert seen["browser"] is True

    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
    assert cli.main(["--open"]) == 2
    assert "--open needs a FILE" in capsys.readouterr().out


def test_browser_mode_starts_on_the_saved_file_list(tmp_path):
    make_scan(tmp_path / "results" / "one.json")

    async def exercise():
        args = cli.build_parser().parse_args([])
        app = ExposureIQApp(args, home=True, browser=True, results_dir=str(tmp_path / "results"))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert app.mode == "browser" and app.query_one("#browser").display
            assert not app.query_one("#home").display
            assert app.query_one("#saved-table", DataTable).row_count == 1
            await pilot.click("#saved-open")
            await pilot.pause(0.2)
            assert app.mode == "results"
            await pilot.click("#back")
            await pilot.pause(0.2)
            await pilot.click("#back")
            await pilot.pause(0.2)
            assert app.mode == "home"
            await pilot.press("q")

    asyncio.run(exercise())


def test_home_is_the_default_screen_with_input_and_buttons(tmp_path):
    async def exercise():
        app = home_app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert app.mode == "home" and app.worker is None
            assert app.query_one("#home").display
            assert not app.query_one("#results").display and not app.query_one("#browser").display
            assert app.focused is not None and app.focused.id == "home-domain"
            for selector in ("#home-domain", "#home-scan", "#home-results", "#home-scope"):
                assert app.query_one(selector).display
            assert "home" in text(app.query_one("#brand", Static))
            await pilot.press("q")  # A q inside the domain box must not quit.
            assert app.is_running
            app.query_one("#home-scan", Button).focus()
            await pilot.press("q")
        assert app.return_value == 0

    asyncio.run(exercise())


def test_home_scan_shows_results_with_domain_and_scan_time(tmp_path):
    async def exercise():
        app = home_app(tmp_path, scan_job=lambda args, stages, report, control, version: fake_result(args.domain))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.query_one("#home-domain", Input).focus()
            await pilot.press(*list("example.com"))
            await pilot.click("#home-scan")
            await app.worker.wait()
            await pilot.pause()
            assert app.mode == "results" and app.result["target"] == "example.com"
            title = text(app.query_one("#brand", Static))
            assert "example.com" in title and "2026-10-21 09:30 UTC" in title
            assert "example.com" in text(app.query_one("#summary-notes", Static))
            await pilot.press("q")
        assert app.return_value == 0

    asyncio.run(exercise())


def test_home_rejects_an_invalid_domain_without_starting_a_scan(tmp_path):
    async def exercise():
        app = home_app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.query_one("#home-domain", Input).value = "not a domain"
            await pilot.click("#home-scan")
            await pilot.pause()
            assert app.mode == "home" and app.worker is None
            assert "valid" in text(app.query_one("#home-message", Static)).lower()
            await pilot.press("q")

    asyncio.run(exercise())


def test_results_browser_previews_a_file_and_back_navigates(tmp_path):
    make_scan(tmp_path / "results" / "one.json", target="one.example.com", started="2026-10-20T08:00:00Z")
    make_scan(tmp_path / "results" / "two.json", target="two.example.com", started="2026-10-21T08:00:00Z")

    async def exercise():
        app = home_app(tmp_path)
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            await pilot.click("#home-results")
            await pilot.pause()
            assert app.mode == "browser" and app.query_one("#browser").display
            assert app.query_one("#saved-table", DataTable).row_count == 2
            app.query_one("#saved-table", DataTable).focus()
            await pilot.press("enter")
            await pilot.pause()
            assert app.mode == "results"
            assert "two.example.com" in text(app.query_one("#brand", Static))
            assert "read-only preview" in text(app.query_one("#scan-status", Static))
            assert not app.query_one("#add-scope", Button).display
            await pilot.click("#back")
            await pilot.pause(0.2)
            assert app.mode == "browser"
            await pilot.click("#back")
            await pilot.pause(0.2)
            assert app.mode == "home"
            await pilot.press("q")

    asyncio.run(exercise())


def test_open_file_app_shows_the_preview_without_a_worker(tmp_path):
    path = make_scan(tmp_path / "saved.json")

    async def exercise():
        args = cli.build_parser().parse_args([])
        app = ExposureIQApp(args, open_file=str(path))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert app.mode == "results" and app.worker is None
            assert "example.com" in text(app.query_one("#brand", Static))
            assert "2026-10-21 08:00 UTC" in text(app.query_one("#brand", Static))
            assert "read-only preview" in text(app.query_one("#scan-status", Static))
            assert app.query_one("#findings-table", DataTable).row_count == 1
            assert not app.query_one("#add-scope", Button).display
            await pilot.press("q")
        assert app.return_value == 0

    asyncio.run(exercise())


def test_demo_saved_scan_is_still_labeled_demo(tmp_path):
    path = make_scan(tmp_path / "demo.json", demo=True)

    async def exercise():
        args = cli.build_parser().parse_args([])
        app = ExposureIQApp(args, open_file=str(path))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            assert app.result["demo"] is True
            assert "DEMO" in text(app.query_one("#brand", Static))
            assert "DEMO" in text(app.query_one("#summary-notes", Static))
            await pilot.press("q")

    asyncio.run(exercise())


def test_home_add_scope_requires_exact_domain_and_never_touches_repo_scope(
        monkeypatch, tmp_path, isolated_user_scope):
    repo = tmp_path / "repo" / "scope.txt"
    repo.parent.mkdir()
    repo.write_text("# fake repository scope\n", encoding="utf-8")
    monkeypatch.setattr(scope, "SCOPE_FILE", repo)
    before = repo.read_bytes()

    async def exercise():
        app = home_app(tmp_path)
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            app.query_one("#home-domain", Input).value = "example.com"
            await pilot.click("#home-scope")
            await pilot.pause()
            assert isinstance(app.screen, ScopeConfirmation)
            confirm = app.screen.query_one("#scope-confirm", Button)
            assert confirm.disabled
            field = app.screen.query_one("#scope-domain-input", Input)
            field.focus()
            for wrong in ("wrong.example.com", "EXAMPLE.COM", "example.com "):
                field.value = wrong
                await pilot.pause()
                assert confirm.disabled
            field.value = "example.com"
            await pilot.pause()
            assert not confirm.disabled
            await pilot.click("#scope-confirm")
            await pilot.pause()
            message = text(app.query_one("#home-message", Static))
            assert "Added example.com to your user scope" in message
            assert str(isolated_user_scope) in message and "repository scope.txt was not changed" in message
            await pilot.press("q")

    asyncio.run(exercise())
    contents = isolated_user_scope.read_text(encoding="utf-8").splitlines()
    assert contents[0].startswith("# added ") and "for example.com (confirmed by user)" in contents[0]
    assert contents[1:] == ["example.com"]
    assert repo.read_bytes() == before


def test_home_add_scope_cancel_writes_nothing(monkeypatch, tmp_path, isolated_user_scope):
    repo = tmp_path / "repo" / "scope.txt"
    repo.parent.mkdir()
    repo.write_text("# fake repository scope\n", encoding="utf-8")
    monkeypatch.setattr(scope, "SCOPE_FILE", repo)

    async def exercise():
        app = home_app(tmp_path)
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            app.query_one("#home-domain", Input).value = "example.com"
            await pilot.click("#home-scope")
            await pilot.pause()
            await pilot.click("#scope-cancel")
            await pilot.pause()
            assert not isinstance(app.screen, ScopeConfirmation)
            assert "cancelled" in text(app.query_one("#home-message", Static)).lower()
            await pilot.press("q")

    asyncio.run(exercise())
    assert not isolated_user_scope.exists()


def test_home_and_browser_fit_an_80_by_24_terminal(tmp_path):
    make_scan(tmp_path / "results" / "one.json")

    async def exercise():
        app = home_app(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert not app.query_one("#back", Button).display
            for selector in ("#home-domain", "#home-scan", "#home-scan-note", "#home-results",
                             "#home-scope", "#home-note"):
                region = app.query_one(selector).region
                assert 0 <= region.y and region.bottom <= 23, (selector, region)
            await pilot.click("#home-results")
            await pilot.pause(0.2)
            table = app.query_one("#saved-table", DataTable)
            assert table.region.bottom <= 21 and table.row_count == 1
            assert app.query_one("#saved-open").region.bottom <= 23
            app.query_one("#saved-table").focus()
            await pilot.press("enter")
            await pilot.pause(0.2)
            assert app.mode == "results"
            assert app.query_one("#results").region.bottom <= 23
            await pilot.press("q")

    asyncio.run(exercise())


def test_preview_ignores_the_add_scope_shortcut(tmp_path):
    path = make_scan(tmp_path / "saved.json")

    async def exercise():
        args = cli.build_parser().parse_args(["scan", "example.com", "--plain"])
        app = ExposureIQApp(args, open_file=str(path))
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause()
            app.export_screenshot(title="read-only preview")
            assert "read-only preview" in text(app.query_one("#scan-status", Static))
            await pilot.press("a")
            await pilot.pause()
            assert not isinstance(app.screen, ScopeConfirmation)
            await pilot.press("q")

    asyncio.run(exercise())


async def export_screens(directory: Path) -> list:
    """Fake saved files only; no scan, probe or scope write happens here."""
    directory.mkdir(parents=True, exist_ok=True)
    results = directory / "results"
    make_scan(results / "academapro_20261021.json", target="academapro.com", started="2026-10-21T08:15:00Z")
    make_scan(results / "demo_20261020.json", target="example.com", started="2026-10-20T19:40:00Z", demo=True)
    paths = []
    app = home_app(directory, results_dir=str(results))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        path = directory / "home.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ — home"), encoding="utf-8")
        paths.append(path)
        await pilot.click("#home-results")
        await pilot.pause(0.2)
        path = directory / "saved-results.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ — saved results"), encoding="utf-8")
        paths.append(path)
        app.query_one("#saved-table", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause(0.2)
        path = directory / "opened-preview.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ — read-only saved scan"), encoding="utf-8")
        paths.append(path)
        await pilot.click("#back")
        await pilot.pause(0.2)
        await pilot.click("#back")
        await pilot.pause(0.2)
        app.query_one("#home-domain", Input).value = "academapro.com"
        await pilot.click("#home-scope")
        await pilot.pause(0.2)
        path = directory / "home-add-scope.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ — authorization confirmation"), encoding="utf-8")
        paths.append(path)
        await pilot.press("escape")
        await pilot.pause(0.2)
        await pilot.press("q")
    return paths


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--export-screens"]:
        raise SystemExit("Use python tests/test_saved_open.py --export-screens")
    for exported in asyncio.run(export_screens(Path("/tmp/opencode/exposureiq-s2-navigation-screens"))):
        print(exported)
