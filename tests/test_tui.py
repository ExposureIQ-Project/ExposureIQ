"""Textual headless tests: fake jobs only, no internet or discovery tools.

Export presentation screenshots (also fake-only):
    python tests/test_tui.py --export-screens
"""

import asyncio
import logging
import socket
import threading
from copy import deepcopy
from pathlib import Path

import pytest
from rich.cells import cell_len
from rich.text import Text
from textual.widgets import Button, DataTable, Input, ProgressBar, Static, TabbedContent, TabPane, Tabs

from exposureiq import cli
from exposureiq.report import branding
from exposureiq.tui.app import ExposureIQApp, _HOME_LOGO
from exposureiq.tui.control import ScanControl
from exposureiq.tui.scan import PHASES, run_scan


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []
    original_connect = socket.socket.connect

    def blocked_connect(sock, address, *args, **kwargs):
        # asyncio's event loop uses a loopback socketpair on Windows.
        if isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "::1", "localhost"):
            return original_connect(sock, address, *args, **kwargs)
        attempts.append((sock, address))
        raise AssertionError("TUI tests must not use the network")

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("TUI tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    yield
    assert attempts == []


def args(*flags):
    return cli.build_parser().parse_args(["scan", "example.com", *flags])


def fake_result():
    assets = [{"host": host, "ips": [{"ip": "192.0.2.10", "open_ports": [
        {"port": 443, "protocol": "tcp", "service": "https"},
    ]}], "technologies": [], "findings": []} for host in ("example.com", "api.example.com")]
    assets[1]["technologies"] = [{"name": "[bold]nginx[/bold]", "version": "1.18.0", "source": "DEMO Server header"}]
    assets[1]["findings"] = [{
        "id": "F-0001", "rule": "headers.missing_csp", "severity": "medium",
        "title": "DEMO: Missing content security policy", "detail": "[bold]saved sample detail[/bold]",
        "recommendation": "Add a Content-Security-Policy header.",
    }]
    assets[0]["findings"] = [{
        "id": "F-0002", "rule": "tech.server_version_disclosed", "severity": "low",
        "title": "DEMO: Server version disclosed", "detail": "DEMO: nginx/1.18.0 was in the saved header.",
        "recommendation": "Hide the Server version.",
    }]
    return {
        "target": "example.com", "demo": True, "names": ["api.example.com"],
        "assets": assets, "elapsed": 2.0, "saved_to": "results/demo_sample.json",
        "phase_states": dict.fromkeys(PHASES, "done"),
        "phase_counts": dict(zip(PHASES, (3, 1, 2, 2, 1, 2))),
        "phase_times": dict.fromkeys(PHASES, 0.2),
        "warnings": [], "skipped_hosts": [], "skipped_ips": [],
        "host_states": {host: "checked" for host in ("example.com", "api.example.com")},
        "port_rows": [("192.0.2.10", [{"port": 443, "protocol": "tcp", "service": "https"}])],
        "return_code": 0,
    }


class FakeJob:
    def __init__(self, finished=False):
        self.release = threading.Event()
        self.entered = threading.Event()
        self.thread_id = None
        if finished:
            self.release.set()

    def __call__(self, args, stages, report, control, version):
        self.thread_id = threading.get_ident()
        report({"kind": "phase", "phase": "Scope", "state": "done", "count": 3})
        report({"kind": "phase", "phase": "Subdomains", "state": "spinner", "count": None,
                "message": "DEMO: reading saved subdomain samples"})
        report({"kind": "counters", "subdomains": 1, "hosts": 2, "ips": 1, "findings": 1})
        self.entered.set()
        while not self.release.wait(0.02):
            control.check()
        control.check()
        return fake_result()


def plain_text(widget):
    rendered = widget.render()
    return rendered.plain if isinstance(rendered, Text) else str(rendered)


def test_tui_badges_and_text_have_readable_shared_palette_colors():
    def luminance(color):
        channels = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4
                    for value in branding.hex_to_rgb(color)]
        return sum(value * weight for value, weight in zip(channels, (.2126, .7152, .0722)))

    for foreground, background in (
        (branding.TUI_HIGH, branding.HIGH_BACKGROUND),
        (branding.AMBER, branding.MEDIUM_BACKGROUND),
        (branding.LOW, branding.LOW_BACKGROUND),
        (branding.AMBER, branding.DEMO_BACKGROUND),
        (branding.TUI_BREADCRUMB, branding.PANEL),
        (branding.TUI_TAB_INACTIVE, branding.PAGE_BACKGROUND),
        (branding.TUI_LABEL, branding.PANEL),
        (branding.TUI_FOOTNOTE, branding.INNER_SURFACE),
        (branding.TUI_KEY_HINT, branding.FOOTER),
        (branding.TUI_HIGH, branding.PANEL),
        (branding.TUI_BODY_TEXT, branding.INNER_SURFACE),
        (branding.TEAL, branding.TUI_TABLE_HEADER),
        (branding.TEXT_PRIMARY, branding.HIGHLIGHT),
    ):
        low, high = sorted((luminance(foreground), luminance(background)))
        assert (high + .05) / (low + .05) >= 4.5, (foreground, background)


def test_shared_palette_colors_controls_and_selected_high_severity():
    async def exercise():
        app = ExposureIQApp(args("--demo"), home=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app.screen.styles.background.hex == branding.PANEL
            assert app.query_one("#topbar").styles.background.hex == branding.PANEL
            assert app.query_one("#home-domain", Input).styles.background.a == 0
            button = app.query_one("#home-scan", Button)
            assert button.styles.background.a == 0
            assert button.styles.color.hex == branding.TEAL
            await pilot.hover("#home-scan")
            button.focus()
            await pilot.pause()
            assert button.styles.background.a == button.styles.background_tint.a == 0
            button.add_class("-active")
            await pilot.pause()
            assert button.styles.background.a == button.styles.tint.a == 0
            button.remove_class("-active")
            button.disabled = True
            await pilot.pause()
            assert button.styles.background.a == 0
            assert button.styles.color.hex == branding.MUTED
            assert button.styles.text_opacity == 1
            assert app.query_one("#keys").styles.background.hex == branding.PANEL

            app.result = fake_result()
            app.result["assets"][0]["findings"][0]["severity"] = "high"
            app._show_results()
            app.query_one("#results", TabbedContent).active = "findings-tab"
            table = app.query_one("#findings-table", DataTable)
            table.focus()
            await pilot.pause()
            segments = list(table.render_line(table.header_height))
            high = next(segment for segment in segments if "HIGH" in segment.text)
            assert high.style.color.name == branding.TUI_HIGH.lower()
            assert high.style.bgcolor.name == branding.HIGH_BACKGROUND.lower()
            host = next(segment for segment in segments if "example.com" in segment.text)
            assert host.style.bgcolor.name == branding.HIGHLIGHT.lower()
            app.result["mode"] = "preview"
            app._show_results()
            app.query_one("#results", TabbedContent).active = "summary-tab"
            await pilot.pause()
            mode = list(app.query_one("#summary-notes", Static).render_line(0))
            demo = next(segment for segment in mode if "DEMO" in segment.text)
            notice = next(segment for segment in mode if "read-only" in segment.text)
            assert demo.style.color.name == branding.AMBER.lower()
            assert notice.style.color.name == branding.INDIGO.lower()
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("size", [(80, 24), (120, 40)])
def test_saved_result_design_keeps_tabs_columns_and_rounded_count_chips(size, tmp_path):
    async def exercise():
        app = ExposureIQApp(args("--demo"), home=True, results_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            app.result = fake_result()
            app.result.update(mode="preview", started_at="2026-10-21T08:00:00Z")
            original = deepcopy(app.result)
            app._show_results()
            await pilot.pause()

            assert "/ saved scan / summary" in plain_text(app.query_one("#brand", Static))
            assert "2026-10-21 08:00 UTC" in plain_text(app.query_one("#brand", Static))
            badge = app.query_one("#mode-badge", Static)
            assert plain_text(badge) == "DEMO · FAKE DATA"
            assert badge.styles.background.a == 0
            assert badge.styles.color.hex == branding.AMBER
            assert all(edge[0] == "round" for edge in badge.styles.border)
            assert badge.styles.border_top[1].hex == branding.DEMO_BORDER

            assert {pane.id for pane in app.query(TabPane)} == {
                "summary-tab", "subdomains-tab", "hosts-tab", "technologies-tab",
                "findings-tab", "ports-tab", "scan-diff-tab",
            }
            assert app.query_one("#severity-counts").parent.id == "results"
            for severity, count, foreground in (
                ("high", 0, branding.TUI_HIGH),
                ("medium", 1, branding.AMBER),
                ("low", 1, branding.LOW),
            ):
                chip = app.query_one(f"#severity-{severity}", Static)
                assert plain_text(chip) == f"{severity.upper()} {count}"
                assert chip.styles.color.hex == foreground
                assert chip.styles.background.a == 0
                assert all(edge[0] == "round" for edge in chip.styles.border)

            table = app.query_one("#phase-counts", DataTable)
            side = app.query_one("#summary-info")
            assert table.region.right + 1 == side.region.x
            assert table.region.height == side.region.height
            assert table.region.bottom <= app.query_one("#results").content_region.bottom
            assert table.region.width / (table.region.width + side.region.width) == pytest.approx(.47, abs=.02)
            for panel in (table, side):
                assert all(edge[0] == "round" for edge in panel.styles.border)
                assert tuple(panel.styles.padding) == (1, 2, 1, 2)
            assert table.styles.background.hex == branding.INNER_SURFACE
            assert side.styles.background.hex == branding.PANEL
            assert side.styles.border_top[1].hex == branding.INDIGO
            assert table.get_component_styles("datatable--header").background.hex == branding.TUI_TABLE_HEADER
            assert [column.label.plain for column in table.ordered_columns] == ["Phase", "State", "Count", "Seconds"]
            assert table.row_count == len(PHASES)
            for index, phase in enumerate(PHASES):
                assert [cell.plain for cell in table.get_row_at(index)] == [
                    phase, original["phase_states"][phase], str(original["phase_counts"][phase]),
                    f"{original['phase_times'][phase]:.1f}",
                ]
            assert table.border_subtitle == "1 subdomains / 2 hosts / 1 unique IPs"
            separator = list(table.render_line(table.header_height + 1))
            assert separator and all(set(segment.text) == {"─"} for segment in separator)
            assert all(segment.style.color.name == branding.TUI_ROW_DIVIDER.lower() for segment in separator)

            assert plain_text(app.query_one("#footer-note", Static)) == "NO PROBES SENT"
            assert app.query_one("#footer-note").styles.color.hex == branding.TEAL
            assert app.query_one("#keys").styles.color.hex == branding.TUI_KEY_HINT
            assert app.query_one("#footer").region.bottom == size[1]
            app.query_one("#results", TabbedContent).active = "hosts-tab"
            await pilot.pause()
            assert app.query_one("#severity-counts").visible
            assert "/ saved scan / hosts" in plain_text(app.query_one("#brand", Static))
            assert app.result == original
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("size", [(80, 24), (120, 40)])
def test_finding_details_preserve_fields_and_recommendation_with_new_layout(size, tmp_path):
    async def exercise():
        app = ExposureIQApp(args("--demo"), home=True, results_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            app.result = fake_result()
            finding = app.result["assets"][0]["findings"][0]
            finding.update(severity="high", ip="192.0.2.10", port=443)
            original = deepcopy(app.result)
            app._show_results()
            app.query_one("#results", TabbedContent).active = "findings-tab"
            await pilot.pause()
            app.query_one("#findings-table", DataTable).focus()

            side = app.query_one("#finding-side")
            table = app.query_one("#findings-table", DataTable)
            assert side.border_title == "SELECTED FINDING / 01 OF 02"
            assert side.region.x == table.region.right + 1
            assert side.region.height == table.region.height
            assert "/ scan / findings" in plain_text(app.query_one("#brand", Static))
            assert plain_text(app.query_one("#finding-title", Static)) == finding["title"]
            title = [segment for segment in app.query_one("#finding-title", Static).render_line(0)
                     if segment.text.strip()]
            assert title and all(segment.style.bold for segment in title)
            assert all(segment.style.color.name == branding.TUI_HIGH.lower() for segment in title)
            detail = plain_text(app.query_one("#finding-detail", Static))
            for label, value in (("Host:", "example.com"), ("ID:", finding["id"]),
                                 ("Rule:", finding["rule"]), ("IP:", "192.0.2.10"), ("Port:", 443)):
                assert f"{label:<12}{value}" in detail
            assert finding["detail"] in detail
            assert plain_text(app.query_one("#finding-next-step", Static)) == "NEXT STEP"
            assert plain_text(app.query_one("#finding-recommendation", Static)) == f"Fix: {finding['recommendation']}"
            side.scroll_end(animate=False)
            await pilot.pause()
            assert app.query_one("#finding-recommendation").region.bottom <= side.content_region.bottom
            await pilot.press("down", "enter")
            assert side.border_title == "SELECTED FINDING / 02 OF 02"
            assert app.result == original
            await pilot.press("q")

    asyncio.run(exercise())


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 40)])
def test_unframed_home_and_running_scan_keep_control_styles(size):
    async def exercise():
        app = ExposureIQApp(args("--demo"), home=True)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            home = app.query_one("#home-center")
            assert home.region.bottom <= app.query_one("#footer").region.y
            assert not home.has_class("panel")
            assert all(not edge[0] for edge in home.styles.border)
            assert home.styles.background.a == 0
            assert tuple(home.styles.padding) == (0, 0, 0, 0)
            assert abs(home.region.x + home.region.width / 2 - size[0] / 2) <= .5
            for widget in (app.screen, app.query_one("#topbar"), app.query_one("#footer")):
                assert widget.styles.background.hex == branding.PANEL
            logo = app.query_one("#ascii-logo", Static)
            assert logo.display
            art_width = max(cell_len(line) for line in _HOME_LOGO.splitlines())
            assert art_width == 119
            assert plain_text(logo) == (_HOME_LOGO if size[0] >= art_width else "ExposureIQ")
            assert logo.region.height == len(plain_text(logo).splitlines())
            assert max(cell_len(line) for line in plain_text(logo).splitlines()) <= logo.content_region.width
            assert 0 <= logo.region.x and logo.region.right <= size[0]
            assert abs(logo.region.x + logo.region.width / 2 - size[0] / 2) <= .5
            assert logo.styles.color.hex == branding.TEAL
            assert logo.styles.text_style.bold
            strips = app.screen._compositor.render_strips()
            for y, line in enumerate(plain_text(logo).splitlines(), logo.region.y):
                assert strips[y].crop(logo.region.x, logo.region.right).text.strip() == line.strip()
            assert app.query_one("#mode-badge").styles.background.a == 0
            assert not app.query_one("#home-message").display
            app._home_message("Sample warning")
            await pilot.pause()
            assert app.query_one("#home-message").display
            assert plain_text(app.query_one("#home-message", Static)) == "Sample warning"
            app._home_message("")
            await pilot.pause()
            assert not app.query_one("#home-message").display
            for selector in ("#home-domain", "#home-scan", "#home-results", "#home-scope"):
                assert all(edge[0] == "round" for edge in app.query_one(selector).styles.border)
                assert app.query_one(selector).styles.background.a == 0
            assert all(button.styles.background.a == 0 for button in app.query(Button))
            for width, height in ((120, 40), (80, 24), (100, 30), size):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                assert plain_text(logo) == (_HOME_LOGO if width >= art_width else "ExposureIQ")
                assert max(cell_len(line) for line in plain_text(logo).splitlines()) <= logo.content_region.width
                assert logo.region.height == len(plain_text(logo).splitlines())
            app._show_scanning("example.com")  # Presentation only; no worker or probes.
            await pilot.pause()
            phases, live = app.query_one("#phase-list"), app.query_one("#live-panel")
            assert phases.region.right + 1 == live.region.x
            assert phases.region.height == live.region.height
            for panel in (phases, live):
                assert all(edge[0] == "round" for edge in panel.styles.border)
                assert tuple(panel.styles.padding) == (1, 2, 1, 2)
            assert phases.styles.background.hex == branding.INNER_SURFACE
            assert live.styles.border_top[1].hex == branding.INDIGO
            assert app.query_one("#safety").region.bottom <= app.query_one("#footer").region.y
            assert plain_text(app.query_one("#footer-note", Static)) == "NO PROBES SENT"
            assert app.worker is None
            await pilot.press("q")

    asyncio.run(exercise())


def test_scanning_screen_has_phases_live_counts_spinner_and_responsive_q():
    async def exercise():
        job = FakeJob()
        app = ExposureIQApp(args("--demo"), scan_job=job)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            assert job.entered.is_set() and job.thread_id != threading.get_ident()
            svg = app.export_screenshot(title="Scanning")
            assert "ExposureIQ" in svg and "example.com" in svg and "DEMO" in svg
            assert "quit/cancel" in svg and "Tab" in svg and "Enter" in svg
            brand = app.query_one("#brand", Static)
            assert brand.content_region.height >= 1
            assert app.query_one("#scanning").display
            assert not app.query_one("#results").display
            for index, phase in enumerate(PHASES):
                assert phase in plain_text(app.query_one(f"#phase-{index}", Static))
            assert "spinner" in plain_text(app.query_one("#phase-1", Static))
            assert "waiting" in plain_text(app.query_one("#phase-2", Static))
            assert app.query_one("#scan-progress", ProgressBar).total is None
            assert "Subdomains" in plain_text(app.query_one("#counters", Static))
            assert app.live_counts == dict(subdomains=1, hosts=2, ips=1, findings=1)
            before = plain_text(app.query_one("#elapsed", Static))
            await pilot.pause(0.2)
            assert plain_text(app.query_one("#elapsed", Static)) != before
            await pilot.press("q")
        assert app.return_value == 130 and app.control.cancelled.is_set()

    asyncio.run(exercise())


def test_results_tabs_grouped_hosts_and_finding_selection_shows_fix():
    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob(finished=True))
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert not app.query_one("#scanning").display and app.query_one("#results").display
            assert len(app.query(TabPane)) >= 6
            svg = app.export_screenshot(title="ExposureIQ DEMO results")
            assert "quit/cancel" in svg and "Tab" in svg and "Enter" in svg
            for label in ("Summary", "Subdomains", "Hosts", "Technologies", "Findings", "Ports"):
                assert label in svg
            assert "results/demo_sample.json" in plain_text(app.query_one("#summary-notes", Static))
            assert app.query_one("#hosts-table", DataTable).row_count == 1
            assert str(app.query_one("#hosts-table", DataTable).get_row_at(0)[1]) == "2"
            assert app.query_one("#subdomains-table", DataTable).row_count == 1
            assert app.query_one("#ports-table", DataTable).row_count == 1
            app.query_one("#results", TabbedContent).active = "findings-tab"
            await pilot.pause()
            app.query_one("#findings-table", DataTable).focus()
            await pilot.press("enter")
            detail = plain_text(app.query_one("#finding-detail", Static))
            recommendation = plain_text(app.query_one("#finding-recommendation", Static))
            assert "Fix: Add a Content-Security-Policy header." in recommendation
            assert "Rule:".ljust(12) + "headers.missing_csp" in detail
            assert "ID:".ljust(12) + "F-0001" in detail
            assert "[bold]saved sample detail[/bold]" in detail
            await pilot.press("down", "enter")
            detail = plain_text(app.query_one("#finding-detail", Static))
            recommendation = plain_text(app.query_one("#finding-recommendation", Static))
            assert "Fix: Hide the Server version." in recommendation
            assert "ID:".ljust(12) + "F-0002" in detail
            app.query_one("#results Tabs", Tabs).focus()
            await pilot.press("right")
            assert app.query_one("#results", TabbedContent).active == "ports-tab"
            await pilot.press("tab")
            assert app.focused is not None
            await pilot.press("q")
        assert app.return_value == 0

    asyncio.run(exercise())


def test_ctrl_c_cancels_without_a_traceback(capsys):
    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob())
        async with app.run_test() as pilot:
            await pilot.pause(0.1)
            await pilot.press("ctrl+c")
        assert app.return_value == 130 and app.control.cancelled.is_set()

    asyncio.run(exercise())
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err


def test_failed_worker_shows_clean_error_and_q_returns_one(capsys):
    def failing(*args):
        raise OSError("fake disk failure")

    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=failing)
        async with app.run_test() as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert "fake disk failure" in plain_text(app.query_one("#live-log", Static))
            await pilot.press("q")
        assert app.return_value == 1

    asyncio.run(exercise())
    assert "Traceback" not in capsys.readouterr().err


def test_tui_demo_shared_pipeline_is_fake_only_and_saves_json(monkeypatch, tmp_path):
    from exposureiq import storage

    def blocked(*args, **kwargs):
        raise AssertionError("DEMO must not load or run real discovery/probe stages")

    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", blocked)
    monkeypatch.setattr(cli, "resolve_hosts", blocked)
    monkeypatch.setattr(cli, "_load_scope", blocked)
    monkeypatch.setattr(cli, "_load_checks", blocked)
    monkeypatch.setattr(cli, "_load_ports", blocked)
    path = tmp_path / "demo_tui.json"

    async def exercise():
        app = ExposureIQApp(args("--demo", "--no-report", "-o", str(path)), stages=cli._stages())
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.result["demo"] and app.result["return_code"] == 0
            assert app.query_one("#findings-table", DataTable).row_count == 5
            assert "DEMO" in plain_text(app.query_one("#mode-badge", Static))
            assert app.query_one("#hosts-table", DataTable).row_count == 2
            await pilot.press("q")

    asyncio.run(exercise())
    snapshot = storage.load_scan(str(path))
    assert snapshot["scan_id"].startswith("DEMO-")
    assert {entry["ip"] for asset in snapshot["assets"] for entry in asset["ips"]} == {"192.0.2.10", "192.0.2.20"}


def test_tui_demo_scan_builds_report_and_shows_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "demo_tui_report.json"

    async def exercise():
        app = ExposureIQApp(args("--demo", "-o", str(path)), stages=cli._stages())
        async with app.run_test(size=(120, 40)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.result["return_code"] == 0
            assert app.result["report_to"]
            assert Path(app.result["report_to"]).is_file()
            assert "Report PDF" in plain_text(app.query_one("#summary-notes", Static))
            await pilot.press("q")

    asyncio.run(exercise())


def test_tui_restores_logging_after_quit():
    handlers = logging.getLogger().handlers[:]

    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob(finished=True))
        async with app.run_test() as pilot:
            await app.worker.wait()
            await pilot.pause()
            await pilot.press("q")

    asyncio.run(exercise())
    assert logging.getLogger().handlers == handlers


def test_standard_80_by_24_terminal_shows_all_phases_and_live_counts():
    async def exercise():
        app = ExposureIQApp(args("--demo"), scan_job=FakeJob())
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause(0.2)
            for selector in ("#phase-5", "#counters", "#elapsed", "#scan-progress", "#live-log"):
                region = app.query_one(selector).region
                assert 0 <= region.y < 22 and region.bottom <= 22
            await pilot.press("q")

    asyncio.run(exercise())


def test_tui_demo_passive_shows_active_phases_as_skipped():
    async def exercise():
        app = ExposureIQApp(args("--demo", "--passive", "--no-save"), stages=cli._stages())
        async with app.run_test(size=(80, 24)) as pilot:
            await app.worker.wait()
            await pilot.pause()
            assert app.result["phase_states"]["Web checks"] == "skipped"
            assert app.result["phase_states"]["Ports"] == "skipped"
            assert app.query_one("#findings-table", DataTable).row_count == 0
            assert "Not saved" in plain_text(app.query_one("#summary-notes", Static))
            await pilot.press("q")

    asyncio.run(exercise())


async def export_screens(directory: Path) -> list:
    """Hold a DEMO stage long enough to export the scanning SVG reliably."""
    release, entered = threading.Event(), threading.Event()
    directory.mkdir(parents=True, exist_ok=True)

    def job(args, stages, report, control, version):
        def events(event):
            report(event)
            if event["kind"] == "phase" and event["phase"] == "Subdomains" and event["state"] == "spinner":
                entered.set()
                while not release.wait(0.02):
                    control.check()
        return run_scan(args, stages, events, control, version)

    app = ExposureIQApp(args("--demo"),
                        stages=cli._stages(), control=ScanControl(), scan_job=job)
    paths = []
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        assert entered.is_set()
        path = directory / "scanning.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ DEMO — scanning"), encoding="utf-8")
        paths.append(path)
        release.set()
        await app.worker.wait()
        await pilot.pause()
        assert app.result["return_code"] == 0
        path = directory / "results.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ DEMO — results"), encoding="utf-8")
        paths.append(path)
        app.query_one("#results", TabbedContent).active = "findings-tab"
        await pilot.pause()
        app.query_one("#findings-table", DataTable).focus()
        await pilot.press("enter")
        path = directory / "findings.svg"
        path.write_text(app.export_screenshot(title="ExposureIQ DEMO — finding and Fix"), encoding="utf-8")
        paths.append(path)
        await pilot.press("q")
    return paths


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--export-screens"]:
        raise SystemExit("Use python tests/test_tui.py --export-screens")
    for path in asyncio.run(export_screens(Path("/tmp/opencode/exposureiq-s2-tui-screens"))):
        print(path)
