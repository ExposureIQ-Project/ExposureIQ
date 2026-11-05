"""Copy fake selections without a network connection or real clipboard writes."""

import asyncio
import socket
import subprocess
import threading
from pathlib import Path

import pytest
from rich.cells import cell_len
from textual import events
from textual.selection import Selection
from textual.widgets import DataTable, Input, Static, TabbedContent

from exposureiq import cli, storage
from exposureiq.report import branding
from exposureiq.tui import app as tui_app
from exposureiq.tui import clipboard
from exposureiq.tui.saved import result_from_snapshot

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"
SAMPLE = "Café – api.example.com\n192.0.2.10"


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    original_connect = socket.socket.connect

    def connect(sock, address, *args, **kwargs):
        if isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "::1", "localhost"):
            return original_connect(sock, address, *args, **kwargs)
        raise AssertionError("clipboard tests must not use the network")

    def blocked(*args, **kwargs):
        raise AssertionError("clipboard tests must not use the network or real clipboard")

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(clipboard.subprocess, "run", blocked)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_TTY", "WSL_DISTRO_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    copied = []
    monkeypatch.setattr(tui_app, "copy_system_text", lambda text: copied.append(text) or True)
    return copied


def new_app(**options):
    args = cli.build_parser().parse_args(["scan", "example.com", "--demo", "--no-save", "--no-report"])
    return tui_app.ExposureIQApp(args, home=True, **options)


def saved_browser_app(tmp_path):
    directory = tmp_path / "results"
    for index in range(2):
        snapshot = storage.build_scan(f"row-{index}.example.com", [], started_at="2026-10-13T20:15:00Z")
        storage.save_scan(snapshot, str(directory / f"saved-{index}.json"))
    return new_app(results_dir=directory)


async def show_results(app, pilot, tab):
    await pilot.pause()
    app.result = result_from_snapshot(storage.load_scan(str(EXAMPLE)), EXAMPLE)
    app.result["names"] = ["api.example.com"]
    app._show_results()
    app.query_one("#results", TabbedContent).active = tab
    await pilot.pause()


def text_point(widget, value, y=0):
    line = widget.render_line(y).text
    index = line.index(value)
    gutter = widget.content_region.offset - widget.region.offset
    return gutter.x + cell_len(line[:index]), gutter.y + y


async def drag_text(pilot, widget, value, y=0, reverse=False):
    line = widget.render_line(y).text
    index = line.index(value)
    start = text_point(widget, value, y)
    gutter = widget.content_region.offset - widget.region.offset
    end = (gutter.x + cell_len(line[:index + len(value) - 1]), gutter.y + y)
    if reverse:
        start, end = end, start
    assert await pilot.mouse_down(widget, offset=start)
    assert await pilot.mouse_up(widget, offset=end)
    await pilot.pause()


async def raw_mouse(pilot, kind, widget, point):
    # Unlike Pilot.click, real terminal events have no widget and pass through
    # App.on_event, which also synthesizes chained clicks after mouse release.
    x, y = widget.region.offset + point
    pilot.app.post_message(kind(None, x, y, 0, 0, 1, False, False, False))
    await pilot.pause()


@pytest.mark.parametrize(("platform", "environment", "tool"), [
    ("linux", {"WAYLAND_DISPLAY": "wayland-1"}, "wl-copy"),
    ("linux", {"DISPLAY": ":1"}, "xclip"),
    ("linux", {"DISPLAY": ":1"}, "xsel"),
    ("darwin", {}, "pbcopy"),
    ("win32", {}, "powershell.exe"),
    ("win32", {}, "pwsh"),
    ("linux", {"WSL_DISTRO_NAME": "SampleWSL"}, "powershell.exe"),
])
def test_native_clipboard_passes_exact_unicode_text_on_stdin(monkeypatch, platform, environment, tool):
    monkeypatch.setattr(clipboard.sys, "platform", platform)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    executable = f"/tools/{tool}"
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: executable if name == tool else None)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(clipboard.subprocess, "run", run)
    assert clipboard.copy_system_text(SAMPLE)
    assert len(calls) == 1
    command, options = calls[0]
    assert command[0] == executable and SAMPLE not in command
    assert options == {"input": SAMPLE, "text": True, "encoding": "utf-8", "check": True,
                       "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                       "timeout": clipboard.TIMEOUT}
    if tool == "wl-copy":
        assert command[1:] == ["--type", "text/plain;charset=utf-8"]
    elif tool == "xclip":
        assert command[1:] == ["-selection", "clipboard", "-in"]
    elif tool == "xsel":
        assert command[1:] == ["--clipboard", "--input"]
    elif tool == "pbcopy":
        assert command == [executable]
    else:
        assert command[1:5] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
        assert "Set-Clipboard" in command[5] and "ReadToEnd()" in command[5]


@pytest.mark.parametrize("error", [OSError("missing tool"),
                                  subprocess.TimeoutExpired("xclip", clipboard.TIMEOUT),
                                  subprocess.CalledProcessError(1, "xclip")])
def test_failed_clipboard_tool_tries_the_next_backend(monkeypatch, caplog, error):
    monkeypatch.setattr(clipboard.sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":1")
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: f"/tools/{name}")
    calls = []

    def run(command, **kwargs):
        calls.append(command[0])
        if command[0].endswith("xclip"):
            raise error
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(clipboard.subprocess, "run", run)
    assert clipboard.copy_system_text(SAMPLE)
    assert calls == ["/tools/xclip", "/tools/xsel"]
    assert "Clipboard tool" in caplog.text and SAMPLE not in caplog.text


def test_missing_tools_empty_selection_and_ssh_do_not_write_a_native_clipboard(monkeypatch):
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: None)
    assert not clipboard.copy_system_text(SAMPLE)
    assert not clipboard.copy_system_text("")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-1")
    monkeypatch.setenv("SSH_CONNECTION", "saved sample")
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: f"/tools/{name}")
    assert not clipboard.copy_system_text(SAMPLE)


@pytest.mark.parametrize("value", [None, 123, []])
def test_clipboard_rejects_non_text(value):
    with pytest.raises(ValueError, match="must be a string"):
        clipboard.copy_system_text(value)


@pytest.mark.parametrize("key", ["ctrl+shift+c", "ctrl+insert"])
def test_copy_shortcut_copies_only_the_input_selection(offline, key):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            field = app.query_one("#home-domain", Input)
            field.value = "api.example.com"
            field.selection = (4, len(field.value))
            await pilot.press(key)
            await app.clipboard_worker.wait()
            assert app.clipboard == "example.com"
            assert offline == ["example.com"]
            assert field.value == "api.example.com"
            assert app.is_running and not app.control.cancelled.is_set()

    asyncio.run(exercise())


@pytest.mark.parametrize("reverse", [False, True])
def test_mouse_selection_in_a_results_table_is_copyable(offline, reverse):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            table = app.query_one("#subdomains-table", DataTable)
            assert table.allow_select
            await drag_text(pilot, table, "api.example.com", table.header_height, reverse)
            assert app.screen.get_selected_text() == "api.example.com"
            selected = [segment for segment in table.render_line(table.header_height)
                        if segment.style.bgcolor and segment.style.bgcolor.name == branding.TEAL.lower()]
            assert "".join(segment.text for segment in selected) == "api.example.com"
            assert app.clipboard_worker is not None  # No copy shortcut was pressed.
            await app.clipboard_worker.wait()
            assert app.clipboard == "api.example.com"
            assert offline == ["api.example.com"]

    asyncio.run(exercise())


@pytest.mark.parametrize("value", ["Café 界", "1.0"])
def test_selection_handles_wide_characters_and_following_columns(offline, value):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "technologies-tab")
            table = app._table("#technologies-table", ("Host", "Product", "Version", "Source"),
                               [("api.example.com", "Café 界", "1.0", "saved sample")])
            await pilot.pause()
            await drag_text(pilot, table, value, table.header_height)
            assert app.screen.get_selected_text() == value
            await app.clipboard_worker.wait()
            assert offline == [value]

    asyncio.run(exercise())


def test_copy_works_after_horizontal_and_vertical_scrolling(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(100, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            names = [f"{'w' * 63}.{'w' * 63}.row-{index}.example.com" for index in range(50)]
            table = app._table("#subdomains-table", ("Subdomain", "State"),
                               [(name, "saved sample") for name in names])
            await pilot.pause()
            table.scroll_to(x=1000, y=30, animate=False)
            await pilot.pause()
            assert table.scroll_offset.x > 0 and table.scroll_offset.y > 0
            await drag_text(pilot, table, "row-30.example.com", table.header_height)
            assert app.screen.get_selected_text() == "row-30.example.com"
            await app.clipboard_worker.wait()
            assert offline == ["row-30.example.com"]

    asyncio.run(exercise())


def test_static_text_selection_copies_and_escape_clears_it(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            widget = app.query_one("#home-note", Static)
            widget.update("Saved sample: example.com")
            await pilot.pause()
            await drag_text(pilot, widget, "example.com")
            await app.clipboard_worker.wait()
            assert offline == ["example.com"]
            await pilot.press("escape", "ctrl+shift+c")
            assert app.screen.get_selected_text() is None
            assert app.clipboard == "example.com" and offline == ["example.com"]

    asyncio.run(exercise())


def test_terminal_fallback_keeps_the_exact_local_clipboard(monkeypatch, offline):
    monkeypatch.setattr(tui_app, "copy_system_text", lambda text: False)

    async def exercise():
        app = new_app()
        notices = []
        monkeypatch.setattr(app, "notify", lambda text, **kwargs: notices.append((text, kwargs)))
        async with app.run_test(size=(120, 40)) as pilot:
            widget = app.query_one("#home-note", Static)
            widget.update(SAMPLE)
            app.screen.selections = {widget: Selection(None, None)}
            await pilot.press("ctrl+shift+c")
            await app.clipboard_worker.wait()
            assert app.clipboard == SAMPLE
            assert notices[-1][1]["severity"] == "warning"
            assert "sent to the terminal clipboard" in notices[-1][0]
            assert offline == []

    asyncio.run(exercise())


def test_empty_selection_does_not_replace_the_clipboard(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            app._clipboard = "saved sample"
            await pilot.press("ctrl+shift+c")
            assert app.clipboard == "saved sample"
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_copy_during_a_scan_does_not_cancel_but_ctrl_c_still_does(offline):
    def job(args, stages, report, control, version):
        while not control.cancelled.wait(0.02):
            control.check()
        control.check()

    async def exercise():
        args = cli.build_parser().parse_args(["scan", "example.com", "--demo", "--no-save"])
        app = tui_app.ExposureIQApp(args, scan_job=job)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            widget = app.query_one("#live-log", Static)
            widget.update("api.example.com")
            await pilot.pause()
            await drag_text(pilot, widget, "api.example.com")
            await app.clipboard_worker.wait()
            assert offline == ["api.example.com"]
            assert app.worker.is_running and not app.control.cancelled.is_set()
            await pilot.press("ctrl+c")
        assert app.return_value == 130 and app.control.cancelled.is_set()

    asyncio.run(exercise())


def test_newer_clipboard_writes_win_and_do_not_block_the_ui(monkeypatch):
    entered, release, copied = threading.Event(), threading.Event(), []
    main_thread = threading.get_ident()

    def copy(text):
        assert threading.get_ident() != main_thread
        if text == "api.example.com":
            entered.set()
            assert release.wait(3)
        copied.append(text)
        return True

    monkeypatch.setattr(tui_app, "copy_system_text", copy)

    async def exercise():
        app = new_app()
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                field = app.query_one("#home-domain", Input)
                field.value = "api.example.com"
                field.select_all()
                await pilot.press("ctrl+shift+c")
                assert await asyncio.to_thread(entered.wait, 1)
                field.value = "www.example.com"
                field.select_all()
                await pilot.press("ctrl+shift+c")
                release.set()
                await app.clipboard_worker.wait()
                assert copied == ["api.example.com", "www.example.com"]
                assert app.clipboard == "www.example.com"
        finally:
            release.set()

    asyncio.run(exercise())


@pytest.mark.parametrize("raw", [False, True])
def test_mouse_selected_input_copies_without_a_shortcut(offline, raw):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            field = app.query_one("#home-domain", Input)
            field.value = "api.example.com"
            await pilot.pause()
            start = text_point(field, "example.com")
            end = (start[0] + len("example.com"), start[1])
            if raw:
                await raw_mouse(pilot, events.MouseDown, field, start)
                await raw_mouse(pilot, events.MouseMove, field, end)
                await raw_mouse(pilot, events.MouseUp, field, end)
            else:
                await pilot.mouse_down(field, offset=start)
                await pilot.mouse_up(field, offset=end)
            await app.clipboard_worker.wait()
            assert app.clipboard == "example.com" and offline == ["example.com"]
            assert field.value == "api.example.com"

    asyncio.run(exercise())


def test_copy_waits_for_mouse_release_not_every_drag_update(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            table = app.query_one("#subdomains-table", DataTable)
            start = text_point(table, "api.example.com", table.header_height)
            end = (start[0] + len("api.example.com") - 1, start[1])
            await pilot.mouse_down(table, offset=start)
            await pilot.hover(table, offset=end)
            assert app.screen.get_selected_text() == "api.example.com"
            assert offline == [] and app.clipboard_worker is None
            await pilot.mouse_up(table, offset=end)
            await app.clipboard_worker.wait()
            assert offline == ["api.example.com"]

    asyncio.run(exercise())


@pytest.mark.parametrize(("tab", "selector", "columns", "row", "clicked", "expected"), [
    ("subdomains-tab", "#subdomains-table", ("Subdomain", "Active checks"),
     ("api.example.com", "saved sample"), "saved sample", "api.example.com"),
    ("technologies-tab", "#technologies-table", ("Host", "Product", "Version", "Source"),
     ("api.example.com", "SampleServer", "1.0", "saved sample"), "SampleServer", "api.example.com"),
    ("findings-tab", "#findings-table", ("Severity", "Host", "Finding"),
     ("HIGH", "api.example.com", "Saved sample"), "HIGH", "api.example.com"),
    ("hosts-tab", "#hosts-table", ("IP", "Host count", "Hosts"),
     ("192.0.2.10", "2", "api.example.com, mail.example.com"), "192.0.2.10", "api.example.com"),
    ("ports-tab", "#ports-table", ("IP", "Port", "Protocol", "Service"),
     ("192.0.2.10", "443", "tcp", "https"), "https", "192.0.2.10"),
])
def test_double_click_copies_only_the_row_hostname_or_ip(offline, tab, selector, columns, row, clicked, expected):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, tab)
            table = app._table(selector, columns, [row])
            await pilot.pause()
            await pilot.click(table, offset=text_point(table, clicked, table.header_height), times=2)
            await app.clipboard_worker.wait()
            assert app.clipboard == expected and offline == [expected]
            assert app.screen.get_selected_text() is None
            assert app.screen.selections == {}

    asyncio.run(exercise())


def test_raw_double_click_after_scrolling_copies_the_full_long_hostname(offline):
    host = f"{'w' * 63}.{'x' * 63}.{'y' * 63}.{'z' * 49}.example.com"
    assert len(host) == 253

    async def exercise():
        app = new_app()
        async with app.run_test(size=(100, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            rows = [(f"row-{index}.example.com", "saved sample") for index in range(50)]
            rows[30] = (host, "saved sample")
            table = app._table("#subdomains-table", ("Subdomain", "Active checks"), rows)
            await pilot.pause()
            table.scroll_to(x=1000, y=30, animate=False)
            await pilot.pause()
            assert table.scroll_offset.x > 0 and table.scroll_offset.y > 0
            point = text_point(table, "saved sample", table.header_height)
            for _ in range(2):
                await raw_mouse(pilot, events.MouseDown, table, point)
                await raw_mouse(pilot, events.MouseUp, table, point)
            await app.clipboard_worker.wait()
            assert app.clipboard == host and offline == [host]
            assert table.cursor_row == 30
            assert app.screen.get_selected_text() is None

    asyncio.run(exercise())


def test_repeated_raw_drags_copy_the_exact_selection_not_the_whole_row(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            table = app.query_one("#subdomains-table", DataTable)
            start = text_point(table, "example.com", table.header_height)
            end = (start[0] + len("example.com") - 1, start[1])
            for _ in range(2):
                await raw_mouse(pilot, events.MouseDown, table, start)
                await raw_mouse(pilot, events.MouseMove, table, end)
                await raw_mouse(pilot, events.MouseUp, table, end)
                await app.clipboard_worker.wait()
            assert offline == ["example.com", "example.com"]
            assert app.clipboard == app.screen.get_selected_text() == "example.com"

    asyncio.run(exercise())


def test_double_click_on_headers_or_empty_rows_copies_nothing(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            table = app.query_one("#subdomains-table", DataTable)
            gutter = table.content_region.offset - table.region.offset
            for point in (text_point(table, "Subdomain"), (gutter.x + 1, gutter.y + 4)):
                await pilot.click(table, offset=point, times=2)
                assert app.screen.get_selected_text() is None
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_triple_click_never_selects_the_table_or_parent(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            table = app.query_one("#subdomains-table", DataTable)
            await pilot.click(table, offset=text_point(table, "api.example.com", table.header_height), times=3)
            await app.clipboard_worker.wait()
            assert offline == ["api.example.com"]
            assert app.screen.selections == {}

    asyncio.run(exercise())


def test_single_click_only_moves_the_table_cursor(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "subdomains-tab")
            table = app._table("#subdomains-table", ("Subdomain", "Active checks"),
                               [("api.example.com", "saved sample"), ("mail.example.com", "saved sample")])
            await pilot.pause()
            await pilot.click(table, offset=text_point(table, "mail.example.com", table.header_height + 1))
            assert table.cursor_row == 1
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_summary_double_click_does_not_copy_phase_status_or_select_all(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await show_results(app, pilot, "summary-tab")
            table = app.query_one("#phase-counts", DataTable)
            await pilot.click(table, offset=text_point(table, "Scope", table.header_height), times=2)
            assert app.screen.selections == {}
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


@pytest.mark.parametrize("size", [(120, 40), (60, 24)])
@pytest.mark.parametrize("mode", ["home", "results"])
def test_auto_copy_shows_a_small_top_right_toast_without_moving_the_layout(offline, size, mode):
    async def exercise():
        app = new_app()
        async with app.run_test(size=size, notifications=True) as pilot:
            if mode == "results":
                await show_results(app, pilot, "subdomains-tab")
                widget = app.query_one("#subdomains-table", DataTable)
                y = widget.header_height
            else:
                widget = app.query_one("#home-note", Static)
                widget.update("Saved sample: example.com")
                y = 0
            await pilot.pause()
            topbar = app.query_one("#topbar").region
            await drag_text(pilot, widget, "example.com", y)
            await app.clipboard_worker.wait()
            await pilot.pause()
            toasts = list(app.query("Toast"))
            assert len(toasts) == 1
            toast = toasts[0]
            assert toast.render().plain == "Text copied"
            assert toast.region.y == topbar.bottom + 1 and toast.region.right == size[0] - 1
            assert toast.region.width <= 24 and toast.region.height == 3
            for selector in ("#topbar", "#brand", "#mode-badge", "#export-report"):
                header_widget = app.query_one(selector)
                if header_widget.display:
                    assert not toast.region.overlaps(header_widget.region)
            assert app.query_one("#topbar").region == topbar
            assert offline == ["example.com"]

    asyncio.run(exercise())


def test_static_double_click_copies_once_without_a_shortcut(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            widget = app.query_one("#home-note", Static)
            widget.update("Café – example.com")
            await pilot.pause()
            await pilot.click(widget, offset=text_point(widget, "example.com"), times=2)
            await app.clipboard_worker.wait()
            assert app.clipboard == "Café – example.com" and offline == ["Café – example.com"]

    asyncio.run(exercise())


def test_clicking_unrelated_text_does_not_copy_a_focused_input_selection(offline):
    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40)) as pilot:
            field = app.query_one("#home-domain", Input)
            field.value = "api.example.com"
            field.select_all()
            widget = app.query_one("#home-note", Static)
            widget.update("Saved sample")
            await pilot.pause()
            await pilot.click(widget, offset=text_point(widget, "Saved sample"))
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_auto_copy_fallback_does_not_claim_desktop_copy_succeeded(monkeypatch, offline):
    monkeypatch.setattr(tui_app, "copy_system_text", lambda text: False)

    async def exercise():
        app = new_app()
        async with app.run_test(size=(120, 40), notifications=True) as pilot:
            widget = app.query_one("#home-note", Static)
            widget.update("Saved sample: example.com")
            await pilot.pause()
            await drag_text(pilot, widget, "example.com")
            await app.clipboard_worker.wait()
            await pilot.pause()
            toast = app.query_one("Toast")
            assert toast.has_class("-warning")
            assert "terminal clipboard" in toast.render().plain and "Text copied" not in toast.render().plain
            assert app.clipboard == "example.com" and offline == []

    asyncio.run(exercise())


@pytest.mark.parametrize("row_index", [0, 1])
@pytest.mark.parametrize("column", [0, 1, 2])
def test_saved_browser_double_click_opens_once_without_copying(tmp_path, monkeypatch, offline, row_index, column):
    async def exercise():
        app = saved_browser_app(tmp_path)
        opened = []
        original_open = app.open_saved
        monkeypatch.setattr(app, "open_saved", lambda path: opened.append(str(path)) or original_open(path))
        async with app.run_test(size=(120, 40), notifications=True) as pilot:
            await pilot.click("#home-results")
            table = app.query_one("#saved-table", DataTable)
            expected = Path(app.saved_paths[str(row_index)])
            before = expected.read_bytes()
            value = table.get_row_at(row_index)[column].plain
            assert not table.allow_select
            await pilot.click(table, offset=text_point(table, value, table.header_height + row_index), times=2)
            await pilot.pause()
            assert app.mode == "results" and app.result["saved_to"] == str(expected)
            assert opened == [str(expected)] and expected.read_bytes() == before
            assert app.worker is None and app.clipboard_worker is None
            assert offline == [] and not app.query("Toast")
            assert app.screen.selections == {}

    asyncio.run(exercise())


def test_saved_browser_single_click_only_chooses_a_row(tmp_path, offline):
    async def exercise():
        app = saved_browser_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.click("#home-results")
            table = app.query_one("#saved-table", DataTable)
            for row_index in (0, 1, 0):
                value = table.get_row_at(row_index)[0].plain
                await pilot.click(table, offset=text_point(table, value, table.header_height + row_index))
                assert table.cursor_row == row_index
                assert app.mode == "browser" and app.result is None
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


@pytest.mark.parametrize("action", ["enter", "button"])
def test_saved_browser_enter_and_open_button_still_open_without_copying(tmp_path, offline, action):
    async def exercise():
        app = saved_browser_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.click("#home-results")
            table = app.query_one("#saved-table", DataTable)
            expected = app.saved_paths["1"]
            value = table.get_row_at(1)[0].plain
            await pilot.click(table, offset=text_point(table, value, table.header_height + 1))
            assert app.mode == "browser"
            if action == "enter":
                await pilot.press("enter")
            else:
                await pilot.click("#saved-open")
            await pilot.pause()
            assert app.mode == "results" and app.result["saved_to"] == str(expected)
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_saved_browser_headers_and_empty_rows_do_not_open_or_copy(tmp_path, offline):
    async def exercise():
        app = saved_browser_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.click("#home-results")
            table = app.query_one("#saved-table", DataTable)
            gutter = table.content_region.offset - table.region.offset
            for point in (text_point(table, "File"), (gutter.x + 1, gutter.y + 5)):
                await pilot.click(table, offset=point, times=2)
                assert app.mode == "browser" and app.result is None
                assert app.screen.selections == {}
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_saved_browser_drag_does_not_select_or_copy_text(tmp_path, offline):
    async def exercise():
        app = saved_browser_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.click("#home-results")
            table = app.query_one("#saved-table", DataTable)
            value = table.get_row_at(0)[1].plain
            await drag_text(pilot, table, value, table.header_height)
            assert app.mode == "browser" and app.result is None
            assert app.screen.selections == {}
            assert offline == [] and app.clipboard_worker is None

    asyncio.run(exercise())


def test_saved_browser_raw_double_click_opens_the_clicked_file_without_copying(tmp_path, offline):
    async def exercise():
        app = saved_browser_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.click("#home-results")
            table = app.query_one("#saved-table", DataTable)
            expected = app.saved_paths["1"]
            value = table.get_row_at(1)[1].plain
            point = text_point(table, value, table.header_height + 1)
            for _ in range(2):
                await raw_mouse(pilot, events.MouseDown, table, point)
                await raw_mouse(pilot, events.MouseUp, table, point)
            assert app.mode == "results" and app.result["saved_to"] == str(expected)
            assert offline == [] and app.clipboard_worker is None
            assert app.screen.selections == {}

    asyncio.run(exercise())
