"""Tier 3: lazy viewer reuse, exact saved deep links and quiet fake launchers."""

import asyncio
import base64
import hashlib
import json
import socket
import subprocess
import threading
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from rich.text import Text
from textual.widgets import Button, DataTable, Input, Static, TabbedContent

from exposureiq import cli, storage
from exposureiq.ai.config import AIConfig
from exposureiq.ai.provider import FakeProvider
from exposureiq.ai.service import AIService
from exposureiq.tui import app as tui
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.domain_browser import DomainScreen
from exposureiq.viewer import browser
from exposureiq.viewer.export import view_id
from exposureiq.viewer.reader import ViewerError
from exposureiq.viewer.session import ViewerSession
from test_viewer import first_id, local_viewer, report_request, request, saved_root


def plain(widget):
    value = widget.render()
    return value.plain if isinstance(value, Text) else str(value)


@pytest.mark.parametrize("platform,outcome", [("linux", 0), ("linux", "timeout"), ("win32", 0), ("darwin", 0)])
def test_browser_launcher_is_quiet_and_does_not_claim_a_page_was_observed(monkeypatch, platform, outcome):
    calls, fallback = [], []
    url = "http://127.0.0.1:12345/?report=" + "1" * 24 + "#" + "2" * 43

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        def wait(timeout):
            assert timeout == 1
            if outcome == "timeout":
                raise subprocess.TimeoutExpired(argv, timeout)
            return outcome
        return SimpleNamespace(wait=wait)

    monkeypatch.setattr(browser.sys, "platform", platform)
    monkeypatch.setattr(browser.subprocess, "Popen", popen)
    monkeypatch.setattr(browser.webbrowser, "open", lambda url: fallback.append(url) or True)
    assert browser.open_browser(url)
    if platform == "linux":
        assert not fallback and calls[0][0] == ["xdg-open", url]
        assert calls[0][1] == {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                               "stderr": subprocess.DEVNULL, "start_new_session": True}
    else:
        assert not calls and fallback == [url]


@pytest.mark.parametrize("failure", ["missing", "nonzero"])
def test_browser_falls_back_if_linux_launcher_cannot_start(monkeypatch, failure):
    monkeypatch.setattr(browser.sys, "platform", "linux")
    def launch(*args, **kwargs):
        if failure == "missing":
            raise OSError("FAKE-RAW-LAUNCH-ERROR-ONLY")
        return SimpleNamespace(wait=lambda timeout: 1)
    fallback = []
    monkeypatch.setattr(browser.subprocess, "Popen", launch)
    monkeypatch.setattr(browser.webbrowser, "open", lambda url: fallback.append(url) or True)
    assert browser.open_browser("http://127.0.0.1:12345/#synthetic") and len(fallback) == 1
    monkeypatch.setattr(browser.webbrowser, "open", lambda url: False)
    assert not browser.open_browser("http://127.0.0.1:12345/#synthetic")


@pytest.mark.parametrize("url", ["https://127.0.0.1:12345/", "http://localhost:12345/", "http://example.com/", "file:///tmp/report.html",
                                "http://private:synthetic@127.0.0.1:12345/", "http://127.0.0.1:0/", "http://127.0.0.1:99999/", "http://127.0.0.1:12345/\n", None])
def test_browser_never_opens_an_unexpected_url(monkeypatch, url):
    monkeypatch.setattr(browser.subprocess, "Popen", lambda *a, **k: pytest.fail("Unexpected URL must not launch"))
    monkeypatch.setattr(browser.webbrowser, "open", lambda *a, **k: pytest.fail("Unexpected URL must not launch"))
    assert not browser.open_browser(url)


def test_session_reuses_one_daemon_free_port_and_stops_on_exit(saved_root):
    service = AIService(AIConfig(), use_cache=False)
    before = {path: path.read_bytes() for path in saved_root.rglob("*.json")}
    session = ViewerSession()
    assert session.server is None
    try:
        one = session.report_url("example.com", saved_root, service)
        server, thread = session.server, session.thread
        two = session.report_url("example.com", saved_root, service)
        assert one == two and session.server is server and session.thread is thread
        assert thread.daemon and thread.is_alive() and server.server_address[0] == "127.0.0.1" and server.server_port > 0
        parsed = urlsplit(one)
        assert parsed.fragment == server.token and len(parsed.fragment) == 43
        assert parse_qs(parsed.query) == {"report": [first_id(server)], "view": ["scan"]}
        assert request(server, "/api/health")[0] == 200 and request(server, "/api/health", authenticated=False)[0] == 403
        assert not service.audit
    finally:
        session.stop()
        session.stop()
    assert not thread.is_alive()
    connection = socket.socket()
    try:
        assert connection.connect_ex(("127.0.0.1", server.server_port)) != 0
    finally:
        connection.close()
    with pytest.raises(ValueError, match="stopped"):
        session.report_url("example.com", saved_root, service)
    assert before == {path: path.read_bytes() for path in saved_root.rglob("*.json")}
    other = ViewerSession()
    try:
        other.report_url("example.com", saved_root, service)
        assert other.server.token != server.token
    finally:
        other.stop()


def test_session_folder_switch_keeps_the_same_server_and_confined_reader(saved_root, tmp_path, ai_scan_factory):
    session, service = ViewerSession(), AIService(AIConfig(), use_cache=False)
    try:
        session.report_url("example.com", saved_root, service)
        server, thread = session.server, session.thread
        root = tmp_path / "other-results"
        path = root / "chosen.json"
        storage.save_scan(ai_scan_factory(9), str(path))
        session.report_url(str(path), root, service)
        assert session.server is server and session.thread is thread and server.state.root == root
        assert len(server.state.entries) == 1
        with pytest.raises(ViewerError):
            session.report_url(str(saved_root / "example.com/scan-2.json"), root, service)
        bad = tmp_path / "root-link"
        bad.symlink_to(root, target_is_directory=True)
        with pytest.raises(ViewerError, match="symlink"):
            session.report_url(str(bad / "chosen.json"), bad, service)
        assert server.state.root == root
        new_service = AIService(AIConfig(mode="demo"), provider=FakeProvider(), use_cache=False)
        session.set_service(new_service)
        assert server.state.service is new_service and not new_service.audit
    finally:
        session.stop()


def test_folder_switch_retains_the_running_request_lock(saved_root, tmp_path, ai_scan_factory):
    class Blocking(FakeProvider):
        def __init__(self):
            super().__init__()
            self.entered, self.release = threading.Event(), threading.Event()

        def complete(self, *args, **kwargs):
            self.entered.set()
            assert self.release.wait(5)
            return super().complete(*args, **kwargs)

    fake = Blocking()
    service = AIService(AIConfig(mode="demo"), provider=fake, use_cache=False)
    session, replies = ViewerSession(), []
    try:
        session.report_url("example.com", saved_root, service)
        server, old_state = session.server, session.server.state
        payload = {"scan": first_id(server), "question": "What is the worst finding?"}
        worker = threading.Thread(target=lambda: replies.append(request(server, "/api/ai/ask", method="POST", payload=payload)))
        worker.start()
        try:
            assert fake.entered.wait(3)
            other = tmp_path / "new-root"
            path = other / "selected.json"
            storage.save_scan(ai_scan_factory(8), str(path))
            session.report_url(str(path), other, service)
            assert old_state is not server.state and server.state.ai_lock is old_state.ai_lock
            assert server.state.ai_lock.locked() and server.state.report_lock is old_state.report_lock
            payload["scan"] = server.state.report_identifier(str(path))
            assert request(server, "/api/ai/ask", method="POST", payload=payload)[0] == 409
        finally:
            fake.release.set()
            worker.join(timeout=5)
        assert replies[0][0] == 200 and not server.state.ai_lock.locked() and not worker.is_alive()
    finally:
        session.stop()


@pytest.mark.parametrize("enabled", [True, False])
def test_scan_deep_link_keeps_auth_csp_off_behavior_and_no_writes(saved_root, portal_html, enabled):
    service = AIService(AIConfig(mode="demo") if enabled else AIConfig(), use_cache=False)
    before = {path: path.read_bytes() for path in saved_root.rglob("*.json")}
    with local_viewer(saved_root, service=service) as server:
        identifier = first_id(server)
        url = urlsplit(server.report_url("example.com", focus_scan=True))
        assert request(server, "/?" + url.query, authenticated=False)[0] == 200
        code, headers, raw = report_request(server, identifier, extra={"view": "scan"})
        page = raw.decode()
        expected = view_id(server.state.selected(identifier))
        assert code == 200 and f'data-start-view="{expected}"' in page
        assert server.token not in page and b"session=" not in raw
        assert ('id="export-chat"' in page) == enabled
        for script in portal_html(page).scripts:
            digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
            assert "'sha256-" + digest + "'" in headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"] and not service.audit
        assert report_request(server, identifier, extra={"view": "scan"}, session="wrong")[0] == 403
        assert report_request(server, identifier, extra={"view": "scan"}, origin="https://other.example.com")[0] == 403
        for view in ("", "home", "../../private", "scan-" + "0" * 20, '<script>bad</script>'):
            assert report_request(server, identifier, extra={"view": view})[0] == 400
        payload = urlencode({"scan": identifier, "session": server.token, "view": "scan"}) + "&view=scan"
        assert request(server, "/api/report", method="POST", authenticated=False, headers={"Content-Type": "application/x-www-form-urlencoded"}, raw=payload.encode())[0] == 400
    assert before == {path: path.read_bytes() for path in saved_root.rglob("*.json")}


def test_tui_report_button_and_h_share_viewer_from_results_ai_and_domain(tmp_path, ai_scan_factory, monkeypatch):
    root = tmp_path / "results"
    paths = []
    for index in range(2):
        path = root / "example.com" / f"scan-{index}.json"
        storage.save_scan(ai_scan_factory(index), str(path))
        paths.append(path)
    opened, notices = [], []
    monkeypatch.setattr(tui, "open_browser", lambda url: opened.append(url) or True)
    monkeypatch.setattr(cli, "_execute_scan", lambda *a, **k: pytest.fail("Report opening must not scan"))
    before = {path: path.read_bytes() for path in paths}

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(paths[0]), results_dir=root)
        app.ai_service = AIService(AIConfig(mode="demo"), provider=FakeProvider(), use_cache=False)
        app.notify = lambda message, **kwargs: notices.append((message, kwargs))
        async with app.run_test(size=(125, 46)) as pilot:
            assert app.viewer.server is None and not app.query_one("#open-html-report", Button).disabled
            assert "h Open HTML report" in plain(app.query_one("#keys", Static))
            await pilot.click("#open-html-report")
            await app.report_open_worker.wait()
            await pilot.pause()
            server, thread = app.viewer.server, app.viewer.thread
            assert len(opened) == 1 and "view=scan" in opened[0]
            assert parse_qs(urlsplit(opened[0]).query)["report"] == [server.state.report_identifier(str(paths[0]))]
            app.query_one("#results", TabbedContent).active = "ai-tab"
            await pilot.pause()
            app.query_one("#open-html-report", Button).focus()
            await pilot.press("h")
            await app.report_open_worker.wait()
            await pilot.pause()
            assert len(opened) == 2 and app.viewer.server is server and app.viewer.thread is thread
            field = app.query_one("#ai-chat-input", Input)
            field.value = ""
            field.focus()
            await pilot.press("h")
            assert field.value == "h" and len(opened) == 2
            await pilot.click("#back")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, DomainScreen)
            table = app.screen.query_one("#domain-scans", DataTable)
            table.move_cursor(row=1)
            table.focus()
            await pilot.press("h")
            await app.report_open_worker.wait()
            await pilot.pause()
            assert len(opened) == 3 and app.viewer.server is server
            assert parse_qs(urlsplit(opened[-1]).query)["report"] == [server.state.report_identifier(str(paths[0]))]
            app.screen.query_one("#domain-tabs", TabbedContent).active = "domain-ai-tab"
            await pilot.pause()
            await pilot.click("#domain-report")
            await app.report_open_worker.wait()
            await pilot.pause()
            assert len(opened) == 4 and app.viewer.server is server and not app.ai_service.audit
            app.screen.query_one("#domain-report", Button).focus()
            await pilot.press("q")
        assert not thread.is_alive() and app.return_value == 0
    asyncio.run(exercise())
    assert all(url in message for url, (message, _) in zip(opened, notices))
    assert all("Browser launch requested" in message and kwargs["markup"] is False for message, kwargs in notices)
    assert before == {path: path.read_bytes() for path in paths}


def test_tui_missing_scan_and_failed_launcher_are_honest(tmp_path, ai_scan_factory, monkeypatch):
    path = tmp_path / "saved.json"
    storage.save_scan(ai_scan_factory(), str(path))
    notices = []
    monkeypatch.setattr(tui, "open_browser", lambda url: False)

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(path), results_dir=tmp_path)
        app.ai_service = AIService(AIConfig(), use_cache=False)
        app.notify = lambda text, **kwargs: notices.append(text)
        async with app.run_test(size=(110, 38)) as pilot:
            await pilot.click("#open-html-report")
            await app.report_open_worker.wait()
            await pilot.pause()
            assert "Browser launch unavailable" in notices[-1] and "http://127.0.0.1:" in notices[-1]
            path.unlink()  # Remove only this test's synthetic fixture.
            await pilot.pause(.25)  # Textual ignores clicks during its .2s button effect.
            await pilot.click("#open-html-report")
            await app.report_open_worker.wait()
            await pilot.pause()
            assert "could not be opened safely" in notices[-1] and "http://" not in notices[-1]
    asyncio.run(exercise())
