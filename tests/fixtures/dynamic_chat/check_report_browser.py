"""Real Firefox check of the TUI's reused viewer and authenticated deep link."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from capture_transcripts import loopback_only
from dynamic_chat_fakes import acceptance_scan
from exposureiq import storage
from exposureiq.ai.config import AIConfig
from exposureiq.ai.provider import FakeProvider
from exposureiq.ai.service import AIService
from exposureiq.viewer.export import view_id
from exposureiq.viewer.session import ViewerSession
import scripts.stage5_firefox_check as firefox

OUT = Path(__file__).parent


def navigate(browser, url, expected):
    browser.script("window.__previousReportCapture = true;")
    browser.command("WebDriver:Navigate", {"url": url})
    browser.wait("window.__previousReportCapture !== true && document.getElementById('report-main') && document.getElementById('report-main').dataset.startView === '" + expected + "' && location.hash === '#" + expected + "' && document.getElementById('" + expected + "').classList.contains('is-active')")
    browser.wait("Number(getComputedStyle(document.getElementById('" + expected + "').querySelector('.page')).opacity) >= .99")


def main():
    loopback_only()
    firefox.os = SimpleNamespace(environ={"HOME": "/tmp/opencode", "PATH": "/usr/bin:/bin"})
    checks, pictures = [], []
    with tempfile.TemporaryDirectory(prefix="s5-report-browser-", dir="/tmp/opencode") as temporary:
        root = Path(temporary) / "results"
        older, newer = acceptance_scan(), copy.deepcopy(acceptance_scan())
        older["scan_id"], older["started_at"] = "synthetic-report-before", "2026-01-01T00:00:00Z"
        newer["scan_id"], newer["started_at"] = "synthetic-report-after", "2026-01-02T00:00:00Z"
        paths = [root / "example.com" / "before.json", root / "example.com" / "after.json"]
        for scan, path in zip((older, newer), paths):
            storage.save_scan(scan, str(path))
        before = {path: path.read_bytes() for path in paths}
        session, fake = ViewerSession(), FakeProvider()
        try:
            service = AIService(AIConfig(), provider=fake, use_cache=False)
            url = session.report_url(str(paths[0]), root, service)
            server, thread = session.server, session.thread
            with firefox.Firefox() as browser:
                navigate(browser, url, view_id(older))
                assert browser.script("return !document.getElementById('export-chat-toggle') && !document.getElementById('exposureiq-chat-data') && document.getElementById('" + view_id(older) + "').textContent.includes('synthetic-report-before');")
                browser.screenshot(OUT / "report-open-off.png")
                pictures.append("report-open-off.png")
                checks += ["authenticated TUI URL opens the exact older scan", "token removed from the address after native handoff", "AI-Off report has no chat or chat metadata"]

                live = AIService(AIConfig(mode="demo"), provider=fake, use_cache=False)
                session.set_service(live)
                next_url = session.report_url(str(paths[1]), root, live)
                assert session.server is server and session.thread is thread and server.state.service is live
                navigate(browser, next_url, view_id(newer))
                browser.wait("window.ExposureIQLiveChat && !document.getElementById('export-chat-toggle').hidden && !document.getElementById('export-chat-input').disabled")
                assert browser.script("return document.getElementById('export-chat-scan').value === '" + view_id(newer) + "';")
                browser.screenshot(OUT / "report-open-live.png")
                pictures.append("report-open-live.png")
                assert fake.calls == 0 and not service.audit and not live.audit
                checks += ["repeated opening keeps one daemon server and port", "TUI settings update the existing viewer service", "live scan selection matches the authenticated deep link", "opening/health make no model call"]
                browser.script("document.getElementById('export-chat-toggle').click(); document.getElementById('export-chat-options-toggle').click();")
                session.stop()
                browser.script("const done=arguments[arguments.length-1]; window.ExposureIQLiveChat.checkHealth().then(done);", asynchronous=True)
                assert not thread.is_alive() and browser.script("return document.getElementById('export-chat-send').disabled && document.getElementById('export-live-status').textContent.includes('No answer is generated here');")
                checks.append("session shutdown stops the real listener and disables the browser chat")
            assert before == {path: path.read_bytes() for path in paths}
            checks.append("saved scan bytes unchanged; no disk report generated")
        finally:
            session.stop()
    result = {"passed": True, "browser": "installed headless Firefox; not a native phone or OS-default-browser test",
              "checks": checks, "network": "loopback only; isolated browser profile refuses non-loopback HTTP", "model_calls": 0,
              "files": [{"file": name, "bytes": (OUT / name).stat().st_size, "sha256": hashlib.sha256((OUT / name).read_bytes()).hexdigest()} for name in pictures],
              "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                  "exposureiq/cli.py", "exposureiq/tui/app.py", "exposureiq/tui/domain_browser.py", "exposureiq/viewer/browser.py", "exposureiq/viewer/session.py",
                  "exposureiq/viewer/server.py", "exposureiq/viewer/export.py", "exposureiq/viewer/static/app.js", "exposureiq/viewer/static/live-chat.js", "exposureiq/viewer/static/report-session.js", "exposureiq/report/html.py")}}
    (OUT / "tier3-browser.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Firefox: {len(checks)} report lifecycle/deep-link checks passed; {len(pictures)} real screenshots captured.")


if __name__ == "__main__":
    main()
