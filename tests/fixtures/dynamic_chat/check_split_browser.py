"""Real Firefox layout/security evidence; no browser package or real AI.

Uses the already-installed browser and the existing local Firefox protocol
helper. Only synthetic scans, a fake model endpoint and loopback HTTP are used.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from capture_transcripts import loopback_only
from dynamic_chat_fakes import acceptance_scan, small_model_server
from exposureiq import storage
from exposureiq.ai.config import AIConfig
from exposureiq.ai.policy import RateLimiter
from exposureiq.ai.service import AIService
from exposureiq.viewer import make_server
import scripts.stage5_firefox_check as firefox

OUT = Path(__file__).parent


def key(browser, value):
    browser.command("WebDriver:PerformActions", {"actions": [{"type": "key", "id": "keyboard", "actions": [
        {"type": "keyDown", "value": value}, {"type": "keyUp", "value": value}]}]})


def layout(browser):
    return browser.script("""const report = document.getElementById('report-pane'), chat = document.getElementById('export-chat');
      const r = report.getBoundingClientRect(), c = chat.getBoundingClientRect();
      return {viewport:[innerWidth,innerHeight], report:[r.x,r.y,r.width,r.height], chat:[c.x,c.y,c.width,c.height],
        font:getComputedStyle(chat).fontSize, report_scroll:getComputedStyle(report).overflowY,
        chat_scroll:getComputedStyle(document.getElementById('export-chat-log')).overflowY,
        report_inert:report.inert, modal:chat.getAttribute('aria-modal')};""")


def navigate_report(browser, url):
    # WebDriver's first navigation is the authenticated handoff document; its
    # form submission is another navigation. An old report can still satisfy
    # the same hash/DOM checks until that submission finishes.
    browser.script("window.__previousSplitCaptureDocument = true; if(document.getElementById('report-main')) document.getElementById('report-main').dataset.previousCapture='yes';")
    browser.command("WebDriver:Navigate", {"url": url})
    browser.wait("window.__previousSplitCaptureDocument !== true && window.ExposureIQLiveChat && location.pathname === '/api/report' && document.getElementById('report-main')?.dataset.previousCapture !== 'yes' && document.getElementById('export-chat-toggle') && !document.getElementById('export-chat-toggle').hidden && !document.getElementById('export-chat-input').disabled && location.hash === '#domain-home'")
    browser.wait("(() => {const cover=document.querySelector('#domain-home .cover'); return cover && cover.getBoundingClientRect().width > 0 && Number(getComputedStyle(cover).opacity) >= .99;})()")


def run():
    loopback_only()
    # Do not pass provider-key environment variables or a user's browser profile
    # to Firefox. Its fresh profile already refuses non-loopback HTTP traffic.
    firefox.os = SimpleNamespace(environ={"HOME": "/tmp/opencode", "PATH": "/usr/bin:/bin"})
    entered, release = threading.Event(), threading.Event()
    block = [False]
    reply_shape = ["tagged"]

    def shape(attempt, pack):
        if block[0]:
            entered.set()
            if not release.wait(10):
                raise RuntimeError("The synthetic browser reply was not released.")
        return reply_shape[0]

    checks, pictures = [], []
    with tempfile.TemporaryDirectory(prefix="s5-split-browser-", dir="/tmp/opencode") as temporary, small_model_server(shape) as (url, calls):
        scan = acceptance_scan()
        scan["assets"][0]["findings"][0]["detail"] = '</script><script>window.__s5injected=true</script><img src="https://assets.example.com/inert">'
        root = Path(temporary) / "results"
        path = root / "example.com" / "synthetic.json"
        storage.save_scan(scan, str(path))
        before = path.read_bytes()
        service = AIService(AIConfig(mode="local", base_url=url, model="synthetic-small-model"), use_cache=False)
        service.limiter = RateLimiter(limit=100)
        server = make_server(root, port=0, service=service)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        stopped = False
        try:
            with firefox.Firefox() as browser:
                navigate_report(browser, server.report_url(str(path)))
                assert not calls and browser.script("return window.__s5injected === undefined && !document.querySelector('img[src^=\"https:\"]');")
                browser.script("document.querySelector('.scan-card').click();")
                browser.wait("document.querySelector('.scan-view.is-active')")
                try:
                    browser.wait("(() => { const toggle=document.getElementById('export-chat-toggle'), chat=document.getElementById('export-chat'); if (!toggle || toggle.hidden || location.hash !== '#domain-home' && !location.hash.startsWith('#scan-')) return false; if (chat.hidden) toggle.click(); return document.body.classList.contains('chat-open') && !document.getElementById('export-chat-input').disabled; })()")
                except RuntimeError:
                    print("Safe open-state diagnostic:", browser.script("return {chat_hidden:document.getElementById('export-chat')?.hidden,toggle_hidden:document.getElementById('export-chat-toggle')?.hidden,body_open:document.body.classList.contains('chat-open'),source:document.getElementById('export-chat-source')?.textContent,settings_status:document.getElementById('export-live-status')?.textContent};"), flush=True)
                    raise
                desktop = layout(browser)
                assert abs(desktop["report"][2] - desktop["chat"][2]) < 2
                assert desktop["font"] == "16px" and desktop["report_scroll"] == desktop["chat_scroll"] == "auto"
                assert desktop["report_inert"] is False and desktop["modal"] == "false"
                assert browser.script("return document.getElementById('export-chat-ideas').children.length === 3 && !document.getElementById('export-chat-options').getClientRects().length;")
                checks += ["opening and health make no model call", "escaped saved injection remains inert", "default desktop 50/50 and 16px chat", "independent report/chat scroll containers", "three empty-only suggestions"]

                # Shift+Enter inserts a real newline without sending; Enter sends.
                browser.script("const input=document.getElementById('export-chat-input'); input.value='What is the worst finding?'; input.focus();")
                browser.command("WebDriver:PerformActions", {"actions": [{"type": "key", "id": "keyboard", "actions": [
                    {"type": "keyDown", "value": "\ue008"}, {"type": "keyDown", "value": "\ue007"},
                    {"type": "keyUp", "value": "\ue007"}, {"type": "keyUp", "value": "\ue008"}]}]})
                assert browser.script("return document.getElementById('export-chat-input').value.includes('\\n');") and not calls
                browser.script("document.getElementById('export-chat-input').value='what is the most bad finding here in this scan?';")
                block[0] = True
                key(browser, "\ue007")
                assert entered.wait(5)
                browser.wait("document.getElementById('export-chat-stage').textContent === 'Phrasing your answer'")
                browser.screenshot(OUT / "split-stage.png")
                pictures.append("split-stage.png")
                block[0] = False
                release.set()
                browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelector('.export-chat-reply').textContent.includes('Live AI')")
                assert browser.script("return document.getElementById('export-chat-ideas').hidden && document.querySelectorAll('.export-chat-evidence').length === 1 && !document.querySelector('.export-chat-evidence').open;")
                assert browser.script("return document.querySelector('.export-chat-reply pre').textContent.includes('database') && !document.querySelector('.export-chat-reply pre').textContent.includes('[R:') && document.querySelector('.export-chat-checked').textContent === 'Facts checked against your saved scan';")
                browser.screenshot(OUT / "split-desktop.png")
                pictures.append("split-desktop.png")
                checks += ["native Enter sends and Shift+Enter adds a newline", "actual blocked phraser stage displayed", "per-message live badge and bounded facts note", "one collapsed Evidence row with hidden inline tags"]
                browser.script("document.querySelector('.export-chat-reply-actions button').click();")
                browser.wait("document.querySelector('.export-chat-reply-actions button').textContent === 'Copied' || document.getElementById('export-chat-status').textContent.includes('selected for you to copy')")
                copied = browser.script("return document.querySelector('.export-chat-reply-actions button').textContent === 'Copied';")
                if not copied:
                    assert browser.script("return getSelection().toString() === document.querySelector('.export-chat-reply pre').textContent;")
                copy_result = "browser clipboard write acknowledged" if copied else "manual-copy selection fallback observed; OS clipboard not tested"
                checks.append("Copy answer: " + copy_result)

                browser.script("document.getElementById('export-chat-options-toggle').click();")
                assert browser.script("return !document.getElementById('export-chat-options').hidden && document.activeElement.id === 'export-chat-scan';")
                for name in ("Scan", "Wording", "Ideas to ask", "Check settings", "Clear chat"):
                    assert name in browser.script("return document.getElementById('export-chat-options').textContent;")
                browser.screenshot(OUT / "split-menu.png")
                pictures.append("split-menu.png")
                key(browser, "\ue00c")
                assert browser.script("return document.getElementById('export-chat-options').hidden && !document.getElementById('export-chat').hidden && document.activeElement.id === 'export-chat-options-toggle';")
                checks.append("one options menu and Escape focus restoration")

                reply_shape[0] = "prose"
                browser.script("document.getElementById('export-chat-input').value='then how can i fix it?'; document.getElementById('export-chat-send').click();")
                browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelector('.export-chat-retry')")
                fallback = browser.script("return document.querySelectorAll('.export-chat-reply')[1].textContent;")
                assert "Built-in answer" in fallback and "usable format" in fallback and "Offline mode" not in fallback
                browser.screenshot(OUT / "split-fallback.png")
                pictures.append("split-fallback.png")
                reply_shape[0] = "tagged"
                browser.script("document.getElementById('export-chat-input').value='what does SMB mean?'; document.getElementById('export-chat-send').click();")
                browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelectorAll('.export-chat-turn').length === 3")
                browser.script("document.querySelector('.export-chat-retry').click();")
                browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelectorAll('.export-chat-turn').length === 4")
                assert browser.script("const last=[...document.querySelectorAll('.export-chat-reply')].at(-1).textContent; return last.includes('Live AI') && last.includes('database') && !last.includes('SMB');")
                checks.append("labelled provider fallback and Try again retains database focus after SMB")

                width, height = desktop["viewport"]
                browser.command("WebDriver:PerformActions", {"actions": [{"type": "pointer", "id": "mouse", "parameters": {"pointerType": "mouse"}, "actions": [
                    {"type": "pointerMove", "duration": 0, "x": int(width / 2), "y": int(height / 2)},
                    {"type": "pointerDown", "button": 0},
                    {"type": "pointerMove", "duration": 200, "x": int(width * .65), "y": int(height / 2)},
                    {"type": "pointerUp", "button": 0}]}]})
                ratio = browser.script("return Number(document.getElementById('export-chat-divider').getAttribute('aria-valuenow'));")
                assert 64 <= ratio <= 66
                browser.script("document.getElementById('export-chat-divider').focus();")
                key(browser, "\ue010")  # End: 70 percent.
                assert browser.script("return document.getElementById('export-chat-divider').getAttribute('aria-valuenow');") == "70"
                key(browser, "\ue012")  # Left: reduce without crossing the bound.
                browser.script("document.getElementById('export-chat-divider').dispatchEvent(new KeyboardEvent('keydown',{key:'Home',bubbles:true}));")
                assert browser.script("return document.getElementById('export-chat-divider').getAttribute('aria-valuenow');") == "30"
                print("Before handoff layout storage:", browser.script("return {ratio:document.getElementById('export-chat-divider').getAttribute('aria-valuenow'),saved:sessionStorage.getItem('exposureiq-report-split')};"), flush=True)
                # Navigate through the authenticated handoff again to prove the
                # tab-only preference is restored by a newly loaded document.
                navigate_report(browser, server.report_url(str(path)))
                print("After handoff layout storage:", browser.script("return {ratio:document.getElementById('export-chat-divider').getAttribute('aria-valuenow'),saved:sessionStorage.getItem('exposureiq-report-split')};"), flush=True)
                assert browser.script("return document.getElementById('export-chat-divider').getAttribute('aria-valuenow');") == "30"
                assert browser.script("return Object.keys(sessionStorage);") == ["exposureiq-report-split"]
                browser.script("document.getElementById('export-chat-toggle').click(); document.getElementById('export-chat-divider').dispatchEvent(new MouseEvent('dblclick',{bubbles:true}));")
                browser.wait("document.body.classList.contains('chat-open') && !document.getElementById('export-chat-send').disabled")
                checks.append("real divider drag, keyboard 30–70 bounds and tab-only persistence")

                # Follow-ups use the same server chat. Long UI text gives a
                # meaningful non-disruptive scrolling check without any model.
                browser.script("document.getElementById('export-chat-input').value='Explain this scan in simple words.'; document.getElementById('export-chat-send').click();")
                try:
                    browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelectorAll('.export-chat-turn').length === 1")
                except RuntimeError:
                    print("Safe send-state diagnostic:", browser.script("return {turns:document.querySelectorAll('.export-chat-turn').length,disabled:document.getElementById('export-chat-send').disabled,status:document.getElementById('export-chat-status').textContent,stage:document.getElementById('export-chat-stage').textContent,source:document.getElementById('export-chat-source').textContent,settings_status:document.getElementById('export-live-status').textContent};"), "fake requests:", len(calls), flush=True)
                    raise
                browser.script("const log=document.getElementById('export-chat-log'); for(let i=0;i<10;i++){const p=document.createElement('p');p.textContent='Synthetic old answer for scroll testing. '.repeat(20);log.append(p);} log.scrollTop=0;")
                browser.script("document.getElementById('export-chat-input').value='what do you think?'; document.getElementById('export-chat-send').click();")
                browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelectorAll('.export-chat-turn').length === 2")
                assert browser.script("return document.getElementById('export-chat-log').scrollTop;") < 2
                browser.script("document.getElementById('report-pane').scrollTop=240; document.getElementById('export-chat-close').click();")
                assert browser.script("return !document.body.classList.contains('chat-open') && document.activeElement.id === 'export-chat-toggle';")
                assert abs(browser.script("return window.scrollY;") - 240) < 3
                checks += ["new reply does not pull a reader down from old answers", "close restores full-width report, scroll and toggle focus"]

                browser.command("WebDriver:SetWindowRect", {"width": 500, "height": 900})
                browser.script("document.getElementById('export-chat-toggle').click();")
                narrow = layout(browser)
                assert narrow["viewport"][0] < 900 and narrow["report_inert"] is True and narrow["modal"] == "true"
                assert abs(narrow["chat"][2] - narrow["viewport"][0]) < 2 and abs(narrow["chat"][3] - narrow["viewport"][1]) < 2
                assert browser.script("const r=document.querySelector('.export-chat-compose').getBoundingClientRect(); return r.bottom <= innerHeight && r.top >= 0;")
                browser.script("document.getElementById('export-chat-options-toggle').focus();")
                browser.command("WebDriver:PerformActions", {"actions": [{"type": "key", "id": "keyboard", "actions": [
                    {"type": "keyDown", "value": "\ue008"}, {"type": "keyDown", "value": "\ue004"},
                    {"type": "keyUp", "value": "\ue004"}, {"type": "keyUp", "value": "\ue008"}]}]})
                assert browser.script("return document.activeElement.id === 'export-chat-send';")
                browser.screenshot(OUT / "split-narrow.png")
                pictures.append("split-narrow.png")
                checks += ["narrow full-screen chat and visible sticky composer", "narrow modal focus stays out of the inert report"]

                # A browser/server error must never produce a prepared answer.
                browser.script("document.getElementById('export-chat-options-toggle').click(); document.getElementById('export-chat-clear').click(); window.__originalFetch=window.fetch; window.fetch=(path,opts)=>String(path)==='/api/ai/ask'?Promise.resolve(new Response('{}',{status:403})):window.__originalFetch(path,opts);")
                browser.script("document.getElementById('export-chat-input').value='what is the worst finding?'; document.getElementById('export-chat-send').click();")
                browser.wait("!document.getElementById('export-chat-send').disabled && document.querySelector('.export-chat-reply').textContent.includes('Reply unavailable')")
                failure = browser.script("return document.querySelector('.export-chat-reply').textContent;")
                assert "No reply was generated by this page" in failure and "No prepared answer was substituted" in failure and "database" not in failure.lower()
                browser.script("window.fetch=window.__originalFetch; delete window.__originalFetch;")
                checks.append("browser authentication failure displays error, never a prepared answer")
                key(browser, "\ue00c")
                assert browser.script("return document.getElementById('export-chat').hidden && !document.getElementById('report-pane').inert;")
                browser.script("document.getElementById('export-chat-toggle').click(); document.getElementById('export-chat-options-toggle').click();")
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
                stopped = True
                browser.script("const done=arguments[arguments.length-1]; window.ExposureIQLiveChat.checkHealth().then(done);", asynchronous=True)
                down = browser.script("return document.getElementById('export-live-status').textContent;")
                assert "No answer is generated here" in down
                assert browser.script("return document.getElementById('export-chat-send').disabled;")
                checks.append("actual stopped local server disables chat without substituting an answer")
                assert browser.script("return window.__s5injected === undefined && !document.querySelector('img[src^=\"https:\"]');")
            assert path.read_bytes() == before
            assert all("response_format" not in item["payload"] and "tools" not in item["payload"] for item in calls)
        finally:
            release.set()
            if not stopped:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
    result = {"passed": True, "browser": "installed Firefox, real headless browser; not a native phone", "desktop": desktop, "narrow": narrow,
              "checks": checks, "copy_result": copy_result, "model_requests": len(calls), "real_model_tested": False,
              "network": "loopback Python sockets only; fresh browser profile sends non-loopback HTTP to a refusing loopback proxy", "server_down_text": down,
              "files": [{"file": name, "bytes": (OUT / name).stat().st_size, "sha256": hashlib.sha256((OUT / name).read_bytes()).hexdigest()} for name in pictures],
              "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                  "exposureiq/report/html.py", "exposureiq/viewer/export.py", "exposureiq/viewer/server.py", "exposureiq/viewer/static/live-chat.js", "exposureiq/viewer/static/live-chat.css")}}
    (OUT / "tier2-browser.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Firefox: {len(checks)} checks passed; {len(pictures)} real screenshots captured.")
    print("Desktop viewport:", desktop["viewport"], "Narrow viewport:", narrow["viewport"])


if __name__ == "__main__":
    run()
