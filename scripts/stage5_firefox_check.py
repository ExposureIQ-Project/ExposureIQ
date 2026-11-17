"""Optional real-browser checks with installed Firefox and its local protocol.

No browser driver/package is installed. A fresh temporary profile disables
background services and sends non-loopback HTTP through a refusing loopback
proxy. Only a synthetic exported file and localhost fakes may be opened.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path


class Firefox:
    def __enter__(self):
        binary = shutil.which("firefox")
        if not binary:
            raise RuntimeError("Firefox is not installed; real-browser checks were not run.")
        self.temporary = tempfile.TemporaryDirectory(prefix="s5-firefox-", dir="/tmp/opencode")
        self.root = Path(self.temporary.name)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        prefs = {
            "marionette.enabled": True, "marionette.port": port,
            "browser.shell.checkDefaultBrowser": False, "browser.startup.page": 0,
            "browser.startup.homepage": "about:blank", "browser.newtabpage.enabled": False,
            "browser.newtabpage.activity-stream.feeds.telemetry": False,
            "network.proxy.type": 1, "network.proxy.http": "127.0.0.1", "network.proxy.http_port": 1,
            "network.proxy.ssl": "127.0.0.1", "network.proxy.ssl_port": 1,
            "network.proxy.share_proxy_settings": True, "network.proxy.no_proxies_on": "localhost,127.0.0.1,::1",
            "network.dns.disablePrefetch": True, "network.prefetch-next": False,
            "network.predictor.enabled": False, "network.http.speculative-parallel-limit": 0,
            "network.captive-portal-service.enabled": False, "network.connectivity-service.enabled": False,
            "app.update.enabled": False, "app.update.auto": False,
            "services.settings.server": "http://127.0.0.1:1", "extensions.update.enabled": False,
            "datareporting.healthreport.uploadEnabled": False, "datareporting.policy.dataSubmissionEnabled": False,
            "toolkit.telemetry.enabled": False, "toolkit.telemetry.unified": False,
        }
        (self.root / "user.js").write_text("\n".join(f"user_pref({json.dumps(key)}, {json.dumps(value)});" for key, value in prefs.items()), encoding="utf-8")
        self.log = (self.root / "firefox.log").open("wb")
        self.process = subprocess.Popen([binary, "--headless", "--no-remote", "--profile", str(self.root), "--marionette", "about:blank"],
                                        stdout=self.log, stderr=self.log, env={**os.environ, "MOZ_CRASHREPORTER_DISABLE": "1"})
        self.socket = socket.socket()
        deadline = time.monotonic() + 30
        while True:
            try:
                self.socket.connect(("127.0.0.1", port))
                break
            except OSError:
                if self.process.poll() is not None or time.monotonic() > deadline:
                    self.__exit__(None, None, None)
                    raise RuntimeError("The isolated Firefox local control connection did not start.")
                time.sleep(.1)
        self.socket.settimeout(30)
        self.identifier = 0
        greeting = self._receive()
        if greeting.get("marionetteProtocol") != 3:
            raise RuntimeError("Unsupported Firefox local protocol.")
        self.command("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": False}}})
        self.command("WebDriver:SetWindowRect", {"width": 1280, "height": 1000})
        return self

    def _receive(self):
        prefix = b""
        while not prefix.endswith(b":"):
            value = self.socket.recv(1)
            if not value or len(prefix) > 12:
                raise RuntimeError("Invalid Firefox local protocol frame.")
            prefix += value
        length = int(prefix[:-1])
        if length > 20_000_000:
            raise RuntimeError("Oversized Firefox local response.")
        content = b""
        while len(content) < length:
            value = self.socket.recv(length - len(content))
            if not value:
                raise RuntimeError("Firefox closed its local control connection.")
            content += value
        return json.loads(content)

    def command(self, name, arguments=None):
        self.identifier += 1
        value = json.dumps([0, self.identifier, name, arguments or {}]).encode("utf-8")
        self.socket.sendall(str(len(value)).encode("ascii") + b":" + value)
        response = self._receive()
        if response[0] != 1 or response[1] != self.identifier:
            raise RuntimeError("Unexpected Firefox local response.")
        if response[2]:
            raise RuntimeError("Firefox check failed: " + str(response[2].get("error")) + ": " + str(response[2].get("message", ""))[:500])
        return response[3]

    def script(self, code, *, asynchronous=False):
        # A null sandbox is WebDriver's normal page context. Named Firefox
        # sandboxes hide page globals and can retain an earlier Window view.
        result = self.command("WebDriver:ExecuteAsyncScript" if asynchronous else "WebDriver:ExecuteScript",
                              {"script": code, "args": [], "newSandbox": True, "sandbox": None, "scriptTimeout": 15000})
        return result.get("value") if isinstance(result, dict) and "value" in result else result

    def wait(self, expression, *, timeout=10000):
        deadline = time.monotonic() + timeout / 1000
        while True:
            remaining = max(1, int((deadline - time.monotonic()) * 1000))
            try:
                result = self.script('const done = arguments[arguments.length - 1], deadline = performance.now() + ' + str(remaining) + '; (function check() { let value = null; try { value = (' + expression + '); } catch (_) {} if (value) { done(value); return; } if (performance.now() > deadline) { done({wait_timed_out:true}); return; } setTimeout(check, 30); })();', asynchronous=True)
                break
            except RuntimeError as error:
                # A newly opened form tab starts at about:blank. Its normal
                # navigation can unload a waiting script before HTML arrives.
                if "Document was unloaded" not in str(error) or time.monotonic() >= deadline:
                    raise
        if isinstance(result, dict) and result.get("wait_timed_out"):
            raise RuntimeError("The browser's expected saved-data state did not appear.")
        return result

    def screenshot(self, path, *, selector=None):
        identifier = None
        if selector is not None:
            element = self.command("WebDriver:FindElement", {"using": "css selector", "value": selector})
            element = element.get("value", element)
            identifier = element["element-6066-11e4-a52e-4f735466cecf"]
        result = self.command("WebDriver:TakeScreenshot", {"id": identifier, "full": False, "scroll": selector is not None})
        value = result.get("value") if isinstance(result, dict) else result
        Path(path).write_bytes(base64.b64decode(value, validate=True))

    def __exit__(self, *args):
        if hasattr(self, "socket"):
            self.socket.close()
        if hasattr(self, "process"):
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if hasattr(self, "log"):
            self.log.close()
        if hasattr(self, "temporary"):
            self.temporary.cleanup()


def check_offline(html_path: Path, screenshot_path: Path) -> dict:
    with Firefox() as browser:
        browser.command("WebDriver:Navigate", {"url": html_path.resolve().as_uri()})
        assert browser.script('return !document.getElementById("export-chat-toggle") && !document.getElementById("export-chat") && !document.getElementById("exposureiq-chat-data");') is True
        assert browser.script('return document.querySelectorAll(".scan-card").length;') == 10
        browser.wait('getComputedStyle(document.querySelector("#domain-home .cover")).opacity === "1"')
        browser.screenshot(screenshot_path)
        browser.script('document.querySelector(".scan-card").click();')
        browser.wait('document.querySelector(".scan-view.is-active")')
        return {"passed": True, "browser": "installed Firefox, real headless browser", "source": "synthetic exported file",
                "checks": ["no AI icon, drawer or metadata", "ten saved scan cards", "scan selection"],
                "screenshot": screenshot_path.name,
                "network": "file page has connect-src none; non-loopback browser HTTP is directed to a refusing localhost proxy"}


def check_live(server, screenshot_path: Path, provider) -> dict:
    from exposureiq.ai.config import AIConfig
    from exposureiq.ai.conversation import PROOF_NOTE
    from exposureiq.ai.glossary import GLOSSARY

    with Firefox() as browser:
        entry = next(entry for entry in server.state.entries.values() if entry["scan"]["scan_id"] == "DEMO-HISTORY-04")
        url = server.report_url(str(entry["path"]))
        browser.command("WebDriver:Navigate", {"url": url})
        try:
            browser.wait('document.getElementById("export-chat-toggle") && !document.getElementById("export-chat-toggle").hidden && window.location.hash === "#domain-home"')
        except RuntimeError:
            state = browser.script('const body = document.body?.textContent || ""; return {ready:document.readyState,content_type:document.contentType,icon_exists:!!document.getElementById("export-chat-toggle"),icon_hidden:document.getElementById("export-chat-toggle")?.hidden,live_status:document.getElementById("export-live-status")?.textContent,chat_status:document.getElementById("export-chat-status")?.textContent,rejected_origin:body.includes("Cross-origin requests are not allowed"),rejected_session:body.includes("per-launch viewer URL"),rejected_form:body.includes("bounded HTML-report form"),rejected_scan:body.includes("Saved scan")};')
            print("Safe live-page diagnostic: " + json.dumps(state))
            raise
        assert provider.calls == 0
        assert browser.script('return document.getElementById("export-chat").hidden;') is True
        browser.wait('getComputedStyle(document.querySelector("#domain-home .cover")).opacity === "1" && document.getElementById("export-chat-toggle").getBoundingClientRect().width > 0')
        browser.screenshot(screenshot_path.with_name(screenshot_path.stem + "-closed.png"))
        try:
            browser.wait('(() => { const toggle = document.getElementById("export-chat-toggle"), drawer = document.getElementById("export-chat"); if (document.readyState !== "complete" || !toggle || toggle.hidden || window.location.hash !== "#domain-home") return false; if (drawer.hidden) toggle.click(); return !drawer.hidden; })()')
        except RuntimeError:
            after_enable = browser.script('return {home_anchor:window.location.hash === "#domain-home",hash_length:window.location.hash.length,drawer_hidden:document.getElementById("export-chat").hidden,source:document.getElementById("export-chat-source").textContent};')
            print("Safe failed enable diagnostic: " + json.dumps(after_enable))
            raise
        address = browser.command("WebDriver:GetCurrentURL")
        address = address.get("value", address) if isinstance(address, dict) else address
        if address != server.origin + "/api/report#domain-home":
            from urllib.parse import urlsplit

            parsed = urlsplit(address)
            state = browser.script('return {drawer_hidden:document.getElementById("export-chat").hidden,source:document.getElementById("export-chat-source").textContent,home_anchor:window.location.hash === "#domain-home",hash_length:window.location.hash.length,live_api:typeof window.ExposureIQLiveChat};')
            state.update(address_home=parsed.fragment == "domain-home", address_session=parsed.fragment == server.token,
                         exact_origin=parsed.scheme + "://" + parsed.netloc == server.origin)
            print("Safe post-enable handoff diagnostic: " + json.dumps(state))
        assert address == server.origin + "/api/report#domain-home"
        browser.script('document.getElementById("export-chat-close").click();')
        assert browser.script('return document.getElementById("export-chat").hidden && document.activeElement.id === "export-chat-toggle";') is True
        browser.script('document.getElementById("export-chat-toggle").click(); document.getElementById("export-chat").dispatchEvent(new KeyboardEvent("keydown", {key:"Escape",bubbles:true}));')
        assert browser.script('return document.getElementById("export-chat").hidden && document.getElementById("export-chat-toggle").getAttribute("aria-expanded") === "false";') is True
        browser.script('document.getElementById("export-chat-toggle").click();')
        browser.script('document.getElementById("export-chat-input").value = "hi"; document.getElementById("export-chat-send").click();')
        browser.wait('!document.getElementById("export-chat-send").disabled && document.getElementById("export-chat-log").lastElementChild.textContent')
        assert provider.calls == 0
        turns = []
        for question in ("Which host is the most exposed?", "then why would i fix it first?", "what would that do or cause if didn't fixed?"):
            browser.script('document.getElementById("export-chat-input").value = ' + json.dumps(question) + '; document.getElementById("export-chat-send").click();')
            result = browser.wait('!document.getElementById("export-chat-send").disabled && document.getElementById("export-chat-log").lastElementChild.textContent')
            turns.append({"question": question, "text": result})
            if not ("db.example.com" in result and "11 high" not in result and "Offline test reply" in result):
                print("Synthetic failed browser turn: " + json.dumps({"question": question, "text": result, "provider_calls": provider.calls,
                      "status": browser.script('return document.getElementById("export-chat-status").textContent;')}))
                raise AssertionError("The synthetic live-transport reply did not retain the expected host/source.")
        assert "45" in turns[0]["text"] and "deserves attention" in turns[0]["text"]
        assert sum(GLOSSARY["database"]["explanation"] in turn["text"] for turn in turns) == 1
        assert sum(turn["text"].count(PROOF_NOTE) for turn in turns) == 1
        evidence = browser.script('const details = document.querySelector("#export-chat-log details"); const closed = !details.open; details.querySelector("summary").click(); return {closed, opened:details.open};')
        assert evidence == {"closed": True, "opened": True}
        browser.screenshot(screenshot_path, selector="#export-chat")
        browser.command("WebDriver:SetWindowRect", {"width": 390, "height": 844})
        bounds = browser.script('const r = document.getElementById("export-chat").getBoundingClientRect(); return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:innerWidth,height:innerHeight};')
        assert bounds["left"] >= 0 and bounds["right"] <= bounds["width"] and bounds["top"] >= 0 and bounds["bottom"] <= bounds["height"]
        browser.screenshot(screenshot_path.with_name(screenshot_path.stem + "-mobile.png"))
        browser.command("WebDriver:SetWindowRect", {"width": 1280, "height": 1000})
        before_thanks = provider.calls
        browser.script('document.getElementById("export-chat-input").value = "thanks"; document.getElementById("export-chat-send").click();')
        browser.wait('!document.getElementById("export-chat-send").disabled && document.getElementById("export-chat-log").lastElementChild.textContent')
        assert provider.calls == before_thanks
        browser.script('document.getElementById("export-chat-mode").value = "technical"; document.getElementById("export-chat-input").value = "Explain F-0005"; document.getElementById("export-chat-send").click();')
        technical = browser.wait('!document.getElementById("export-chat-send").disabled && document.getElementById("export-chat-log").lastElementChild.textContent')
        assert "ports.database_exposed" in technical
        provider.failure = "timeout"
        browser.script('document.getElementById("export-chat-input").value = "What could happen?"; document.getElementById("export-chat-send").click();')
        fallback = browser.wait('!document.getElementById("export-chat-send").disabled && document.getElementById("export-chat-log").lastElementChild.textContent')
        assert "Built-in fallback" in fallback and "FAKE-RAW-ERROR" not in fallback
        assert PROOF_NOTE not in fallback
        provider.failure = ""
        literal = '<img src=x onerror="literal-text-only">'
        browser.script('document.getElementById("export-chat-input").value = ' + json.dumps("Explain this scan " + literal) + '; document.getElementById("export-chat-send").click();')
        rendered = browser.wait('!document.getElementById("export-chat-send").disabled && document.getElementById("export-chat-log").lastElementChild.textContent')
        assert literal in rendered and browser.script('return document.querySelectorAll("#export-chat-log img").length;') == 0
        browser.script('const select = document.getElementById("export-chat-scan"); select.value = Array.from(select.options).find(option => option.value !== select.value).value; select.dispatchEvent(new Event("change"));')
        browser.wait('document.querySelector(".scan-view.is-active")?.id === document.getElementById("export-chat-scan").value && document.getElementById("export-chat-log").children.length === 0 && !document.getElementById("export-chat-send").disabled')
        server.state.service.config = AIConfig()
        browser.script('document.getElementById("export-live-refresh").click();')
        browser.wait('document.getElementById("export-chat-toggle").hidden && document.getElementById("export-chat").hidden && document.getElementById("export-chat-log").children.length === 0')
        assert browser.script('return document.getElementById("export-chat-send").disabled;') is True
        browser.command("WebDriver:Navigate", {"url": url})
        browser.wait('window.location.pathname === "/api/report" && window.location.hash === "#domain-home"')
        assert browser.script('return !document.getElementById("export-chat-toggle") && !document.getElementById("export-chat") && !document.getElementById("exposureiq-chat-data");') is True
        server.state.service.config = AIConfig(mode="local", base_url="http://127.0.0.1:11434/v1", model="offline-browser-fake")
        browser.command("WebDriver:Navigate", {"url": url})
        browser.wait('document.getElementById("export-chat-toggle") && !document.getElementById("export-chat-toggle").hidden && !document.getElementById("export-chat-send").disabled')
        browser.script('document.getElementById("export-chat-toggle").click();')
        server.shutdown()
        server.server_close()
        browser.script('document.getElementById("export-chat-input").value = "Which host is the most exposed?"; document.getElementById("export-chat-send").click();')
        # A focus/periodic health check can disable Send just before this click.
        # Accept only the two honest outcomes: a sent-question unavailable reply,
        # or a disabled composer with the failed-health explanation and no answer.
        unavailable = browser.wait('(() => { const log = document.getElementById("export-chat-log"), footer = document.getElementById("export-chat-status").textContent, status = document.getElementById("export-live-status").textContent; if (log.lastElementChild?.textContent.includes("Reply unavailable")) return log.lastElementChild.textContent + "\\n" + footer; if (document.getElementById("export-chat-send").disabled && status.includes("could not be checked") && !document.querySelector("#export-chat-log .export-chat-turn")) return status; return false; })()', timeout=12000)
        assert "45" not in unavailable and ("No prepared answer was substituted" in unavailable or "No answer is generated here" in unavailable)
        return {"passed": True, "browser": "installed Firefox, real headless browser", "source": "synthetic local-server report with offline fresh-wording fake",
                "checks": ["one-command native token-protected report handoff", "same-origin health", "settings automatically enable icon", "open/close/Escape/focus", "mobile bounds", "no provider call on health/greeting/thanks", "three-turn fresh-wording host context", "code-added first-use definition and once-only disclaimer", "collapsed/opened Evidence", "technical mode", "literal HTML text", "scan selection clears context", "safe provider fallback", "Off hides icon and clears chat", "initial Off report has no chat", "backend-down does not substitute prepared text"],
                "transcript": turns, "fallback_text": fallback, "backend_down_text": unavailable,
                "screenshot": screenshot_path.name, "mobile_bounds": bounds,
                "model": "offline fake only; no real provider/key", "network": "same-origin loopback HTTP; non-loopback browser HTTP is sent to a refusing localhost proxy"}
