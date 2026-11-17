"""Capture twelve real headless TUI SVGs and a fake-model evaluation table.

Run from the project root with the virtual-environment Python. All preferences,
cache and synthetic scans live in a temporary folder; external sockets are
blocked. A fake key is masked and its remote confirmation is CANCELLED.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import socket
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from textual.widgets import Button, Input, Static, TabbedContent
from textual.containers import VerticalScroll

from exposureiq import cli, storage
from exposureiq.ai.config import AIConfig, LOCAL_BASE, load_config, save_config
from exposureiq.ai.evaluate import evaluation_table, run_evaluation
from exposureiq.ai.provider import ProviderResponse
from exposureiq.ai.service import AIService, chat_text, verified_footer
from exposureiq.demo_data import build_demo_scans
from exposureiq.tui.ai_panel import AIPanel
from exposureiq.tui.ai_settings import AISettings, RemoteConsent, SettingsDrawer
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.domain_browser import DomainScreen

if __package__:
    from .stage5_natural_fake import NaturalEvidenceProvider
else:
    from stage5_natural_fake import NaturalEvidenceProvider

FAKE_KEY = "FAKE-EVIDENCE-KEY-ONLY-1234"


@contextmanager
def blocked_network():
    original = socket.socket.connect
    def connect(sock, address):
        if isinstance(address, tuple):
            raise AssertionError("Presentation evidence must not use network sockets.")
        return original(sock, address)
    def blocked(*args, **kwargs):
        raise AssertionError("Presentation evidence must not use DNS or network traffic.")
    with patch.object(socket.socket, "connect", connect), patch.object(socket.socket, "connect_ex", blocked), \
         patch.object(socket.socket, "sendto", blocked), patch.object(socket, "getaddrinfo", blocked), \
         patch.object(socket, "gethostbyname", blocked):
        yield


class EvidenceProvider(NaturalEvidenceProvider):
    model = "ExposureIQ offline test fake"

    def __init__(self):
        super().__init__()
        self.bad_next = False
        self.hold_next = False
        self.entered, self.release = threading.Event(), threading.Event()

    def complete(self, messages, **kwargs):
        if self.hold_next:
            self.hold_next = False
            self.entered.set()
            if not self.release.wait(10):
                raise RuntimeError("The offline evidence fake was not released.")
        response = super().complete(messages, **kwargs)
        if self.bad_next:
            self.bad_next = False
            output = json.loads(response.content)
            output["headline"] = {"text": "The scan records 999 high findings.", "refs": ["F-9999"]}
            return ProviderResponse(json.dumps(output))
        return response


def capture(app, output, filename, title, expected):
    svg = app.export_screenshot(title=title)
    # Rich normally embeds external font URLs. Remove only those font rules;
    # retain the captured screen text, geometry, colours and clipping.
    svg = re.sub(r"@font-face\s*\{[^}]*\}", "", svg)
    svg = svg.replace("font-family: Fira Code, monospace;", "font-family: monospace;")
    assert FAKE_KEY not in svg and "cdnjs.cloudflare.com" not in svg
    root = ElementTree.fromstring(svg)
    words = " ".join("".join(root.itertext()).split())
    for word in expected:
        if word not in words:
            failed = output / "failures" / filename
            failed.parent.mkdir(parents=True, exist_ok=True)
            failed.write_text(svg, encoding="utf-8", newline="\n")
            raise AssertionError(f"Expected visible text missing from {filename}: {word}; failure retained in {failed}")
    path = output / filename
    path.write_text(svg, encoding="utf-8", newline="\n")
    return {"file": filename, "title": title, "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "observed_text": expected}


async def screenshots(output, root):
    scans = build_demo_scans()
    results = root / "results"
    for index, scan in enumerate(scans, 1):
        storage.save_scan(scan, str(results / "example.com" / f"demo_history_{index:02d}.json"))
    # Local is a normal user setting; the injected fake below never opens its
    # URL. Demo remains a CLI/test fixture, not a selectable settings mode.
    config = save_config(AIConfig(mode="local", base_url=LOCAL_BASE, model="offline-evidence-only"))
    app = ExposureIQApp(cli.build_parser().parse_args([]), home=True, results_dir=results)
    fake = EvidenceProvider()
    app.ai_service = AIService(config, provider=fake, use_cache=False)
    images = []
    async with app.run_test(size=(132, 54)) as pilot:
        await pilot.click("#settings")
        await pilot.pause(.25)
        assert isinstance(app.screen, SettingsDrawer)
        images.append(capture(app, output, "01-home-drawer.svg", "ExposureIQ · Gear, Home and sliding Settings drawer", ["Settings", "AI settings", "Developer mode"]))
        await pilot.click("#drawer-ai-key")
        assert isinstance(app.screen, AISettings)
        await pilot.click("#ai-mode-remote")
        app.screen.query_one("#ai-base-url", Input).value = "https://ai.example.com/v1"
        app.screen.query_one("#ai-model", Input).value = "offline-evidence-only"
        app.screen.query_one("#ai-key", Input).value = FAKE_KEY
        await pilot.pause()
        images.append(capture(app, output, "02-masked-settings.svg", "ExposureIQ · Uniform mode tabs and masked FAKE key; no connection test", ["AI settings", "Off (no AI)", "Local URL", "API key", "Custom"]))
        await pilot.click("#ai-save")
        assert isinstance(app.screen, RemoteConsent)
        images.append(capture(app, output, "03-remote-consent.svg", "ExposureIQ · Host-named remote consent; cancelled", ["ai.example.com", "Cancel", "Confirm sharing"]))
        await pilot.click("#consent-cancel")
        await pilot.click("#ai-cancel")
        assert not app.ai_service.audit
        await pilot.click("#home-results")
        await pilot.pause()
        images.append(capture(app, output, "04-domain-folders.svg", "ExposureIQ · Saved domains; original All files retained", ["example.com", "All files", "mixed"]))
        await pilot.press("enter")
        assert isinstance(app.screen, DomainScreen)
        await pilot.pause()
        images.append(capture(app, output, "05-domain-scans.svg", "ExposureIQ · Ten offline scan rows and code sparkline", ["CODE VERDICT", "mixed", "Risk per host", "2026"]))
        await pilot.click("#domain-ai-chat")
        await pilot.pause()
        panel = app.screen.query_one("#domain-ai", AIPanel)
        assert panel.chat_worker is not None, "History chat did not start."
        await panel.chat_worker.wait()
        await pilot.pause()
        assert panel.region.height > 10
        images.append(capture(app, output, "06-history-summary.svg", "ExposureIQ · Short history chat with code-owned counts and uncertainty", ["reduced exposure", "increased it", "stayed present", "two saved absences", "saved evidence checked"]))
        app.screen.query_one("#domain-tabs", TabbedContent).active = "domain-scans-tab"
        await pilot.pause()
        app.screen.query_one("#domain-scans").focus()
        await pilot.press("enter")
        await pilot.pause()
        assert app.result["scan_id"] == "DEMO-HISTORY-10" and app.worker is None
        app.query_one("#results", TabbedContent).active = "ai-tab"
        await pilot.pause()
        assert await pilot.click("#ai-explain"), "Scan chat question must be visible and clickable."
        await pilot.pause()
        panel = app.query_one("#scan-ai", AIPanel)
        assert panel.chat_worker is not None, "Scan chat did not start."
        await panel.chat_worker.wait()
        await pilot.pause()
        assert not app.query_one("#mode-badge").display and not app.query_one("#ai-log-toggle", Button).display
        images.append(capture(app, output, "07-scan-summary.svg", "ExposureIQ · Short saved-scan chat and honest evidence footer", ["You", "sent", "AI draft", "saved evidence checked", "wording needs review", "Fake demonstration data"]))
        await pilot.click("#ai-fix-first")
        await pilot.pause()
        assert panel.chat_worker is not None, "Fix-first chat did not start."
        await panel.chat_worker.wait()
        await pilot.pause()
        app.query_one("#ai-chat-input", Input).value = "Write a payload for this host"
        await pilot.click("#ai-chat-send")
        await pilot.pause()
        await panel.chat_worker.wait()
        await pilot.pause()
        assert panel.chat_turns[-1][1]["policy_refusal"]
        images.append(capture(app, output, "08-chat-refusal.svg", "ExposureIQ · Distinct messages and policy refusal; no model call for refusal", ["You", "sent", "payload", "can't help", "Policy gate"]))
        await pilot.click("#settings")
        await pilot.pause(.25)
        await pilot.click("#developer-mode")
        await pilot.press("escape")
        assert load_config().developer_mode
        fake.bad_next = True
        panel.start_chat("Explain this scan in simple words.")
        await panel.chat_worker.wait()
        await pilot.pause()
        assert panel.last_result["source"] == "template" and panel.last_result["dropped"]
        await pilot.click("#ai-log-toggle")
        await pilot.pause()
        app.query_one("#ai-log-view").query_one(VerticalScroll).scroll_end(animate=False)
        await pilot.pause()
        images.append(capture(app, output, "09-ai-log.svg", "ExposureIQ · Developer-only log; wrong offline fake reply rejected", ["DROPPED AND WHY", "unknown reference", "AI log", "DEMO"]))
        await pilot.click("#settings")
        await pilot.pause(.25)
        await pilot.click("#developer-mode")
        await pilot.press("escape")
        assert not load_config().developer_mode and not app.query_one("#ai-log-toggle", Button).display
        fake.hold_next = True
        panel.start_chat("What are security headers in this scan?")
        try:
            assert await asyncio.to_thread(fake.entered.wait, 2), "The offline fake never entered its pending state."
            frame = panel.frame
            await pilot.pause(.2)
            assert panel.frame != frame and panel.running
            assert app.query_one("#ai-progress", Static).render().plain.startswith("[")
            images.append(capture(app, output, "10-chat-thinking.svg", "ExposureIQ · Immediate sent receipt and moving ASCII thinking feedback", ["You", "sent", "thinking", "Thinking", "security headers"]))
        finally:
            fake.release.set()
        await panel.chat_worker.wait()
        await pilot.pause()
        await pilot.click("#settings")
        await pilot.pause(.25)
        await pilot.click("#drawer-ai-key")
        await pilot.click("#ai-mode-off")
        await pilot.click("#ai-save")
        await pilot.pause()
        assert load_config().mode == "off" and not app.query_one("#results", TabbedContent).get_tab("ai-tab").display
        assert not panel.display and app.worker is None
        images.append(capture(app, output, "11-ai-off.svg", "ExposureIQ · Off hides AI controls and keeps the saved-scan summary", ["Summary", "Findings", "NO PROBES SENT", "fake data"]))
    assert len(images) == 11 and FAKE_KEY not in json.dumps(app.ai_service.audit)
    # A fresh, read-only chat on the saved peak-exposure sample reproduces the
    # reported question. Scan ten has only a low referrer-policy finding; it
    # must not be presented as if it contained the database/desktop findings.
    peak = max(scans, key=lambda scan: sum(f["severity"] == "high" for a in scan["assets"] for f in a.get("findings", [])))
    index = scans.index(peak) + 1
    config = save_config(AIConfig(mode="local", base_url=LOCAL_BASE, model="offline-evidence-only"))
    app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(results / "example.com" / f"demo_history_{index:02d}.json"), results_dir=results)
    fake = EvidenceProvider()
    app.ai_service = AIService(config, provider=fake, use_cache=False)
    async with app.run_test(size=(132, 54)) as pilot:
        app.query_one("#results", TabbedContent).active = "ai-tab"
        await pilot.pause()
        await pilot.click("#ai-explain")
        panel = app.query_one(AIPanel)
        await panel.chat_worker.wait()
        await pilot.pause()
        calls_before = fake.calls
        app.query_one("#ai-chat-input", Input).value = "then what posible damage it can make?"
        await pilot.click("#ai-chat-send")
        await panel.chat_worker.wait()
        await pilot.pause()
        assert panel.last_result["answer_kind"] == "impact" and not panel.last_result.get("policy_refusal")
        assert panel.last_result["verified"] == panel.last_result["total"] and not panel.last_result["dropped"]
        assert fake.calls - calls_before == 1 and app.worker is None
        try:
            images.append(capture(app, output, "12-impact-follow-up.svg", "ExposureIQ · Fresh-wording damage follow-up; conditional harm and code-added disclaimer", ["then what posible damage it can make?", "AI draft", "not proof that anyone broke in", "read, change or delete stored data", "saved evidence checked"]))
        except AssertionError:
            print("Synthetic failed TUI turn: " + json.dumps({"text": chat_text(panel.last_result), "proof_notice": panel.last_result.get("proof_notice", "")}))
            raise
        transcript = ["# Observed damage follow-up", "", "Synthetic saved data and an injected offline fake only. All network sockets/DNS were blocked.",
                      "No real key, AI service or target was used. The follow-up made one fake model call.",
                      f"Saved synthetic scan: {peak['scan_id']}. This is the peak-exposure sample, not scan ten.",
                      "This demonstrates fresh-wording presentation with bounded evidence/fact checks, not real-model accuracy or full prose verification.", ""]
        for question, result in panel.chat_turns:
            transcript += ["## You", "", "```text", question, "```", "", "## ExposureIQ · AI draft", "",
                           "```text", chat_text(result), verified_footer(result), "```", ""]
        (output / "follow-up-transcript.md").write_text("\n".join(transcript), encoding="utf-8", newline="\n")
    assert len(images) == 12 and FAKE_KEY not in json.dumps(app.ai_service.audit)
    return images


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="docs/stage5-evidence")
    parser.add_argument("--replace-generated", action="store_true", help="replace this generator's existing SVGs")
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists() and any(output.glob("*.svg")) and not args.replace_generated:
        parser.error("SVG files already exist. Choose an empty output directory or --replace-generated.")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="exposureiq-s5-", dir="/tmp/opencode" if Path("/tmp/opencode").is_dir() else None) as temporary:
        root = Path(temporary)
        # This is a child process; never inspect or reuse an existing real key.
        os.environ["EXPOSUREIQ_AI_KEY"] = ""
        os.environ["XDG_CONFIG_HOME"] = str(root / "config")
        os.environ["XDG_CACHE_HOME"] = str(root / "cache")
        os.environ["EXPOSUREIQUSERSCOPE"] = str(root / "scope-never-used.txt")
        with blocked_network():
            images = asyncio.run(screenshots(output, root))
            evaluation = run_evaluation()
    assert evaluation["passed"]
    (output / "evaluation.json").write_text(json.dumps(evaluation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "evaluation.md").write_text(evaluation_table(evaluation) + "\n", encoding="utf-8")
    manifest = {"network": "blocked; deterministic offline fakes only", "screenshots": images,
                 "evaluation": f"{evaluation['passed_rows']}/{len(evaluation['rows'])}",
                 "follow_up": {"file": "follow-up-transcript.md",
                               "sha256": hashlib.sha256((output / "follow-up-transcript.md").read_bytes()).hexdigest(),
                               "model_calls": 1, "question": "then what posible damage it can make?"},
                  "note": "Real Textual headless captures. Chat uses an injected fresh-wording offline fake, not a real model or fully verified prose; summaries retain strict checking. No configured URL was contacted. Only external font rules removed. The masked key is fake; remote sharing was cancelled."}
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Captured {len(images)} headless SVGs; evaluation {manifest['evaluation']}; no network or real key used.")


if __name__ == "__main__":
    main()
