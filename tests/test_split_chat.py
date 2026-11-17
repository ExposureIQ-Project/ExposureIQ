"""Tier 2 structure, real progress and unchanged authenticated boundaries."""

import json
import threading
from importlib.resources import files

import pytest

from dynamic_chat_fakes import acceptance_scan
from exposureiq.ai.config import AIConfig
from exposureiq.ai.provider import FakeProvider
from exposureiq.ai.service import AIService
from exposureiq.viewer.export import live_report_page
from exposureiq.viewer.server import MAX_PROGRESS_CONTEXTS
from test_viewer import first_id, local_viewer, request, saved_root


def test_split_markup_has_one_options_menu_and_only_live_report_gets_a_pane(portal_html):
    scan = acceptance_scan()
    page = live_report_page(scan, [scan], ai_enabled=True)
    parsed = portal_html(page)
    assert parsed.ids.count("report-pane") == parsed.ids.count("export-chat-divider") == 1
    assert parsed.ids.count("export-chat-options") == parsed.ids.count("export-chat-clear") == 1
    assert 'role="separator" tabindex="0"' in page and 'aria-valuemin="30" aria-valuemax="70" aria-valuenow="50"' in page
    options = page.split('<div id="export-chat-options"', 1)[1].split('<p id="export-chat-stage"', 1)[0]
    for identifier in ("export-chat-scan", "export-chat-mode", "export-chat-common", "export-chat-source", "export-live-status", "export-live-refresh", "export-chat-clear"):
        assert f'id="{identifier}"' in options
    for name in ("report-pane", "export-chat-divider", "export-chat-options", "exposureiq-chat-data"):
        assert f'id="{name}"' not in live_report_page(scan, [scan], ai_enabled=False)
    assert 'aria-label="Suggested questions"' in page and 'Shift+Enter for a new line' in page


def test_split_style_and_script_are_bounded_accessible_and_literal():
    static = files("exposureiq.viewer").joinpath("static")
    css = static.joinpath("live-chat.css").read_text(encoding="utf-8")
    script = static.joinpath("live-chat.js").read_text(encoding="utf-8")
    for value in ("var(--report-split, 50%)", "font: 16px/1.5", "position: sticky; bottom: 0", "max-width: 899px", "prefers-reduced-motion", "overflow-y: auto"):
        assert value in css
    assert 'Math.max(30, Math.min(70,' in script
    assert 'pane.inert = opened && narrow.matches' in script and 'event.key === "Tab"' in script
    assert 'log.scrollTop = nearBottom ?' in script and 'Copy answer' in script
    assert script.count('chip.type = "button"') == 1 and 'turns > 0' in script
    assert 'credentials: "omit"' in script and 'mode: "same-origin"' in script
    assert 'Status failure never substitutes an answer' in script
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function", "localStorage", "api_key", "base_url"):
        assert forbidden not in script


def test_status_reads_a_real_blocked_phraser_without_unlocking_ai_or_leaking_text(saved_root):
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
    with local_viewer(saved_root, service=service) as server:
        payload = {"scan": first_id(server), "question": "What is the worst finding?", "conversation": "1" * 32, "progress_id": "2" * 32}
        response = []
        worker = threading.Thread(target=lambda: response.append(request(server, "/api/ai/ask", method="POST", payload=payload)))
        worker.start()
        try:
            assert fake.entered.wait(3)
            path = "/api/ai/progress?conversation=" + payload["conversation"] + "&request=" + payload["progress_id"]
            code, _, raw = request(server, path)
            assert code == 200 and json.loads(raw) == {"stage": "Phrasing your answer", "done": False}
            assert server.state.ai_lock.locked() and "question" not in raw.decode()
            assert request(server, path, authenticated=False)[0] == 403
            assert request(server, path, origin="https://other.example.com")[0] == 403
            assert request(server, path.replace("1" * 32, "3" * 32))[0] == 400
            assert request(server, path + "&request=" + "4" * 32)[0] == 400
        finally:
            fake.release.set()
            worker.join(timeout=5)
        assert response[0][0] == 200 and not worker.is_alive()
        assert json.loads(request(server, path)[2]) == {"stage": "Reply ready", "done": True}


@pytest.mark.parametrize("progress,conversation", [(None, "1" * 32), ("../private", "1" * 32), ("", "1" * 32), ("2" * 32, "")])
def test_progress_requires_bounded_conversation_identifiers(saved_root, progress, conversation):
    with local_viewer(saved_root) as server:
        payload = {"scan": first_id(server), "question": "thanks", "conversation": conversation, "progress_id": progress}
        assert request(server, "/api/ai/ask", method="POST", payload=payload)[0] == 400
        assert not server.state.service.audit


def test_progress_is_memory_bounded_and_no_call_turns_do_not_claim_live_ai(saved_root):
    with local_viewer(saved_root) as server:
        identifier = first_id(server)
        for index in range(MAX_PROGRESS_CONTEXTS + 2):
            result = server.state.ask({"scan": identifier, "question": "thanks", "conversation": "1" * 32, "progress_id": f"{index:032x}"})
            assert result["source"] == "built-in" and not result.get("fact_check_ran")
        assert len(server.state.chat_progress) == MAX_PROGRESS_CONTEXTS and not server.state.service.audit
        assert ("1" * 32, "0" * 32) not in server.state.chat_progress
        server.state.service.config = AIConfig()
        server.state.health()
        assert not server.state.chat_progress
