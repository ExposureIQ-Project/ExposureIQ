import asyncio
import json
import threading

import pytest
from rich.text import Text
from textual.widgets import Button, ContentSwitcher, DataTable, Input, Select, Static, Switch, Tab, TabbedContent, Tabs

from exposureiq import cli, storage
from exposureiq.ai.config import AIConfig, config_path, load_config, save_config
from exposureiq.ai.provider import FakeProvider
from exposureiq.ai.service import AIService
from exposureiq.demo_data import build_demo_scans
from exposureiq.tui.ai_panel import AIPanel, ChatMessage
from exposureiq.tui.ai_settings import AISettings, RemoteConsent, SettingsDrawer
from exposureiq.tui.app import ExposureIQApp
from exposureiq.tui.domain_browser import DomainScreen


def plain(widget):
    result = widget.render()
    return result.plain if isinstance(result, Text) else str(result)


def test_top_left_gear_drawer_closes_with_escape_and_uniform_mode_tabs_save_local(monkeypatch):
    monkeypatch.setattr("exposureiq.ai.service.make_provider", lambda config: FakeProvider())
    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True)
        async with app.run_test(size=(110, 40)) as pilot:
            settings = app.query_one("#settings", Button)
            assert settings.region.x <= 2 and settings.region.y <= 1
            assert str(settings.label) == "⚙" and settings.tooltip == "Settings"
            await pilot.click("#settings")
            await pilot.pause(.2)
            assert isinstance(app.screen, SettingsDrawer)
            assert "off" in str(app.screen.query_one("#drawer-ai-key", Button).label)
            await pilot.press("escape")
            assert not isinstance(app.screen, SettingsDrawer)
            await pilot.click("#settings")
            await pilot.pause(.2)
            await pilot.click("#drawer-ai-key")
            assert isinstance(app.screen, AISettings)
            tabs = list(app.screen.query_one("#ai-modes", Tabs).query(Tab))
            assert {tab.id for tab in tabs} == {"ai-mode-off", "ai-mode-remote", "ai-mode-local"}
            assert max(tab.region.width for tab in tabs) - min(tab.region.width for tab in tabs) <= 1
            await pilot.click("#ai-mode-local")
            app.screen.query_one("#ai-model", Input).value = "offline-test"
            await pilot.click("#ai-test")
            await app.screen.connection_worker.wait()
            await pilot.pause()
            assert "No scan summary" in plain(app.screen.query_one("#ai-settings-result", Static))
            await pilot.click("#ai-save")
            assert not isinstance(app.screen, AISettings)
            assert load_config().mode == "local" and not load_config().developer_mode
            assert config_path().stat().st_mode & 0o777 == 0o600
    asyncio.run(exercise())


@pytest.mark.parametrize("size", [(66, 28), (110, 34), (132, 54)])
def test_settings_gear_and_default_off_controls_do_not_clip_or_offer_ai(size):
    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True)
        async with app.run_test(size=size) as pilot:
            gear = app.query_one("#settings", Button)
            assert str(gear.label) == "⚙" and gear.content_region.width >= 1
            assert gear.region.right <= size[0] and gear.region.bottom <= 4
            tabs = app.query_one("#results", TabbedContent)
            assert not tabs.get_tab("ai-tab").display
            panel = app.query_one("#scan-ai", AIPanel)
            assert not panel.display and not panel.query_one("#ai-log-toggle", Button).display
            assert app.ai_service.audit == []
    asyncio.run(exercise())


def test_developer_toggle_controls_logs_and_fake_badge_without_enabling_ai_or_network(tmp_path):
    save_config(AIConfig(mode="local", base_url="http://127.0.0.1:11434/v1", model="offline-test"))
    path = tmp_path / "results" / "demo.json"
    storage.save_scan(build_demo_scans()[-1], str(path))

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(path), results_dir=path.parent)
        async with app.run_test(size=(120, 42)) as pilot:
            base = app.screen
            panel = base.query_one("#scan-ai", AIPanel)
            assert not base.query_one("#mode-badge").display
            assert "fake data" in plain(base.query_one("#summary-notes", Static)).lower()
            assert not panel.query_one("#ai-log-toggle", Button).display
            panel.show_log()
            assert panel.query_one(ContentSwitcher).current == "ai-chat-view"
            await pilot.click("#settings")
            await pilot.pause(.2)
            await pilot.click("#developer-mode")
            await pilot.pause()
            assert load_config().developer_mode and load_config().mode == "local"
            assert base.query_one("#mode-badge").display and panel.query_one("#ai-log-toggle", Button).display
            await pilot.press("escape")
            base.query_one("#results", TabbedContent).active = "ai-tab"
            await pilot.pause()
            await pilot.click("#ai-log-toggle")
            assert panel.query_one(ContentSwitcher).current == "ai-log-view"
            await pilot.click("#settings")
            await pilot.pause(.2)
            await pilot.click("#developer-mode")
            await pilot.press("escape")
            assert not load_config().developer_mode
            assert not base.query_one("#mode-badge").display and not panel.query_one("#ai-log-toggle", Button).display
            assert panel.query_one(ContentSwitcher).current == "ai-chat-view"
            assert app.ai_service.audit == [] and app.worker is None
    asyncio.run(exercise())


def test_off_hides_active_scan_and_domain_ai_and_blocks_programmatic_chat(tmp_path, ai_scan_factory):
    save_config(AIConfig(mode="local", base_url="http://127.0.0.1:11434/v1", model="offline-test"))
    root = tmp_path / "results"
    for index in range(2):
        storage.save_scan(ai_scan_factory(index), str(root / "example.com" / f"scan-{index}.json"))

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True, results_dir=root)
        async with app.run_test(size=(120, 44)) as pilot:
            base = app.screen
            await pilot.click("#home-results")
            await pilot.press("enter")
            domain = app.screen
            assert isinstance(domain, DomainScreen)
            domain.query_one("#domain-tabs", TabbedContent).active = "domain-ai-tab"
            await pilot.pause()
            await pilot.click("#domain-settings")
            await pilot.pause(.2)
            await pilot.click("#drawer-ai-key")
            await pilot.click("#ai-mode-off")
            await pilot.click("#ai-save")
            await pilot.pause()
            assert not domain.query_one("#domain-tabs", TabbedContent).get_tab("domain-ai-tab").display
            assert domain.query_one("#domain-tabs", TabbedContent).active == "domain-scans-tab"
            assert not domain.query_one("#domain-ai-chat").display
            assert not base.query_one("#results", TabbedContent).get_tab("ai-tab").display
            for panel in (domain.query_one(AIPanel), base.query_one(AIPanel)):
                panel.start_chat("Explain this saved scan")
                assert not panel.display and panel.chat_worker is None
                assert panel.query_one(".ai-chat-actions Button", Button).disabled
            assert load_config().mode == "off" and app.ai_service.audit == []
    asyncio.run(exercise())


def test_provider_presets_and_switching_tabs_keep_local_and_remote_drafts_separate():
    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True)
        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(AISettings())
            await pilot.pause()
            await pilot.click("#ai-mode-remote")
            provider = app.screen.query_one("#ai-provider", Select)
            for name, url in (("OpenAI", "https://api.openai.com/v1"), ("Anthropic", "https://api.anthropic.com/v1")):
                provider.value = name
                await pilot.pause()
                assert app.screen.query_one("#ai-base-url", Input).value == url
            app.screen.query_one("#ai-model", Input).value = "fake-remote-model"
            await pilot.click("#ai-mode-local")
            assert app.screen.query_one("#ai-base-url", Input).value == "http://127.0.0.1:11434/v1"
            assert app.screen.query_one("#ai-model", Input).value == ""
            app.screen.query_one("#ai-model", Input).value = "fake-local-model"
            await pilot.click("#ai-mode-remote")
            assert app.screen.query_one("#ai-model", Input).value == "fake-remote-model"
            assert app.screen.query_one("#ai-base-url", Input).value == "https://api.anthropic.com/v1"
            await pilot.click("#ai-cancel")
            assert not config_path().exists() and not app.ai_service.audit
    asyncio.run(exercise())


def test_remote_settings_require_host_named_confirmation_and_mask_key(monkeypatch):
    fake_key = "FAKE-TUI-KEY-ONLY-1234"
    copied = []
    from exposureiq.tui import app as app_module
    monkeypatch.setattr(app_module, "copy_system_text", lambda value: copied.append(value) or True)

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True)
        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(AISettings())
            await pilot.pause()
            await pilot.click("#ai-mode-remote")
            app.screen.query_one("#ai-base-url", Input).value = "https://ai.example.com/v1"
            app.screen.query_one("#ai-model", Input).value = "fake/model"
            key_input = app.screen.query_one("#ai-key", Input)
            key_input.value = fake_key
            key_input.focus()
            await pilot.press("ctrl+a")
            app.action_copy_selection()
            assert copied == []
            svg = app.export_screenshot(title="Masked fake key")
            assert fake_key not in svg
            await pilot.click("#ai-save")
            assert isinstance(app.screen, RemoteConsent)
            assert "ai.example.com" in plain(app.screen.query_one("#consent-host", Static))
            assert not config_path().exists()
            await pilot.click("#consent-confirm")
            await pilot.pause()
            assert load_config().ready
            assert fake_key not in json.dumps(app.ai_service.audit)
    asyncio.run(exercise())


def test_domain_browser_enter_domain_enter_scan_and_back(tmp_path, ai_scan_factory):
    root = tmp_path / "results"
    for i in range(3):
        storage.save_scan(ai_scan_factory(i), str(root / "example.com" / f"scan-{i}.json"))

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True, results_dir=root)
        async with app.run_test(size=(110, 40)) as pilot:
            await pilot.click("#home-results")
            assert app.query_one("#domain-table", DataTable).row_count == 1
            assert not app.query_one("#saved-table").display
            await pilot.press("enter")
            assert isinstance(app.screen, DomainScreen)
            assert app.screen.query_one("#domain-scans", DataTable).row_count == 3
            assert "stable" in plain(app.screen.query_one("#domain-verdict", Static))
            assert "▁" in plain(app.screen.query_one("#domain-sparkline", Static))
            await pilot.press("enter")
            await pilot.pause()
            assert app.mode == "results" and app.result["scan_id"] == "scan-0002"
            assert app.worker is None
            await pilot.click("#back")
            assert isinstance(app.screen, DomainScreen)
    asyncio.run(exercise())


def test_chat_echoes_sent_message_shows_ascii_thinking_and_a_clean_verified_footer(tmp_path, ai_scan_factory):
    class BlockingFake(FakeProvider):
        def __init__(self):
            super().__init__()
            self.entered, self.release = threading.Event(), threading.Event()

        def complete(self, messages, **kwargs):
            self.entered.set()
            assert self.release.wait(5)
            return super().complete(messages, **kwargs)

    path = tmp_path / "results" / "one.json"
    storage.save_scan(ai_scan_factory(), str(path))

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(path), results_dir=path.parent)
        provider = BlockingFake()
        app.ai_service = AIService(AIConfig(mode="demo"), provider=provider, use_cache=False)
        async with app.run_test(size=(120, 42)) as pilot:
            app.query_one("#results", TabbedContent).active = "ai-tab"
            await pilot.pause()
            await pilot.click("#ai-explain")
            assert await asyncio.to_thread(provider.entered.wait, 2)
            panel = app.query_one("#scan-ai", AIPanel)
            before = panel.frame
            await pilot.pause(.15)
            assert panel.frame != before
            progress = plain(app.query_one("#ai-progress", Static))
            assert "Thinking" in progress and "Phrasing your answer" in progress and progress.startswith("[")
            user, reply = panel.exchanges[-1]
            assert "sent" in plain(user.heading) and "Explain this scan" in plain(user.body)
            assert "thinking" in plain(reply.heading) and panel.running
            assert app.query_one("#ai-chat-send", Button).disabled
            assert not app.query_one("#ai-chat-input", Input).value
            provider.release.set()
            await panel.chat_worker.wait()
            await pilot.pause()
            assert panel.stage_history == ["Reading your scan", "Phrasing your answer", "Checking the facts"]
            assert "Built-in answer" in plain(reply.heading) and "F-0001" in plain(reply.evidence_text)
            footer = plain(app.query_one("#ai-chat-verified", Static))
            assert "Facts checked against your saved scan" in footer and "s5-" not in footer and panel.last_result["prompt_version"] not in footer
            assert "Reply ready" in plain(app.query_one("#ai-progress", Static))
            assert user.styles.border_left != reply.styles.border_left
            assert user.styles.background != reply.styles.background
    asyncio.run(exercise())


def test_settings_can_turn_ai_off_and_forget_stored_fake_key():
    from exposureiq.ai.config import confirm_remote

    key = "FAKE-OFF-SETTING-KEY-ONLY-1234"
    save_config(confirm_remote(AIConfig(mode="remote", base_url="https://ai.example.com/v1", model="fake", api_key=key), accepted=True))

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True)
        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(AISettings())
            await pilot.pause()
            await pilot.click("#ai-mode-off")
            assert app.screen.query_one("#ai-test", Button).disabled
            assert "forgets the stored key" in plain(app.screen.query_one("#ai-off-note", Static))
            await pilot.click("#ai-save")
            assert load_config().mode == "off" and key not in config_path().read_text(encoding="utf-8")
    asyncio.run(exercise())


@pytest.mark.parametrize("size", [(110, 34), (132, 54)])
def test_history_diff_pane_does_not_clip_selected_ai_tab(tmp_path, size):
    root = tmp_path / "results"
    for index, scan in enumerate(build_demo_scans(), 1):
        storage.save_scan(scan, str(root / "example.com" / f"history-{index:02d}.json"))

    async def exercise():
        app = ExposureIQApp(cli.build_parser().parse_args([]), home=True, results_dir=root)
        app.ai_service = AIService(AIConfig(mode="demo"), use_cache=False)
        async with app.run_test(size=size) as pilot:
            await pilot.click("#home-results")
            await pilot.press("enter")
            assert isinstance(app.screen, DomainScreen)
            await pilot.press("enter")
            await pilot.pause()
            tabs = app.query_one("#results", TabbedContent)
            assert tabs.get_tab("scan-diff-tab").display
            switcher = tabs.query_one(ContentSwitcher)
            assert [pane.id for pane in switcher.children if pane.display] == ["summary-tab"]
            tabs.active = "ai-tab"
            await pilot.pause()
            assert [pane.id for pane in switcher.children if pane.display] == ["ai-tab"]
            button = app.query_one("#ai-explain", Button)
            assert button.region.bottom < app.query_one("#footer").region.y
            assert await pilot.click("#ai-explain")
            await pilot.pause()
            panel = app.query_one("#scan-ai", AIPanel)
            assert panel.chat_worker is not None
            await panel.chat_worker.wait()
            await pilot.pause()
            assert panel.last_result["verified"] == panel.last_result["total"]
            assert app.worker is None
            assert await pilot.click(tabs.get_tab("scan-diff-tab"))
            await pilot.pause()
            assert [pane.id for pane in switcher.children if pane.display] == ["scan-diff-tab"]
            assert app.open_saved(root / "example.com" / "history-01.json")
            await pilot.pause()
            assert not tabs.get_tab("scan-diff-tab").display
            assert not app.query_one("#scan-diff-tab").display
            assert len([pane for pane in switcher.children if pane.display]) == 1

    asyncio.run(exercise())
