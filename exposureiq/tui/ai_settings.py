"""Top-left settings drawer and private, explicitly consented AI preferences."""

from __future__ import annotations

from dataclasses import replace

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.geometry import Offset
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static, Switch, Tab, Tabs

from exposureiq.ai.config import (AIConfig, ConfigError, LOCAL_BASE, PRESETS, confirm_remote,
                                  consent_message, load_config, public_config, save_config, validate_config,
                                  PRESETS_VERIFIED_DATE)
from exposureiq.ai.policy import RateLimitError
from exposureiq.ai.provider import ProviderError
from exposureiq.ai.service import AIService


class DeveloperModeChanged(Message):
    """Preferences were saved privately; this notification contains no key."""


class SettingsDrawer(ModalScreen[bool]):
    slide = reactive(-34.0)
    BINDINGS = [Binding("escape", "close", "Close", priority=True)]
    CSS = """
    SettingsDrawer { align: left top; background: $background 55%; }
    #settings-drawer { width: 34; max-width: 90%; height: 100%; padding: 1 2;
                       background: $panel; border-right: solid $primary; }
    #drawer-heading { height: auto; color: $primary; text-style: bold; margin-bottom: 1; }
    #drawer-ai-key { width: 100%; height: auto; min-height: 3; }
    #drawer-developer { height: 3; margin-top: 1; align-vertical: middle; }
    #drawer-developer-label { width: 1fr; height: 3; content-align: left middle; }
    #developer-mode { width: 10; }
    #drawer-result { height: auto; color: $warning; }
    #drawer-note { height: auto; color: $text-muted; margin-top: 1; }
    """

    def __init__(self, config: AIConfig, *, readable=True):
        super().__init__()
        self.original, self.readable = config, readable
        self.state = public_config(config)["state"] if readable else "not set"

    def compose(self) -> ComposeResult:
        with Vertical(id="settings-drawer"):
            yield Static("Settings", id="drawer-heading", markup=False)
            yield Button(f"AI settings · {self.state}", id="drawer-ai-key")
            with Horizontal(id="drawer-developer"):
                yield Static("Developer mode", id="drawer-developer-label", markup=False)
                yield Switch(value=self.original.developer_mode, id="developer-mode", disabled=not self.readable)
            yield Static("Show AI logs and the fake-data badge. Off by default.", id="drawer-result", markup=False)
            yield Static("Advisory only. No scanning or scope changes.\n\nEsc closes this menu.", id="drawer-note", markup=False)

    def on_mount(self) -> None:
        self.watch_slide(self.slide)
        self.animate("slide", 0.0, duration=0.18)
        self.query_one("#drawer-ai-key", Button).focus()

    def watch_slide(self, value: float):
        if self.is_mounted:
            self.query_one("#settings-drawer").styles.offset = Offset(round(value), 0)

    @on(Button.Pressed, "#drawer-ai-key")
    def open_ai(self):
        self.dismiss(True)

    @on(Switch.Changed, "#developer-mode")
    def developer_changed(self, event: Switch.Changed):
        event.stop()
        try:
            self.original = save_config(replace(self.original, developer_mode=event.value))
        except ConfigError:
            self.query_one("#drawer-result", Static).update("Developer preference could not be saved. Check private AI settings first.")
            with self.prevent(Switch.Changed):
                event.switch.value = self.original.developer_mode
        else:
            self.query_one("#drawer-result", Static).update("Developer mode on: logs and fake-data badge shown." if event.value else
                                                          "User view: logs and fake-data badge hidden.")
            self.post_message(DeveloperModeChanged())

    def action_close(self):
        self.dismiss(False)


class RemoteConsent(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]
    CSS = """
    RemoteConsent { align: center middle; background: $background 80%; }
    #remote-consent { width: 72; max-width: 94%; height: auto; max-height: 90%;
                      background: $panel; border: solid $warning; padding: 1 2; }
    #remote-consent Static { height: auto; margin-bottom: 1; }
    #consent-actions { height: 3; align-horizontal: right; }
    #consent-actions Button { margin-left: 1; }
    """

    def __init__(self, config: AIConfig):
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        with Vertical(id="remote-consent"):
            yield Static("Remote AI data sharing", markup=False)
            yield Static(consent_message(self.config), id="consent-host", markup=False)
            yield Static("This includes domain/host names and normalized findings, not raw banners. "
                         "The provider may retain this data under its own policy. "
                         "Only continue with your team's permission.", markup=False)
            with Horizontal(id="consent-actions"):
                yield Button("Cancel", id="consent-cancel")
                yield Button("Confirm sharing", id="consent-confirm", variant="primary")

    def on_mount(self):
        self.query_one("#consent-cancel", Button).focus()

    @on(Button.Pressed, "#consent-confirm")
    def accept(self):
        self.dismiss(True)

    @on(Button.Pressed, "#consent-cancel")
    def action_cancel(self):
        self.dismiss(False)


class ConnectionResult(Message):
    def __init__(self, result: str):
        super().__init__()
        self.result = result


class AISettings(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]
    CSS = """
    AISettings { align: center middle; background: $background 75%; }
    #ai-settings-dialog { width: 78; max-width: 96%; height: 36; max-height: 96%;
                          background: $panel; border: solid $secondary; padding: 1 2; }
    #ai-settings-title { height: 1; color: $primary; text-style: bold; margin-bottom: 1; }
    #ai-modes { height: 3; margin-bottom: 1; }
    #ai-modes Tab { width: 1fr; padding: 0 1; }
    #ai-settings-fields { height: 1fr; }
    #ai-settings-fields Static { height: auto; }
    #ai-remote-fields, #ai-endpoint-fields { height: auto; }
    #ai-settings-fields Input, #ai-settings-fields Select { margin-bottom: 1; }
    #ai-settings-result { height: auto; max-height: 4; color: $warning; }
    #ai-settings-actions { height: 3; margin-top: 1; align-horizontal: right; }
    #ai-settings-actions Button { margin-left: 1; min-width: 9; }
    #ai-key { text-style: none; }
    """

    def __init__(self):
        super().__init__()
        try:
            self.original = load_config()
            self.initial_error = ""
        except ConfigError:
            self.original, self.initial_error = AIConfig(), "Saved settings could not be read; no key was loaded."
        self.mode = self.original.mode
        self.provider = self.original.provider
        self.endpoints = {
            "local": (self.original.base_url, self.original.model) if self.mode == "local" else (LOCAL_BASE, ""),
            "remote": (self.original.base_url, self.original.model) if self.mode == "remote" else (PRESETS[self.provider]["url"], ""),
        }
        self.pending = None
        self.connection_worker = None

    def compose(self) -> ComposeResult:
        with Vertical(id="ai-settings-dialog"):
            yield Static("AI settings", id="ai-settings-title", markup=False)
            yield Tabs(Tab("Off (no AI)", id="ai-mode-off"), Tab("Remote API", id="ai-mode-remote"),
                       Tab("Local URL", id="ai-mode-local"), active=f"ai-mode-{self.mode}", id="ai-modes")
            with VerticalScroll(id="ai-settings-fields"):
                with Vertical(id="ai-remote-fields"):
                    yield Static("Provider (or Custom for another compatible endpoint)", markup=False)
                    yield Select([(name, name) for name in PRESETS], value=self.original.provider,
                                 allow_blank=False, id="ai-provider")
                    yield Static(id="ai-preset-note", markup=False)
                    yield Static("API key (masked; leave blank to keep the saved key on the same endpoint)", markup=False)
                    yield Input(password=True, placeholder=public_config(self.original)["key_mask"], id="ai-key")
                with Vertical(id="ai-endpoint-fields"):
                    yield Static("Base URL", markup=False)
                    yield Input(value=self.original.base_url or LOCAL_BASE, id="ai-base-url")
                    yield Static("Model name", markup=False)
                    yield Input(value=self.original.model if self.original.mode in ("remote", "local") else "",
                                placeholder="A model available at your configured endpoint", id="ai-model")
                yield Static("Off disables AI and hides its tabs and buttons. Saving Off forgets the stored key.",
                             id="ai-off-note", markup=False)
                yield Static("Preferences are private user files, never scan JSON. "
                             "EXPOSUREIQ_AI_KEY overrides a stored remote key. "
                             "Local mode sends no key and permits loopback only.", markup=False)
            yield Static(self.initial_error, id="ai-settings-result", markup=False)
            with Horizontal(id="ai-settings-actions"):
                yield Button("Test connection", id="ai-test")
                yield Button("Save", id="ai-save", variant="primary")
                yield Button("Cancel", id="ai-cancel")

    def on_mount(self):
        self._show_mode()
        self._preset_note()

    def _show_mode(self):
        self.query_one("#ai-remote-fields").display = self.mode == "remote"
        self.query_one("#ai-endpoint-fields").display = self.mode in ("remote", "local")
        self.query_one("#ai-off-note").display = self.mode == "off"
        self.query_one("#ai-test", Button).disabled = self.mode == "off"

    @on(Tabs.TabActivated, "#ai-modes")
    def switch_mode(self, event: Tabs.TabActivated):
        mode = event.tab.id.removeprefix("ai-mode-")
        if mode != self.mode:
            if self.mode in self.endpoints:
                self.endpoints[self.mode] = (self.query_one("#ai-base-url", Input).value,
                                            self.query_one("#ai-model", Input).value)
            self.mode = mode
            if mode in self.endpoints:
                base, model = self.endpoints[mode]
                self.query_one("#ai-base-url", Input).value = base
                self.query_one("#ai-model", Input).value = model
        self._show_mode()

    def _preset_note(self):
        preset = PRESETS[str(self.query_one("#ai-provider", Select).value)]
        note = f"URL checked in official docs ({preset.get('date', PRESETS_VERIFIED_DATE)}); no live API was tested."
        if self.query_one("#ai-provider", Select).value == "Anthropic":
            note += " Uses the native Messages API; choose a workspace-scoped key."
        self.query_one("#ai-preset-note", Static).update(
            note
            if preset["verified"] else "Unverified preset / Custom: verify the endpoint yourself before sharing scan data.")

    @on(Select.Changed, "#ai-provider")
    def preset_changed(self, event: Select.Changed):
        if event.value in PRESETS:
            self._preset_note()
            if self.mode == "remote" and event.value != self.provider:
                self.query_one("#ai-base-url", Input).value = PRESETS[str(event.value)]["url"]
            self.provider = str(event.value)

    def _draft(self) -> AIConfig:
        base = self.query_one("#ai-base-url", Input).value.strip().rstrip("/")
        typed_key = self.query_one("#ai-key", Input).value
        key = typed_key or (self.original.api_key if base == self.original.base_url else "")
        return validate_config(AIConfig(mode=self.mode, provider=str(self.query_one("#ai-provider", Select).value),
                                        base_url=base, model=self.query_one("#ai-model", Input).value.strip(),
                                        api_key=key if self.mode == "remote" else "",
                                        consent_base=self.original.consent_base, developer_mode=self.original.developer_mode))

    def _request(self, purpose: str):
        try:
            draft = self._draft()
        except ConfigError as error:
            self.query_one("#ai-settings-result", Static).update(str(error))
            return
        if draft.mode == "remote" and draft.consent_base != draft.base_url:
            self.pending = (purpose, draft)
            self.app.push_screen(RemoteConsent(draft), self._consented)
        else:
            self._perform(purpose, draft)

    def _consented(self, accepted: bool):
        purpose, draft = self.pending
        self.pending = None
        if not accepted:
            self.query_one("#ai-settings-result", Static).update("Remote sharing cancelled. No request or settings write occurred.")
            return
        draft = confirm_remote(draft, accepted=True)
        self.original = replace(self.original, consent_base=draft.base_url)
        self._perform(purpose, draft)

    def _perform(self, purpose: str, draft: AIConfig):
        if purpose == "save":
            try:
                save_config(draft)
            except ConfigError as error:
                self.query_one("#ai-settings-result", Static).update(str(error))
            else:
                self.query_one("#ai-key", Input).value = ""
                self.dismiss(True)
        else:
            self.query_one("#ai-settings-result", Static).update("Testing the configured AI endpoint…")
            self.query_one("#ai-test", Button).disabled = True
            self.connection_worker = self._test(draft)

    @work(thread=True, exclusive=True, group="ai-test", exit_on_error=False)
    def _test(self, draft: AIConfig):
        try:
            service = getattr(self.app, "ai_service", None) or AIService()
            result = service.test_connection(draft)
        except (ProviderError, ConfigError) as error:
            result = str(error)
        except RateLimitError:
            result = "AI request limit reached. Wait one minute before trying again."
        except Exception:
            result = "Connection check failed. No credential details are shown."
        self.post_message(ConnectionResult(result))

    def on_connection_result(self, event: ConnectionResult):
        self.query_one("#ai-settings-result", Static).update(event.result)
        self.query_one("#ai-test", Button).disabled = self.mode == "off"

    @on(Button.Pressed, "#ai-save")
    def save(self):
        self._request("save")

    @on(Button.Pressed, "#ai-test")
    def test(self):
        self._request("test")

    @on(Button.Pressed, "#ai-cancel")
    def action_cancel(self):
        if self.connection_worker is not None:
            self.connection_worker.cancel()
        self.query_one("#ai-key", Input).value = ""
        self.dismiss(False)
