"""Read-only domain folders, scan rows and a code-derived risk sparkline."""

from __future__ import annotations

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Button, DataTable, Input, Static, TabbedContent, TabPane

from exposureiq.history import domain_history, sparkline, trend_arrow
from exposureiq.insight.risk import RISK_FORMULA, has_check_evidence, risk_score
from exposureiq.insight.verdict import history_verdict
from exposureiq.insight.history_digest import build_history_layers
from exposureiq.tui.ai_panel import AIPanel
from exposureiq.ai.config import AIConfig
from exposureiq.tui.saved import display_time


class OpenDomainScan(Message):
    def __init__(self, path: str, domain: str):
        super().__init__()
        self.path, self.domain = path, domain


class DomainScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Domains", priority=True), Binding("q", "quit", "Quit"),
                Binding("h", "open_html_report", "Open HTML report")]
    CSS = """
    DomainScreen { padding: 1 2; }
    #domain-actions { height: 3; margin-bottom: 1; }
    #domain-actions Button { margin-right: 1; }
    #domain-settings { width: 5; min-width: 5; padding: 0; }
    #domain-title { height: auto; color: $primary; text-style: bold; }
    #domain-verdict { height: auto; margin-top: 1; color: $secondary; }
    #domain-sparkline { height: auto; color: $primary; margin: 1 0; }
    #domain-scans { height: 1fr; }
    #domain-formula, #domain-note { height: auto; color: $text-muted; }
    #domain-keys { dock: bottom; height: auto; color: $key-hint; }
    #domain-tabs { height: 1fr; }
    #domain-tabs > ContentSwitcher { height: 1fr; overflow: hidden hidden; }
    #domain-tabs TabPane { height: 100%; }
    """

    def __init__(self, domain: str, results_dir="results"):
        super().__init__()
        self.domain, self.results_dir = domain, results_dir
        self.entries = domain_history(domain, results_dir, include_demo=True)
        self.verdict = history_verdict([e["scan"] for e in self.entries])

    def compose(self) -> ComposeResult:
        with Horizontal(id="domain-actions"):
            yield Button("⚙", id="domain-settings", tooltip="Settings")
            yield Button("← Domains", id="domain-back")
            yield Button("Open selected scan", id="domain-open", variant="primary")
            yield Button("Open HTML report", id="domain-report", disabled=not self.entries)
            yield Button("Ask about history", id="domain-ai-chat", variant="primary")
        yield Static(Text("Domain / " + self.domain), id="domain-title", markup=False)
        yield Static(f"CODE VERDICT  {self.verdict['value']} {trend_arrow(self.verdict['value'])}", id="domain-verdict", markup=False)
        risk_values = [risk_score(e["scan"])["per_host"] for e in self.entries if has_check_evidence(e["scan"])]
        yield Static("Risk per host  " + sparkline(risk_values), id="domain-sparkline", markup=False)
        with TabbedContent(initial="domain-scans-tab", id="domain-tabs"):
            with TabPane("Scans", id="domain-scans-tab"):
                yield DataTable(id="domain-scans", cursor_type="row", zebra_stripes=True)
            with TabPane("AI chat", id="domain-ai-tab"):
                yield AIPanel(id="domain-ai", prefix="history", history=True)
        yield Static(RISK_FORMULA, id="domain-formula", markup=False)
        note = "Enter opens a scan. Code trend only; browsing sends no probes or AI requests."
        if self.entries and str(self.entries[-1]["scan"].get("scan_id", "")).startswith("DEMO-"):
            note += " Fake demonstration data; no real probes were sent."
        yield Static(note, id="domain-note", markup=False)
        yield Static("Enter opens a scan   h Open HTML report   Esc domains   q quit", id="domain-keys", markup=False)

    def on_mount(self):
        if self.entries:
            scans = [entry["scan"] for entry in self.entries]
            digest = build_history_layers(scans)["L4"]
            self.query_one("#domain-ai", AIPanel).set_data(digest, scan=scans[-1], scans=scans)
        table = self.query_one("#domain-scans", DataTable)
        table.add_columns(*(Text(s) for s in ("Date (UTC)", "Hosts", "H / M / L", "Risk / host", "Trend")))
        for index in range(len(self.entries) - 1, -1, -1):
            scan = self.entries[index]["scan"]
            risk = risk_score(scan)
            verdict = history_verdict([e["scan"] for e in self.entries[:index + 1]])
            table.add_row(Text(display_time(scan["started_at"])), Text(str(risk["hosts"])),
                          Text(f"{risk['high']} / {risk['medium']} / {risk['low']}"),
                          Text(f"{risk['per_host']:.2f}"), Text(trend_arrow(verdict["value"])), key=str(index))
        table.focus()
        self.apply_preferences(self.app.ai_service._configuration())

    def apply_preferences(self, config: AIConfig, *, reset=False):
        enabled = config.mode != "off"
        self.query_one("#domain-ai-chat", Button).display = enabled
        self.query_one("#domain-ai-chat", Button).disabled = not self.entries
        tabs = self.query_one("#domain-tabs", TabbedContent)
        if enabled:
            tabs.show_tab("domain-ai-tab")
        else:
            if tabs.active == "domain-ai-tab":
                tabs.active = "domain-scans-tab"
            tabs.hide_tab("domain-ai-tab")
        self.query_one("#domain-ai", AIPanel).apply_preferences(config, reset=reset)

    @on(Button.Pressed, "#domain-settings")
    def settings(self):
        self.app.settings_button()

    @on(Button.Pressed, "#domain-ai-chat")
    def history_chat(self):
        if self.app.ai_service._configuration().mode == "off" or not self.entries:
            return
        self.query_one("#domain-tabs", TabbedContent).active = "domain-ai-tab"
        self.query_one("#domain-ai", AIPanel).start_chat("What changed in this domain's saved history?")

    @on(DataTable.RowSelected, "#domain-scans")
    def selected(self, event: DataTable.RowSelected):
        self.post_message(OpenDomainScan(self.entries[int(event.row_key.value)]["path"], self.domain))

    @on(Button.Pressed, "#domain-open")
    def open_scan(self):
        table = self.query_one("#domain-scans", DataTable)
        if table.row_count:
            table.action_select_cursor()

    def report_source(self):
        if not self.is_mounted:
            return None
        table = self.query_one("#domain-scans", DataTable)
        if not table.row_count or not 0 <= table.cursor_row < len(self.entries):
            return None
        # Rows are newest-first; entries remain oldest-first for history.
        return self.entries[-1 - table.cursor_row]["path"]

    def check_action(self, action, parameters):
        if action == "open_html_report":
            return not isinstance(self.app.focused, Input) and self.app.check_action(action, parameters)
        return True

    @on(Button.Pressed, "#domain-report")
    def action_open_html_report(self):
        self.app.action_open_html_report()

    @on(Button.Pressed, "#domain-back")
    def action_back(self):
        self.app.pop_screen()
