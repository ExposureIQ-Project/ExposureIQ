"""Full-screen scan progress and results. All stages run off the UI thread."""

import logging
import time

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.theme import Theme
from textual.widgets import Button, DataTable, Input, ProgressBar, Static, TabbedContent, TabPane, Tabs

from exposureiq import output, storage
from exposureiq.tui.control import ScanCancelled, ScanControl
from exposureiq.tui.confirm_scope import ScopeConfirmation
from exposureiq.tui.rerun import rerun_hosts
from exposureiq.tui.saved import display_time, list_saved, result_from_snapshot
from exposureiq.tui.scan import PHASES, ScanStages, run_scan
from exposureiq.tui.user_scope import MAX_HOSTS, append_hosts, eligible_hosts

_SEVERITY = {"high": "bold #EF4444", "medium": output.AMBER, "low": "#60A5FA"}
_SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


class ScanEvent(Message):
    def __init__(self, data: dict):
        super().__init__()
        self.data = data


class _ScanLogHandler(logging.Handler):
    def __init__(self, app):
        super().__init__(logging.WARNING)
        self.app = app

    def emit(self, record):
        if not self.app.control.cancelled.is_set():
            self.app.post_message(ScanEvent({"kind": "log", "level": "warn",
                "message": record.getMessage()}))


class ExposureIQApp(App[int]):
    TITLE = "ExposureIQ"
    ENABLE_COMMAND_PALETTE = False
    AUTO_FOCUS = None
    BINDINGS = [
        Binding("q", "quit", "Quit / cancel", priority=True),
        Binding("ctrl+c", "cancel_scan", "Cancel", priority=True),
        Binding("a", "add_scope", "Add to scope"),
        Binding("tab", "focus_next", "Next panel"),
        Binding("shift+tab", "focus_previous", "Previous", show=False),
    ]
    CSS = """
    Screen { background: #111827; color: #E5E7EB; }
    #topbar { height: 3; background: #111827; border-bottom: solid #16B8A6; }
    #brand { height: 3; padding: 0 1; content-align: left middle; background: #111827; }
    #back { width: 5; min-width: 5; height: 3; border: none; background: #111827;
            color: #16B8A6; text-style: bold; }
    #back:hover { background: #1F2937; }
    #home { height: 1fr; padding: 1 2; }
    #home-panel { width: 100%; max-width: 100; height: auto; }
    .home-heading { height: auto; margin-top: 1; color: #16B8A6; text-style: bold; }
    #home-domain { height: 3; }
    #home-scan { margin-top: 1; }
    #home-actions { height: auto; margin-top: 1; }
    #home-actions Button { margin-right: 1; }
    #saved-open { margin-top: 1; }
    #home-scan-note { height: auto; color: #9CA3AF; }
    #home-note { height: auto; margin-top: 1; color: #9CA3AF; }
    #home-message { height: auto; margin-top: 1; }
    #browser { height: 1fr; padding: 1 2; }
    #saved-table { height: 1fr; }
    #browser-note { height: auto; color: #9CA3AF; }
    #scan-status { height: 1; margin: 1 2 0 2; color: #7C83FD; text-style: bold; }
    #scanning { height: 1fr; padding: 1 2; }
    #scan-layout { height: auto; }
    #phase-list { width: 1fr; height: auto; border: round #16B8A6; padding: 1 2; }
    .phase { height: 1; }
    #live-panel { width: 1fr; height: auto; margin-left: 2; border: round #7C83FD; padding: 0 2; }
    #counters { height: 4; }
    #elapsed { height: 1; margin-top: 1; color: #7C83FD; }
    #scan-progress { width: 100%; margin: 1 0; }
    #scan-progress Bar > .bar--indeterminate { color: #16B8A6; }
    #live-log { height: 1; padding: 0 1; border-left: thick #F59E0B; text-wrap: nowrap; text-overflow: ellipsis; }
    #safety { height: auto; margin: 1 0 0 0; color: #9CA3AF; }
    #results { height: 1fr; margin: 0 1; }
    TabPane { padding: 1; }
    DataTable { height: 1fr; background: #111827; }
    DataTable > .datatable--header { background: #1F2937; color: #16B8A6; text-style: bold; }
    DataTable > .datatable--cursor { background: #283855; }
    #severity-counts { height: 2; margin: 0 1; }
    #summary-layout { height: 1fr; }
    #phase-counts { width: 1fr; }
    #summary-info { width: 1fr; height: 1fr; margin-left: 2; padding: 1 2; border: round #7C83FD; }
    #summary-notes { height: auto; }
    #scope-skipped-panel { height: auto; border: round #F59E0B; padding: 0 1; margin-bottom: 1; }
    #scope-skipped-text { height: auto; color: #F59E0B; }
    #add-scope { margin-top: 1; }
    #user-scope-saved { height: auto; margin: 0 2; color: #16B8A6; }
    #result-log { height: 1; margin: 0 2; color: #7C83FD; text-wrap: nowrap; text-overflow: ellipsis; }
    #rerun-panel { height: auto; max-height: 40%; border: round #16B8A6; margin: 0 2; padding: 0 1; }
    #rerun-hosts { height: auto; max-height: 8; }
    #finding-layout { height: 1fr; }
    #findings-table { width: 3fr; }
    #finding-side { width: 2fr; height: 1fr; margin-left: 1; padding: 1; border: round #7C83FD; }
    #finding-detail { height: auto; }
    #keys { height: 1; dock: bottom; padding: 0 2; color: #9CA3AF; background: #1F2937; text-wrap: nowrap; }
    Screen.compact #scan-layout { layout: vertical; }
    Screen.compact #phase-list, Screen.compact #live-panel { width: 100%; margin-left: 0; }
    Screen.compact #live-panel { margin-top: 1; }
    Screen.narrow #finding-layout { layout: vertical; }
    Screen.narrow #findings-table { width: 100%; height: 1fr; }
    Screen.narrow #finding-side { width: 100%; height: 1fr; margin-left: 0; }
    """
    HORIZONTAL_BREAKPOINTS = [(0, "compact"), (72, "narrow"), (100, "wide")]

    def __init__(self, args, *, stages: ScanStages | None = None, control: ScanControl | None = None,
                 version: str = "0.1.0", scan_job=None, home: bool = False,
                 open_file: str | None = None, browser: bool = False, results_dir="results"):
        super().__init__()
        self.args, self.stages, self.version = args, stages, version
        self.verbose = bool(getattr(args, "verbose", False))
        self.control = control or ScanControl()
        self.scan_job = scan_job or run_scan
        self.home_mode = home
        self.open_file = open_file
        self.browser_mode = browser
        self.results_dir = results_dir
        self.mode = "browser" if browser else ("home" if home or open_file else "scanning")
        self.saved_paths = {}
        self.result = None
        self.exit_code = 0
        self.phase_states = dict.fromkeys(PHASES, "waiting")
        self.phase_counts = dict.fromkeys(PHASES, 0)
        self.live_counts = dict(subdomains=0, hosts=0, ips=0, findings=0)
        self.warnings = []
        self.finding_rows = {}
        self._started = time.monotonic()
        self._frame = 0
        self._finished = False
        self._rerunning = False
        self.rerun_states = {}
        self.worker = None
        self._log_handler = None
        self.register_theme(Theme(
            name="exposureiq", primary=output.TEAL, secondary=output.INDIGO,
            accent=output.INDIGO, warning=output.AMBER, error="#EF4444",
            success=output.TEAL, background=output.DARK, surface=output.DARK,
            panel="#1F2937", foreground="#E5E7EB", dark=True,
        ))
        self.theme = "exposureiq"

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Button("←", id="back")
            yield Static(Text.assemble(("ExposureIQ", f"bold {output.TEAL}"),
                                       (f" · v{self.version}", "dim")), id="brand")
        yield Static("Scanning", id="scan-status", markup=False)
        with VerticalScroll(id="home"):
            with Vertical(id="home-panel"):
                yield Static("Scan a domain", classes="home-heading")
                yield Input(placeholder="example.com", id="home-domain")
                yield Button("Scan this domain", id="home-scan", variant="primary")
                yield Static("Listed in scope: web checks + ports. Unlisted: passive discovery only.",
                             id="home-scan-note", markup=False)
                with Horizontal(id="home-actions"):
                    yield Button("View saved results", id="home-results")
                    yield Button("Add domain to my scope", id="home-scope")
                yield Static("Only add domains you own or may test. A domain covers its subdomains. "
                             "Saved to your user scope, never the repository scope.txt.",
                             id="home-note", markup=False)
                yield Static(id="home-message", markup=False)
        with VerticalScroll(id="browser"):
            yield Static("Saved scans", classes="home-heading")
            yield DataTable(id="saved-table", cursor_type="row", zebra_stripes=True)
            yield Button("Open selected file", id="saved-open", variant="primary")
            yield Static("Select a file, then Enter or Open selected. Read-only: no probes are sent.",
                         id="browser-note", markup=False)
        with VerticalScroll(id="scanning"):
            with Horizontal(id="scan-layout"):
                with Vertical(id="phase-list"):
                    for index, phase in enumerate(PHASES):
                        yield Static(f"○  {phase:<12} waiting", id=f"phase-{index}", classes="phase", markup=False)
                with Vertical(id="live-panel"):
                    yield Static("Subdomains  0\nHosts       0\nIPs         0\nFindings    0", id="counters", markup=False)
                    yield Static("Elapsed  0.0s", id="elapsed", markup=False)
                    yield ProgressBar(total=None, show_eta=False, show_percentage=False, id="scan-progress")
            yield Static("Preparing scan…", id="live-log", markup=False)
            yield Static("Active HTTP/TLS and ports require the unchanged scope gate. "
                         "Out-of-scope targets are skipped. No crawling or exploits.", id="safety", markup=False)
        with TabbedContent(initial="summary-tab", id="results"):
            with TabPane("Summary", id="summary-tab"):
                with Vertical(id="scope-skipped-panel"):
                    yield Static(id="scope-skipped-text", markup=False)
                    yield Button("Add to scope and scan", id="add-scope", variant="success")
                yield Static(id="severity-counts", markup=False)
                with Horizontal(id="summary-layout"):
                    yield DataTable(id="phase-counts", cursor_type="row")
                    with VerticalScroll(id="summary-info"):
                        yield Static(id="summary-notes", markup=False)
            with TabPane("Subdomains", id="subdomains-tab"):
                yield DataTable(id="subdomains-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Hosts", id="hosts-tab"):
                yield DataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Technologies", id="technologies-tab"):
                yield DataTable(id="technologies-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Findings", id="findings-tab"):
                with Horizontal(id="finding-layout"):
                    yield DataTable(id="findings-table", cursor_type="row", zebra_stripes=True,
                                    cursor_foreground_priority="renderable")
                    with VerticalScroll(id="finding-side"):
                        yield Static("Select a finding to see its detail and Fix.", id="finding-detail", markup=False)
            with TabPane("Ports", id="ports-tab"):
                yield Static(id="ports-skip-notes", markup=False)
                yield DataTable(id="ports-table", cursor_type="row", zebra_stripes=True)
        with Vertical(id="rerun-panel"):
            yield Static("Web-only re-run (no port scans)", markup=False)
            yield DataTable(id="rerun-hosts", cursor_type="row")
        yield Static(id="user-scope-saved", markup=False)
        yield Static(id="result-log", markup=False)
        yield Static("q / Ctrl+C quit/cancel   a add scope   Tab panels   ↑↓←→ move   Enter detail",
                     id="keys", markup=False)

    def on_mount(self) -> None:
        self.query_one("#results").display = False
        self.query_one("#scope-skipped-panel").display = False
        self.query_one("#rerun-panel").display = False
        self.query_one("#user-scope-saved").display = False
        self.query_one("#result-log").display = False
        self.query_one("#browser").display = False
        self.query_one("#home").display = False
        self.query_one("#scan-status").display = False
        self.query_one("#phase-list").border_title = "Phases"
        self.query_one("#live-panel").border_title = "Live totals"
        self.set_interval(0.1, self._tick)
        self._log_handler = _ScanLogHandler(self)
        self._previous_handlers = logging.getLogger().handlers[:]
        logging.getLogger().handlers = [self._log_handler]
        if self.open_file:
            self._finished = True
            if not self.open_saved(self.open_file):
                self._show_home()
        elif self.browser_mode:
            self._show_saved_list()
        elif self.home_mode:
            self._show_home()
        else:
            target = "example.com" if self.args.demo else self.args.domain
            self._show_scanning(target)
            self.worker = self._run_scan()

    def on_unmount(self) -> None:
        if self._rerunning or (self.mode == "scanning" and not self._finished):
            self.control.cancel()
        root = logging.getLogger()
        if self._log_handler in root.handlers:
            root.handlers = self._previous_handlers

    # --------------------------------------------------------------- navigation
    def _set_title(self, target=None, started_at=None, suffix="", demo=None):
        text = Text()
        text.append("ExposureIQ", style=f"bold {output.TEAL}")
        if target:
            # Keep the domain and scan time visible even in an 80-column terminal.
            text.append(f"  |  {target}", style="bold")
        else:
            text.append(f" · v{self.version}", style="dim")
        if started_at:
            text.append(f"  ·  {display_time(started_at)}", style="dim")
        if suffix:
            text.append(f"  ·  {suffix}", style=output.INDIGO)
        if demo is None:
            demo = bool(getattr(self.args, "demo", False))
        if demo:
            text.append("  |  DEMO (fake data)", style=f"bold {output.AMBER}")
        self.query_one("#brand", Static).update(text)

    def _keys(self, text):
        self.query_one("#keys", Static).update(text)

    def _set_back(self, visible):
        self.query_one("#back", Button).display = visible

    def _home_message(self, text, style=None):
        self.query_one("#home-message", Static).update(Text(text, style=style or output.AMBER))

    def _hide_all_views(self):
        for selector in ("#home", "#browser", "#scanning", "#results", "#scan-status", "#result-log",
                         "#rerun-panel", "#user-scope-saved", "#scope-skipped-panel"):
            self.query_one(selector).display = False

    def _show_home(self):
        self.mode = "home"
        self._finished, self.exit_code = True, 0
        self._hide_all_views()
        self.query_one("#home").display = True
        self._set_back(False)
        self._set_title(suffix="home", demo=False)
        self._keys("Type a domain   Tab move   Enter scan   Ctrl+C quit")
        self.call_after_refresh(self.query_one("#home-domain", Input).focus)

    def _show_saved_list(self):
        self.mode = "browser"
        self._finished, self.exit_code = True, 0
        self._hide_all_views()
        self.query_one("#browser").display = True
        self._set_back(True)
        self._set_title(suffix="saved results", demo=False)
        self._keys("Enter open   ← back   Tab move   q quit")
        self._populate_saved()
        self.call_after_refresh(self.query_one("#saved-table", DataTable).focus)

    def _populate_saved(self):
        entries = list_saved(self.results_dir)
        table = self.query_one("#saved-table", DataTable)
        table.clear(columns=True)
        table.add_columns(Text("File"), Text("Domain"), Text("Scan time"))
        self.saved_paths.clear()
        for index, entry in enumerate(entries):
            key = str(index)
            self.saved_paths[key] = entry["path"]
            third = entry["started"] or entry["error"] or "unknown time"
            table.add_row(Text(entry["name"]), Text(entry["target"]), Text(third), key=key)
        note = self.query_one("#browser-note", Static)
        if entries:
            note.update(f"{len(entries)} saved file(s) in {self.results_dir}. "
                        "Select a file, then Enter or Open selected. Read-only; no probes are sent.")
        else:
            note.update(f"No readable JSON files in {self.results_dir}.")

    def open_saved(self, path) -> bool:
        try:
            snapshot = storage.load_scan(str(path))
        except (OSError, ValueError) as error:
            self._home_message(f"Could not open {path}: {error}", "#EF4444")
            return False
        self.result = result_from_snapshot(snapshot, path)
        self._finished, self.exit_code = True, 0
        self._show_results()
        return True

    def start_scan(self, value: str) -> None:
        from exposureiq import cli
        from exposureiq.discovery import subdomains as sub

        try:
            domain = sub.normalize_domain((value or "").strip())
        except ValueError as error:
            self._home_message(str(error))
            return
        self.args = cli.build_parser().parse_args(["scan", domain])
        self.verbose = False
        if self.control.cancelled.is_set():
            self.control = ScanControl()
        self.result = None
        self.exit_code = 0
        self.phase_states = dict.fromkeys(PHASES, "waiting")
        self.phase_counts = dict.fromkeys(PHASES, 0)
        self.live_counts = dict(subdomains=0, hosts=0, ips=0, findings=0)
        self.warnings, self.finding_rows, self.rerun_states = [], {}, {}
        self._finished = self._rerunning = False
        self._show_scanning(domain)
        self.worker = self._run_scan()

    def _show_scanning(self, target: str) -> None:
        self.mode = "scanning"
        self._finished = False
        self._hide_all_views()
        self.query_one("#scanning").display = True
        self.query_one("#scan-status").display = True
        self.query_one("#scan-status", Static).update("Scanning")
        self._set_back(False)
        self._set_title(target)
        self._reset_phases()
        self._keys("q / Ctrl+C quit/cancel   Tab panels   ↑↓←→ move   Enter detail")
        self._started = time.monotonic()

    def _reset_phases(self) -> None:
        for index, phase in enumerate(PHASES):
            self.query_one(f"#phase-{index}", Static).update(f"○  {phase:<12} waiting")
        self.query_one("#counters", Static).update("Subdomains  0\nHosts       0\nIPs         0\nFindings    0")
        self.query_one("#elapsed", Static).update("Elapsed  0.0s")
        self.query_one("#live-log", Static).update("Preparing scan…")
        self.query_one("#scan-progress", ProgressBar).display = True

    def action_back(self) -> None:
        if self.mode == "browser":
            self._show_home()
        elif self.mode == "results":
            self._show_saved_list()

    @on(Button.Pressed, "#back")
    def back_button(self) -> None:
        self.action_back()

    @on(Button.Pressed, "#home-results")
    def home_results_button(self) -> None:
        self._show_saved_list()

    @on(Button.Pressed, "#home-scan")
    def home_scan_button(self) -> None:
        self.start_scan(self.query_one("#home-domain", Input).value)

    @on(Input.Submitted, "#home-domain")
    def home_domain_submitted(self, event: Input.Submitted) -> None:
        self.start_scan(event.value)

    @on(Button.Pressed, "#home-scope")
    def home_scope_button(self) -> None:
        from exposureiq.discovery import subdomains as sub

        try:
            domain = sub.normalize_domain(self.query_one("#home-domain", Input).value.strip())
        except ValueError as error:
            self._home_message(str(error))
            return
        dialog = ScopeConfirmation(domain, [domain])
        self.push_screen(dialog, lambda typed: self._home_scope_confirmed(domain, typed))

    def _home_scope_confirmed(self, domain: str, typed: str | None) -> None:
        if typed is None:
            self._home_message("Scope confirmation cancelled; no file changed.", output.INDIGO)
            return
        try:
            path, added = append_hosts(domain, [domain], typed)
        except (OSError, ValueError) as error:
            self._home_message(f"Could not add {domain} to your user scope: {error}", "#EF4444")
            return
        if added:
            self._home_message(f"Added {domain} to your user scope: {path}. "
                               "The repository scope.txt was not changed.", output.TEAL)
        else:
            self._home_message(f"{domain} was already in your user scope: {path}.", output.TEAL)

    @on(DataTable.RowSelected, "#saved-table")
    def saved_selected(self, event: DataTable.RowSelected) -> None:
        path = self.saved_paths.get(event.row_key.value)
        if path:
            self.open_saved(path)

    @on(Button.Pressed, "#saved-open")
    def saved_open_button(self) -> None:
        table = self.query_one("#saved-table", DataTable)
        if table.row_count:
            path = self.saved_paths.get(str(table.cursor_row))
            if path:
                self.open_saved(path)

    @work(thread=True, exclusive=True, exit_on_error=False)
    def _run_scan(self) -> None:
        try:
            result = self.scan_job(self.args, self.stages,
                                   lambda data: self.post_message(ScanEvent(data)),
                                   self.control, self.version)
        except ScanCancelled:
            return
        except Exception as error:
            self.post_message(ScanEvent({"kind": "failed", "message": str(error)}))
        else:
            # Fake jobs may return a result instead of emitting one.
            if not self.control.cancelled.is_set():
                self.post_message(ScanEvent({"kind": "result", "result": result}))

    def _tick(self) -> None:
        if self._finished:
            return
        self._frame = (self._frame + 1) % len(_SPINNER)
        self.query_one("#elapsed", Static).update(f"Elapsed  {time.monotonic() - self._started:.1f}s")
        for phase in PHASES:
            self._render_phase(phase)

    def _render_phase(self, phase: str) -> None:
        state = self.phase_states[phase]
        icon, color = {"waiting": ("○", "#9CA3AF"), "spinner": (_SPINNER[self._frame], output.INDIGO),
                       "done": ("✓", output.TEAL), "skipped": ("–", output.AMBER)}[state]
        count = f"  {self.phase_counts[phase]}" if state == "done" else ""
        self.query_one(f"#phase-{PHASES.index(phase)}", Static).update(
            Text(f"{icon}  {phase:<12} {state}{count}", style=color))

    def on_scan_event(self, message: ScanEvent) -> None:
        if self.control.cancelled.is_set():
            return
        data, kind = message.data, message.data["kind"]
        if kind == "phase":
            self.phase_states[data["phase"]] = data["state"]
            if data.get("count") is not None:
                self.phase_counts[data["phase"]] = data["count"]
            self._render_phase(data["phase"])
            if data.get("message"):
                self.query_one("#live-log", Static).update(data["message"])
        elif kind == "counters":
            for key in self.live_counts:
                self.live_counts[key] = data[key]
            self.query_one("#counters", Static).update(
                "\n".join(f"{key.title():<12} {value}" for key, value in self.live_counts.items()))
        elif kind in ("log", "skipped"):
            text = output.readable_message(data["message"], verbose=self.verbose)
            self.query_one("#live-log", Static).update(Text(text,
                 style=output.AMBER if data.get("level") == "warn" or kind == "skipped" else ""))
            self.query_one("#result-log", Static).update(Text(text,
                style=output.AMBER if data.get("level") == "warn" or kind == "skipped" else ""))
            if data.get("level") == "warn":
                self.warnings.append(data["message"])
        elif kind == "result" and not self._finished:
            self.result = data["result"]
            self.exit_code = self.result["return_code"]
            self._finished = True
            self._show_results()
        elif kind == "failed":
            self._finished, self.exit_code = True, 1
            self.query_one("#scan-status", Static).update("Scan stopped; discovery or storage failed")
            self.query_one("#live-log", Static).update(Text(
                output.readable_message(data["message"], verbose=self.verbose), style="bold #EF4444"))
            self.query_one("#scan-progress", ProgressBar).display = False
        elif kind == "scope_saved":
            self.result["user_scope_path"] = data["path"]
            self.query_one("#user-scope-saved").display = True
            self.query_one("#user-scope-saved", Static).update(f"User scope saved to {data['path']}")
            self.query_one("#scan-status", Static).update("Running confirmed web checks — no port scans")
            self.query_one("#result-log", Static).update(f"Scope saved to {data['path']}; running web checks only")
        elif kind == "host_progress":
            self.rerun_states[data["host"]] = data["state"]
            self._table("#rerun-hosts", ("Host", "State"), list(self.rerun_states.items()))
            self.query_one("#result-log", Static).update(
                output.readable_message(data["message"], verbose=self.verbose, host=data["host"]))
        elif kind == "rerun_result":
            self.result = data["result"]
            self.exit_code = self.result["return_code"]
            self._rerunning = False
            self._show_results()
        elif kind == "rerun_failed":
            self._rerunning = False
            self.exit_code = 1
            self.result.setdefault("warnings", []).append(data["message"])
            self._show_results()
            self.query_one("#scan-status", Static).update("Scope/web update failed — see warnings")
            self.query_one("#result-log", Static).update(Text(
                output.readable_message(data["message"], verbose=self.verbose), style="bold #EF4444"))

    def _table(self, selector: str, columns: tuple, rows: list) -> DataTable:
        table = self.query_one(selector, DataTable)
        table.clear(columns=True)
        table.add_columns(*(Text(column) for column in columns))
        for row in rows:
            table.add_row(*(cell if isinstance(cell, Text) else Text(str(cell)) for cell in row))
        return table

    def _show_results(self) -> None:
        result, assets = self.result, self.result["assets"]
        self.mode = "results"
        preview = result.get("mode") == "preview"
        self._hide_all_views()
        self.query_one("#scanning").display = False
        self.query_one("#results").display = True
        self.query_one("#scan-status").display = True
        self.query_one("#result-log").display = True
        self._set_back(True)
        self._set_title(result["target"], result.get("started_at"), demo=bool(result.get("demo")))
        if preview:
            self.query_one("#scan-status", Static).update("Saved scan · read-only preview — no probes sent")
            self._keys("← saved results   Tab panels   ↑↓←→ move   Enter detail   q quit")
        else:
            self.query_one("#scan-status", Static).update(
                "Scan finished" if not self.exit_code else "Scan finished — results could not be saved")
            self._keys("← saved results   a add scope   Tab panels   ↑↓←→ move   Enter detail   "
                       "q / Ctrl+C quit/cancel")
        if result.get("user_scope_path"):
            self.query_one("#user-scope-saved").display = True
            self.query_one("#user-scope-saved", Static).update(f"User scope saved to {result['user_scope_path']}")
        counts = dict.fromkeys(_SEVERITY, 0)
        for asset in assets:
            for finding in asset.get("findings", []):
                counts[finding["severity"]] += 1
        severity_text = Text("Findings  ", style="bold")
        for severity, count in counts.items():
            severity_text.append(f"{severity.upper()} {count}    ", style=_SEVERITY[severity])
        self.query_one("#severity-counts", Static).update(severity_text)
        self._table("#phase-counts", ("Phase", "State", "Count", "Seconds"), [
            (phase, result["phase_states"][phase], result["phase_counts"][phase],
             f"{result['phase_times'][phase]:.1f}") for phase in PHASES
        ])
        groups = output.grouped_ips(assets)
        if preview:
            mode = ("DEMO — saved fake data; read-only preview (no probes sent)"
                    if result["demo"] else result.get("mode_detail") or "Saved scan — read-only preview")
            when = f"Scan time  {result.get('started_time') or 'unknown'}\n"
        else:
            mode = ("DEMO — fake data; no network" if result["demo"]
                    else result.get("mode_detail") or "Active checks limited to authorized scope")
            when = f"Time  {result['elapsed']:.1f}s\n"
        notes = Text()
        style = output.TEAL if result.get("mode") == "full" else output.AMBER
        notes.append(f"{mode}\n", style=style)
        notes.append(f"\nTarget  {result['target']}\n"
                     f"Subdomains  {len(result['names'])}\nHosts  {len(assets)}\n"
                     f"Unique IPs  {len(groups)}\n{when}\n"
                     f"Saved file\n{result['saved_to'] or 'Not saved'}\n\n")
        warnings = list(dict.fromkeys(result.get("warnings", []) + self.warnings))
        if warnings:
            notes.append("Warnings (a missing result is not proof of safety)\n", style=output.AMBER)
            notes.append("\n".join(dict.fromkeys(output.readable_message(message, verbose=self.verbose)
                                                 for message in warnings)) + "\n\n")
        skipped_hosts = result.get("skipped_hosts", [])
        if skipped_hosts:
            notes.append(f"{len(skipped_hosts)} hosts skipped: not in scope\n", style=output.AMBER)
            notes.append("\n".join(dict.fromkeys(skipped_hosts)) + "\n\n")
        scope_ips = result.get("skipped_scope_ips", result.get("skipped_ips", []))
        ipv6_ips = result.get("skipped_ipv6_ips", [])
        if scope_ips:
            notes.append("Skipped: not in scope (ports)\n", style=output.AMBER)
            notes.append("\n".join(scope_ips) + "\n\n")
        if ipv6_ips:
            notes.append("Skipped: IPv6 ports not supported\n", style=output.AMBER)
            notes.append("\n".join(ipv6_ips) + "\n\n")
        if result.get("user_scope_path"):
            notes.append(f"User scope saved to\n{result['user_scope_path']}\n", style=output.TEAL)
        candidates = eligible_hosts(result["target"], skipped_hosts)
        self.query_one("#scope-skipped-panel").display = bool(skipped_hosts)
        self.query_one("#scope-skipped-text", Static).update(
            f"{len(skipped_hosts)} hosts skipped: not in scope. "
            "Confirm ownership or written permission to add host names and run web checks only.")
        button = self.query_one("#add-scope", Button)
        button.display = bool(candidates) and not result.get("demo", False) and not preview
        button.disabled = self._rerunning
        self.query_one("#summary-notes", Static).update(notes)
        host_states = result.get("host_states", {})
        self._table("#subdomains-table", ("Subdomain", "Active checks"), [
            (name, host_states.get(name, "skipped: no IP address")) for name in result["names"]
        ])
        self._table("#hosts-table", ("IP", "Host count", "Hosts"), [
            (ip, len(hosts), ", ".join(hosts)) for ip, hosts in groups
        ])
        self._table("#technologies-table", ("Host", "Product", "Version", "Source"), [
            (asset["host"], technology["name"], technology["version"] or "unknown", technology["source"])
            for asset in assets for technology in asset.get("technologies", [])
        ])
        table = self.query_one("#findings-table", DataTable)
        table.clear(columns=True)
        self.finding_rows.clear()
        table.add_columns(Text("Severity"), Text("Host"), Text("Finding"))
        findings = [(asset["host"], finding) for asset in assets for finding in asset.get("findings", [])]
        rank = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda row: (rank[row[1]["severity"]], row[0], row[1]["id"]))
        for index, (host, finding) in enumerate(findings):
            key = str(index)
            self.finding_rows[key] = (host, finding)
            table.add_row(Text(finding["severity"].upper(), style=_SEVERITY[finding["severity"]]),
                          Text(host), Text(finding["title"]), key=key)
        if findings:
            self._show_finding("0")
        else:
            self.query_one("#finding-detail", Static).update(
                "No findings returned. Out-of-scope targets or failed requests are not proof of safety.")
        self._table("#ports-table", ("IP", "Port", "Protocol", "Service"), [
            (ip, port["port"], port["protocol"], port["service"])
            for ip, ports in result["port_rows"] for port in ports
        ])
        port_notes = []
        if scope_ips:
            port_notes.append("Skipped: not in scope — " + ", ".join(scope_ips))
        if ipv6_ips:
            port_notes.append("Skipped: IPv6 ports not supported — " + ", ".join(ipv6_ips))
        if result.get("mode") == "passive" and not result["port_rows"]:
            port_notes.append(result.get("mode_detail") or "Ports skipped: no authorized host.")
        self.query_one("#ports-skip-notes", Static).update("\n".join(port_notes))
        self.query_one("#ports-skip-notes").styles.height = "auto"
        self.call_after_refresh(self.query_one("#results Tabs", Tabs).focus)

    def _show_finding(self, key: str) -> None:
        if key not in self.finding_rows:
            return
        host, finding = self.finding_rows[key]
        detail = Text()
        detail.append(finding["title"] + "\n", style=_SEVERITY[finding["severity"]])
        detail.append(f"\nHost: {host}\nID: {finding['id']}\nRule: {finding['rule']}\n")
        if "ip" in finding:
            detail.append(f"IP: {finding['ip']}\n")
        if "port" in finding:
            detail.append(f"Port: {finding['port']}\n")
        detail.append(f"\n{finding['detail']}\n\n")
        detail.append("Fix: ", style=f"bold {output.TEAL}")
        detail.append(finding["recommendation"])
        self.query_one("#finding-detail", Static).update(detail)

    @on(DataTable.RowSelected, "#findings-table")
    def select_finding(self, event: DataTable.RowSelected) -> None:
        self._show_finding(event.row_key.value)

    @on(DataTable.RowHighlighted, "#findings-table")
    def highlight_finding(self, event: DataTable.RowHighlighted) -> None:
        self._show_finding(event.row_key.value)

    def action_quit(self) -> None:
        if self._rerunning or (self.mode == "scanning" and not self._finished):
            self.control.cancel()
            if self.worker is not None:
                self.worker.cancel()
            self.exit(130)
        else:
            self.exit(self.exit_code)

    def action_cancel_scan(self) -> None:
        self.action_quit()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in ("quit", "add_scope") and isinstance(self.focused, Input):
            return False  # Let the user type q/a in a domain box.
        if action == "add_scope":
            return bool(self._finished and not self._rerunning and self.result
                        and self.mode == "results" and self.result.get("mode") != "preview"
                        and not self.result.get("demo") and not isinstance(self.screen, ScopeConfirmation)
                        and eligible_hosts(self.result["target"], self.result.get("skipped_hosts", [])))
        return True

    @on(Button.Pressed, "#add-scope")
    def add_scope_button(self) -> None:
        self.action_add_scope()

    def action_add_scope(self) -> None:
        if not self.check_action("add_scope", ()):
            return
        dialog = ScopeConfirmation(self.result["target"], self.result["skipped_hosts"])
        self.push_screen(dialog, lambda typed: self._scope_confirmed(dialog.hosts, typed))

    def _scope_confirmed(self, hosts: list, typed: str | None) -> None:
        if typed is None:
            self.query_one("#result-log", Static).update("Scope confirmation cancelled; no file changed")
            return
        if typed != self.result["target"]:
            return
        self._rerunning = True
        self.rerun_states = dict.fromkeys(hosts[:MAX_HOSTS], "waiting")
        self.query_one("#rerun-panel").display = True
        self.query_one("#add-scope", Button).disabled = True
        self._table("#rerun-hosts", ("Host", "State"), list(self.rerun_states.items()))
        self.worker = self._add_scope_and_rerun(hosts, typed)

    @work(thread=True, exclusive=True, exit_on_error=False)
    def _add_scope_and_rerun(self, hosts: list, typed: str) -> None:
        report = lambda data: self.post_message(ScanEvent(data))
        try:
            self.control.check()
            path, added = append_hosts(self.result["target"], hosts, typed)
            report({"kind": "scope_saved", "path": str(path)})
            # No ports, DNS, or discovery calls in this path.
            seed = {**self.result, "user_scope_path": str(path)}
            rerun_hosts(seed, added, self.stages, report, self.control)
        except ScanCancelled:
            return
        except Exception as error:
            report({"kind": "rerun_failed", "message": f"Scope/web update failed: {error}"})
