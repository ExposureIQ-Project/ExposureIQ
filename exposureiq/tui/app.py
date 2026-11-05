"""Full-screen scan progress and results. All stages run off the UI thread."""

import logging
import threading
import time
from pathlib import Path

from rich.cells import cell_len
from rich.segment import Segment
from rich.text import Text
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.geometry import Size
from textual.message import Message
from textual.strip import Strip
from textual.theme import Theme
from textual.worker import get_current_worker
from textual.widgets import Button, DataTable, Input, ProgressBar, Rule, Static, TabbedContent, TabPane, Tabs

from exposureiq import output, storage
from exposureiq.report import branding
from exposureiq.tui.clipboard import copy_system_text
from exposureiq.tui.control import ScanCancelled, ScanControl
from exposureiq.tui.confirm_scope import ScopeConfirmation
from exposureiq.tui.export import ExportDialog
from exposureiq.tui.rerun import rerun_hosts
from exposureiq.tui.saved import display_time, list_saved, result_from_snapshot
from exposureiq.tui.selectable_table import SelectableDataTable
from exposureiq.tui.scan import PHASES, ScanStages, run_scan
from exposureiq.tui.user_scope import MAX_HOSTS, append_hosts, eligible_hosts
from exposureiq.diffing import pipeline as diff_pipeline
from exposureiq.diffing import summary as diff_summary

_SEVERITY = {"high": f"bold {branding.TUI_HIGH} on {branding.HIGH_BACKGROUND}",
             "medium": branding.AMBER, "low": branding.LOW}
_SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_HOME_LOGO = (
    "▄████████ ▀████    ▐████▀    ▄███████▄  ▄██████▄     ▄████████ ███    █▄     ▄████████    ▄████████  ▄█  ████████▄  \n"
    "  ███    ███   ███▌   ████▀    ███    ███ ███    ███   ███    ███ ███    ███   ███    ███   ███    ███ ███  ███    ███ \n"
    "  ███    █▀     ███  ▐███      ███    ███ ███    ███   ███    █▀  ███    ███   ███    ███   ███    █▀  ███▌ ███    ███ \n"
    " ▄███▄▄▄        ▀███▄███▀      ███    ███ ███    ███   ███        ███    ███  ▄███▄▄▄▄██▀  ▄███▄▄▄     ███▌ ███    ███ \n"
    "▀▀███▀▀▀        ████▀██▄     ▀█████████▀  ███    ███ ▀███████████ ███    ███ ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███▌ ███    ███ \n"
    "  ███    █▄    ▐███  ▀███      ███        ███    ███          ███ ███    ███ ▀███████████   ███    █▄  ███  ███    ███ \n"
    "  ███    ███  ▄███     ███▄    ███        ███    ███    ▄█    ███ ███    ███   ███    ███   ███    ███ ███  ███  ▀ ███ \n"
    "  ██████████ ████       ███▄  ▄████▀       ▀██████▀   ▄████████▀  ████████▀    ███    ███   ██████████ █▀    ▀██████▀▄█\n"
    "                                                                               ███    ███ "
)
_HOME_LOGO_WIDTH = max(cell_len(line) for line in _HOME_LOGO.splitlines())


def _append_labeled_row(text: Text, label: str, value) -> None:
    """Align existing details without changing their values."""
    text.append(f"{label:<12}", style=branding.TUI_LABEL)
    text.append(f"{value}\n", style=branding.TEXT_PRIMARY)


def _diff_body(diff: dict) -> Text:
    """One readable baseline/history view for the browser and results tab."""
    body = Text()
    categories = (
        ("Subdomains/Hosts", ("host.new", "host.removed")),
        ("IP addresses", ("ip.new", "ip.removed")),
        ("Open ports / services", ("port.opened", "port.closed", "port.service_changed")),
        ("Technologies", ("tech.new", "tech.removed", "tech.version_changed")),
        ("Findings", ("finding.new", "finding.resolved", "finding.severity_changed")),
    )
    changes = diff.get("changes") or []
    for title, kinds in categories:
        items = [change for change in changes if isinstance(change, dict) and change.get("kind") in kinds]
        if not items:
            continue
        body.append(f"\n{title}\n", style=f"bold {branding.TEAL}")
        for change in items:
            direction = change.get("direction")
            color = branding.HIGH if direction == "worse" else branding.TEAL if direction == "better" else branding.MUTED
            prefix = "!" if direction == "worse" else "~" if direction == "better" else "•"
            body.append(f"  {prefix} {diff_summary.describe_change(change)}\n", style=color)
    for note in diff.get("notes") or []:
        body.append(f"\nNote: {note}\n", style=branding.MUTED)
    history = diff.get("history") or []
    if history:
        body.append("\nScan-by-scan history\n", style=f"bold {branding.TEAL}")
        body.append("Overall counts above are net changes; the steps retain temporary issues.\n", style=branding.MUTED)
        for step in history:
            old, new = step.get("old") or {}, step.get("new") or {}
            summary = step.get("summary") or {}
            body.append(f"\n{old.get('scan_id', '?')} → {new.get('scan_id', '?')}\n", style="bold")
            body.append(f"{summary.get('headline') or 'No changes'}\n")
            for line in summary.get("lines") or []:
                body.append(f"  • {line}\n")
            for note in step.get("notes") or []:
                body.append(f"  Note: {note}\n", style=branding.MUTED)
    return body


class _SavedResultsTable(DataTable):
    """Browse files: single-click chooses a row; double-click or Enter opens it."""

    ALLOW_SELECT = False

    def _on_click(self, event: events.Click) -> None:
        # The normal table handler may open an already-highlighted row on its
        # first click. Make opening explicit, and never select/copy browser text.
        event.prevent_default()
        event.stop()
        row_index = event.style.meta.get("row")
        if (event.button == 1 and isinstance(row_index, int)
                and 0 <= row_index < self.row_count):
            self.move_cursor(row=row_index, scroll=False)
            if event.chain == 2:
                self.action_select_cursor()  # Reuse the normal RowSelected/Enter path.


class _PhaseTable(SelectableDataTable):
    """Draw separators in each row's spare line, not as extra data rows."""
    COMPONENT_CLASSES = DataTable.COMPONENT_CLASSES | {"datatable--separator"}

    def render_line(self, y: int) -> Strip:
        header = self.header_height if self.show_header else 0
        if y >= header:
            offset = y - header + self.scroll_offset.y
            for row in self.ordered_rows:
                if offset < row.height:
                    if row.height > 1 and offset == row.height - 1:
                        style = self.rich_style + self.get_component_rich_style("datatable--separator")
                        return Strip([Segment("─" * self.size.width, style)])
                    break
                offset -= row.height
        return super().render_line(y)


class _ResultsTabs(TabbedContent):
    """Keep all existing tabs, with one shared findings row beneath them."""

    def compose(self) -> ComposeResult:
        content = super().compose()
        yield next(content)  # The normal tab bar and its keyboard handling.
        with Horizontal(id="severity-counts"):
            yield Static("Findings", id="severity-label", markup=False)
            yield Static("HIGH 0", id="severity-high", classes="severity-chip", markup=False)
            yield Static("MEDIUM 0", id="severity-medium", classes="severity-chip", markup=False)
            yield Static("LOW 0", id="severity-low", classes="severity-chip", markup=False)
        yield from content


class ScanEvent(Message):
    def __init__(self, data: dict):
        super().__init__()
        self.data = data


class ReportExported(Message):
    def __init__(self, result: dict, fmt: str, *, path: str | None = None, error: str | None = None):
        super().__init__()
        self.result, self.fmt, self.path, self.error = result, fmt, path, error


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
        Binding("ctrl+shift+c,ctrl+insert", "copy_selection", "Copy", priority=True),
        Binding("a", "add_scope", "Add to scope"),
        Binding("d", "diff_view", "Diff"),
        Binding("e", "export_report", "Export"),
        Binding("tab", "focus_next", "Next panel"),
        Binding("shift+tab", "focus_previous", "Previous", show=False),
    ]
    CSS = """
    Screen { background: $background; color: $body-text; }
    /* Start one row below the four-row header, clear of its title and buttons. */
    ToastRack { dock: top; align: right top; margin: 5 0 0 0; padding: 0 1; overflow-y: auto; }
    Toast { width: auto; max-width: 50%; margin: 0 0 1 0; padding: 0 1; background: $panel; }
    Toast.-information { border: round $primary; }
    Toast.-warning { border: round $warning; }
    Toast.-error { border: round $error; }
    .panel, DataTable {
        background: $surface; border: round $panel-border; padding: 1 2;
        border-title-color: $primary; border-title-style: bold;
        border-subtitle-color: $footnote;
    }
    .detail-panel {
        background: $panel; border: round $secondary;
        border-title-color: $secondary; border-title-style: bold;
    }
    Button, Button.-primary, Button.-success, Button:hover, Button.-primary:hover,
    Button.-success:hover, Button.-active {
        border: round $panel-border; padding: 0 2;
        background: transparent; background-tint: transparent; tint: transparent;
    }
    Button { color: $foreground; }
    Button.-primary, Button.-success {
        color: $primary; border: round $primary;
    }
    Button:disabled { color: $text-muted; text-opacity: 1; border: round $panel-border; }
    Button:focus, Button.-primary:focus, Button.-success:focus { background-tint: transparent; border: round $primary; }
    Input { background: transparent; color: $foreground; border: round $panel-border; padding: 0 2; }
    Input:focus { background-tint: transparent; border: round $primary; }
    Input.-invalid, Input.-invalid:focus { border: round $error; }
    Tab { color: $tab-inactive; }
    Tab:hover, Tab.-active, Tabs:focus Tab.-active { color: $primary; }
    Tab.-active, Tabs:focus Tab.-active { text-style: bold; background: transparent; }
    Tab:disabled { color: $text-disabled; }
    Underline > .underline--bar { color: $primary; background: $tab-divider; }
    Tabs:focus .underline--bar { background: $tab-divider; }
    #topbar { height: 4; background: $panel; border-bottom: solid $primary; padding: 0 1; }
    #brand { width: 1fr; height: 3; padding: 0 1; content-align: left middle; background: $panel; }
    #header-actions { width: auto; height: 3; margin-left: 1; padding-right: 1; }
    #mode-badge {
        width: auto; height: 3; padding: 0 1; border: round $secondary;
        background: transparent; color: $secondary; text-style: bold; content-align: center middle;
    }
    #mode-badge.demo { color: $warning; border: round $demo-border; }
    #export-report { display: none; width: auto; min-width: 12; height: 3; margin-left: 1; }
    #back { width: 5; min-width: 5; height: 3; padding: 0; border: round $panel-border;
            color: $primary; text-style: bold; }
    #home { height: 1fr; align: center middle; }
    #home-center { width: 100%; max-width: 120; height: auto; align: center middle; content-align: center middle; }
    #ascii-logo { height: auto; color: $primary; text-style: bold; text-align: center; }
    #home-bar { height: auto; margin-top: 1; align: center middle; }
    #home-domain { width: 40; height: 3; }
    #home-scan { height: 3; margin-left: 1; }
    .home-heading { height: auto; margin-top: 1; color: $primary; text-style: bold; }
    #home-actions { height: auto; margin-top: 1; align: center middle; }
    #home-actions Button { margin-right: 1; }
    #saved-open { margin-top: 1; }
    #saved-diff-domain { margin-top: 1; margin-left: 1; }
    #browser-actions { height: auto; }
    #home-scan-note { height: auto; margin-top: 1; color: $footnote; text-align: center; }
    #home-note { height: auto; margin-top: 1; color: $footnote; text-align: center; }
    #home-message { display: none; height: auto; margin-top: 1; text-align: center; }
    #home-message.has-message { display: block; }
    #browser { height: 1fr; padding: 1 2; }
    #saved-table { height: 1fr; }
    #browser-note { height: auto; margin-top: 1; color: $footnote; }
    #scan-status { height: 1; margin: 0 2; color: $secondary; text-style: bold; }
    #scanning { height: 1fr; padding: 0 2; }
    #scan-layout { height: auto; align-vertical: top; }
    #phase-list { width: 47fr; height: 10; }
    .phase { height: 1; }
    #live-panel { width: 53fr; height: 10; margin-left: 1; }
    #counters { height: 4; }
    #elapsed { height: 1; color: $secondary; }
    #scan-progress { width: 100%; }
    #scan-progress Bar > .bar--indeterminate { color: $primary; }
    #live-log { height: 3; margin-top: 1; padding: 0 2; border: round $warning; text-wrap: nowrap; text-overflow: ellipsis; }
    #safety { height: auto; margin: 1 0 0 0; color: $footnote; }
    #results { height: 1fr; margin: 0 1; }
    #results > ContentSwitcher { height: 1fr; overflow: hidden hidden; }
    TabPane { height: 100%; padding: 1; }
    DataTable { height: 1fr; color: $body-text; }
    DataTable:focus, DataTable:focus > .datatable--header { background-tint: transparent; }
    DataTable > .datatable--header { background: $table-header; color: $primary; text-style: bold; }
    DataTable > .datatable--odd-row { background: $surface; }
    DataTable > .datatable--even-row { background: $surface; }
    DataTable > .datatable--separator { color: $row-divider; background: $surface; }
    DataTable > .datatable--cursor, DataTable > .datatable--fixed-cursor,
    DataTable:focus > .datatable--cursor, DataTable:focus > .datatable--fixed-cursor {
        background: $block-cursor-background; color: $foreground;
    }
    DataTable > .datatable--hover, DataTable > .datatable--header-hover,
    DataTable > .datatable--header-cursor { background: $block-cursor-background; }
    #severity-counts { height: 3; margin: 1 1 0 1; }
    #severity-label { width: auto; height: 3; margin-right: 1; content-align: left middle; color: $foreground; text-style: bold; }
    .severity-chip { width: auto; height: 3; margin-right: 1; padding: 0 1; background: transparent; text-style: bold; content-align: center middle; }
    #severity-high { color: $severity-high; border: round $severity-high; }
    #severity-medium { color: $warning; border: round $warning; }
    #severity-low { color: $severity-low; border: round $severity-low; }
    #summary-layout { height: 1fr; }
    #phase-counts { width: 47fr; }
    #summary-info { width: 53fr; height: 1fr; margin-left: 1; }
    #summary-notes, #report-exports { height: auto; }
    #scope-skipped-panel { height: auto; border: round $warning; margin-bottom: 1; }
    #scope-skipped-text { height: auto; color: $warning; }
    #add-scope { margin-top: 1; }
    #user-scope-saved { height: auto; margin: 0 2; color: $primary; }
    #result-log { height: 1; margin: 0 2; color: $secondary; text-wrap: nowrap; text-overflow: ellipsis; }
    #rerun-panel { height: auto; max-height: 40%; border: round $primary; margin: 0 2; }
    #rerun-hosts { height: auto; max-height: 8; }
    #finding-layout { height: 1fr; }
    #findings-table { width: 47fr; }
    #finding-side { width: 53fr; height: 1fr; margin-left: 1; }
    #finding-title, #finding-detail, #finding-recommendation { height: auto; }
    #finding-title { margin-bottom: 1; text-style: bold; }
    #finding-detail { color: $foreground; }
    #finding-next-step { height: 1; color: $primary; text-style: bold; margin-bottom: 1; }
    #finding-recommendation { color: $body-text; }
    .details-divider { height: 1; margin: 0 0 1 0; color: $detail-divider; }
    #finding-side.empty-findings .finding-extra { display: none; }
    #diff-view { height: 1fr; padding: 1 2; }
    #diff-target { height: auto; color: $primary; text-style: bold; }
    #diff-meta { height: auto; color: $text-muted; }
    #diff-headline { height: auto; margin-top: 1; text-style: bold; }
    #diff-sections { height: 1fr; }
    .diff-section { height: auto; margin-top: 1; }
    .diff-worse { color: $error; text-style: bold; }
    .diff-better { color: $primary; text-style: bold; }
    .diff-other { color: $text-muted; }
    #diff-notes { height: auto; color: $text-muted; }
    #diff-message { height: auto; margin-top: 1; }
    #scan-diff-scroll { height: 1fr; }
    #footer { height: auto; dock: bottom; padding: 0 2; background: $footer-background; }
    #keys { width: 1fr; height: auto; min-height: 1; color: $key-hint; background: $footer-background; }
    #footer-note { width: auto; max-width: 38%; height: auto; margin-left: 1; color: $primary; text-align: right; }
    Screen.compact #scan-layout { layout: vertical; }
    Screen.compact #phase-list, Screen.compact #live-panel { width: 100%; margin-left: 0; }
    Screen.compact #live-panel { margin-top: 1; }
    Screen.compact #summary-layout, Screen.compact #finding-layout { layout: vertical; }
    Screen.compact #phase-counts, Screen.compact #summary-info,
    Screen.compact #findings-table, Screen.compact #finding-side { width: 100%; height: 1fr; margin-left: 0; }
    Screen.compact #summary-info, Screen.compact #finding-side { margin-top: 1; }
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
        self._exporting = False
        self.export_worker = None
        self.clipboard_worker = None
        self._clipboard_lock = threading.Lock()
        self._selection_copy_pending = False
        self._selection_input = None
        self.rerun_states = {}
        self.worker = None
        self._log_handler = None
        self._diff_target = None
        self.register_theme(Theme(
            name="exposureiq", primary=branding.TEAL, secondary=branding.INDIGO,
            accent=branding.TEAL, warning=branding.AMBER, error=branding.HIGH,
            success=branding.TEAL, background=branding.PANEL,
            surface=branding.INNER_SURFACE, panel=branding.PANEL,
            foreground=branding.TEXT_PRIMARY, dark=True,
            variables={
                "primary": branding.TEAL, "secondary": branding.INDIGO,
                "accent": branding.TEAL, "warning": branding.AMBER,
                "error": branding.HIGH, "success": branding.TEAL,
                "background": branding.PANEL, "surface": branding.INNER_SURFACE,
                "panel": branding.PANEL, "foreground": branding.TEXT_PRIMARY,
                "text": branding.TEXT_PRIMARY, "text-muted": branding.MUTED,
                "text-disabled": branding.TEXT_DISABLED,
                "text-primary": branding.TEAL, "text-secondary": branding.INDIGO,
                "text-accent": branding.TEAL, "text-warning": branding.AMBER,
                "text-error": branding.HIGH, "text-success": branding.TEAL,
                "border": branding.TEAL, "border-blurred": branding.LINE,
                "table-header": branding.TUI_TABLE_HEADER,
                "body-text": branding.TUI_BODY_TEXT,
                "tab-inactive": branding.TUI_TAB_INACTIVE,
                "footnote": branding.TUI_FOOTNOTE, "label": branding.TUI_LABEL,
                "key-hint": branding.TUI_KEY_HINT,
                "panel-border": branding.TUI_PANEL_BORDER,
                "tab-divider": branding.TUI_TAB_DIVIDER,
                "row-divider": branding.TUI_ROW_DIVIDER,
                "detail-divider": branding.TUI_DETAIL_DIVIDER,
                "demo-background": branding.DEMO_BACKGROUND,
                "demo-border": branding.DEMO_BORDER,
                "severity-high": branding.TUI_HIGH, "severity-low": branding.LOW,
                "high-background": branding.HIGH_BACKGROUND,
                "medium-background": branding.MEDIUM_BACKGROUND,
                "low-background": branding.LOW_BACKGROUND,
                "surface-lighten-1": branding.BORDER_SOFT,
                "surface-darken-1": branding.BORDER_MUTED,
                "primary-lighten-3": branding.GLOW, "primary-darken-3": branding.LINE,
                "primary-darken-2": branding.BUTTON_FILL,
                "success-lighten-2": branding.GLOW, "success-darken-3": branding.LINE,
                "success-darken-2": branding.BUTTON_FILL,
                "button-fill": branding.BUTTON_FILL,
                "button-foreground": branding.TEXT_PRIMARY,
                "button-color-foreground": branding.BUTTON_TEXT,
                "button-focus-text-style": "b",
                "block-cursor-background": branding.HIGHLIGHT,
                "block-cursor-foreground": branding.TEXT_PRIMARY,
                "block-cursor-blurred-background": branding.HIGHLIGHT,
                "block-cursor-blurred-foreground": branding.TEXT_PRIMARY,
                "block-hover-background": branding.HIGHLIGHT,
                "input-cursor-background": branding.TEAL,
                "input-cursor-foreground": branding.BUTTON_TEXT,
                "input-selection-background": branding.HIGHLIGHT,
                "input-selection-foreground": branding.TEXT_PRIMARY,
                "screen-selection-background": branding.TEAL,
                "screen-selection-foreground": branding.DARK,
                "scrollbar": branding.LINE, "scrollbar-hover": branding.BORDER_SOFT,
                "scrollbar-active": branding.TEAL,
                "scrollbar-background": branding.PANEL,
                "scrollbar-background-hover": branding.PANEL,
                "scrollbar-background-active": branding.PANEL,
                "scrollbar-corner-color": branding.PANEL,
                "footer-background": branding.PANEL,
            },
        ))
        self.theme = "exposureiq"

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Button("←", id="back")
            yield Static(Text.assemble(("ExposureIQ", f"bold {output.TEAL}"),
                                       (f" · v{self.version}", branding.TUI_BREADCRUMB)), id="brand")
            with Horizontal(id="header-actions"):
                yield Static(id="mode-badge", markup=False)
                yield Button("Export", id="export-report", variant="primary", disabled=True)
        yield Static("Scanning", id="scan-status", markup=False)
        with VerticalScroll(id="home"):
            with Vertical(id="home-center"):
                yield Static("ExposureIQ", id="ascii-logo", markup=False)
                with Horizontal(id="home-bar"):
                    yield Input(placeholder="example.com", id="home-domain")
                    yield Button("Scan", id="home-scan", variant="primary")
                with Horizontal(id="home-actions"):
                    yield Button("View saved results", id="home-results")
                    yield Button("Add domain to my scope", id="home-scope")
                yield Static("Listed in scope: web checks + ports. Unlisted: passive discovery only.", id="home-scan-note", markup=False)
                yield Static("Only test domains you own or have permission to test.", id="home-note", markup=False)
                yield Static(id="home-message", markup=False)
        with VerticalScroll(id="browser"):
            yield Static("Saved scans", classes="home-heading")
            yield _SavedResultsTable(id="saved-table", cursor_type="row", zebra_stripes=True)
            with Horizontal(id="browser-actions"):
                yield Button("Open selected file", id="saved-open", variant="primary")
                yield Button("View selected scan history", id="saved-diff-domain", variant="default")
            yield Static("Select a file, then Enter or Open selected. Diff available if domain has 2+ scans.",
                         id="browser-note", markup=False)
        with VerticalScroll(id="diff-view"):
            yield Static(id="diff-target", markup=False)
            yield Static(id="diff-meta", markup=False)
            yield Static(id="diff-headline", markup=False)
            with VerticalScroll(id="diff-sections", classes="panel detail-panel"):
                yield Static(id="diff-body", markup=False)
            yield Static(id="diff-notes", markup=False)
            yield Static(id="diff-message", markup=False)
        with VerticalScroll(id="scanning"):
            with Horizontal(id="scan-layout"):
                with Vertical(id="phase-list", classes="panel"):
                    for index, phase in enumerate(PHASES):
                        yield Static(f"○  {phase:<12} waiting", id=f"phase-{index}", classes="phase", markup=False)
                with Vertical(id="live-panel", classes="panel detail-panel"):
                    yield Static("Subdomains  0\nHosts       0\nIPs         0\nFindings    0", id="counters", markup=False)
                    yield Static("Elapsed  0.0s", id="elapsed", markup=False)
                    yield ProgressBar(total=None, show_eta=False, show_percentage=False, id="scan-progress")
            yield Static("Preparing scan…", id="live-log", markup=False)
            yield Static("Active HTTP/TLS and ports require the unchanged scope gate. "
                         "Out-of-scope targets are skipped. No crawling or exploits.", id="safety", markup=False)
        with _ResultsTabs(initial="summary-tab", id="results"):
            with TabPane("Summary", id="summary-tab"):
                with Vertical(id="scope-skipped-panel", classes="panel"):
                    yield Static(id="scope-skipped-text", markup=False)
                    yield Button("Add to scope and scan", id="add-scope", variant="success")
                with Horizontal(id="summary-layout"):
                    yield _PhaseTable(id="phase-counts", cursor_type="row")
                    with VerticalScroll(id="summary-info", classes="panel detail-panel"):
                        yield Rule(line_style="solid", classes="details-divider")
                        yield Static(id="summary-notes", markup=False)
                        yield Static(id="report-exports", markup=False)
            with TabPane("Subdomains", id="subdomains-tab"):
                yield SelectableDataTable(id="subdomains-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Hosts", id="hosts-tab"):
                yield SelectableDataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Technologies", id="technologies-tab"):
                yield SelectableDataTable(id="technologies-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Findings", id="findings-tab"):
                with Horizontal(id="finding-layout"):
                    yield SelectableDataTable(id="findings-table", cursor_type="row", zebra_stripes=True,
                                              cursor_foreground_priority="renderable",
                                              cursor_background_priority="renderable")
                    with VerticalScroll(id="finding-side", classes="panel detail-panel empty-findings"):
                        yield Rule(line_style="solid", classes="details-divider finding-extra")
                        yield Static(id="finding-title", classes="finding-extra", markup=False)
                        yield Static("Select a finding to see its detail and Fix.", id="finding-detail", markup=False)
                        yield Rule(line_style="solid", classes="details-divider finding-extra")
                        yield Static("NEXT STEP", id="finding-next-step", classes="finding-extra", markup=False)
                        yield Static(id="finding-recommendation", classes="finding-extra", markup=False)
            with TabPane("Ports", id="ports-tab"):
                yield Static(id="ports-skip-notes", markup=False)
                yield SelectableDataTable(id="ports-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Diff", id="scan-diff-tab"):
                yield Static("Compare with previous saved scan", id="scan-diff-title", markup=False)
                yield Static(id="scan-diff-meta", markup=False)
                yield Static(id="scan-diff-headline", markup=False)
                with VerticalScroll(id="scan-diff-scroll", classes="panel detail-panel"):
                    yield Static(id="scan-diff-body", markup=False)
                yield Static(id="scan-diff-message", markup=False)
        with Vertical(id="rerun-panel", classes="panel"):
            yield Static("Web-only re-run (no port scans)", markup=False)
            yield SelectableDataTable(id="rerun-hosts", cursor_type="row")
        yield Static(id="user-scope-saved", markup=False)
        yield Static(id="result-log", markup=False)
        with Horizontal(id="footer"):
            yield Static("q / Ctrl+C quit/cancel   a add scope   Tab panels   ↑↓←→ move   Enter detail",
                         id="keys", markup=False)
            yield Static(id="footer-note", markup=False)

    def on_mount(self) -> None:
        self.query_one("#results").display = False
        self.query_one("#scope-skipped-panel").display = False
        self.query_one("#rerun-panel").display = False
        self.query_one("#user-scope-saved").display = False
        self.query_one("#result-log").display = False
        self.query_one("#browser").display = False
        self.query_one("#home").display = False
        self.query_one("#scan-status").display = False
        try:
            self.query_one("#scan-diff-tab").display = False
        except Exception:
            pass
        self.query_one("#phase-list").border_title = "Phases"
        self.query_one("#live-panel").border_title = "Live totals"
        self.query_one("#phase-counts").border_title = "PHASES"
        self.query_one("#summary-info").border_title = "SCAN SUMMARY"
        self.query_one("#finding-side").border_title = "SELECTED FINDING"
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
            target = "example.com" if self.args.demo or getattr(self.args, "demos", False) else self.args.domain
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
            text.append(" | ", style=branding.TUI_BREADCRUMB)
            text.append(target, style=branding.TEXT_PRIMARY)
        else:
            text.append(f" · v{self.version}", style=branding.TUI_BREADCRUMB)
        if not suffix:
            suffix = "scan"
            if self.mode == "results" and self.result:
                tab = self.query_one("#results", TabbedContent).active
                tab_name = "diff" if tab == "scan-diff-tab" else tab.removesuffix("-tab")
                view = "saved scan" if self.result.get("mode") == "preview" else "scan"
                suffix = f"{view} / {tab_name}"
        if suffix:
            text.append(f" / {suffix}", style=branding.TUI_BREADCRUMB)
        if started_at:
            # Use the second header line so the scan time is not lost to the badge.
            text.append(f"\n{display_time(started_at)}", style=branding.TUI_BREADCRUMB)
        if demo is None:
            demo = bool(getattr(self.args, "demo", False) or getattr(self.args, "demos", False))
        badge = self.query_one("#mode-badge", Static)
        badge.set_class(demo, "demo")
        if demo:
            badge.update("DEMO · FAKE DATA")
        elif self.mode == "results" and self.result and self.result.get("mode") == "preview":
            badge.update("SAVED · READ ONLY")
        else:
            badge.update({"home": "HOME", "browser": "SAVED RESULTS", "scanning": "SCANNING",
                          "results": "RESULTS", "diff": "READ ONLY"}[self.mode])
        self.query_one("#brand", Static).update(text)

    def _keys(self, text, note=""):
        self.query_one("#keys", Static).update(text)
        self.query_one("#footer-note", Static).update(note)
        self.query_one("#footer-note").display = bool(note)

    @on(TabbedContent.TabActivated, "#results")
    def results_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if self.mode == "results" and self.result:
            self._set_title(self.result["target"], self.result.get("started_at"),
                            demo=bool(self.result.get("demo")))

    def _set_back(self, visible):
        self.query_one("#back", Button).display = visible

    def _home_message(self, text, style=None):
        message = self.query_one("#home-message", Static)
        message.set_class(bool(text), "has-message")
        message.update(Text(text, style=style or output.AMBER))

    def _hide_all_views(self):
        self.clear_selection()
        for selector in ("#home", "#browser", "#scanning", "#results", "#scan-status", "#result-log",
                         "#rerun-panel", "#user-scope-saved", "#scope-skipped-panel", "#export-report"):
            try:
                self.query_one(selector).display = False
            except Exception:
                pass
        try:
            self.query_one("#diff-view").display = False
        except Exception:
            pass

    def _show_home(self):
        self.mode = "home"
        self._finished, self.exit_code = True, 0
        self._hide_all_views()
        self.query_one("#home").display = True
        self._fit_home_logo()
        self._set_back(False)
        self._set_title(suffix="home", demo=False)
        self._keys("Type a domain   Tab move   Enter scan   Ctrl+C quit")
        field = self.query_one("#home-domain", Input)
        field.focus()
        self.call_after_refresh(field.focus)

    def _fit_home_logo(self, size: Size | None = None) -> None:
        """Use the full art only when it fits, keeping a title on small screens."""
        size = size or self.size
        try:
            logo = self.query_one("#ascii-logo", Static)
            logo.update(_HOME_LOGO if size.width >= _HOME_LOGO_WIDTH and size.height >= 30 else "ExposureIQ")
        except Exception:
            pass

    def on_resize(self, event) -> None:
        self._fit_home_logo(event.size)

    def _show_saved_list(self):
        self.mode = "browser"
        self._finished, self.exit_code = True, 0
        self._hide_all_views()
        self.query_one("#browser").display = True
        self._set_back(True)
        self._set_title(suffix="saved results", demo=False)
        self._keys("Double-click/Enter open   d Diff   ← back   Tab move   q quit", "NO PROBES SENT")
        self._populate_saved()
        try:
            self.query_one("#diff-view").display = False
        except Exception:
            pass
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
            self._home_message(f"Could not open {path}: {error}", branding.HIGH)
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
        self._keys("q / Ctrl+C quit/cancel   Tab panels   ↑↓←→ move   Enter detail",
                   "NO PROBES SENT" if self.args.demo or getattr(self.args, "demos", False) else "Scanning")
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
        elif self.mode == "diff":
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
            self._home_message(f"Could not add {domain} to your user scope: {error}", branding.HIGH)
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

    @on(Button.Pressed, "#saved-diff-domain")
    def saved_diff_domain_button(self) -> None:
        self._open_diff_from_browser()

    def action_diff_view(self) -> None:
        if self.mode == "browser":
            self._open_diff_from_browser()
            return
        if self.mode == "results" and self.result and self.result.get("saved_to"):
            try:
                selected = storage.load_scan(self.result["saved_to"])
            except (OSError, ValueError) as error:
                self.query_one("#result-log", Static).update(f"Could not load scan history: {error}")
                return
            self._show_diff_browser(selected["target"], selected=selected,
                                    history_dir=Path(self.result["saved_to"]).parent)
            return
        self._show_diff_browser()

    def _open_diff_from_browser(self) -> None:
        target, selected = None, None
        try:
            table = self.query_one("#saved-table", DataTable)
            if table.row_count and table.cursor_row is not None:
                key = str(table.cursor_row)
                path = self.saved_paths.get(key)
                if path:
                    try:
                        from exposureiq import storage
                        snap = storage.load_scan(path)
                        target = snap.get("target")
                        selected = snap
                    except Exception:
                        pass
        except Exception:
            target = None
        if not target:
            try:
                entries = list_saved(self.results_dir)
                from collections import Counter
                c = Counter([e.get("target") for e in entries if e.get("target") and e.get("target") != "unreadable"])
                for t, cnt in c.items():
                    if cnt >= 2:
                        target = t
                        break
                if target is None and entries:
                    for e in entries:
                        if e.get("target") and e.get("target") != "unreadable":
                            target = e["target"]
                            break
            except Exception:
                target = None
        self._show_diff_browser(target, selected=selected)

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
        icon, color = {"waiting": ("○", branding.MUTED), "spinner": (_SPINNER[self._frame], output.INDIGO),
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
                output.readable_message(data["message"], verbose=self.verbose), style=f"bold {branding.HIGH}"))
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
                output.readable_message(data["message"], verbose=self.verbose), style=f"bold {branding.HIGH}"))

    def _table(self, selector: str, columns: tuple, rows: list, *, row_height: int = 1) -> DataTable:
        table = self.query_one(selector, DataTable)
        table.clear(columns=True)
        table.add_columns(*(Text(column) for column in columns))
        for row in rows:
            table.add_row(*(cell if isinstance(cell, Text) else Text(str(cell)) for cell in row), height=row_height)
        return table

    def _show_results(self) -> None:
        result, assets = self.result, self.result["assets"]
        custom_output = getattr(self.args, "output", None)
        if custom_output and result.get("saved_to") and result.get("mode") != "preview":
            root = Path(custom_output)
            self.results_dir = root.parent if root.suffix.lower() == ".json" else root
        self.mode = "results"
        preview = result.get("mode") == "preview"
        self._hide_all_views()
        self.query_one("#scanning").display = False
        self.query_one("#results").display = True
        self.query_one("#scan-status").display = True
        self.query_one("#result-log").display = True
        self._update_export_button()
        self._set_back(True)
        self._set_title(result["target"], result.get("started_at"), demo=bool(result.get("demo")))
        if preview:
            self.query_one("#scan-status", Static).update("Saved scan · read-only preview — no probes sent")
            self._keys("← saved results   e Export   Tab panels   ↑↓←→ move   Enter detail   q quit", "NO PROBES SENT")
        else:
            status = "Scan finished" if not self.exit_code else "Scan finished — results could not be saved"
            self.query_one("#scan-status", Static).update(
                status)
            self._keys("← saved results   e Export   a add scope   Tab panels   ↑↓←→ move   Enter detail   "
                       "q / Ctrl+C quit/cancel", "NO PROBES SENT" if result.get("demo") else status)
        if result.get("user_scope_path"):
            self.query_one("#user-scope-saved").display = True
            self.query_one("#user-scope-saved", Static).update(f"User scope saved to {result['user_scope_path']}")
        counts = dict.fromkeys(_SEVERITY, 0)
        for asset in assets:
            for finding in asset.get("findings", []):
                counts[finding["severity"]] += 1
        for severity, count in counts.items():
            self.query_one(f"#severity-{severity}", Static).update(f"{severity.upper()} {count}")
        phases = self._table("#phase-counts", ("Phase", "State", "Count", "Seconds"), [
            (phase, result["phase_states"][phase], result["phase_counts"][phase],
             f"{result['phase_times'][phase]:.1f}") for phase in PHASES
        ], row_height=2)
        groups = output.grouped_ips(assets)
        phases.border_subtitle = (f"{len(result['names'])} subdomains / {len(assets)} hosts / "
                                  f"{len(groups)} unique IPs")
        if preview:
            mode = ("DEMO — saved fake data; read-only preview (no probes sent)"
                    if result["demo"] else result.get("mode_detail") or "Saved scan — read-only preview")
            time_label, time_value = "Scan time", result.get("started_time") or "unknown"
        else:
            mode = ("DEMO — fake data; no network" if result["demo"]
                    else result.get("mode_detail") or "Active checks limited to authorized scope")
            time_label, time_value = "Time", f"{result['elapsed']:.1f}s"
        notes = Text(style=branding.TUI_BODY_TEXT)
        style = (output.INDIGO if preview else
                 output.TEAL if result.get("mode") == "full" else output.AMBER)
        notes.append(f"{mode}\n", style=style)
        if result["demo"]:
            notes.stylize(output.AMBER, 0, 4)
        notes.append("\n")
        for label, value in (("Target", result["target"]), ("Subdomains", len(result["names"])),
                             ("Hosts", len(assets)), ("Unique IPs", len(groups)), (time_label, time_value)):
            _append_labeled_row(notes, label, value)
        notes.append("\nSaved file\n", style=branding.TUI_LABEL)
        notes.append(f"{result['saved_to'] or 'Not saved'}\n\n", style=branding.TEXT_PRIMARY)
        if result.get("demo_count"):
            notes.append("Demo history\n", style=branding.TUI_LABEL)
            notes.append(f"{len(result.get('saved_scans', []))} of {result['demo_count']} snapshots saved; "
                         f"{len(result.get('demo_reports', []))} PDFs.\n"
                         "Showing scan 10. Open scans 3–4 to see peak exposure, then scan 10 for recovery.\n\n")
        if not preview:
            notes.append("Report PDF\n", style=branding.TUI_LABEL)
            notes.append(f"{result.get('report_to') or 'Not generated'}\n\n", style=branding.TEXT_PRIMARY)
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
        button.disabled = self._rerunning or self._exporting
        self.query_one("#summary-notes", Static).update(notes)
        self._update_report_exports()
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
            self.query_one("#finding-side").add_class("empty-findings")
            self.query_one("#finding-side").border_title = "FINDING DETAILS"
            self.query_one("#finding-title", Static).update("")
            self.query_one("#finding-recommendation", Static).update("")
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
        self._update_scan_diff_tab()
        try:
            self.call_after_refresh(self.query_one("#results Tabs", Tabs).focus)
        except Exception:
            pass

    def _show_finding(self, key: str) -> None:
        if key not in self.finding_rows:
            return
        host, finding = self.finding_rows[key]
        side = self.query_one("#finding-side")
        side.remove_class("empty-findings")
        position = list(self.finding_rows).index(key) + 1
        side.border_title = f"SELECTED FINDING / {position:02d} OF {len(self.finding_rows):02d}"
        title_color = branding.TUI_HIGH if finding["severity"] == "high" else _SEVERITY[finding["severity"]]
        self.query_one("#finding-title", Static).update(Text(finding["title"], style=f"bold {title_color}"))
        detail = Text(style=branding.TUI_BODY_TEXT)
        for label, value in (("Host:", host), ("ID:", finding["id"]), ("Rule:", finding["rule"])):
            _append_labeled_row(detail, label, value)
        if "ip" in finding:
            _append_labeled_row(detail, "IP:", finding["ip"])
        if "port" in finding:
            _append_labeled_row(detail, "Port:", finding["port"])
        detail.append(f"\n{finding['detail']}\n")
        self.query_one("#finding-detail", Static).update(detail)
        recommendation = Text(style=branding.TUI_BODY_TEXT)
        recommendation.append("Fix: ", style=f"bold {output.TEAL}")
        recommendation.append(finding["recommendation"])
        self.query_one("#finding-recommendation", Static).update(recommendation)

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

    def on_mouse_down(self, event: events.MouseDown) -> None:
        # Input owns its selection separately from the screen. Remember the
        # actual drag source, rather than copying an unrelated focused input.
        field = self.focused
        self._selection_input = (field if event.button == 1 and isinstance(field, Input)
                                 and event.screen_offset in field.region else None)

    def on_text_selected(self) -> None:
        self._queue_selection_copy()

    def on_click(self, event: events.Click) -> None:
        # Static widgets select text on double-click, after the mouse-up event.
        # Tables intercept this themselves to copy only the row's host value.
        if event.button == 1 and event.chain == 2:
            self._queue_selection_copy()

    def _queue_selection_copy(self) -> None:
        if not self._selection_copy_pending:
            self._selection_copy_pending = True
            self.call_after_refresh(self._auto_copy_selection, self.screen, self._selection_input)

    def _auto_copy_selection(self, screen, field: Input | None) -> None:
        self._selection_copy_pending = False
        self._selection_input = None
        if screen is not self.screen:
            return  # Never copy text from a new view or a dismissed dialog.
        selected = screen.get_selected_text()
        if not selected and field is not None and field.is_attached and field.screen is screen:
            if not field.password:
                selected = field.selected_text
        if selected and selected.strip():
            self.copy_to_clipboard(selected)

    def action_copy_selection(self) -> None:
        selected = self.focused.selected_text if isinstance(self.focused, Input) else ""
        selected = selected or self.screen.get_selected_text()
        if selected:
            self.copy_to_clipboard(selected)
        else:
            self.notify("Drag-select text to copy it automatically.", title="Copy", timeout=2)

    def copy_to_clipboard(self, text: str) -> None:
        if not text:
            return
        super().copy_to_clipboard(text)  # Preserve local paste and the terminal's OSC 52 fallback.
        if self.is_running:
            self.clipboard_worker = self._copy_system_clipboard(text)

    @work(thread=True, exclusive=True, group="clipboard", exit_on_error=False)
    def _copy_system_clipboard(self, text: str) -> None:
        worker = get_current_worker()
        # Serialize clipboard writes so an older, slower copy cannot win a race.
        with self._clipboard_lock:
            if worker.is_cancelled:
                return
            copied = copy_system_text(text)
        if not worker.is_cancelled:
            message = ("Text copied" if copied else
                       "Selection sent to the terminal clipboard. If paste fails, use "
                       "Shift+drag then Ctrl+Shift+C for your terminal's native copy.")
            self.call_from_thread(self.notify, message, timeout=2 if copied else 4, markup=False,
                                  severity="information" if copied else "warning")

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in ("quit", "add_scope", "export_report") and isinstance(self.focused, Input):
            return False  # Let the user type q/a/e in a domain box.
        if action == "export_report":
            return self._can_export() and not isinstance(self.screen, (ScopeConfirmation, ExportDialog))
        if action == "add_scope":
            return bool(self._finished and not self._rerunning and not self._exporting and self.result
                        and self.mode == "results" and self.result.get("mode") != "preview"
                        and not self.result.get("demo") and not isinstance(self.screen, (ScopeConfirmation, ExportDialog))
                        and eligible_hosts(self.result["target"], self.result.get("skipped_hosts", [])))
        return True

    # ----------------------------------------------------------------- exports
    def _can_export(self) -> bool:
        return bool(self.mode == "results" and self._finished and self.result
                    and self.result.get("saved_to") and not self._rerunning and not self._exporting)

    def _update_export_button(self) -> None:
        button = self.query_one("#export-report", Button)
        button.display = self.mode == "results"
        button.disabled = not self._can_export()
        self.query_one("#add-scope", Button).disabled = self._rerunning or self._exporting
        button.label = "Exporting…" if self._exporting else "Export"
        button.tooltip = ("Export a domain HTML dashboard or this scan's DOCX to report/<domain>/." if self.result
                          and self.result.get("saved_to") else "Reports require a saved scan. Saving was skipped or failed.")

    def _update_report_exports(self) -> None:
        paths = (self.result or {}).get("report_exports") or {}
        text = Text()
        for fmt in ("html", "docx"):
            if paths.get(fmt):
                text.append(f"Report {fmt.upper()}\n", style=branding.TUI_LABEL)
                text.append(f"{paths[fmt]}\n\n", style=branding.TEXT_PRIMARY)
        panel = self.query_one("#report-exports", Static)
        panel.update(text)
        panel.display = bool(paths)

    @on(Button.Pressed, "#export-report")
    def export_button(self) -> None:
        self.action_export_report()

    def action_export_report(self) -> None:
        if self.check_action("export_report", ()):
            self.push_screen(ExportDialog(self.result["target"]), self._export_chosen)

    def _export_chosen(self, fmt: str | None) -> None:
        if fmt is None or fmt not in ("html", "docx") or not self._can_export():
            return
        self._exporting = True
        self._update_export_button()
        self.query_one("#result-log", Static).update(f"Exporting {fmt.upper()} report…")
        # Capture this scan, not whichever result might be opened while we work.
        self.export_worker = self._export_report(self.result, fmt)

    @work(thread=True, exclusive=True, group="report-export", exit_on_error=False)
    def _export_report(self, result: dict, fmt: str) -> None:
        try:
            from exposureiq.report.render import DEFAULT_REPORT_DIR, generate_report

            exported = generate_report(result["saved_to"], output=str(DEFAULT_REPORT_DIR),
                                       format=fmt, results_dir=Path(result["saved_to"]).parent)
        except Exception as error:
            self.post_message(ReportExported(result, fmt, error=str(error)))
        else:
            self.post_message(ReportExported(result, fmt, path=exported[fmt]))

    def on_report_exported(self, message: ReportExported) -> None:
        self._exporting = False
        self._update_export_button()
        if message.error is None:
            message.result.setdefault("report_exports", {})[message.fmt] = message.path
        if self.result is message.result and self.mode == "results":
            self._update_report_exports()
            if message.error is not None:
                text = Text(f"Could not export {message.fmt.upper()} report: {message.error}", style=branding.HIGH)
            else:
                text = Text(f"{message.fmt.upper()} report saved to {message.path}", style=output.TEAL)
            self.query_one("#result-log", Static).update(text)
        else:
            self.notify("Report export failed." if message.error is not None else
                        f"{message.fmt.upper()} report saved to {message.path}",
                        severity="error" if message.error is not None else "information")

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
        self._update_export_button()
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

    def _show_diff_browser(self, target: str | None = None, *, selected: dict | None = None,
                           history_dir: str | Path | None = None) -> None:
        self.mode = "diff"
        self._hide_all_views()
        self.query_one("#topbar").display = True
        self.query_one("#diff-view").display = True
        self._set_back(True)
        self._set_title(target, suffix="scan history",
                        demo=bool(selected and diff_pipeline.is_demo(selected)))
        self._keys("← saved results   ↑↓ scroll   q quit", "NO PROBES SENT")
        self._load_diff_for_target(target, selected=selected, history_dir=history_dir)

    def _load_diff_for_target(self, target: str | None, *, selected: dict | None = None,
                              history_dir: str | Path | None = None) -> None:
        directory = self.results_dir if history_dir is None else history_dir
        try:
            self.query_one("#diff-body").update("")
            self.query_one("#diff-notes").update("")
            self.query_one("#diff-message").update("")
            self.query_one("#diff-target").update("")
            self.query_one("#diff-meta").update("")
            self.query_one("#diff-headline").update("")
        except Exception:
            pass
        t = target
        if t is None:
            try:
                entries = list_saved(directory)
                for e in entries:
                    if e.get("target") and e.get("target") != "unreadable":
                        t = e["target"]
                        break
            except Exception:
                t = None
        if not t:
            try:
                self.query_one("#diff-message").update("No saved scans found.")
            except Exception:
                pass
            return
        self._diff_target = t
        try:
            if selected is None:
                diff = diff_pipeline.diff_domain(t, results_dir=directory)
            else:
                history = diff_pipeline.find_scan_history(selected, directory)
                diff = diff_pipeline.build_history_diff(selected, history)
                if diff is None:
                    raise ValueError("Need at least two saved scans through the selected scan.")
        except ValueError as e:
            try:
                self.query_one("#diff-target").update(f"Diff  {t}")
                msg = str(e)
                if "at least" in msg.lower() and "2" in msg and "scan" in msg.lower():
                    self.query_one("#diff-message").update("Need at least two saved scans")
                else:
                    self.query_one("#diff-message").update(msg)
            except Exception:
                pass
            return
        except Exception as e:
            try:
                self.query_one("#diff-target").update(f"Diff  {t}")
                self.query_one("#diff-message").update(str(e))
            except Exception:
                pass
            return
        target_name = diff.get("target") or t
        old_meta = diff.get("old") or {}
        new_meta = diff.get("new") or {}
        try:
            self.query_one("#diff-target").update(f"Diff  {target_name}")
            self._set_title(target_name, new_meta.get("started_at"), suffix="scan history",
                            demo=diff_pipeline.is_demo(new_meta))
            meta = (f"baseline: {old_meta.get('started_at', '?')} ({old_meta.get('scan_id', '')})  |  "
                    f"selected: {new_meta.get('started_at', '?')} ({new_meta.get('scan_id', '')})")
            self.query_one("#diff-meta").update(meta)
            summary = diff.get("summary") or {}
            self.query_one("#diff-headline").update(summary.get("headline") or "")
            self.query_one("#diff-body").update(_diff_body(diff))
            notes = diff.get("notes") or []
            note_text = "\n".join([n for n in notes if isinstance(n, str)])
            self.query_one("#diff-notes").update(note_text)
        except Exception:
            pass


    def _update_scan_diff_tab(self) -> None:
        """Read history through the exact saved scan, including read-only previews."""
        try:
            tab = self.query_one("#scan-diff-tab", TabPane)
        except Exception:
            return
        result = self.result
        saved_to = result.get("saved_to") if result else None
        for name in ("meta", "headline", "body", "message"):
            self.query_one(f"#scan-diff-{name}", Static).update("")
        if not saved_to:
            tab.display = False
            return
        try:
            selected = storage.load_scan(saved_to)
            directory = Path(saved_to).parent
            history = diff_pipeline.find_scan_history(selected, directory)
            diff = diff_pipeline.build_history_diff(selected, history)
        except (OSError, ValueError) as error:
            tab.display = True
            self.query_one("#scan-diff-message", Static).update(f"Could not load scan history: {error}")
            return
        tab.display = diff is not None
        if diff is None:
            return
        old, new = diff.get("old") or {}, diff.get("new") or {}
        self.query_one("#scan-diff-meta", Static).update(
            f"baseline: {old.get('started_at', '?')} ({old.get('scan_id', '')})  |  "
            f"selected: {new.get('started_at', '?')} ({new.get('scan_id', '')})")
        self.query_one("#scan-diff-headline", Static).update((diff.get("summary") or {}).get("headline") or "")
        self.query_one("#scan-diff-body", Static).update(_diff_body(diff))
