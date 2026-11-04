"""Choose an offline report format. Opening or cancelling writes nothing."""

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ExportDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]
    CSS = """
    ExportDialog { align: center middle; background: $background 75%; }
    #export-dialog { width: 64; max-width: 94%; height: auto; max-height: 96%; }
    #export-body { height: auto; max-height: 12; }
    #export-target, #export-description, #export-destination { height: auto; margin-bottom: 1; }
    #export-target { color: $primary; text-style: bold; }
    #export-description { color: $body-text; }
    #export-destination { color: $footnote; }
    #export-formats { height: 3; }
    #export-formats Button { width: 1fr; }
    #export-docx { margin-left: 1; }
    #export-cancel { margin-top: 1; align-horizontal: right; }
    """

    def __init__(self, target: str):
        super().__init__()
        self.target = target

    def compose(self) -> ComposeResult:
        with Vertical(id="export-dialog", classes="panel detail-panel"):
            with VerticalScroll(id="export-body"):
                yield Static(self.target, id="export-target", markup=False)
                yield Static("Choose your report format:\n\n"
                             "HTML  — Domain home with all saved scans and interactive charts.\n"
                             "DOCX  — Editable Word document for this scan.",
                             id="export-description", markup=False)
                yield Static(f"Saved in report/{self.target}/. Open index.html for HTML.\n"
                             "PDF remains the default after a scan.\n"
                             "Exporting reads saved results only; no probes are sent.",
                             id="export-destination", markup=False)
            with Horizontal(id="export-formats"):
                yield Button("HTML", id="export-html", variant="primary")
                yield Button("DOCX", id="export-docx", variant="primary")
            yield Button("Cancel", id="export-cancel")

    def on_mount(self) -> None:
        self.query_one("#export-dialog").border_title = "Export report"
        self.query_one("#export-html", Button).focus()

    @on(Button.Pressed, "#export-html")
    def html_button(self) -> None:
        self.dismiss("html")

    @on(Button.Pressed, "#export-docx")
    def docx_button(self) -> None:
        self.dismiss("docx")

    @on(Button.Pressed, "#export-cancel")
    def cancel_button(self) -> None:
        self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)
