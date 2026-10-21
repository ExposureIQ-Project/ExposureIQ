"""Mandatory exact-domain confirmation. Opening or cancelling it writes nothing."""

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from exposureiq.tui.user_scope import MAX_HOSTS, eligible_hosts, responsibility


class ScopeConfirmation(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel", priority=True)]
    CSS = """
    ScopeConfirmation { align: center middle; background: #111827 75%; }
    #scope-dialog { width: 80; max-width: 94%; height: 30; max-height: 96%;
                    background: #111827; border: round #16B8A6; padding: 0 1; }
    #scope-body { height: 1fr; }
    #scope-cap, #scope-responsibility, #scope-type-label { height: auto; margin-bottom: 1; }
    #scope-cap { color: #F59E0B; }
    #scope-hosts { height: 3; max-height: 6; border: round #7C83FD; margin-bottom: 1; padding: 0 1; }
    #scope-host-names { height: auto; }
    #scope-domain-input { height: 3; }
    #scope-actions { height: 3; align-horizontal: right; }
    #scope-actions Button { margin-left: 1; }
    """

    def __init__(self, domain: str, hosts: list):
        super().__init__()
        self.domain = domain
        all_names = eligible_hosts(domain, hosts)
        self.hosts = all_names[:MAX_HOSTS]
        self.total = len(all_names)

    def compose(self) -> ComposeResult:
        with Vertical(id="scope-dialog"):
            with VerticalScroll(id="scope-body"):
                noun = "host name" if self.total == 1 else "host names"
                cap = (f"{self.total} eligible hosts; only the first {MAX_HOSTS} will be added. "
                       "IP addresses will NOT be added." if self.total > MAX_HOSTS else
                       f"{self.total} {noun} will be added. IP addresses will NOT be added.")
                yield Static(cap, id="scope-cap", markup=False)
                with VerticalScroll(id="scope-hosts"):
                    yield Static("\n".join(self.hosts), id="scope-host-names", markup=False)
                yield Static(responsibility(self.domain), id="scope-responsibility", markup=False)
                yield Static(f"Type {self.domain} exactly to accept responsibility:",
                             id="scope-type-label", markup=False)
            # The field and buttons stay visible even in a short terminal.
            yield Input(placeholder=self.domain, id="scope-domain-input")
            with Horizontal(id="scope-actions"):
                yield Button("Cancel", id="scope-cancel")
                yield Button("Confirm", id="scope-confirm", variant="success", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#scope-dialog").border_title = f"Add to scope: {self.domain}"
        self.query_one("#scope-cancel", Button).focus()

    @on(Input.Changed, "#scope-domain-input")
    def typed_domain(self, event: Input.Changed) -> None:
        self.query_one("#scope-confirm", Button).disabled = event.value != self.domain or not self.hosts

    @on(Button.Pressed, "#scope-cancel")
    def cancel_button(self) -> None:
        self.action_cancel()

    @on(Button.Pressed, "#scope-confirm")
    def confirm_button(self) -> None:
        value = self.query_one("#scope-domain-input", Input).value
        if value == self.domain and self.hosts:
            self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)
