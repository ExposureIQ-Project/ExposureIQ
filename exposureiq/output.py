"""Nice terminal output for ExposureIQ (built on the 'rich' library).

Everything the command prints goes through here, so the look of the tool is
defined in one place. Colors follow the ExposureIQ brand.
"""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

TEAL = "#16B8A6"
INDIGO = "#7C83FD"
AMBER = "#F59E0B"

console = Console()

_UTF = (console.encoding or "").lower().startswith("utf")
OK_MARK = "✓" if _UTF else "+"
WARN_MARK = "!"
ARROW = "→" if _UTF else "->"


def banner(domain: str, version: str) -> None:
    title = Text.assemble(("ExposureIQ", f"bold {TEAL}"), (f"  v{version}", "dim"))
    body = Text.assemble("Scanning ", (domain, "bold white"))
    console.print(Panel(Text("\n").join([title, body]), border_style=TEAL,
                        box=box.ROUNDED, expand=False, padding=(0, 2)))


def step(number: int, total: int, text: str) -> None:
    console.print()
    console.print(Text.assemble((f"[{number}/{total}] ", f"bold {TEAL}"), (text, "bold")))


def status(text: str):
    """Use as:  with output.status("working..."):  (shows a spinner)"""
    return console.status(text, spinner="dots", spinner_style=TEAL)


def ok(text: str) -> None:
    console.print(Text.assemble((f"  {OK_MARK} ", "bold green"), text))


def info(text: str) -> None:
    console.print(Text(f"  {text}", style="dim"))


def warn(text: str) -> None:
    console.print(Text.assemble((f"  {WARN_MARK} ", f"bold {AMBER}"), (text, AMBER)))


def error(text: str) -> None:
    console.print(Text.assemble(("  error: ", "bold red"), text))


def _more(shown: int, total: int) -> None:
    if shown < total:
        info(f"... and {total - shown} more (use --all to show every row, or open the JSON file)")


def sources_line(by_source: dict) -> None:
    parts = [f"{name}: {len(items)}" for name, items in by_source.items()]
    info("Sources  " + "   ".join(parts))


def subdomain_table(names: list, limit: int) -> None:
    if not names:
        return
    shown = names if limit == 0 else names[:limit]
    table = Table(box=box.SIMPLE_HEAD, header_style=f"bold {TEAL}", pad_edge=False, show_edge=False)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Subdomain", overflow="fold")
    for number, name in enumerate(shown, 1):
        table.add_row(str(number), Text(name))
    console.print(table)
    _more(len(shown), len(names))


def _ip_text(ip: str) -> Text:
    return Text(ip, style=INDIGO if ":" in ip else TEAL)


def ip_table(resolved: list, limit: int) -> None:
    if not resolved:
        return
    shown = resolved if limit == 0 else resolved[:limit]
    table = Table(box=box.SIMPLE_HEAD, header_style=f"bold {TEAL}", pad_edge=False, show_edge=False)
    table.add_column("Host", overflow="fold")
    table.add_column("IP addresses")
    for item in shown:
        table.add_row(Text(item["host"]), Text("\n").join(_ip_text(ip) for ip in item["ips"]))
    console.print(table)
    _more(len(shown), len(resolved))


def ports_table(rows: list) -> None:
    """rows: list of (ip, [ {port, protocol, service}, ... ])"""
    table = Table(box=box.SIMPLE_HEAD, header_style=f"bold {TEAL}", pad_edge=False, show_edge=False)
    table.add_column("IP")
    table.add_column("Port", justify="right")
    table.add_column("Protocol")
    table.add_column("Service")
    for ip, ports in rows:
        if not ports:
            table.add_row(_ip_text(ip), "-", "-", Text("no open ports", style="dim"))
        for index, item in enumerate(ports):
            table.add_row(_ip_text(ip) if index == 0 else "", str(item["port"]), item["protocol"], item["service"])
    console.print(table)


def summary(rows: list, saved_to=None) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    for label, value in rows:
        grid.add_row(label, Text(str(value)))
    if saved_to:
        grid.add_row("Saved to", Text(str(saved_to), style=f"bold {TEAL}"))
    console.print()
    console.print(Panel(grid, title="Summary", title_align="left", border_style=TEAL,
                        box=box.ROUNDED, expand=False, padding=(0, 2)))
