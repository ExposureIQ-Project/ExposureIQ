"""Compact plain output for ExposureIQ, with optional Rich colors.

Everything the command prints goes through here, so the look of the tool is
defined in one place. Colors follow the ExposureIQ brand.
"""

from contextlib import nullcontext
import copy
import logging
import re

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text

TEAL = "#16B8A6"
INDIGO = "#7C83FD"
AMBER = "#F59E0B"
DARK = "#111827"
SEVERITY_STYLES = {"high": "bold red", "medium": AMBER, "low": "dim blue"}

console = Console()

_UTF = (console.encoding or "").lower().startswith("utf")
OK_MARK = "✓" if _UTF else "+"
WARN_MARK = "!"
ARROW = "→" if _UTF else "->"


def _network_reason(message: str) -> str | None:
    lower = message.lower()
    reasons = (
        (("errno 101", "network is unreachable", "network unreachable"), "network unreachable"),
        (("errno 113", "no route to host"), "host unreachable"),
        (("errno 111", "connection refused"), "connection refused"),
        (("timed out", "timeout", "connecttimeout", "readtimeout"), "request timed out"),
        (("name or service not known", "name resolution", "nodename nor servname", "gaierror"), "DNS lookup failed"),
        (("certificate verify failed", "certificate_verify_failed"), "certificate could not be verified"),
        (("errno 104", "connection reset", "remotedisconnected"), "connection interrupted"),
        (("sslerror", "ssl error"), "TLS connection failed"),
        (("newconnectionerror", "maxretryerror", "connectionpool", "connectionerror", "requestexception", "errno"),
         "connection failed"),
    )
    return next((description for hints, description in reasons if any(hint in lower for hint in hints)), None)


def readable_message(message: str, *, verbose: bool = False, host: str | None = None) -> str:
    """Keep ordinary warnings; translate transport trace text unless --verbose."""
    if verbose:
        return message
    lower = message.lower()
    reason = _network_reason(message)
    if reason is None:
        return message
    if host is None:
        match = re.search(r"(?:https?://|host=['\"])([a-zA-Z0-9.-]+)", message)
        if not match:
            match = re.search(r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})\b", message)
        host = match.group(1) if match else None
    if "no web server answered" in lower:
        label = "no web server answered on ports 80 and 443"
    elif any(word in lower for word in ("certificate", "tls", "could not connect to")):
        label = "certificate check failed"
    else:
        label = "front-page request failed"
    return f"{host + ': ' if host else ''}{label} ({reason})"


def web_check_status(host: str, observation: dict) -> tuple:
    """A failed request is not a clean bill of health; successful findings are kept."""
    messages = observation["warnings"]
    if observation["answered"] is False:
        reason = _network_reason(" ".join(messages))
        suffix = f" ({reason})" if reason else " (no response)"
        return True, f"{host}: no web server answered on ports 80 and 443{suffix}"
    failures = ("checks failed", "not in scope", "scope check failed", "no usable tls answer",
                "could not connect to", "could not read the certificate")
    if any(any(hint in message.lower() for hint in failures) for message in messages):
        return True, f"{host}: some web checks failed; collected results kept"
    return False, f"{host}: web checks done"


class ReadableLogHandler(RichHandler):
    """Render a copy so tests/log collectors can still inspect raw evidence."""
    def __init__(self, *, verbose: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.verbose = verbose

    def emit(self, record: logging.LogRecord) -> None:
        rendered = copy.copy(record)
        rendered.msg = readable_message(record.getMessage(), verbose=self.verbose)
        rendered.args = ()
        if not self.verbose:
            rendered.exc_info = rendered.exc_text = rendered.stack_info = None
        super().emit(rendered)


def banner(domain: str, version: str) -> None:
    console.print(Text.assemble(("ExposureIQ", f"bold {TEAL}"), (f" v{version}", "dim"),
                               " | Target: ", (domain, "bold")))


def step(number: int, total: int, text: str) -> None:
    console.print(Text.assemble((f"[{number}/{total}] ", f"bold {TEAL}"), (text, "bold")))


def status(text: str):
    """Plain output has no transient animations; the TUI owns its own spinner."""
    return nullcontext()


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
    console.print(Text("Subdomains", style=f"bold {TEAL}"))
    for name in shown:
        console.print(Text(f"  {name}"))
    _more(len(shown), len(names))


def _ip_text(ip: str) -> Text:
    return Text(ip, style=INDIGO if ":" in ip else TEAL)


def grouped_ips(resolved: list) -> list:
    """One row per IP, accepting either resolver rows or saved asset rows."""
    groups = {}
    for item in resolved:
        for entry in item.get("ips", []):
            ip = entry["ip"] if isinstance(entry, dict) else entry
            groups.setdefault(ip, set()).add(item["host"])
    return [(ip, sorted(hosts)) for ip, hosts in sorted(groups.items())]


def ip_table(resolved: list, limit: int) -> None:
    if not resolved:
        return
    groups = grouped_ips(resolved)
    shown = groups if limit == 0 else groups[:limit]
    console.print(Text("IP addresses (grouped)", style=f"bold {TEAL}"))
    for ip, hosts in shown:
        console.print(Text.assemble("  ", _ip_text(ip), f"  <- {len(hosts)} hosts"))
    _more(len(shown), len(groups))


def ports_table(rows: list) -> None:
    """rows: list of (ip, [ {port, protocol, service}, ... ])"""
    console.print(Text("Ports", style=f"bold {TEAL}"))
    for ip, ports in rows:
        services = "; ".join(f"{item['protocol']}/{item['port']} {item['service']}" for item in ports)
        console.print(Text.assemble("  ", _ip_text(ip), f"  {services or 'no open ports'}"))


def technology_table(assets: list, limit: int) -> None:
    rows = [(asset["host"], technology)
            for asset in assets for technology in asset.get("technologies", [])]
    if not rows:
        info("No technology hints returned.")
        return
    shown = rows if limit == 0 else rows[:limit]
    console.print(Text("Technologies", style=f"bold {TEAL}"))
    for host, technology in shown:
        console.print(Text(f"  {host}: {technology['name']} {technology['version'] or 'unknown'} "
                           f"({technology['source']})"))
    _more(len(shown), len(rows))


def findings_table(assets: list, limit: int, verbose: bool = False) -> None:
    rows = [(asset["host"], finding) for asset in assets for finding in asset.get("findings", [])]
    if not rows:
        info("No findings returned; hosts may be out of scope or checks may have failed.")
        return
    shown = rows if limit == 0 else rows[:limit]
    console.print(Text("Findings", style=f"bold {TEAL}"))
    for host, finding in shown:
        severity = finding["severity"]
        style = SEVERITY_STYLES[severity]
        console.print(Text.assemble("  ", (severity.upper(), style), f"  {host}  {finding['title']}"))
        if verbose:
            endpoint = f" | {finding['ip']}" if "ip" in finding else ""
            if "port" in finding:
                endpoint += f" | Port {finding['port']}"
            console.print(Text(f"    {finding['id']} | {finding['rule']}{endpoint}", style="dim"))
            console.print(Text(f"    {finding['detail']}"))
            console.print(Text(f"    Fix: {finding['recommendation']}", style="dim"))
    _more(len(shown), len(rows))


def summary(rows: list, saved_to=None, assets=None) -> None:
    console.print(Text("Summary", style=f"bold {TEAL}"))
    for label, value in rows:
        console.print(Text(f"  {label}  {value}"))
    if assets is not None:
        counts = {severity: 0 for severity in SEVERITY_STYLES}
        for asset in assets:
            for finding in asset.get("findings", []):
                counts[finding["severity"]] += 1
        for severity, count in counts.items():
            console.print(Text.assemble(f"  Findings ({severity}) ", (str(count), SEVERITY_STYLES[severity])))
    if saved_to:
        console.print(Text.assemble("  Saved to  ", (str(saved_to), f"bold {TEAL}")))


class PlainReporter:
    """Turn the shared scan's events into compact lines, never a full-screen UI."""

    def __init__(self, args):
        self.limit = 0 if args.all else max(args.limit, 0)
        self.verbose = args.verbose
        self.active = not args.passive
        self.skipped = {}

    def __call__(self, event: dict) -> None:
        from exposureiq.tui.scan import PHASES

        kind = event["kind"]
        if kind == "start":
            version = event["version"] + (" | DEMO (fake data; no network)" if event["demo"] else "")
            banner(event["target"], version)
        elif kind == "phase":
            if event["state"] == "spinner":
                step(PHASES.index(event["phase"]) + 1, len(PHASES), event["message"])
            elif event["message"]:
                info(event["message"])
        elif kind == "skipped":
            group = event["active_step"]
            self.skipped[group] = self.skipped.get(group, 0) + 1
            if not self.limit or self.skipped[group] <= self.limit:
                info(event["message"])
        elif kind == "log":
            if event["level"] != "live":
                text = readable_message(event["message"], verbose=self.verbose)
                {"ok": ok, "warn": warn, "error": error}.get(event["level"], info)(text)
        elif kind == "data":
            table, rows = event["table"], event["rows"]
            if table == "subdomains":
                sources_line(event["by_source"])
                subdomain_table(rows, self.limit)
            elif table == "ips":
                ip_table(rows, self.limit)
            elif table == "ports":
                ports_table(rows)
            elif table == "technologies":
                technology_table(rows, self.limit)
            elif table == "findings":
                findings_table(rows, self.limit, self.verbose)
        elif kind == "result":
            for group, count in self.skipped.items():
                if self.limit and count > self.limit:
                    info(f"... and {count - self.limit} more skipped: not in scope.txt ({group}; use --all)")
            result = event["result"]
            show_assets = result["assets"] if self.active and result.get("mode") != "passive" else None
            summary(result["summary_rows"], result["saved_to"], assets=show_assets)
            if result.get("skipped_hosts") and not result.get("demo") and result.get("saved_to"):
                info(f"Authorize skipped hosts: exposureiq scope add {result['target']}")


def diff_report(diff: dict, show_all: bool = False) -> None:
    from rich.console import Console
    from rich.text import Text

    console = Console()

    target = diff.get("target") or (diff.get("new") or {}).get("target") or ""
    old_meta = diff.get("old") or {}
    new_meta = diff.get("new") or {}
    console.print(Text.assemble(("Diff", f"bold {TEAL}"), f"  {target}"))
    if old_meta.get("started_at") or new_meta.get("started_at"):
        console.print(Text.assemble("  ", f"old: {old_meta.get('started_at','?')} ({old_meta.get('scan_id','')})", "  |  ", f"new: {new_meta.get('started_at','?')} ({new_meta.get('scan_id','')})", style="dim"))
    headline = (diff.get("summary") or {}).get("headline") or ""
    if headline:
        console.print(Text(headline, style="bold"))

    changes = diff.get("changes") or []
    ignored = diff.get("ignored") or []
    from exposureiq.diffing import summary as diff_summary

    def _fmt(c):
        msg = diff_summary.describe_change(c)
        status = c.get("status")
        if status == "confirmed":
            if "not seen this time" in msg:
                msg = msg.replace("not seen this time", "removed")
            elif msg and "removed" not in msg:
                msg = msg + " (removed)"
        return msg

    def _is_new(c):
        k = c.get("kind", "")
        if k in ("host.new", "ip.new", "port.opened", "tech.new", "finding.new"):
            return True
        return False

    def _is_gone(c):
        k = c.get("kind", "")
        if k in ("host.removed", "ip.removed", "port.closed", "tech.removed", "finding.resolved"):
            return True
        if status := c.get("status"):
            if status == "confirmed" or status == "missing":
                if k.endswith(".removed") or k in ("port.closed", "finding.resolved"):
                    return True
        return False

    # group by category
    categories = [
        ("Subdomains/Hosts", lambda c: c.get("kind") in ("host.new", "host.removed")),
        ("IP addresses", lambda c: c.get("kind") in ("ip.new", "ip.removed")),
        ("Open ports / services", lambda c: c.get("kind") in ("port.opened", "port.closed", "port.service_changed")),
        ("Technologies", lambda c: c.get("kind") in ("tech.new", "tech.removed", "tech.version_changed")),
        ("Findings", lambda c: c.get("kind") in ("finding.new", "finding.resolved", "finding.severity_changed")),
    ]

    for title, pred in categories:
        items = [c for c in changes if isinstance(c, dict) and pred(c)]
        if not items:
            continue
        console.print(Text(title, style=f"bold {TEAL}"))
        for c in items:
            msg = _fmt(c)
            k = c.get("kind", "")
            if _is_new(c) and not (k.endswith(".removed") or k in ("port.closed", "finding.resolved") or c.get("status") == "confirmed"):
                console.print(Text.assemble(("  + ", "bold green"), (msg, "green")))
            elif _is_gone(c):
                console.print(Text.assemble(("  - ", "bold red"), (msg, "red")))
            elif c.get("direction") == "better":
                console.print(Text.assemble(("  ~ ", "bold green"), (msg, "green")))
            elif c.get("direction") == "worse":
                console.print(Text.assemble(("  ! ", "bold red"), (msg, "red")))
            else:
                console.print(Text(f"  • {msg}", style="dim"))

    if show_all and ignored:
        console.print(Text("Ignored", style="dim"))
        for c in ignored:
            if isinstance(c, dict):
                console.print(Text(f"  { _fmt(c) }", style="dim"))

    notes = diff.get("notes") or []
    for n in notes:
        if isinstance(n, str):
            console.print(Text(f"  note: {n}", style="dim"))
