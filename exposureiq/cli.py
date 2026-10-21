"""The ExposureIQ command line.

    exposureiq scan example.com

Steps: scope -> subdomains -> IP addresses -> scoped web/certificate checks
-> scoped ports and offline risky-port rules -> save everything as JSON.
Use --passive to send no active HTTP, TLS, or port probes.

The IP lookup and the JSON saving live in other modules (dns_resolver.py and
storage.py). If one of them is not in your copy of the project yet, the command
still runs and tells you which part is missing.
"""

import argparse
import importlib
import logging
import shutil
import sys

from exposureiq import output
from exposureiq.discovery import subdomains as sub
from exposureiq.tui.control import ScanCancelled, ScanControl
from exposureiq.tui.scan import ScanStages, demo_scope as _demo_scope, run_scan as _execute_scan
from exposureiq.tui.user_scope import MAX_HOSTS, append_hosts, eligible_hosts, last_scan, responsibility, user_scope_path


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("exposureiq") or "0.1.0"
    except Exception:
        return "0.1.0"


def _optional(module: str, *names: str) -> tuple:
    """Import names from a module that may not exist yet. Missing module -> Nones.

    A different missing package (for example a library that was not installed)
    is NOT hidden: that error is raised so it can be fixed.
    """
    try:
        loaded = importlib.import_module(module)
    except ModuleNotFoundError as error:
        if error.name == module:
            return (None,) * len(names)
        raise
    return tuple(getattr(loaded, name) for name in names)


# These two come from teammates' modules (see the top of this file).
(resolve_hosts,) = _optional("exposureiq.discovery.dns_resolver", "resolve_hosts")
build_scan, save_scan = _optional("exposureiq.storage", "build_scan", "save_scan")


def _load_ports():
    """Return the port scanner and its unchanged scope gate, or fail closed."""
    try:
        return _optional("exposureiq.discovery.ports", "scan_ports")[0], _load_scope()
    except (ModuleNotFoundError, AttributeError):
        return None, None


def _load_scope():
    try:
        return _optional("exposureiq.discovery.scope", "is_in_scope")[0]
    except Exception:
        # Scope failures must never stop saving passive results or allow probes.
        return None


def _load_checks():
    """Load the existing active checks; absent teammate modules fail closed."""
    try:
        return _optional("exposureiq.fingerprint.runner", "run_checks")[0]
    except AttributeError:
        return None
    except ModuleNotFoundError as error:
        # runner.py imports the other checks. Missing any of those (or scope)
        # must disable checks, not stop passive discovery or saving.
        name = error.name or ""
        if name == "exposureiq.fingerprint" or name.startswith("exposureiq.fingerprint.") \
                or name == "exposureiq.discovery.scope":
            return None
        raise  # Missing external dependencies still need to be installed.


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exposureiq",
        description="ExposureIQ: discover what an organization exposes to the internet. "
                    "Run it with no command for the home screen.",
        epilog="Only scan domains you own or have written permission to test.",
    )
    parser.add_argument("--version", action="version", version=f"exposureiq {_version()}")
    parser.add_argument("--open", "--op", dest="open_file", metavar="FILE", nargs="?", const="",
                        help="open a saved results JSON read-only; omit FILE to browse results/")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan = commands.add_parser("scan", help="discover assets, run scoped checks and ports, and save JSON",
                               description="Find subdomains and IP addresses, then run active HTTP/TLS "
                                           "checks and Nmap. A domain in scope.txt also authorizes its "
                                           "subdomains; a domain that is not listed is discovered passively. "
                                           "--passive skips every active step.")
    scan.add_argument("domain", help="the domain to scan, for example example.com")
    scan.add_argument("-o", "--output", metavar="FILE", help="JSON file to write (default: results/<domain>_<time>.json)")
    scan.add_argument("--no-save", action="store_true", help="do not write a JSON file")
    scan.add_argument("--no-apex", action="store_true", help="do not include the domain itself in the IP lookup")
    scan.add_argument("--no-subfinder", action="store_true", help="skip Subfinder (use crt.sh only, finds fewer)")
    scan.add_argument("--minutes", type=int, default=sub.SUBFINDER_MAX_MINUTES, metavar="N",
                      help="maximum minutes for Subfinder (default: %(default)s)")
    scan.add_argument("--passive", action="store_true", help="skip all active web, TLS, and port probes")
    scan.add_argument("--plain", action="store_true", help="use compact plain output instead of the terminal UI")
    scan.add_argument("--verbose", action="store_true", help="include raw warnings, and finding details/Fix in plain output")
    scan.add_argument("--demo", action="store_true", help="use clearly labeled example.com sample data; no network")
    scan.add_argument("--ports", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--checks", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--limit", type=int, default=30, metavar="N", help="rows to show per table (default: %(default)s)")
    scan.add_argument("--all", action="store_true", help="show every row in the tables")

    scope = commands.add_parser("scope", help="view scope or confirm host-name authorization")
    scope_commands = scope.add_subparsers(dest="scope_command", metavar="<command>")
    scope_commands.add_parser("list", help="show the repository and user scope files")
    add = scope_commands.add_parser("add", help="confirm scope-skipped names from the last saved scan, then run web checks")
    add.add_argument("domain", help="the domain from the last saved scan")
    add.add_argument("--verbose", action="store_true", help="include raw warning details")
    return parser


def _stages() -> ScanStages:
    return ScanStages(sub.find_subdomains_by_source, resolve_hosts, build_scan, save_scan,
                      _load_scope, _load_checks, _load_ports,
                      lambda: shutil.which("nmap") is not None, _demo_scope)


def _use_tui(args) -> bool:
    return not args.plain and sys.stdout.isatty()


def run_scan(args) -> int:
    try:
        args.domain = sub.normalize_domain(args.domain)
    except ValueError as error:
        output.error(str(error))
        return 2

    if args.demo:
        args.domain = "example.com"
    stages, control = _stages(), ScanControl()
    try:
        if _use_tui(args):
            try:
                from exposureiq.tui.app import ExposureIQApp
            except ModuleNotFoundError as error:
                if error.name != "textual":
                    raise
                output.warn("Textual is not installed; using plain output. Install the project dependencies for the TUI.")
            else:
                return ExposureIQApp(args, stages=stages, control=control, version=_version()).run()
        result = _execute_scan(args, stages, output.PlainReporter(args), control, _version())
        return result["return_code"]
    except (KeyboardInterrupt, ScanCancelled):
        control.cancel()
        output.error("Cancelled.")
        return 130


def run_scope(args) -> int:
    from exposureiq.discovery import scope
    from exposureiq.tui.rerun import rerun_hosts

    if args.scope_command == "list":
        for label, path in (("Repository scope (never modified)", scope.SCOPE_FILE),
                            ("User scope", user_scope_path())):
            output.info(f"{label}: {path}")
            try:
                contents = path.read_text(encoding="utf-8-sig")
            except FileNotFoundError:
                output.info("  (missing; no entries)")
            except (OSError, UnicodeError):
                output.warn("  Unreadable; entries are not used.")
            else:
                for line in contents.splitlines():
                    output.info(line)
        return 0
    if args.scope_command != "add":
        output.error("Use exposureiq scope list or exposureiq scope add <domain>.")
        return 2
    try:
        domain = sub.normalize_domain(args.domain)
        record = last_scan(domain)
        from exposureiq.storage import load_scan
        snapshot = load_scan(record["saved_to"])
        if snapshot["target"] != domain or snapshot["scan_id"] != record.get("scan_id"):
            raise ValueError("The last-scan record does not match the saved scan.")
        asset_hosts = {asset["host"] for asset in snapshot["assets"]}
        names = eligible_hosts(domain, [host for host in record.get("skipped_hosts", []) if host in asset_hosts])
    except (OSError, ValueError, KeyError) as error:
        output.error(f"Cannot find a saved scan for {getattr(args, 'domain', '')}: {error}")
        output.info("First run exposureiq scan <domain> --plain; it will record any scope-skipped hosts.")
        return 1
    if not names:
        output.info(f"No eligible hosts were skipped for scope in the last scan of {domain}.")
        return 0
    selected = names[:MAX_HOSTS]
    output.info(f"{len(names)} hosts skipped: not in scope for {domain}")
    if len(names) > MAX_HOSTS:
        output.warn(f"Only the first {MAX_HOSTS} of {len(names)} hosts will be added.")
    for name in selected:
        output.info(name)
    output.info("Host names only. No IP addresses will be added or port scanned.")
    output.info(responsibility(domain))
    control = ScanControl()
    try:
        typed = input(f"Type {domain} exactly to confirm (anything else cancels): ")
        if typed != domain:
            output.info("Cancelled: domain did not match exactly; no scope file changed.")
            return 1
        path, added = append_hosts(domain, selected, typed)
        output.ok(f"Added {len(added)} host names to {path}")
        result = {**record, "demo": False, "snapshot": snapshot, "assets": snapshot["assets"],
                  "warnings": [], "user_scope_path": str(path), "return_code": 0,
                  "port_rows": [], "started_at": snapshot["started_at"]}

        def report(event):
            if event["kind"] == "host_progress":
                message = output.readable_message(event["message"], verbose=args.verbose, host=event["host"])
                output.info(f"{event['state']} — {message}")
            elif event["kind"] == "log":
                output.info(output.readable_message(event["message"], verbose=args.verbose))

        updated = rerun_hosts(result, added, _stages(), report, control)
        output.technology_table(updated["assets"], 30)
        output.findings_table(updated["assets"], 30, args.verbose)
        output.ok(f"Web-only update saved to {record['saved_to']}; scan ID and start time kept.")
        output.info("No port scans ran. Run a new scan now that the domain is authorized for full mode.")
        return 0
    except (EOFError, KeyboardInterrupt, ScanCancelled):
        control.cancel()
        output.info("Cancelled; no later checks sent. Any already-confirmed scope entries are kept.")
        return 130
    except (OSError, ValueError) as error:
        output.error(f"Scope/web update failed: {error}")
        return 1


def run_home(args, *, browser: bool = False) -> int:
    """Bare `exposureiq` starts at home; `--open` alone starts at the file list."""
    try:
        from exposureiq.tui.app import ExposureIQApp
    except ModuleNotFoundError as error:
        if error.name != "textual":
            raise
        output.error("The terminal UI needs Textual. Install the project dependencies first.")
        return 1
    return ExposureIQApp(args, stages=_stages(), control=ScanControl(),
                         version=_version(), home=True, browser=browser).run()


def run_open(args) -> int:
    """Preview a saved JSON. Never scans, saves, or sends a request."""
    path = getattr(args, "open_file", None)
    try:
        from exposureiq.storage import load_scan
        from exposureiq.tui.saved import print_preview, result_from_snapshot
        snapshot = load_scan(str(path))
    except (OSError, ValueError, ModuleNotFoundError) as error:
        output.error(f"Could not open {path}: {error}")
        return 1
    result = result_from_snapshot(snapshot, path)
    verbose = bool(getattr(args, "verbose", False))
    if not sys.stdout.isatty():
        print_preview(result, verbose=verbose)
        return 0
    try:
        from exposureiq.tui.app import ExposureIQApp
    except ModuleNotFoundError as error:
        if error.name != "textual":
            raise
        print_preview(result, verbose=verbose)
        output.warn("Textual is not installed; showing the compact preview.")
        return 0
    return ExposureIQApp(args, stages=_stages(), control=ScanControl(),
                         version=_version(), open_file=str(path)).run()


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.WARNING, format="%(message)s", force=True,
                        handlers=[output.ReadableLogHandler(verbose=getattr(args, "verbose", False),
                                  console=output.console, show_time=False, show_path=False, markup=False)])
    if args.command is None:
        if args.open_file is not None:
            if args.open_file:
                return run_open(args)
            if not sys.stdout.isatty():
                output.error("--open needs a FILE when output is not a terminal.")
                output.info("Try: exposureiq --open results/<file>.json")
                return 2
            return run_home(args, browser=True)
        if not sys.stdout.isatty():
            parser.print_help()
            return 2
        return run_home(args)
    if args.command not in ("scan", "scope"):
        parser.print_help()
        return 2
    return run_scope(args) if args.command == "scope" else run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
