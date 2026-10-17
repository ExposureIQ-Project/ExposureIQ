"""The ExposureIQ command line.

    exposureiq scan example.com

Five steps, always in this order:
    [1/5] check the scope                (exposureiq/scope.py or discovery/scope.py)
    [2/5] find subdomains                (discovery/subdomains.py)
    [3/5] look up IP addresses           (discovery/dns_resolver.py)
    [4/5] scan ports (only --ports)      (discovery/ports.py)
    [5/5] build and save the scan        (storage.py)

Passive steps (2 and 3) only read public data (Subfinder's sources and DNS),
so they work on any domain. The active step (4, port scanning) sends real
traffic, so it only runs with --ports, and only on IP addresses listed in
scope.txt. If the scope check is missing or broken, no port scan runs (fail closed).

Use --require-scope to refuse the whole scan when the domain is not in scope.
Use --demo to run the whole flow on fake data, with no network at all.

If the IP lookup or the JSON saving is not in your copy of the project yet, the
command still runs and tells you which part is missing.
"""

import argparse
import importlib
import logging
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from rich.logging import RichHandler

from exposureiq import demo_data, output
from exposureiq.discovery import subdomains as sub

EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_OUT_OF_SCOPE = 3     # 1 = error, 2 = bad input / usage, 3 = target not in scope
TOTAL_STEPS = 5


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("exposureiq")
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


# These come from teammates' modules (see the top of this file).
(resolve_hosts,) = _optional("exposureiq.discovery.dns_resolver", "resolve_hosts")
build_scan, save_scan = _optional("exposureiq.storage", "build_scan", "save_scan")


def _load_scope():
    """Return is_in_scope, or None if it is missing or broken.

    exposureiq/scope.py is looked at first, then exposureiq/discovery/scope.py.
    """
    for module in ("exposureiq.scope", "exposureiq.discovery.scope"):
        try:
            (function,) = _optional(module, "is_in_scope")
        except Exception:        # broken module (syntax error, ...): treat as unavailable
            return None
        if function is not None:
            return function
    return None


def _load_ports():
    """Port scanning is optional (--ports). Returns (scan_ports, is_in_scope)."""
    return _optional("exposureiq.discovery.ports", "scan_ports")[0], _load_scope()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _seconds(start: float) -> str:
    total = int(time.monotonic() - start)
    return f"{total // 60}m {total % 60}s" if total >= 60 else f"{total}s"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exposureiq",
        description="ExposureIQ: discover what an organization exposes to the internet.",
        epilog="Only scan domains you own or have written permission to test.",
    )
    parser.add_argument("--version", action="version", version=f"exposureiq {_version()}")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    scan = commands.add_parser("scan", help="find subdomains and their IP addresses, and save them as JSON",
                               description="Find the subdomains of a domain, look up their IP addresses, "
                                           "and save the result as a JSON file.")
    scan.add_argument("domain", help="the domain to scan, for example example.com")
    scan.add_argument("-o", "--output", metavar="FILE",
                      help="JSON file to write (default: results/<domain>_<time>.json)")
    scan.add_argument("--no-save", action="store_true", help="do not write a JSON file")
    scan.add_argument("--no-apex", action="store_true", help="do not include the domain itself in the IP lookup")
    scan.add_argument("--no-subfinder", action="store_true", help="skip Subfinder (use crt.sh only, finds fewer)")
    scan.add_argument("--minutes", type=int, default=sub.SUBFINDER_MAX_MINUTES, metavar="N",
                      help="maximum minutes for Subfinder (default: %(default)s)")
    scan.add_argument("--ports", action="store_true",
                      help="also scan open ports, but only on IPs listed in scope.txt (needs Nmap)")
    scan.add_argument("--require-scope", action="store_true",
                      help="refuse to scan at all if the domain is not listed in scope.txt")
    scan.add_argument("--demo", action="store_true",
                      help="use fake data and no network, to try the tool or show it safely")
    scan.add_argument("--limit", type=int, default=30, metavar="N", help="rows to show per table (default: %(default)s)")
    scan.add_argument("--all", action="store_true", help="show every row in the tables")
    scan.add_argument("--debug", action="store_true", help="show the full error details if something fails")
    return parser


def _scan_ports_for(resolved: list, ports_by_ip: dict, demo: bool = False) -> tuple:
    """Port scan IPv4 addresses that are in scope. Returns (scanned_rows, skipped_count)."""
    if demo:
        scan_ports, is_in_scope = demo_data.scan_ports, demo_data.is_in_scope
    else:
        scan_ports, is_in_scope = _load_ports()
    if scan_ports is None or is_in_scope is None:
        output.warn("Port scanning is not available (ports.py or the scope check is missing), so nothing was scanned.")
        return [], 0
    ips = sorted({ip for item in resolved for ip in item["ips"]})
    rows, skipped = [], 0
    for ip in ips:
        try:
            allowed = ":" not in ip and is_in_scope(ip) is True    # IPv6 is not scanned yet
        except Exception as error:                                  # a broken scope check never means "allowed"
            output.warn(f"Could not check the scope of {ip}, so it was not scanned: {error}")
            allowed = False
        if not allowed:
            skipped += 1
            continue
        try:
            ports_by_ip[ip] = scan_ports(ip)
        except (ValueError, RuntimeError, TimeoutError) as error:
            output.warn(f"Port scan of {ip} failed: {error}")
            continue
        rows.append((ip, ports_by_ip[ip]))
    return rows, skipped


def run_scan(args) -> int:
    try:
        domain = sub.normalize_domain(args.domain)
    except ValueError as error:
        output.error(str(error))
        return EXIT_USAGE

    demo = args.demo
    limit = 0 if args.all else max(args.limit, 0)
    started_at, clock = _utc_now(), time.monotonic()
    output.banner(domain, _version())
    if demo:
        output.warn("DEMO MODE: all data is fake and no network is used. Leave out --demo for a real scan.")

    # 1) scope -------------------------------------------------------------
    output.step(1, TOTAL_STEPS, "Checking scope")
    is_in_scope = _load_scope()
    in_scope = False
    if demo:
        output.info("Demo mode: nothing real is scanned, so the scope is not checked.")
    elif is_in_scope is None:
        if args.require_scope:                                     # fail closed
            output.error("The scope check is not available (scope.py is missing or broken), so nothing was scanned.")
            return EXIT_ERROR
        output.warn("The scope check is not available, so port scanning is disabled. Passive lookups still run.")
    else:
        try:
            in_scope = is_in_scope(domain) is True                 # only a clear True counts
        except Exception as error:
            if args.require_scope:
                output.error(f"Could not check the scope, so nothing was scanned: {error}")
                return EXIT_ERROR
            output.warn(f"Could not check the scope ({error}). Passive lookups still run.")
        if in_scope:
            output.ok(f"{domain} is listed in scope.txt")
        elif args.require_scope:
            output.error(f"{domain} is not in scope, so nothing was scanned. Only scan targets you are authorized to test.")
            return EXIT_OUT_OF_SCOPE
        else:
            output.info(f"{domain} is not listed in scope.txt: only passive lookups (public data) will run.")
            output.info("Port scanning is limited to IP addresses listed in scope.txt.")

    # 2) subdomains ---------------------------------------------------------
    output.step(2, TOTAL_STEPS, f"Finding subdomains of {domain}")
    if demo:
        by_source = {"subfinder": [], "crtsh": demo_data.find_subdomains(domain)}
    else:
        with output.status("Asking Subfinder's sources (this can take a few minutes)..."):
            by_source = sub.find_subdomains_by_source(
                domain, use_subfinder=not args.no_subfinder, subfinder_max_minutes=args.minutes)
    names = sorted(set(by_source["subfinder"]) | set(by_source["crtsh"]))
    if names:
        output.ok(f"Found {len(names)} subdomains")
        if not demo:
            output.sources_line(by_source)
        output.subdomain_table(names, limit)
    else:
        output.warn("No subdomains found. Only the domain itself will be looked up.")

    # 3) IP addresses -------------------------------------------------------
    output.step(3, TOTAL_STEPS, "Looking up IP addresses")
    hosts = names if args.no_apex else [domain] + names
    resolver = demo_data.resolve_hosts if demo else resolve_hosts
    resolved, dropped = [], 0
    if resolver is None:
        output.warn("IP lookup is not available yet (exposureiq/discovery/dns_resolver.py is missing).")
    else:
        with output.status(f"Asking DNS about {len(hosts)} names..."):
            resolved = resolver(hosts)
        dropped = len(set(hosts)) - len(resolved)
        if resolved:
            output.ok(f"{len(resolved)} names have an IP address ({dropped} had no DNS answer and were dropped)")
            output.ip_table(resolved, limit)
        else:
            output.warn("None of the names resolved to an IP address.")

    # 4) ports (optional) ---------------------------------------------------
    ports_by_ip, port_rows = {}, []
    if not args.ports:
        output.step(4, TOTAL_STEPS, "Scanning ports")
        output.info("Skipped. Port scanning sends real traffic, so it only runs with --ports.")
    else:
        output.step(4, TOTAL_STEPS, "Scanning ports (only IPs listed in scope.txt)")
        port_rows, skipped = _scan_ports_for(resolved, ports_by_ip, demo=demo)
        if port_rows:
            output.ports_table(port_rows)
        if skipped:
            output.info(f"Skipped {skipped} IP address(es): not in scope.txt, or IPv6. We only scan targets we are allowed to.")

    # 5) save ---------------------------------------------------------------
    output.step(5, TOTAL_STEPS, "Saving results")
    saved_to = None
    if args.no_save:
        output.info("Not saved (--no-save).")
    elif resolver is None:
        output.warn("Nothing to save yet, because the IP lookup is missing.")
    elif build_scan is None or save_scan is None:
        output.warn("Saving is not available yet (exposureiq/storage.py is missing).")
    else:
        assets = [
            {"host": item["host"],
             "ips": [{"ip": ip, "open_ports": ports_by_ip.get(ip, [])} for ip in item["ips"]]}
            for item in resolved
        ]
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        name = f"{'demo_' if demo else ''}{domain}_{stamp}.json"
        path = Path(args.output) if args.output else Path("results") / name
        try:
            save_scan(build_scan(domain, assets, started_at=started_at), str(path))
        except (ValueError, OSError) as error:
            output.error(f"Could not save the results: {error}")
            return EXIT_ERROR
        saved_to = path
        output.ok(f"Saved {len(assets)} hosts to {path}")

    rows = [("Target", domain)]
    if demo:
        rows.append(("Mode", "DEMO (fake data)"))
    rows.append(("Subdomains found", len(names)))
    if resolver is not None:
        rows += [("Names with an IP", len(resolved)), ("Dropped (no DNS answer)", dropped)]
    if args.ports:
        rows.append(("IPs port scanned", len(port_rows)))
    rows.append(("Time", _seconds(clock)))
    output.summary(rows, saved_to)
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if args.command != "scan":
        parser.print_help()
        return EXIT_USAGE
    logging.basicConfig(level=logging.WARNING, format="%(message)s", force=True,
                        handlers=[RichHandler(console=output.console, show_time=False, show_path=False, markup=False)])
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        output.error("Cancelled.")
        return 130
    except Exception as error:      # no confusing tracebacks for ordinary failures (use --debug to see them)
        output.error(f"The scan failed: {error}")
        if args.debug:
            traceback.print_exc()
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
