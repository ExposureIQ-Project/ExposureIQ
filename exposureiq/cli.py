"""The ExposureIQ command line.

    exposureiq scan example.com

Steps: find subdomains -> look up their IP addresses -> (optional) port scan
-> save everything as a JSON file.

The IP lookup and the JSON saving live in other modules (dns_resolver.py and
storage.py). If one of them is not in your copy of the project yet, the command
still runs and tells you which part is missing.
"""

import argparse
import importlib
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.logging import RichHandler

from exposureiq import output
from exposureiq.discovery import subdomains as sub


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


# These two come from teammates' modules (see the top of this file).
(resolve_hosts,) = _optional("exposureiq.discovery.dns_resolver", "resolve_hosts")
build_scan, save_scan = _optional("exposureiq.storage", "build_scan", "save_scan")


def _load_ports():
    """Port scanning is optional (--ports). Returns (scan_ports, is_in_scope)."""
    return _optional("exposureiq.discovery.ports", "scan_ports")[0], \
        _optional("exposureiq.discovery.scope", "is_in_scope")[0]


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
    scan.add_argument("-o", "--output", metavar="FILE", help="JSON file to write (default: results/<domain>_<time>.json)")
    scan.add_argument("--no-save", action="store_true", help="do not write a JSON file")
    scan.add_argument("--no-apex", action="store_true", help="do not include the domain itself in the IP lookup")
    scan.add_argument("--no-subfinder", action="store_true", help="skip Subfinder (use crt.sh only, finds fewer)")
    scan.add_argument("--minutes", type=int, default=sub.SUBFINDER_MAX_MINUTES, metavar="N",
                      help="maximum minutes for Subfinder (default: %(default)s)")
    scan.add_argument("--ports", action="store_true",
                      help="also scan open ports, but only on IPs listed in scope.txt (needs Nmap)")
    scan.add_argument("--limit", type=int, default=30, metavar="N", help="rows to show per table (default: %(default)s)")
    scan.add_argument("--all", action="store_true", help="show every row in the tables")
    return parser


def _scan_ports_for(resolved: list, ports_by_ip: dict) -> tuple:
    """Port scan IPv4 addresses that are in scope. Returns (scanned_rows, skipped_count)."""
    scan_ports, is_in_scope = _load_ports()
    if scan_ports is None or is_in_scope is None:
        output.warn("Port scanning is not available yet (ports.py or scope.py is missing).")
        return [], 0
    ips = sorted({ip for item in resolved for ip in item["ips"]})
    rows, skipped = [], 0
    for ip in ips:
        if ":" in ip or not is_in_scope(ip):      # IPv6 is not scanned yet; out of scope is never scanned
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
        return 2

    limit = 0 if args.all else max(args.limit, 0)
    total = 3 + (1 if args.ports else 0)
    started_at, clock = _utc_now(), time.monotonic()
    output.banner(domain, _version())

    # 1) subdomains ---------------------------------------------------------
    output.step(1, total, f"Finding subdomains of {domain}")
    with output.status("Asking Subfinder's sources (this can take a few minutes)..."):
        by_source = sub.find_subdomains_by_source(
            domain, use_subfinder=not args.no_subfinder, subfinder_max_minutes=args.minutes)
    names = sorted(set(by_source["subfinder"]) | set(by_source["crtsh"]))
    if names:
        output.ok(f"Found {len(names)} subdomains")
        output.sources_line(by_source)
        output.subdomain_table(names, limit)
    else:
        output.warn("No subdomains found. Only the domain itself will be looked up.")

    # 2) IP addresses -------------------------------------------------------
    output.step(2, total, "Looking up IP addresses")
    hosts = names if args.no_apex else [domain] + names
    resolved, dropped = [], 0
    if resolve_hosts is None:
        output.warn("IP lookup is not available yet (exposureiq/discovery/dns_resolver.py is missing).")
    else:
        with output.status(f"Asking DNS about {len(hosts)} names..."):
            resolved = resolve_hosts(hosts)
        dropped = len(set(hosts)) - len(resolved)
        if resolved:
            output.ok(f"{len(resolved)} names have an IP address ({dropped} had no DNS answer and were dropped)")
            output.ip_table(resolved, limit)
        else:
            output.warn("None of the names resolved to an IP address.")

    # 3) ports (optional) ---------------------------------------------------
    ports_by_ip, port_rows = {}, []
    if args.ports:
        output.step(3, total, "Scanning open ports (only IPs listed in scope.txt)")
        port_rows, skipped = _scan_ports_for(resolved, ports_by_ip)
        if port_rows:
            output.ports_table(port_rows)
        if skipped:
            output.info(f"Skipped {skipped} IP address(es): not in scope.txt, or IPv6. We only scan targets we are allowed to.")

    # 4) save -----------------------------------------------------------------
    output.step(total, total, "Saving results")
    saved_to = None
    if args.no_save:
        output.info("Not saved (--no-save).")
    elif resolve_hosts is None:
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
        path = Path(args.output) if args.output else Path("results") / f"{domain}_{stamp}.json"
        try:
            save_scan(build_scan(domain, assets, started_at=started_at), str(path))
        except (ValueError, OSError) as error:
            output.error(f"Could not save the results: {error}")
            return 1
        saved_to = path
        output.ok(f"Saved {len(assets)} hosts to {path}")

    rows = [("Target", domain), ("Subdomains found", len(names))]
    if resolve_hosts is not None:
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
        return 2
    logging.basicConfig(level=logging.WARNING, format="%(message)s", force=True,
                        handlers=[RichHandler(console=output.console, show_time=False, show_path=False, markup=False)])
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        output.error("Cancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
