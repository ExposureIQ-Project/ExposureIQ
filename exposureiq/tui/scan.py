"""One shared scan pipeline, reporting plain dict events to either interface.

No Textual import, no new network probes, and no changes to saved JSON fields.
All active calls still use the existing scope, web, TLS, and Nmap interfaces.
"""

import importlib
import ipaddress
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from exposureiq import output
from exposureiq.tui.control import ScanControl, cancellable_checks, observe_checks, tracked_processes

PHASES = ("Scope", "Subdomains", "IP lookup", "Web checks", "Ports", "Save")
DEMO_IPS = {
    "example.com": "192.0.2.10", "api.example.com": "192.0.2.20",
    "blog.example.com": "192.0.2.10", "legacy.example.com": "192.0.2.20",
    "www.example.com": "192.0.2.10",
}


@dataclass
class ScanStages:
    find_subdomains: Callable
    resolve_hosts: Callable | None
    build_scan: Callable | None
    save_scan: Callable | None
    load_scope: Callable
    load_checks: Callable
    load_ports: Callable
    nmap_available: Callable
    demo_scope: Callable
    # Optional: build a report after a successful save. Tests that do not want
    # report output simply leave this unset.
    report_job: Callable | None = None


def demo_scope(target: str) -> bool:
    """Only fixed demo hosts backed by 192.0.2.0/24, or IPs in that range."""
    try:
        return ipaddress.ip_address(DEMO_IPS.get(target, target)) in ipaddress.ip_network("192.0.2.0/24")
    except ValueError:
        return False


def _demo_checks(assets: list) -> list:
    from exposureiq.fingerprint.severity import build_findings

    samples = {
        "example.com": ("headers.missing_csp", "DEMO: the sample front page has no Content-Security-Policy."),
        "api.example.com": ("tech.server_version_disclosed", "DEMO: the sample Server header says nginx/1.18.0."),
        "legacy.example.com": ("https.cert_expired", "DEMO: this fake certificate expired yesterday."),
    }
    for asset in assets:
        if asset["host"] == "api.example.com":
            asset["technologies"] = [{"name": "nginx", "version": "1.18.0", "source": "DEMO Server header"}]
        if asset["host"] in samples:
            rule, detail = samples[asset["host"]]
            asset["findings"] = build_findings([{"rule": rule, "detail": detail}])
            for finding in asset["findings"]:
                finding["title"] = "DEMO: " + finding["title"]
    return assets


def _demo_ports(target: str) -> list:
    # Ports are requested by authorized host name; DEMO maps it to its fake IP.
    ip = DEMO_IPS.get(target, target)
    ports = [{"port": 443, "protocol": "tcp", "service": "https"}]
    if ip == "192.0.2.20":
        ports.append({"port": 3306, "protocol": "tcp", "service": "mysql"})
    return ports


def _demo_paths(output: str | None) -> list[Path]:
    """A directory uses demo_history_01..10; a JSON name gets _01..10."""
    from exposureiq.paths import domain_directory

    path = Path(output) if output else Path("results")
    if output and path.suffix.lower() == ".json":
        return [path.with_name(f"{path.stem}_{number:02d}{path.suffix}")
                for number in range(1, 11)]
    folder = domain_directory(path, "example.com")
    return [folder / f"demo_history_{number:02d}.json" for number in range(1, 11)]


def run_demo_history(args, stages: ScanStages, report: Callable, control: ScanControl,
                     version: str = "0.1.0") -> dict:
    """Save a fixed ten-scan story and its PDFs without loading network stages."""
    from exposureiq import storage
    from exposureiq.demo_data import DEMO_STORY, build_demo_scans
    from exposureiq.tui.saved import result_from_snapshot

    clock = time.monotonic()
    scans = build_demo_scans(passive=args.passive, include_apex=not args.no_apex)
    result = result_from_snapshot(scans[-1], "")
    result.update(saved_to=None, report_to=None, saved_scans=[], demo_reports=[],
                  mode="passive" if args.passive else "full",
                  mode_detail="DEMO history: simulated data only; no network traffic.",
                  phase_states=dict.fromkeys(PHASES, "waiting"),
                  phase_counts=dict.fromkeys(PHASES, 0), demo_count=len(scans))

    def emit(kind: str, **data):
        control.check()
        report({"kind": kind, **data})

    def log(message: str, level: str = "info"):
        if level == "warn":
            result["warnings"].append(message)
        emit("log", message=message, level=level)

    def phase(name: str, state: str, count: int, message: str = ""):
        result["phase_states"][name] = state
        result["phase_counts"][name] = count
        emit("phase", phase=name, state=state, count=count, message=message)

    emit("start", target="example.com", version=version, demo=True)
    log("DEMO history: 10 fixed example.com snapshots. No network, real exploits or real incidents.")
    phase("Scope", "done", 0, "Simulated fixtures only; no scope files or active probes are used.")
    phase("Subdomains", "done", len(result["names"]), "Using the ten-part demo story (no discovery calls).")
    phase("IP lookup", "done", len(result["assets"]), "Using documentation-only IP addresses (no DNS calls).")
    phase("Web checks", "skipped" if args.passive else "done",
          0 if args.passive else len(result["assets"]),
          "Sample web findings skipped (--passive)." if args.passive else "Using simulated front-page and certificate evidence.")
    phase("Ports", "skipped" if args.passive else "done", len(result["port_rows"]),
          "Sample ports skipped (--passive)." if args.passive else "Using fixed ports and the existing offline severity rules.")
    phase("Save", "spinner", 0, "Preparing ten demo snapshots")
    paths = _demo_paths(args.output)
    try:
        if not args.no_save:
            if stages.save_scan is None:
                raise ValueError("Saving is unavailable; the demo history needs storage.py.")
            # Check the entire set before writing. Repeating an identical demo
            # reuses the JSON; a changed or unrelated file is never overwritten.
            for scan, path in zip(scans, paths):
                control.check()
                if path.exists() and storage.load_scan(str(path)) != scan:
                    raise ValueError(f"Demo output already contains different data: {path}. Choose another --output directory.")
        for number, (scan, path, story) in enumerate(zip(scans, paths, DEMO_STORY), 1):
            control.check()
            findings = [finding for asset in scan["assets"] for finding in asset["findings"]]
            counts = {name: sum(finding["severity"] == name for finding in findings)
                      for name in ("high", "medium", "low")}
            log(f"DEMO scan {number:02d}/10: {story}. "
                f"{len(scan['assets'])} hosts; {counts['high']} high, "
                f"{counts['medium']} medium, {counts['low']} low.")
            emit("counters", subdomains=sum(asset["host"] != "example.com" for asset in scan["assets"]),
                 hosts=len(scan["assets"]), ips=len({ip["ip"] for asset in scan["assets"] for ip in asset["ips"]}),
                 findings=len(findings))
            if args.no_save:
                continue
            if not path.exists():
                stages.save_scan(scan, str(path))
            result["saved_scans"].append(str(path))
            result["saved_to"] = str(path)
            phase("Save", "spinner", number, f"Demo snapshot {number:02d}/10 saved to {path}")
            if not getattr(args, "no_report", False) and stages.report_job is not None:
                control.check()
                try:
                    exported = stages.report_job(str(path), path.parent)
                except Exception as error:
                    log(f"PDF for demo scan {number:02d} could not be generated: {error}", "warn")
                else:
                    pdf = exported.get("pdf")
                    if pdf:
                        result["demo_reports"].append(pdf)
                        if number == 10:
                            result["report_to"] = pdf
                        log(f"Demo scan {number:02d} PDF saved to {pdf}", "ok")
    except (ValueError, OSError) as error:
        result["return_code"] = 1
        result["saved_to"] = None  # Never export scan 10 from a partially saved set.
        log(f"Could not save demo history: {error}", "error")
    phase("Save", "done" if result["saved_scans"] else "skipped", len(result["saved_scans"]))
    if args.no_save:
        log("Demo history not saved (--no-save); no reports were generated.")
    result["elapsed"] = time.monotonic() - clock
    result["summary_rows"] = [
        ("Mode", "DEMO history (fake data; no network)"), ("Target", "example.com"),
        ("Demo snapshots saved", len(result["saved_scans"])),
        ("Demo PDFs", len(result["demo_reports"])), ("Selected scan", scans[-1]["scan_id"]),
        ("Hosts", len(result["assets"])), ("Findings", sum(len(asset["findings"]) for asset in result["assets"])),
        ("Report PDF", result["report_to"] or "not generated"),
    ]
    if result["saved_to"]:
        log("Showing scan 10. Open the earlier saved demo files to explore the regression and recovery.")
    emit("data", table="technologies", rows=result["assets"])
    emit("data", table="findings", rows=result["assets"])
    emit("result", result=result)
    return result


def run_scan(args, stages: ScanStages, report: Callable, control: ScanControl,
              version: str = "0.1.0") -> dict:
    """Run all phases sequentially. The UI calls this in a thread worker."""
    if getattr(args, "demos", False):
        return run_demo_history(args, stages, report, control, version)
    domain = "example.com" if args.demo else args.domain
    active = not args.passive
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    clock = time.monotonic()
    result = {
        "target": domain, "demo": args.demo, "started_at": started_at,
        "names": [], "resolved": [], "assets": [], "by_source": {},
        "port_rows": [], "skipped_hosts": [], "skipped_ips": [],
        "skipped_scope_ips": [], "skipped_ipv6_ips": [],
        "host_states": {}, "phase_counts": dict.fromkeys(PHASES, 0),
        "phase_states": dict.fromkeys(PHASES, "waiting"),
        "phase_times": dict.fromkeys(PHASES, 0.0), "warnings": [],
        "saved_to": None, "report_to": None, "elapsed": 0.0, "return_code": 0,
    }
    phase_clock = clock
    scope_check = None

    def emit(kind: str, **data):
        control.check()
        report({"kind": kind, **data})

    def log(message: str, level: str = "info"):
        if level == "warn":
            result["warnings"].append(message)
        emit("log", message=message, level=level)

    def phase(name: str, state: str, message: str = "", count: int | None = None):
        nonlocal phase_clock
        control.check()
        if state == "spinner":
            phase_clock = time.monotonic()
        else:
            result["phase_times"][name] = time.monotonic() - phase_clock
        if count is not None:
            result["phase_counts"][name] = count
        result["phase_states"][name] = state
        emit("phase", phase=name, state=state, message=message, count=count)

    def counters():
        emit("counters", subdomains=len(result["names"]), hosts=len(result["resolved"]),
             ips=len({ip for item in result["resolved"] for ip in item["ips"]}),
             findings=sum(len(asset.get("findings", [])) for asset in result["assets"]))

    def allows(checker, target: str) -> bool:
        control.check()
        if checker is None:
            return False
        try:
            return checker(target) is True
        except Exception as error:
            log(f"Scope check failed for {target}: {error}; no active probes sent.", "warn")
            return False

    def skipped(target: str, kind: str):
        emit("skipped", target=target, active_step=kind,
             message=f"{target}: skipped: not in scope.txt ({kind})")

    emit("start", target=domain, version=version, demo=args.demo)

    # Scope FIRST. An authorized domain also covers its subdomains, so this one
    # decision tells the user whether the rest of the scan can be active.
    phase("Scope", "spinner", "Checking scope (active probes require scope.txt)")
    apex_allowed = False
    if active:
        scope_check = stages.demo_scope if args.demo else stages.load_scope()
        if scope_check is None:
            log("Scope check is unavailable; all active steps fail closed.", "warn")
            phase("Scope", "skipped",
                  "Scope check unavailable: web checks and ports skipped.", count=0)
        else:
            apex_allowed = allows(scope_check, domain)
            if apex_allowed:
                phase("Scope", "done",
                      "Domain is in scope: its subdomains are authorized for web checks and ports.",
                      count=1)
            else:
                phase("Scope", "done",
                      "Domain is not in scope.txt: passive discovery only, unless a host is listed.",
                      count=0)
    else:
        phase("Scope", "skipped", "Web checks and ports skipped (--passive).", count=0)

    phase("Subdomains", "spinner", f"Finding subdomains of {domain}")
    if args.demo:
        control.pause(0.3)
        by_source = {"subfinder": [], "crtsh": [], "DEMO": sorted(set(DEMO_IPS) - {domain})}
    else:
        with tracked_processes(stages.find_subdomains, control):
            by_source = stages.find_subdomains(domain, use_subfinder=not args.no_subfinder,
                                               subfinder_max_minutes=args.minutes)
    names = sorted({name for items in by_source.values() for name in items})
    result.update(names=names, by_source=by_source)
    if names:
        log(f"Found {len(names)} subdomains", "ok")
        emit("data", table="subdomains", rows=names, by_source=by_source)
    else:
        log("No subdomains found. Only the domain itself will be looked up.", "warn")
    counters()
    phase("Subdomains", "done", count=len(names))

    phase("IP lookup", "spinner", "Looking up IP addresses")
    hosts = names if args.no_apex else list(dict.fromkeys([domain] + names))
    resolved, dropped = [], 0
    if stages.resolve_hosts is None and not args.demo:
        log("IP lookup is not available yet (exposureiq/discovery/dns_resolver.py is missing).", "warn")
    else:
        if args.demo:
            control.pause(0.3)
            resolved = [{"host": host, "ips": [DEMO_IPS[host]]} for host in hosts]
        else:
            resolved = stages.resolve_hosts(hosts)
        dropped = len(set(hosts)) - len(resolved)
        if resolved:
            log(f"{len(resolved)} names have an IP address ({dropped} had no DNS answer and were dropped)", "ok")
            emit("data", table="ips", rows=resolved)
        else:
            log("None of the names resolved to an IP address.", "warn")
    assets = [{"host": item["host"], "ips": [{"ip": ip, "open_ports": []} for ip in item["ips"]]}
              for item in resolved]
    result.update(resolved=resolved, assets=assets)
    counters()
    phase("IP lookup", "done" if stages.resolve_hosts or args.demo else "skipped", count=len(resolved))

    phase("Web checks", "spinner",
          "Checking front pages and certificates (authorized hosts and their subdomains)")
    web_allowed, checked = [], 0
    if active:
        for asset in assets:
            asset.update(technologies=[], findings=[])
            host = asset["host"]
            if allows(scope_check, host):
                web_allowed.append(asset)
                result["host_states"][host] = "in scope"
            else:
                result["skipped_hosts"].append(host)
                result["host_states"][host] = "skipped: not in scope.txt"
                skipped(host, "web checks")
        if not web_allowed:
            if scope_check is None:
                log("Scope check unavailable; no web checks sent.", "warn")
            else:
                log("No resolved host is in scope.txt; web checks skipped.", "warn")
        else:
            run_checks = _demo_checks if args.demo else stages.load_checks()
            if run_checks is None:
                log("Checks are not available yet (fingerprint modules or scope.py are missing); no checks sent.", "warn")
            else:
                next_id = 1
                try:
                    # One existing runner call per host lets q stop before the next
                    # host. Rebase its IDs so they still continue across this scan.
                    for asset in web_allowed:
                        control.check()
                        log(f"Checking {asset['host']}", "live")
                        if args.demo:
                            control.pause(0.12)
                        with observe_checks(run_checks) as observed, cancellable_checks(run_checks, control):
                            updated = run_checks([asset])
                        result["warnings"].extend(observed["warnings"])
                        if not isinstance(updated, list):
                            raise ValueError("run_checks must return a list of assets")
                        if updated:
                            asset.update(updated[0])
                        for finding in asset.get("findings", []):
                            finding["id"] = f"F-{next_id:04d}"
                            next_id += 1
                        checked += 1
                        failed, message = output.web_check_status(asset["host"], observed)
                        result["host_states"][asset["host"]] = (
                            "failed: see warning" if failed
                            else "checked (see warnings if a request failed)")
                        if failed:
                            log(message, "warn")
                        counters()
                except Exception as error:
                    log(f"Checks failed: {error}. Keeping discovery results with empty check lists.", "warn")
                    for asset in assets:
                        asset.update(technologies=[], findings=[])
                    checked = 0
        phase("Web checks", "done" if checked else "skipped", count=checked)
    else:
        result["host_states"] = {asset["host"]: "skipped: --passive" for asset in assets}
        phase("Web checks", "skipped", "Skipped web checks (--passive).", count=0)

    phase("Ports", "spinner", "Scanning open ports on authorized host names")
    ports_by_ip, port_rows, port_allowed = {}, [], []
    if active:
        scanner, port_scope = ((_demo_ports, stages.demo_scope) if args.demo else stages.load_ports())
        if scope_check is None:
            port_scope = None  # A missing initial gate must never authorize ports.
        ipv6_ips = sorted({ip for item in resolved for ip in item["ips"] if ":" in ip})
        for ip in ipv6_ips:
            result["skipped_ips"].append(ip)
            result["skipped_ipv6_ips"].append(ip)
            log(f"{ip}: skipped: IPv6 port scanning is not supported")
        ipv4_by_host = {}
        for item in resolved:
            ipv4 = [ip for ip in item["ips"] if ":" not in ip]
            if ipv4:
                ipv4_by_host[item["host"]] = ipv4
        authorized = []
        for host, ipv4 in ipv4_by_host.items():
            if allows(scope_check, host) and allows(port_scope, host):
                authorized.append((host, ipv4))
            else:
                skipped(host, "ports")
        all_ipv4 = {ip for ipv4 in ipv4_by_host.values() for ip in ipv4}
        covered_ips = {ip for _, ipv4 in authorized for ip in ipv4}
        port_allowed = sorted(covered_ips)
        for ip in sorted(all_ipv4 - covered_ips):
            result["skipped_ips"].append(ip)
            result["skipped_scope_ips"].append(ip)
        if scanner is None or port_scope is None:
            log("Port scanning is not available yet (ports.py or scope.py is missing).", "warn")
        elif not authorized:
            log("No authorized host could be port scanned.", "warn")
        elif not args.demo and not stages.nmap_available():
            log("Nmap was not found; continuing without ports.", "warn")
        else:
            already = set()
            for host, ipv4 in authorized:
                if len(ipv4) != 1:
                    # Nmap reports several addresses in one run, and ports.py
                    # reads only the first host block, so do not guess.
                    log(f"{host}: has {len(ipv4)} IPv4 addresses; ports skipped "
                        "(add the exact IP to scope.txt to scan it)", "warn")
                    continue
                ip = ipv4[0]
                if ip in already:
                    continue
                already.add(ip)
                control.check()
                log(f"Scanning ports on {host} ({ip})", "live")
                try:
                    if args.demo:
                        control.pause(0.2)
                    with tracked_processes(scanner, control):
                        found = scanner(host)
                except (ValueError, RuntimeError, TimeoutError) as error:
                    log(f"Port scan of {host} failed: {error}", "warn")
                    text = str(error).lower()
                    if "nmap" in text and any(word in text for word in ("not found", "missing", "not installed")):
                        break
                    continue
                ports_by_ip[ip] = found
                port_rows.append((ip, found))
        for asset in assets:
            for entry in asset["ips"]:
                entry["open_ports"] = ports_by_ip.get(entry["ip"], [])
        if port_rows:
            emit("data", table="ports", rows=port_rows)
        if result["skipped_ips"]:
            log(f"Skipped {len(result['skipped_ips'])} IP address(es); no probes sent to them.")
            if result["skipped_scope_ips"]:
                log(f"Skipped: not in scope — {len(result['skipped_scope_ips'])} IP address(es).")
            if result["skipped_ipv6_ips"]:
                log(f"Skipped: IPv6 ports not supported — {len(result['skipped_ipv6_ips'])} IP address(es).")
        if port_rows and web_allowed:
            # The same pure rules as runner.py; this adds no HTTP/TLS requests.
            try:
                check_risky_ports = importlib.import_module("exposureiq.fingerprint.risky_ports").check_risky_ports
                build_findings = importlib.import_module("exposureiq.fingerprint.severity").build_findings
                next_id = 1 + sum(len(asset.get("findings", [])) for asset in assets)
                for asset in web_allowed:
                    control.check()
                    if not allows(scope_check, asset["host"]):
                        continue
                    extra = build_findings(check_risky_ports(asset["ips"]), start_id=next_id)
                    if args.demo:
                        for finding in extra:
                            finding["title"] = "DEMO: " + finding["title"]
                            finding["detail"] = "DEMO: " + finding["detail"]
                    asset["findings"].extend(extra)
                    next_id += len(extra)
            except Exception as error:
                log(f"Risky-port rules are unavailable or failed ({error}); collected ports will still be saved.", "warn")
        if web_allowed:
            emit("data", table="technologies", rows=assets)
            emit("data", table="findings", rows=assets)
        phase("Ports", "done" if port_rows else "skipped", count=len(port_rows))
    else:
        phase("Ports", "skipped", "Skipped ports (--passive).", count=0)
    result["port_rows"] = port_rows
    result["phase_counts"]["Scope"] = len(web_allowed) + len(port_allowed)
    if not active:
        result["mode"], result["mode_detail"] = "passive", "Passive only (--passive): web checks and ports skipped."
    elif apex_allowed:
        result["mode"] = "full"
        result["mode_detail"] = "Full active scan: the domain is in scope, so its subdomains are authorized."
    elif web_allowed:
        result["mode"] = "partial"
        result["mode_detail"] = "Active checks only for individually authorized hosts."
    else:
        result["mode"] = "passive"
        result["mode_detail"] = "Passive only: the domain is not in scope.txt, so no probes were sent."
    counters()

    phase("Save", "spinner", "Saving results")
    saved_to = None
    if args.no_save:
        log("Not saved (--no-save).")
    elif stages.resolve_hosts is None and not args.demo:
        log("Nothing to save yet, because the IP lookup is missing.", "warn")
    elif stages.build_scan is None or stages.save_scan is None:
        log("Saving is not available yet (exposureiq/storage.py is missing).", "warn")
    else:
        if args.demo:
            control.pause(0.2)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        prefix = "demo" if args.demo else domain
        from exposureiq.paths import scan_output_path

        path = scan_output_path(domain, f"{prefix}_{stamp}.json", args.output)
        try:
            snapshot = stages.build_scan(domain, assets, started_at=started_at)
            if args.demo:
                snapshot["scan_id"] = f"DEMO-{snapshot.get('scan_id', stamp)}"
            control.check()
            stages.save_scan(snapshot, str(path))
            result["snapshot"] = snapshot
        except (ValueError, OSError) as error:
            log(f"Could not save the results: {error}", "error")
            result["return_code"] = 1
        else:
            saved_to = str(path)
            log(f"Saved {len(assets)} hosts to {path}", "ok")
    phase("Save", "done" if saved_to else "skipped", count=len(assets) if saved_to else 0)

    report_to = None
    if (saved_to and not getattr(args, "no_report", False)
            and stages.report_job is not None):
        log("Building PDF report...", "live")
        try:
            report_result = stages.report_job(saved_to, Path(saved_to).parent)
        except Exception as error:  # optional output must never fail the scan
            log(f"Report could not be generated: {error}", "warn")
        else:
            report_to = report_result.get("pdf") or report_result.get("html")
            if report_to:
                log(f"Report PDF saved to {report_to}", "ok")
            else:
                log("Report generation finished without an output file.", "warn")

    result.update(saved_to=saved_to, report_to=report_to, elapsed=time.monotonic() - clock)
    rows = [("Target", domain), ("Subdomains found", len(names))]
    if args.demo:
        rows.insert(0, ("Mode", "DEMO (fake data; no network)"))
    else:
        rows.insert(0, ("Active checks", {
            "full": "Full scan (domain in scope)",
            "partial": "Only individually authorized hosts",
            "passive": "Skipped (domain not in scope)" if active else "Skipped (--passive)",
        }[result["mode"]]))
    if stages.resolve_hosts is not None or args.demo:
        rows += [("Names with an IP", len(resolved)), ("Dropped (no DNS answer)", dropped)]
    if result["mode"] != "passive":
        rows += [("IPs port scanned", len(port_rows)),
                 ("Technology hints", sum(len(asset.get("technologies", [])) for asset in assets))]
    seconds = int(result["elapsed"])
    rows.append(("Time", f"{seconds // 60}m {seconds % 60}s" if seconds >= 60 else f"{seconds}s"))
    if saved_to:
        rows.append(("Report PDF", report_to or "not generated"))
    result["summary_rows"] = rows
    if saved_to and not args.demo:
        try:
            from exposureiq.tui.user_scope import remember_scan
            remember_scan(result)
        except (OSError, ValueError) as error:
            log(f"Could not remember the last scan for scope add: {error}", "warn")
    emit("result", result=result)
    return result
