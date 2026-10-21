"""Read-only saved-scan previews and the results-folder listing.

Nothing here sends traffic, writes a file, or imports Textual. The existing
storage.load_scan() decides whether a saved file is valid.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from exposureiq import output, storage

RESULTS_DIR = Path("results")


def display_time(value) -> str:
    """Turn the saved ISO time into a short, predictable UTC label."""
    if not isinstance(value, str) or not value.strip():
        return "unknown time"
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return value
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _port_rows(assets: list) -> list:
    rows, seen = [], set()
    for asset in assets:
        for entry in asset.get("ips", []):
            ip, ports = entry.get("ip"), entry.get("open_ports", [])
            if ports and ip not in seen:
                seen.add(ip)
                rows.append((ip, ports))
    return rows


def result_from_snapshot(snapshot: dict, saved_to) -> dict:
    """Adapt a validated scan snapshot to the shape the results screen reads."""
    target = snapshot["target"]
    assets = snapshot.get("assets", [])
    names = [asset["host"] for asset in assets if asset["host"] != target]
    port_rows = _port_rows(assets)
    scan_id = snapshot.get("scan_id", "")
    demo = str(scan_id).startswith("DEMO-")
    started_at = snapshot.get("started_at")
    findings = sum(len(asset.get("findings", [])) for asset in assets)
    return {
        "target": target,
        "demo": demo,
        "started_at": started_at,
        "started_time": display_time(started_at),
        "scan_id": scan_id,
        "names": names,
        "assets": assets,
        "elapsed": 0.0,
        "saved_to": str(saved_to),
        "snapshot": snapshot,
        "phase_states": dict.fromkeys(("Scope", "Subdomains", "IP lookup", "Web checks", "Ports", "Save"), "saved"),
        "phase_counts": {
            "Scope": len(assets), "Subdomains": len(names), "IP lookup": len(assets),
            "Web checks": sum(1 for asset in assets if asset.get("technologies") or asset.get("findings")),
            "Ports": len(port_rows), "Save": len(assets),
        },
        "phase_times": dict.fromkeys(("Scope", "Subdomains", "IP lookup", "Web checks", "Ports", "Save"), 0.0),
        "warnings": [],
        "host_states": {asset["host"]: "saved scan" for asset in assets},
        "skipped_hosts": [], "skipped_ips": [], "skipped_scope_ips": [], "skipped_ipv6_ips": [],
        "port_rows": port_rows,
        "return_code": 0,
        "mode": "preview",
        "mode_detail": "Saved scan — read-only preview. No probes were sent.",
        "summary_rows": [
            ("Target", target), ("Scan ID", scan_id), ("Scan time", display_time(started_at)),
            ("Subdomains found", len(names)), ("Hosts", len(assets)),
            ("IPs with open ports", len(port_rows)), ("Findings", findings),
            ("Schema", snapshot.get("schema_version", "unknown")),
        ],
    }


def list_saved(directory=RESULTS_DIR, limit: int = 200) -> list:
    """Newest first. An unreadable file is listed with an error, never hidden."""
    try:
        paths = sorted(Path(directory).glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return []
    entries = []
    for path in paths[:limit]:
        try:
            snapshot = storage.load_scan(str(path))
        except (OSError, ValueError) as error:
            entries.append({"path": str(path), "name": path.name, "target": "unreadable",
                            "started": "", "scan_id": "", "error": str(error)})
        else:
            entries.append({"path": str(path), "name": path.name, "target": snapshot["target"],
                            "started": display_time(snapshot.get("started_at")),
                            "scan_id": snapshot.get("scan_id", ""), "error": None})
    return entries


def print_preview(result: dict, *, limit: int = 30, verbose: bool = False) -> None:
    """Compact terminal preview for non-interactive stdout."""
    from rich.text import Text

    output.console.print(Text.assemble(
        ("ExposureIQ", f"bold {output.TEAL}"), " | Saved scan: ", (result["target"], "bold"),
        ("  ·  read-only preview (no probes sent)", output.INDIGO)))
    output.info(f"Scan time  {result['started_time']}")
    output.info(f"Scan ID    {result['scan_id']}")
    output.info(f"File       {result['saved_to']}")
    if result["demo"]:
        output.warn("DEMO — this saved file contains fake sample data, not a real scan.")
    output.ip_table(result["assets"], limit)
    if result["port_rows"]:
        output.ports_table(result["port_rows"])
    output.technology_table(result["assets"], limit)
    output.findings_table(result["assets"], limit, verbose)
    output.summary(result["summary_rows"], None, assets=result["assets"])
