"""Pure scan comparison (Stage 3).

``compare_scans(old, new)`` turns two validated scan dictionaries into a list of
change dictionaries, and ``present_in(scan, change)`` answers whether the thing
described by a removal change still exists in another scan.

No network, no file access, and the input scans are never changed. The change
shape is the shared one used by ``diffing.summary`` and the CLI/TUI:

    {
        "kind": "port.opened", "direction": "worse",
        "host": "www.example.com", "ip": "203.0.113.10", "port": 443,
        "before": None, "after": {"port": 443, "protocol": "tcp", "service": "https"},
        "status": "new",
    }

Direction is about security posture: new attack surface is "worse", a confirmed
removal is "better", and changes with no clear effect are "neutral".
"""

from __future__ import annotations

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

KIND_ORDER = {
    "host.new": 0,
    "host.removed": 1,
    "ip.new": 2,
    "ip.removed": 3,
    "port.opened": 4,
    "port.closed": 5,
    "port.service_changed": 6,
    "tech.new": 7,
    "tech.removed": 8,
    "tech.version_changed": 9,
    "finding.new": 10,
    "finding.resolved": 11,
    "finding.severity_changed": 12,
}


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _host_key(value) -> str:
    return _text(value).lower().rstrip(".")


def _assets(scan: dict) -> list[dict]:
    if not isinstance(scan, dict):
        return []
    return [asset for asset in scan.get("assets") or [] if isinstance(asset, dict)]


def _asset_map(scan: dict) -> dict[str, dict]:
    result = {}
    for asset in _assets(scan):
        host = _host_key(asset.get("host"))
        if host and host not in result:
            result[host] = asset
    return result


def _ips(asset: dict) -> list[dict]:
    return [entry for entry in asset.get("ips") or [] if isinstance(entry, dict)]


def _ip_key(entry: dict) -> str:
    return _text(entry.get("ip"))


def _ip_map(asset: dict) -> dict[str, dict]:
    result = {}
    for entry in _ips(asset):
        key = _ip_key(entry)
        if key and key not in result:
            result[key] = entry
    return result


def _ports(entry: dict) -> list[dict]:
    return [port for port in entry.get("open_ports") or [] if isinstance(port, dict)]


def _port_key(entry: dict) -> tuple:
    port = entry.get("port")
    if isinstance(port, bool) or not isinstance(port, int):
        port = 0
    return port, _text(entry.get("protocol")).lower()


def _port_map(entry: dict) -> dict[tuple, dict]:
    result = {}
    for port in _ports(entry):
        key = _port_key(port)
        if key[0] and key not in result:
            result[key] = port
    return result


def _technologies(asset: dict) -> list[dict]:
    return [tech for tech in asset.get("technologies") or [] if isinstance(tech, dict)]


def _tech_key(tech: dict) -> tuple:
    return _text(tech.get("name")).lower(), _text(tech.get("source")).lower()


def _tech_map(asset: dict) -> dict[tuple, dict]:
    result = {}
    for tech in _technologies(asset):
        key = _tech_key(tech)
        if key[0] and key not in result:
            result[key] = tech
    return result


def _findings(asset: dict) -> list[dict]:
    return [finding for finding in asset.get("findings") or [] if isinstance(finding, dict)]


def _finding_key(finding: dict) -> tuple:
    port = finding.get("port")
    if isinstance(port, bool) or not isinstance(port, int):
        port = None
    return (
        _text(finding.get("rule")).lower(),
        _text(finding.get("ip")),
        port,
    )


def _finding_map(asset: dict) -> dict[tuple, dict]:
    result = {}
    for finding in _findings(asset):
        key = _finding_key(finding)
        if key[0] and key not in result:
            result[key] = finding
    return result


def _change(kind: str, direction: str, status: str, host=None, ip=None, port=None,
            before=None, after=None) -> dict:
    return {
        "kind": kind,
        "direction": direction,
        "host": host,
        "ip": ip,
        "port": port,
        "before": before,
        "after": after,
        "status": status,
    }


def _tech_payload(tech: dict) -> dict:
    return {
        "technology": tech.get("name"),
        "version": tech.get("version", ""),
        "source": tech.get("source"),
    }


def _port_payload(port: dict) -> dict:
    return {
        "port": port.get("port"),
        "protocol": port.get("protocol"),
        "service": port.get("service"),
    }


def change_key(change: dict) -> tuple:
    """Identity of a change, used to match confirmed removals.

    The key is deliberately independent of the per-scan finding ID, because
    IDs are re-numbered on every scan.
    """
    if not isinstance(change, dict):
        return ()
    kind = _text(change.get("kind"))
    host = _host_key(change.get("host"))
    ip = _text(change.get("ip"))
    port = change.get("port")
    if isinstance(port, bool) or not isinstance(port, int):
        port = None
    before = change.get("before") if isinstance(change.get("before"), dict) else {}

    if kind == "host.removed":
        return kind, host
    if kind == "ip.removed":
        return kind, host, ip or _text(before.get("ip"))
    if kind == "port.closed":
        return kind, host, ip, port or before.get("port"), _text(before.get("protocol")).lower()
    if kind == "tech.removed":
        name = _text(before.get("technology") or before.get("name")).lower()
        source = _text(before.get("source")).lower()
        return kind, host, name, source
    if kind == "finding.resolved":
        return (
            kind, host,
            _text(before.get("rule")).lower(),
            _text(before.get("ip")),
            before.get("port"),
        )
    return kind, host, ip, port


def _sort_key(change: dict) -> tuple:
    port = change.get("port")
    if isinstance(port, bool) or not isinstance(port, int):
        port = 0
    return (
        KIND_ORDER.get(_text(change.get("kind")), len(KIND_ORDER)),
        _host_key(change.get("host")),
        _text(change.get("ip")),
        port,
    )


def compare_scans(old: dict, new: dict) -> dict:
    """Return the changes that turn ``old`` into ``new``.

    Only the scan contents are inspected. The result includes both scan
    metadata blocks because the CLI and TUI show the old/new scan IDs.
    """
    old_assets = _asset_map(old)
    new_assets = _asset_map(new)
    changes = []

    def add(*args, **kwargs):
        changes.append(_change(*args, **kwargs))

    for host in sorted(old_assets.keys() - new_assets.keys()):
        add("host.removed", "better", "missing", host=host,
            before={"host": host})
    for host in sorted(new_assets.keys() - old_assets.keys()):
        add("host.new", "worse", "new", host=host,
            after={"host": host})

    for host in sorted(old_assets.keys() & new_assets.keys()):
        old_asset, new_asset = old_assets[host], new_assets[host]
        old_ips, new_ips = _ip_map(old_asset), _ip_map(new_asset)
        for address in sorted(old_ips.keys() - new_ips.keys()):
            add("ip.removed", "neutral", "missing", host=host, ip=address,
                before={"ip": address})
        for address in sorted(new_ips.keys() - old_ips.keys()):
            add("ip.new", "neutral", "new", host=host, ip=address,
                after={"ip": address})

        for address in sorted(old_ips.keys() & new_ips.keys()):
            old_ports = _port_map(old_ips[address])
            new_ports = _port_map(new_ips[address])
            for key in sorted(old_ports.keys() - new_ports.keys()):
                port = old_ports[key]
                add("port.closed", "better", "missing", host=host, ip=address,
                    port=key[0], before=_port_payload(port))
            for key in sorted(new_ports.keys() - old_ports.keys()):
                port = new_ports[key]
                add("port.opened", "worse", "new", host=host, ip=address,
                    port=key[0], after=_port_payload(port))
            for key in sorted(old_ports.keys() & new_ports.keys()):
                before, after = old_ports[key], new_ports[key]
                old_service = _text(before.get("service"))
                new_service = _text(after.get("service"))
                if old_service.lower() != new_service.lower():
                    add("port.service_changed", "neutral", "changed", host=host,
                        ip=address, port=key[0],
                        before=_port_payload(before), after=_port_payload(after))

        old_tech, new_tech = _tech_map(old_asset), _tech_map(new_asset)
        for key in sorted(old_tech.keys() - new_tech.keys()):
            add("tech.removed", "neutral", "missing", host=host,
                before=_tech_payload(old_tech[key]))
        for key in sorted(new_tech.keys() - old_tech.keys()):
            add("tech.new", "neutral", "new", host=host,
                after=_tech_payload(new_tech[key]))
        for key in sorted(old_tech.keys() & new_tech.keys()):
            before, after = old_tech[key], new_tech[key]
            if _text(before.get("version")) != _text(after.get("version")):
                add("tech.version_changed", "neutral", "changed", host=host,
                    before=_tech_payload(before), after=_tech_payload(after))

        old_findings, new_findings = _finding_map(old_asset), _finding_map(new_asset)
        for key in sorted(old_findings.keys() - new_findings.keys()):
            finding = old_findings[key]
            add("finding.resolved", "better", "missing", host=host,
                ip=finding.get("ip"), port=finding.get("port"), before=finding)
        for key in sorted(new_findings.keys() - old_findings.keys()):
            finding = new_findings[key]
            add("finding.new", "worse", "new", host=host,
                ip=finding.get("ip"), port=finding.get("port"), after=finding)
        for key in sorted(old_findings.keys() & new_findings.keys()):
            before, after = old_findings[key], new_findings[key]
            old_severity = _text(before.get("severity")).lower()
            new_severity = _text(after.get("severity")).lower()
            if old_severity != new_severity:
                old_rank = SEVERITY_RANK.get(old_severity, 0)
                new_rank = SEVERITY_RANK.get(new_severity, 0)
                direction = "worse" if new_rank > old_rank else "better" if new_rank < old_rank else "neutral"
                add("finding.severity_changed", direction, "changed", host=host,
                    ip=after.get("ip"), port=after.get("port"),
                    before=before, after=after)

    changes.sort(key=_sort_key)
    return {
        "target": _text((new or {}).get("target")) or _text((old or {}).get("target")),
        "old": _scan_meta(old),
        "new": _scan_meta(new),
        "changes": changes,
    }


def _scan_meta(scan) -> dict:
    if not isinstance(scan, dict):
        return {}
    return {
        key: scan.get(key)
        for key in ("scan_id", "started_at", "target", "schema_version")
    }


def _change_value(change: dict, *names):
    for name in names:
        value = change.get(name)
        if value not in (None, ""):
            return value
    for side in ("before", "after"):
        block = change.get(side)
        if not isinstance(block, dict):
            continue
        for name in names:
            value = block.get(name)
            if value not in (None, ""):
                return value
    return None


def present_in(scan: dict, change: dict) -> bool:
    """Return True when the entity a removal change refers to exists in ``scan``."""
    if not isinstance(change, dict):
        return False
    kind = _text(change.get("kind"))
    host = _host_key(_change_value(change, "host"))
    assets = _asset_map(scan)
    candidates = [assets[host]] if host in assets else list(assets.values())

    if kind == "host.removed":
        return host in assets

    if kind == "ip.removed":
        address = _text(_change_value(change, "ip"))
        return any(address in _ip_map(asset) for asset in candidates)

    if kind == "port.closed":
        port = _change_value(change, "port")
        protocol = _text(_change_value(change, "protocol")).lower()
        for asset in candidates:
            for entry in _ips(asset):
                for item in _ports(entry):
                    if item.get("port") != port:
                        continue
                    if not protocol or _text(item.get("protocol")).lower() == protocol:
                        return True
        return False

    if kind == "tech.removed":
        name = _text(_change_value(change, "technology", "name")).lower()
        source = _text(_change_value(change, "source")).lower()
        for asset in candidates:
            for tech in _technologies(asset):
                if _text(tech.get("name")).lower() != name:
                    continue
                if not source or _text(tech.get("source")).lower() == source:
                    return True
        return False

    if kind == "finding.resolved":
        rule = _text(_change_value(change, "rule")).lower()
        ip = _text(_change_value(change, "ip"))
        port = _change_value(change, "port")
        for asset in candidates:
            for finding in _findings(asset):
                if _text(finding.get("rule")).lower() != rule:
                    continue
                if ip and _text(finding.get("ip")) != ip:
                    continue
                if port is not None and finding.get("port") != port:
                    continue
                return True
        return False

    return False
