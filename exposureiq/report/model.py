"""Build the report model from one validated scan.

This module is pure data work: it never touches the network, never writes a
file, and never mutates the scan it is given. The result is a plain dictionary
that both renderers can use, which also makes the report easy to test.
"""

from __future__ import annotations

from datetime import datetime, timezone

from exposureiq.report import branding

SEVERITY_ORDER = ("high", "medium", "low")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

# The order used when explaining severity on the methodology page.
SEVERITY_HELP = {
    "high": "Direct exposure of a sensitive service, or a broken HTTPS setup. Fix first.",
    "medium": "A weakened protection or an exposed administration surface. Fix soon.",
    "low": "Information disclosure or a smaller hardening gap. Fix as routine work.",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _items(value) -> list:
    return value if isinstance(value, list) else []


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def format_time(value) -> str:
    """Turn an ISO timestamp into a short, predictable UTC label."""
    text = _text(value)
    if not text:
        return "unknown time"
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")


def short_time(value) -> str:
    """A compact label for a chart axis."""
    text = _text(value)
    if not text:
        return "?"
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:10]
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%d %b")


def short_datetime(value) -> str:
    """A compact date and time label, used when several scans share a day."""
    text = _text(value)
    if not text:
        return "?"
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:16]
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%d %b %H:%M")


def _assets(scan: dict) -> list[dict]:
    return [asset for asset in _items(scan.get("assets")) if isinstance(asset, dict)]


def _findings(scan: dict) -> list[dict]:
    """Every finding in the scan, with the asset host attached."""
    rows = []
    for asset in _assets(scan):
        host = _text(asset.get("host"))
        for finding in _items(asset.get("findings")):
            if not isinstance(finding, dict):
                continue
            severity = _text(finding.get("severity")).lower()
            if severity not in SEVERITY_RANK:
                severity = "low"
            rows.append({**finding, "host": host or _text(finding.get("host")), "severity": severity})
    rows.sort(key=lambda item: (
        SEVERITY_RANK.get(item["severity"], len(SEVERITY_RANK)),
        item["host"].lower(),
        _text(item.get("id")),
    ))
    return rows


def _severity_counts(findings: list[dict]) -> dict:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    counts["total"] = len(findings)
    return counts


def _severity_rows(counts: dict) -> list[dict]:
    total = counts.get("total") or 0
    rows = []
    for name in SEVERITY_ORDER:
        count = counts.get(name, 0)
        rows.append({
            "key": name,
            "label": branding.SEVERITY_LABELS[name],
            "count": count,
            "percent": round(count * 100 / total) if total else 0,
            "color": branding.SEVERITY_COLORS[name],
        })
    return rows


def _risk(counts: dict) -> dict:
    if counts.get("high"):
        level = "high"
        note = "High-severity findings need attention first."
    elif counts.get("medium"):
        level = "medium"
        note = "Medium-severity findings should be scheduled soon."
    elif counts.get("low"):
        level = "low"
        note = "Only low-severity hardening items were recorded."
    else:
        level = "none"
        note = "No findings were recorded in this scan."
    return {
        "level": level,
        "label": f"{branding.SEVERITY_LABELS[level]} risk" if level != "none" else "No findings",
        "note": note,
        "color": branding.SEVERITY_COLORS[level],
    }


def _asset_rows(scan: dict) -> list[dict]:
    rows = []
    for asset in _assets(scan):
        host = _text(asset.get("host")) or "unknown host"
        ips, ports, technologies = [], [], []
        for entry in _items(asset.get("ips")):
            if not isinstance(entry, dict):
                continue
            ip = _text(entry.get("ip"))
            if ip:
                ips.append(ip)
            for port in _items(entry.get("open_ports")):
                if isinstance(port, dict) and port.get("port"):
                    ports.append(
                        f"{_text(port.get('protocol')) or 'tcp'}/{port['port']} "
                        f"{_text(port.get('service')) or 'unknown'}"
                    )
        for technology in _items(asset.get("technologies")):
            if not isinstance(technology, dict):
                continue
            name = _text(technology.get("name"))
            version = _text(technology.get("version"))
            if name:
                technologies.append(f"{name} {version}".strip())

        findings = [item for item in _items(asset.get("findings")) if isinstance(item, dict)]
        severities = [_text(item.get("severity")).lower() for item in findings]
        highest = next((name for name in SEVERITY_ORDER if name in severities), None)
        rows.append({
            "host": host,
            "ips": sorted(set(ips)),
            "ports": ports,
            "technologies": sorted(set(technologies)),
            "findings": len(findings),
            "highest": highest,
            "highest_label": branding.SEVERITY_LABELS[highest] if highest else "—",
            "highest_color": branding.SEVERITY_COLORS[highest] if highest else branding.MUTED,
        })
    rows.sort(key=lambda item: (
        SEVERITY_RANK.get(item["highest"], len(SEVERITY_RANK)),
        item["host"].lower(),
    ))
    return rows


def _technology_rows(scan: dict) -> list[dict]:
    grouped: dict[tuple, set] = {}
    for asset in _assets(scan):
        host = _text(asset.get("host"))
        for technology in _items(asset.get("technologies")):
            if not isinstance(technology, dict):
                continue
            name = _text(technology.get("name"))
            if not name:
                continue
            key = (name, _text(technology.get("version")), _text(technology.get("source")))
            grouped.setdefault(key, set()).add(host)
    rows = [
        {"name": name, "version": version, "source": source, "hosts": sorted(hosts)}
        for (name, version, source), hosts in grouped.items()
    ]
    rows.sort(key=lambda item: (item["name"].lower(), item["version"]))
    return rows


def _port_rows(scan: dict) -> list[dict]:
    grouped: dict[tuple, set] = {}
    for asset in _assets(scan):
        host = _text(asset.get("host"))
        for entry in _items(asset.get("ips")):
            if not isinstance(entry, dict):
                continue
            for port in _items(entry.get("open_ports")):
                if not isinstance(port, dict) or not port.get("port"):
                    continue
                key = (port["port"], _text(port.get("protocol")) or "tcp",
                       _text(port.get("service")) or "unknown")
                grouped.setdefault(key, set()).add(host)
    rows = [
        {"port": port, "protocol": protocol, "service": service, "hosts": sorted(hosts)}
        for (port, protocol, service), hosts in grouped.items()
    ]
    rows.sort(key=lambda item: (item["port"], item["protocol"]))
    return rows


def _history_points(scan: dict, history: list | None) -> list[dict]:
    scans = [item for item in (history or []) if isinstance(item, dict)]
    current_key = (_text(scan.get("scan_id")), _text(scan.get("started_at")))
    if not any((_text(item.get("scan_id")), _text(item.get("started_at"))) == current_key
               for item in scans):
        scans.append(scan)

    unique = {}
    for item in scans:
        key = (_text(item.get("scan_id")), _text(item.get("started_at")))
        unique[key] = item
    ordered = sorted(unique.values(), key=lambda item: (
        _text(item.get("started_at")), _text(item.get("scan_id"))))

    points = []
    labels = [short_time(item.get("started_at")) for item in ordered]
    duplicates = {label for label in labels if labels.count(label) > 1}
    for item, label in zip(ordered, labels):
        findings = _findings(item)
        points.append({
            "started_at": _text(item.get("started_at")),
            "label": short_datetime(item.get("started_at")) if label in duplicates else label,
            "assets": len(_assets(item)),
            "findings": len(findings),
            "high": sum(1 for finding in findings if finding["severity"] == "high"),
        })
    return points


def _executive_summary(report: dict) -> list[str]:
    target = report["target"]
    counts = report["counts"]
    severity = report["severity"]
    risk = report["risk"]
    paragraphs = []

    paragraphs.append(
        f"ExposureIQ assessed {target} on {report['started_label']}. "
        f"The scan covered {_plural(counts['assets'], 'host')}, "
        f"{_plural(counts['ips'], 'IP address', 'IP addresses')}, "
        f"{_plural(counts['ports'], 'open port')} and "
        f"{_plural(counts['technologies'], 'technology hint')}, and recorded "
        f"{_plural(severity['total'], 'finding')}."
    )

    findings = report["findings"]
    if findings:
        first = findings[0]
        where = f" on {first['host']}" if first.get("host") else ""
        paragraphs.append(
            f"{risk['note']} The scan recorded {_plural(severity['high'], 'high-severity issue')}, "
            f"{_plural(severity['medium'], 'medium-severity issue')} and "
            f"{_plural(severity['low'], 'low-severity issue')}. "
            f"The most urgent item is \u201c{first.get('title') or 'a finding'}\u201d{where}."
        )
    else:
        paragraphs.append(
            "No findings were recorded. This means the checks that ran did not see a "
            "problem; it is not proof that the target is secure."
        )

    summary = report.get("diff_summary")
    if summary:
        headline = summary.get("headline") or "Changes were compared with the previous scan."
        highlights = summary.get("highlights") or []
        extra = f" For example: {highlights[0]}." if highlights else ""
        paragraphs.append(f"Compared with the previous scan, {headline[0].lower() + headline[1:]}.{extra}")
    else:
        paragraphs.append(
            "There is no earlier saved scan for this target, so this report describes "
            "the current exposure only. Run another scan later to unlock the change section."
        )

    paragraphs.append(
        "Findings reflect only the hosts that were in scope and the checks ExposureIQ "
        "ran. Review the evidence and recommendation for each item before assigning work."
    )
    return paragraphs


def build_report(scan: dict, *, diff: dict | None = None, history: list | None = None,
                 generated_at: str | None = None, title: str | None = None) -> dict:
    """Return a renderer-ready report dictionary for one validated scan.

    ``diff`` is the Stage 3 diff document (``diffing.pipeline.build_diff``) when
    an earlier scan exists. ``history`` is a list of older scans for the same
    target, used by the "assets over time" chart.
    """
    if not isinstance(scan, dict):
        raise ValueError("scan must be a dictionary")
    target = _text(scan.get("target"))
    if not target:
        raise ValueError("scan must have a target")

    findings = _findings(scan)
    severity = _severity_counts(findings)
    asset_rows = _asset_rows(scan)
    ports = _port_rows(scan)
    technologies = _technology_rows(scan)
    history_points = _history_points(scan, history)
    generated = generated_at or _utc_now()

    report = {
        "title": title or "Security Assessment Report",
        "target": target,
        "scan_id": _text(scan.get("scan_id")) or "unknown",
        "schema_version": _text(scan.get("schema_version")) or "unknown",
        "started_at": _text(scan.get("started_at")),
        "started_label": format_time(scan.get("started_at")),
        "generated_at": generated,
        "generated_label": format_time(generated),
        "counts": {
            "assets": len(asset_rows),
            "ips": len({ip for row in asset_rows for ip in row["ips"]}),
            "ports": sum(len(row["ports"]) for row in asset_rows),
            "technologies": sum(len(row["technologies"]) for row in asset_rows),
            "findings": len(findings),
        },
        "severity": severity,
        "severity_rows": _severity_rows(severity),
        "findings": findings,
        "top_findings": findings[:5],
        "assets": asset_rows,
        "ports": ports,
        "technologies": technologies,
        "diff": diff if isinstance(diff, dict) else None,
        "diff_summary": (diff or {}).get("summary") if isinstance(diff, dict) else None,
        "history": history_points,
    }
    report["risk"] = _risk(severity)
    report["executive_summary"] = _executive_summary(report)
    report["severity_help"] = SEVERITY_HELP
    return report
