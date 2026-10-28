
"""Human-readable summaries for scan differences.

Pure data processing: no network access and no input mutation.
"""

from collections import Counter


KINDS = (
    "host.new",
    "host.removed",
    "ip.new",
    "ip.removed",
    "port.opened",
    "port.closed",
    "port.service_changed",
    "tech.new",
    "tech.removed",
    "tech.version_changed",
    "finding.new",
    "finding.resolved",
    "finding.severity_changed",
)

KIND_ORDER = {kind: index for index, kind in enumerate(KINDS)}

REMOVAL_KINDS = {
    "host.removed",
    "ip.removed",
    "port.closed",
    "tech.removed",
    "finding.resolved",
}

NEW_FINDING_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


def _text(value):
    """Return a safe, readable string for an optional value."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _nested(change, side, *keys):
    """Find the first available value in a before/after dictionary."""
    data = change.get(side)
    if not isinstance(data, dict):
        return ""

    for key in keys:
        value = _text(data.get(key))
        if value:
            return value

    return ""


def _field(change, *keys):
    """Find a value at the top level, then in before/after data."""
    for key in keys:
        value = _text(change.get(key))
        if value:
            return value

    for side in ("after", "before"):
        value = _nested(change, side, *keys)
        if value:
            return value

    return ""


def _subject(change):
    """Build a useful asset prefix without empty punctuation."""
    host = _field(change, "host", "hostname", "domain", "subdomain")
    ip = _field(change, "ip", "address")
    port = _field(change, "port")

    if host:
        return host
    if ip:
        return ip
    if port:
        return f"port {port}"
    return ""


def _prefix(change, message):
    subject = _subject(change)
    return f"{subject}: {message}" if subject else message


def _service(change, side):
    return _nested(change, side, "service", "service_name", "name")


def _technology(change, side):
    return _nested(change, side, "technology", "tech", "name", "title")


def _version(change, side):
    return _nested(change, side, "version", "version_number")


def _finding_title(change, side):
    return _nested(change, side, "title", "finding", "name", "description")


def _severity(change, side):
    return _nested(change, side, "severity", "risk")


def describe_change(change: dict) -> str:
    """Describe one change in plain English."""
    if not isinstance(change, dict):
        return "Unrecognized change"

    kind = _text(change.get("kind"))
    subject = _subject(change)
    status = _text(change.get("status")).lower()
    port = _field(change, "port")
    ip = _field(change, "ip", "address")

    if status == "missing" and kind in REMOVAL_KINDS:
        return _prefix(change, "not seen this time")

    if kind == "host.new":
        return _prefix(change, "new host discovered")

    if kind == "host.removed":
        return _prefix(change, "host no longer detected")

    if kind == "ip.new":
        address = _nested(change, "after", "ip", "address") or ip
        message = f"new IP address: {address}" if address else "new IP address detected"
        return _prefix(change, message) if subject and subject != address else message

    if kind == "ip.removed":
        address = _nested(change, "before", "ip", "address") or ip
        message = f"IP address no longer detected: {address}" if address else "IP address no longer detected"
        return _prefix(change, message) if subject and subject != address else message

    if kind == "port.opened":
        service = _service(change, "after") or _field(change, "service", "service_name")
        target = f"port {port}" if port else "a port"
        if service:
            target += f" ({service})"
        message = f"{target} is now open"
        if ip:
            message += f" on {ip}"
        return _prefix(change, message) if subject and subject != ip else message

    if kind == "port.closed":
        service = _service(change, "before") or _field(change, "service", "service_name")
        target = f"port {port}" if port else "a port"
        if service:
            target += f" ({service})"
        return _prefix(change, f"{target} is now closed")

    if kind == "port.service_changed":
        old = _service(change, "before")
        new = _service(change, "after")
        port_text = f"port {port}" if port else "service"
        if old and new:
            message = f"{port_text} service changed from {old} to {new}"
        elif new:
            message = f"{port_text} service is now {new}"
        elif old:
            message = f"{port_text} service changed from {old}"
        else:
            message = f"{port_text} service changed"
        return _prefix(change, message)

    if kind == "tech.new":
        name = _technology(change, "after") or _field(change, "technology", "tech", "name")
        version = _version(change, "after")
        item = " ".join(part for part in (name, version) if part)
        return _prefix(change, f"new technology: {item}" if item else "new technology detected")

    if kind == "tech.removed":
        name = _technology(change, "before") or _field(change, "technology", "tech", "name")
        version = _version(change, "before")
        item = " ".join(part for part in (name, version) if part)
        return _prefix(change, f"technology no longer detected: {item}" if item else "technology no longer detected")

    if kind == "tech.version_changed":
        name = (
            _technology(change, "after")
            or _technology(change, "before")
            or _field(change, "technology", "tech", "name")
        )
        old = _version(change, "before")
        new = _version(change, "after")
        if name and old and new:
            message = f"{name} changed from {old} to {new}"
        elif name and new:
            message = f"{name} version is now {new}"
        elif name:
            message = f"{name} version changed"
        else:
            message = "technology version changed"
        return _prefix(change, message)

    if kind == "finding.new":
        title = _finding_title(change, "after") or _field(change, "title", "finding", "name")
        severity = _severity(change, "after") or _field(change, "severity", "risk")
        details = f" ({severity})" if severity else ""
        message = f"new finding: {title}{details}" if title else f"new finding{details}"
        return _prefix(change, message)

    if kind == "finding.resolved":
        title = _finding_title(change, "before") or _field(change, "title", "finding", "name")
        message = f"finding resolved: {title}" if title else "finding resolved"
        return _prefix(change, message)

    if kind == "finding.severity_changed":
        title = (
            _finding_title(change, "after")
            or _finding_title(change, "before")
            or _field(change, "title", "finding", "name")
        )
        old = _severity(change, "before")
        new = _severity(change, "after")
        if title and old and new:
            message = f"{title} severity changed from {old} to {new}"
        elif title and new:
            message = f"{title} severity is now {new}"
        elif title:
            message = f"{title} severity changed"
        else:
            message = "finding severity changed"
        return _prefix(change, message)

    return _prefix(change, f"change detected ({kind})" if kind else "change detected")


def _sort_key(change):
    """Stable sort by agreed kind order, then host, IP, and port."""
    kind = _text(change.get("kind"))
    host = _field(change, "host", "hostname", "domain", "subdomain").lower()
    ip = _field(change, "ip", "address").lower()
    port = _field(change, "port")
    try:
        port_key = (0, int(port))
    except (ValueError, TypeError):
        port_key = (1, port.lower())

    return (KIND_ORDER.get(kind, len(KIND_ORDER)), host, ip, port_key)


def _direction(change):
    direction = _text(change.get("direction")).lower()
    return direction if direction in {"worse", "better"} else "neutral"


def _finding_priority(change):
    severity = (
        _severity(change, "after")
        or _field(change, "severity", "risk")
        or "info"
    ).lower()
    return NEW_FINDING_SEVERITY_ORDER.get(severity, len(NEW_FINDING_SEVERITY_ORDER))


def _highlight_key(change):
    """Order highlights: new findings, opened ports, other worse, better."""
    kind = _text(change.get("kind"))
    direction = _direction(change)

    if kind == "finding.new":
        return (0, _finding_priority(change), *_sort_key(change))
    if kind == "port.opened":
        return (1, 0, *_sort_key(change))
    if direction == "worse":
        return (2, 0, *_sort_key(change))
    if direction == "better":
        return (3, 0, *_sort_key(change))
    return (4, 0, *_sort_key(change))


def summarize_diff(diff: dict) -> dict:
    """Return counts, headline, highlights, and grouped plain-text lines."""
    if not isinstance(diff, dict):
        diff = {}

    raw_changes = diff.get("changes") or []
    changes = [change for change in raw_changes if isinstance(change, dict)]
    changes = sorted(changes, key=_sort_key)

    counts_by_direction = Counter(_direction(change) for change in changes)
    by_kind = dict(sorted(Counter(
        _text(change.get("kind")) or "unknown" for change in changes
    ).items(), key=lambda item: (KIND_ORDER.get(item[0], len(KIND_ORDER)), item[0])))

    worse = counts_by_direction["worse"]
    better = counts_by_direction["better"]
    neutral = counts_by_direction["neutral"]
    total = len(changes)

    if total == 0:
        headline = "No changes since the previous scan"
    else:
        parts = []
        if worse:
            parts.append(f"{worse} things got worse")
        if better:
            parts.append(f"{better} got better")
        other = total - worse - better
        if other:
            parts.append(f"{other} other changes")
        headline = ", ".join(parts)

    ordered_lines = []
    for direction in ("worse", "better", "neutral"):
        ordered_lines.extend(
            describe_change(change)
            for change in changes
            if _direction(change) == direction
        )

    priority_changes = sorted(changes, key=_highlight_key)
    highlights = [
        describe_change(change)
        for change in priority_changes[:5]
    ]

    return {
        "headline": headline,
        "counts": {
            "total": total,
            "worse": worse,
            "better": better,
            "neutral": neutral,
        },
        "by_kind": by_kind,
        "highlights": highlights,
        "lines": ordered_lines,
    }
