"""User-owned authorization and last-scan pointers; no network or Textual.

Only the confirmation interfaces call append_hosts. They must pass the exact
typed domain; there is no confirmation-bypass flag or environment variable.
The versioned scan JSON stays unchanged. A separate small last-scan pointer
lets `scope add` find the scan and its actual scope-skipped names later.
"""

import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_HOSTS = 50
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})+")


def user_scope_path() -> Path:
    override = os.environ.get("EXPOSUREIQUSERSCOPE")
    if override:
        return Path(override).expanduser()
    config = os.environ.get("XDGCONFIGHOME") or os.environ.get("XDG_CONFIG_HOME")
    root = Path(config).expanduser() if config else Path.home() / ".config"
    return root / "exposureiq" / "scope.txt"


def responsibility(domain: str) -> str:
    return (f"I own {domain} or have written permission to test it and its subdomains. "
            "I understand ExposureIQ cannot verify this and I accept responsibility.")


def eligible_hosts(domain: str, hosts) -> list:
    """Strict name validation, same-domain boundary, no IPs, stable order."""
    if not isinstance(domain, str) or len(domain) > 253 or not _HOST.fullmatch(domain):
        raise ValueError("The target must be a normalized domain name.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("An IP address cannot authorize a domain.")
    selected, seen = [], set()
    for host in hosts:
        if not isinstance(host, str) or host != host.strip():
            continue
        name = host.lower().rstrip(".")
        if len(name) > 253 or not _HOST.fullmatch(name):
            continue
        if name != domain and not name.endswith("." + domain):
            continue
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            continue
        if name not in seen:
            selected.append(name)
            seen.add(name)
    return selected


def _outside_repository(path: Path, repo_scope: Path) -> None:
    resolved = path.resolve()
    if resolved.is_relative_to(repo_scope.parent.resolve()):
        raise ValueError("The user scope file must be outside the repository; repo scope.txt is never modified.")
    if path.is_symlink() or (path.exists() and repo_scope.exists() and path.samefile(repo_scope)):
        raise ValueError("The user scope file cannot be a link to another scope file.")


def append_hosts(domain: str, hosts: list, typed_domain: str) -> tuple:
    """Append at most 50 safe host names, only after an exact-domain confirmation."""
    from exposureiq.discovery import scope

    if typed_domain != domain:
        raise ValueError("Confirmation cancelled: the typed domain did not match exactly.")
    names = eligible_hosts(domain, hosts)[:MAX_HOSTS]
    path = user_scope_path()
    _outside_repository(path, scope.SCOPE_FILE)
    # Authorization cannot repair or bypass a broken repository scope gate.
    scope.SCOPE_FILE.read_text(encoding="utf-8-sig")
    try:
        existing = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        existing = ""
    entries = {line.split("#", 1)[0].strip().lower().rstrip(".") for line in existing.splitlines()}
    names = [name for name in names if name not in entries]
    if not names:
        return path, []
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    block = ("\n" if existing and not existing.endswith("\n") else "")
    block += f"# added {timestamp} for {domain} (confirmed by user)\n" + "\n".join(names) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as stream:
        stream.write(block)
    return path, names


def _last_scan_path(domain: str) -> Path:
    eligible_hosts(domain, [])  # Validate the filename before joining a path.
    return user_scope_path().parent / "last-scans" / f"{domain}.json"


def remember_scan(result: dict) -> None:
    """Remember a saved real scan, not a demo and never a --no-save scan."""
    from exposureiq.discovery import scope

    if result.get("demo") or not result.get("saved_to"):
        return
    domain = result["target"]
    path = _last_scan_path(domain)
    _outside_repository(path, scope.SCOPE_FILE)
    snapshot = result.get("snapshot", {})
    data = {key: result.get(key) for key in (
        "target", "names", "skipped_hosts", "skipped_ips", "skipped_scope_ips", "skipped_ipv6_ips",
        "host_states", "phase_counts", "phase_states", "phase_times", "elapsed",
    )}
    data["saved_to"] = str(Path(result["saved_to"]).resolve())
    data["scan_id"] = snapshot.get("scan_id")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Use a private unique file, not a predictable .tmp path that could be a
    # link to repo scope.txt. The pointer is separate from the scan format.
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{domain}-", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def last_scan(domain: str) -> dict:
    data = json.loads(_last_scan_path(domain).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("target") != domain or not isinstance(data.get("saved_to"), str):
        raise ValueError("The last-scan record does not match this domain.")
    return data
