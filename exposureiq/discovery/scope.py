import ipaddress
from pathlib import Path


SCOPE_FILE = Path(__file__).resolve().parents[2] / "scope.txt"


def is_in_scope(target: str) -> bool:
    """Return True only for localhost or an explicitly authorized target."""
    if not isinstance(target, str) or not target.strip():
        return False

    target = target.strip().rstrip(".").lower()

    # Localhost is always permitted for safe local testing.
    if target == "localhost":
        return True

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None

    if address is not None and address.is_loopback:
        return True

    try:
        # utf-8-sig also accepts a file saved with a hidden BOM mark (common on Windows).
        entries = SCOPE_FILE.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return False

    for line in entries:
        entry = line.split("#", 1)[0].strip().lower().rstrip(".")
        if not entry:
            continue

        # Explicit hostname or exact IP match.
        if target == entry:
            return True

        # An explicitly authorized IP range can include a target IP.
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue

        if address is not None and address in network:
            return True

    return False
