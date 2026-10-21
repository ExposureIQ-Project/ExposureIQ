import ipaddress
import logging
from pathlib import Path

from exposureiq.tui.user_scope import user_scope_path

logger = logging.getLogger(__name__)

SCOPE_FILE = Path(__file__).resolve().parents[2] / "scope.txt"


def _is_domain_entry(entry: str) -> bool:
    """True for a plain domain such as example.com, never an IP or wildcard."""
    try:
        ipaddress.ip_address(entry)
    except ValueError:
        pass
    else:
        return False  # An IP entry must not authorize a name that merely ends in it.
    labels = entry.split(".")
    if len(labels) < 2:
        return False
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def is_in_scope(target: str) -> bool:
    """True for localhost or an authorized target; a domain covers its subdomains."""
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
    except (OSError, UnicodeError):
        return False

    try:
        entries += user_scope_path().read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        pass  # A missing user file adds no authorization.
    except (OSError, UnicodeError):
        logger.warning("User scope file is unreadable (%s); ignoring its entries", user_scope_path())

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
            network = None

        if address is not None and network is not None and address in network:
            return True

        # A domain entry also authorizes its subdomains. The dot boundary keeps
        # notexample.com and example.com.evil.net out; exact IP/CIDR rules stay
        # unchanged, and raw IP targets never gain authorization this way.
        if address is None and _is_domain_entry(entry) and target.endswith("." + entry):
            return True

    return False
