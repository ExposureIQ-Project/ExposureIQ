"""Noise control (Stage 3, Hassan).

Pure data work, no network. Two jobs:
  1. Ignore rules: hide harmless changes (for example a CDN rotating its IPs)
     using the rules written in ignore.txt.
  2. Removal confirmation: something missing in one scan is only "gone" when
     it is also missing in the next scan.
"""

import logging
from fnmatch import fnmatchcase
from pathlib import Path

try:
    from exposureiq.diffing.compare import compare_scans, present_in
except ModuleNotFoundError as exc:
    # Marwan's compare.py is not merged yet: tests replace these two names.
    # Once it is merged this block can become a plain import.
    if exc.name not in ("exposureiq.diffing", "exposureiq.diffing.compare"):
        raise
    compare_scans = present_in = None

logger = logging.getLogger(__name__)

# Same way scope.py finds scope.txt: the project root.
IGNORE_FILE = Path(__file__).resolve().parents[2] / "ignore.txt"

KINDS = (
    "host.new", "host.removed", "ip.new", "ip.removed",
    "port.opened", "port.closed", "port.service_changed",
    "tech.new", "tech.removed", "tech.version_changed",
    "finding.new", "finding.resolved", "finding.severity_changed",
)
REMOVAL_KINDS = frozenset({
    "host.removed", "ip.removed", "port.closed", "tech.removed", "finding.resolved",
})


def load_ignore_rules(path: str | None = None) -> list[dict]:
    """Read ignore.txt (or `path`) and return [{"kind": ..., "host": ...}].

    A missing file gives []. A bad line is skipped with a warning.
    """
    file = Path(path) if path is not None else IGNORE_FILE
    try:
        # utf-8-sig also accepts a file saved with a hidden BOM mark (Windows).
        text = file.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError) as exc:
        logger.warning("Ignore file %s is unreadable (%s); no rules loaded", file, exc)
        return []

    rules = []
    for number, line in enumerate(text.splitlines(), start=1):
        content = line.split("#", 1)[0].strip()  # "#" starts a comment
        if not content:
            continue
        parts = content.split()
        if len(parts) != 2:
            logger.warning(
                "Ignore file %s line %d skipped: expected '<kind pattern> <host pattern>', got %r",
                file, number, content)
            continue
        kind, host = parts
        if not any(fnmatchcase(known, kind.lower()) for known in KINDS):
            # Kept, but a typo here would silently ignore nothing, so say so.
            logger.warning(
                "Ignore file %s line %d: kind pattern %r matches no known kind", file, number, kind)
        rules.append({"kind": kind, "host": host})
    return rules


def apply_ignore_rules(changes: list[dict], rules: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split `changes` into (kept, ignored). Nothing is changed or lost.

    A change is ignored when some rule matches both its kind and its host.
    Matching ignores letter case. Both lists keep the original order.
    """
    # fnmatchcase + lower() gives the same result on Windows and Linux
    # (plain fnmatch changes case and slashes depending on the system).
    patterns = [
        (rule["kind"].lower(), rule["host"].lower())
        for rule in rules or []
        if isinstance(rule, dict)
        and isinstance(rule.get("kind"), str) and isinstance(rule.get("host"), str)
    ]

    kept, ignored = [], []
    for change in changes:
        if patterns and isinstance(change, dict):
            kind = str(change.get("kind", "")).lower()
            host = str(change.get("host", "")).lower()
            if any(fnmatchcase(kind, k) and fnmatchcase(host, h) for k, h in patterns):
                ignored.append(change)
                continue
        kept.append(change)
    return kept, ignored


def confirmed_removals(before_old: dict, old: dict, new: dict) -> list[dict]:
    """Removals present in before_old, missing in old, and still missing in new.

    The three scans are oldest first. Each result is a copy of the removal
    change with "status": "confirmed".
    """
    if compare_scans is None or present_in is None:
        raise RuntimeError("exposureiq.diffing.compare is not available yet")

    result = compare_scans(before_old, old)
    candidates = result["changes"] if isinstance(result, dict) else result

    confirmed = []
    for change in candidates:
        if change.get("kind") not in REMOVAL_KINDS:
            continue
        if present_in(new, change):
            continue  # it came back, so it was not really gone
        confirmed.append({**change, "status": "confirmed"})
    return confirmed
