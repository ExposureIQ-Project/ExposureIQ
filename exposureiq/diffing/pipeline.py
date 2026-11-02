"""Build the diff document used by the CLI and TUI (Stage 3).

This module joins the pure comparison (``compare.compare_scans``) with the
noise controls (``noise``) and the readable summary (``summary``). It reads
saved scans only in ``diff_domain``; ``build_diff`` works on dictionaries.

The result shape is:

    {
        "target": "example.com",
        "old": {"scan_id": ..., "started_at": ...},
        "new": {"scan_id": ..., "started_at": ...},
        "changes": [...],       # after ignore rules
        "ignored": [...],       # hidden by ignore.txt
        "notes": ["..."],
        "summary": {"headline": ..., "counts": ..., ...},
    }
"""

from __future__ import annotations

from pathlib import Path

from exposureiq import storage
from exposureiq.diffing import noise
from exposureiq.diffing.compare import change_key, compare_scans
from exposureiq.diffing.summary import summarize_diff


def _target(scan) -> str:
    if not isinstance(scan, dict):
        return ""
    value = scan.get("target")
    return value.strip().lower().rstrip(".") if isinstance(value, str) else ""


def _require_scan(scan, label: str) -> None:
    if not isinstance(scan, dict):
        raise ValueError(f"{label} scan must be a dictionary")
    if not _target(scan):
        raise ValueError(f"{label} scan must have a target")


def _same_target(old: dict, new: dict) -> None:
    old_target, new_target = _target(old), _target(new)
    if old_target != new_target:
        raise ValueError(
            f"Targets differ: {old_target or '?'} and {new_target or '?'}. "
            "Only scans of the same target can be compared."
        )


def _apply_confirmed_removals(changes: list[dict], before_old: dict, old: dict,
                              new: dict) -> list[dict]:
    """Replace unconfirmed removals with copies marked ``confirmed``.

    A removal is only confirmed when the thing was present in ``before_old``,
    missing in ``old``, and still missing in ``new``. Everything else keeps the
    honest ``missing`` status, which the UI words as "not seen this time".
    """
    confirmed = noise.confirmed_removals(before_old, old, new)
    if not confirmed:
        return changes
    confirmed_keys = {change_key(change) for change in confirmed}
    kept = [change for change in changes if change_key(change) not in confirmed_keys]
    kept.extend(confirmed)
    return kept


def build_diff(old_scan: dict, new_scan: dict, before_old: dict | None = None,
               rules: list[dict] | None = None) -> dict:
    """Compare two validated scans and return the complete diff document.

    ``before_old`` is the scan before ``old_scan`` when one is available; it is
    used only to confirm that a removal stayed gone. ``rules=None`` loads
    ``ignore.txt``; pass ``[]`` to disable ignore rules (useful in tests).
    """
    _require_scan(old_scan, "Old")
    _require_scan(new_scan, "New")
    _same_target(old_scan, new_scan)
    if before_old is not None:
        _require_scan(before_old, "Previous")
        _same_target(before_old, old_scan)

    result = compare_scans(old_scan, new_scan)
    changes = result["changes"]
    if before_old is not None:
        changes = _apply_confirmed_removals(changes, before_old, old_scan, new_scan)

    ignore_rules = noise.load_ignore_rules() if rules is None else rules
    kept, ignored = noise.apply_ignore_rules(changes, ignore_rules)

    notes = []
    unconfirmed = sum(1 for change in kept if change.get("status") == "missing")
    if unconfirmed:
        notes.append(
            f"{unconfirmed} removal(s) are not seen this time; a later scan "
            "confirms whether they are really gone."
        )
    if ignored:
        notes.append(f"{len(ignored)} change(s) hidden by ignore rules.")

    diff = {
        "target": result["target"],
        "old": result["old"],
        "new": result["new"],
        "changes": kept,
        "ignored": ignored,
        "notes": notes,
    }
    diff["summary"] = summarize_diff(diff)
    return diff


def find_domain_scans(domain: str, results_dir: str | Path = "results") -> list[dict]:
    """Return saved scans for ``domain``, oldest first, with their paths.

    Unreadable or invalid files are skipped. A file for another target is
    ignored. Each entry is ``{"path": str, "scan": dict}``.
    """
    from exposureiq.discovery.subdomains import normalize_domain

    wanted = normalize_domain(domain)
    found = []
    try:
        paths = sorted(Path(results_dir).glob("*.json"))
    except OSError:
        return []

    for path in paths:
        try:
            scan = storage.load_scan(str(path))
        except (OSError, ValueError):
            continue
        if _target(scan) != wanted:
            continue
        found.append({"path": str(path), "scan": scan})

    found.sort(key=lambda entry: (
        str(entry["scan"].get("started_at") or ""),
        str(entry["scan"].get("scan_id") or ""),
        entry["path"],
    ))
    return found


def diff_domain(domain: str, results_dir: str | Path = "results") -> dict:
    """Compare the two newest saved scans for ``domain``.

    When a third older scan exists it is used to confirm removals. Raises
    ``ValueError`` if fewer than two readable scans exist for the domain.
    """
    from exposureiq.discovery.subdomains import normalize_domain

    wanted = normalize_domain(domain)
    scans = find_domain_scans(wanted, results_dir)
    if len(scans) < 2:
        raise ValueError(
            f"Need at least two saved scans for {wanted} in {results_dir}."
        )

    before_old = scans[-3]["scan"] if len(scans) >= 3 else None
    return build_diff(scans[-2]["scan"], scans[-1]["scan"], before_old=before_old)
