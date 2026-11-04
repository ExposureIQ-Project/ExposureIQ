"""Build the diff document used by the CLI and TUI (Stage 3).

This module joins the pure comparison (``compare.compare_scans``) with the
noise controls (``noise``) and the readable summary (``summary``). It reads
saved scans in the history helpers; the comparison builders work on dictionaries.

The result shape is:

    {
        "target": "example.com",
        "old": {"scan_id": ..., "started_at": ...},
        "new": {"scan_id": ..., "started_at": ...},
        "changes": [...],       # after ignore rules
        "ignored": [...],       # hidden by ignore.txt
        "notes": ["..."],
        "summary": {"headline": ..., "counts": ..., ...},
        "history": [...],       # adjacent comparisons, in history mode only
    }
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from exposureiq import storage
from exposureiq.diffing import noise
from exposureiq.diffing.compare import change_key, compare_scans
from exposureiq.diffing.summary import summarize_diff
from exposureiq.paths import saved_json_paths


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


def scan_key(scan: dict) -> tuple[str, str]:
    """The saved snapshot identity, independent of its filename."""
    return (str(scan.get("scan_id") or ""), str(scan.get("started_at") or ""))


def scan_order(scan: dict) -> tuple[str, str]:
    """Order by the saved UTC time, then scan ID to break same-time ties."""
    stamp = str(scan.get("started_at") or "")
    try:
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        stamp = moment.astimezone(timezone.utc).isoformat()
    except ValueError:
        pass  # Older schemas accept non-empty timestamps; keep them readable.
    return stamp, str(scan.get("scan_id") or "")


def is_demo(scan: dict) -> bool:
    return str(scan.get("scan_id") or "").startswith("DEMO-")


def history_group(scan: dict) -> str:
    """Keep real scans, one-off demos, and the ten-part story separate."""
    # The ten-part story is separate from unrelated one-off --demo samples.
    if str(scan.get("scan_id") or "").startswith("DEMO-HISTORY-"):
        return "demo-history"
    return "demo" if is_demo(scan) else "real"


def scan_history(scan: dict, history: list[dict] | None = None) -> list[dict]:
    """Same-target snapshots through ``scan``, sorted and deduplicated.

    Never include future snapshots, real/demo mixtures, or a second copy of the
    selected scan. The caller's selected data wins over a duplicate on disk.
    """
    _require_scan(scan, "Selected")
    selected_order = scan_order(scan)
    unique = {
        scan_key(item): item for item in (history or [])
        if isinstance(item, dict) and _target(item) == _target(scan)
        and history_group(item) == history_group(scan)
        and scan_order(item) <= selected_order
    }
    unique[scan_key(scan)] = scan
    return sorted(unique.values(), key=scan_order)


def find_scan_history(scan: dict, results_dir: str | Path = "results") -> list[dict]:
    """Load compatible saved history, stopping at the selected snapshot."""
    entries = find_domain_scans(_target(scan), results_dir)
    return scan_history(scan, [entry["scan"] for entry in entries])


def domain_scans(scan: dict, scans: list[dict] | None = None) -> list[dict]:
    """All distinct snapshots for a domain, including later scans for its home page."""
    _require_scan(scan, "Selected")
    unique = {scan_key(item): item for item in (scans or [])
              if isinstance(item, dict) and _target(item) == _target(scan)}
    unique[scan_key(scan)] = scan
    return sorted(unique.values(), key=scan_order)


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
    return _diff_document(result, changes, ignore_rules)


def _diff_document(result: dict, changes: list[dict], ignore_rules: list[dict]) -> dict:
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


def build_history_diff(scan: dict, history: list[dict] | None = None, *,
                       baseline: dict | None = None,
                       rules: list[dict] | None = None) -> dict | None:
    """Baseline-to-selected change plus every adjacent scan comparison.

    Overall counts describe the net change, not the sum of repeated events.
    ``history`` preserves regressions that appeared and were later fixed. A net
    removal is confirmed only when absent in the final two included snapshots.
    An explicit ``baseline`` limits the comparison window to that older scan.
    """
    ordered = scan_history(scan, history)
    if baseline is not None:
        _require_scan(baseline, "Baseline")
        _same_target(baseline, scan)
        if history_group(baseline) != history_group(scan):
            raise ValueError("Demo and real scans, or unrelated demos, cannot be compared.")
        if scan_order(baseline) >= scan_order(scan):
            raise ValueError("The comparison baseline must be an earlier scan.")
        ordered = scan_history(scan, [*ordered, baseline])
        ordered = [item for item in ordered if scan_order(item) >= scan_order(baseline)]
        # Keep the explicit file's evidence if another copy shares its identity.
        ordered[0] = baseline
    if len(ordered) < 2:
        return None

    ignore_rules = noise.load_ignore_rules() if rules is None else rules
    net = compare_scans(ordered[0], scan)
    changes = net["changes"]
    if len(ordered) >= 3:
        previous = compare_scans(ordered[0], ordered[-2])
        missing_keys = {change_key(change) for change in previous["changes"]
                        if change.get("kind") in noise.REMOVAL_KINDS}
        changes = [{**change, "status": "confirmed"}
                   if change.get("kind") in noise.REMOVAL_KINDS
                   and change_key(change) in missing_keys else change
                   for change in changes]
    diff = _diff_document(net, changes, ignore_rules)
    diff["history"] = [
        build_diff(ordered[index - 1], ordered[index],
                   before_old=ordered[index - 2] if index >= 2 else None,
                   rules=ignore_rules)
        for index in range(1, len(ordered))
    ]
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
        paths = saved_json_paths(results_dir, wanted)
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

    found.sort(key=lambda entry: (*scan_order(entry["scan"]), entry["path"]))
    return found


def diff_domain(domain: str, results_dir: str | Path = "results") -> dict:
    """Compare the earliest compatible scan through the newest for ``domain``.

    Include every intermediate comparison. Raises ``ValueError`` if fewer than
    two distinct, compatible snapshots exist (demo data stays separate).
    """
    from exposureiq.discovery.subdomains import normalize_domain

    wanted = normalize_domain(domain)
    scans = find_domain_scans(wanted, results_dir)
    diff = build_history_diff(scans[-1]["scan"], [entry["scan"] for entry in scans]) if scans else None
    if diff is None:
        raise ValueError(
            f"Need at least two saved scans for {wanted} in {results_dir}."
        )
    return diff
