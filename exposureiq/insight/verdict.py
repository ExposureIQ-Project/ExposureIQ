"""Code-owned trend labels with deliberately simple, named thresholds.

A meaningful risk-per-host delta is >= max(0.5, 10% of the baseline).
Use both first→last and previous→last. Opposing movement or opposing finding
changes is mixed. Finding diffs (not added passive hosts) can prevent stable.
At least two scans with check evidence are required. This is an observation,
not proof of remediation, coverage, or future safety.
"""

from __future__ import annotations

from exposureiq.diffing.pipeline import build_diff, scan_order
from exposureiq.insight.risk import has_check_evidence, risk_score

MIN_COMPARISON_SCANS = 2
ABSOLUTE_THRESHOLD = 0.5
RELATIVE_THRESHOLD = 0.10
DIFF_CHANGE_THRESHOLD = 1
VERDICTS = ("improving", "worse", "stable", "mixed", "not_enough_data")


def movement(before: float, after: float) -> int:
    threshold = max(ABSOLUTE_THRESHOLD, abs(before) * RELATIVE_THRESHOLD)
    delta = after - before
    if abs(delta) + 1e-9 < threshold:
        return 0
    return 1 if delta > 0 else -1


def history_verdict(scans: list[dict], diff: dict | None = None) -> dict:
    checked = sorted((s for s in scans if has_check_evidence(s)), key=scan_order)
    result = {"ref": "V:history", "value": "not_enough_data", "compared": len(checked),
              "first": None, "previous": None, "last": None, "better": 0, "worse": 0}
    if len(checked) < MIN_COMPARISON_SCANS:
        return result
    first, previous, last = (risk_score(checked[i])["per_host"] for i in (0, -2, -1))
    diff = diff if diff is not None else build_diff(checked[-2], checked[-1], rules=[])
    changes = [c for c in diff.get("changes", []) if c.get("kind", "").startswith("finding.")]
    better = sum(c.get("direction") == "better" for c in changes)
    worse = sum(c.get("direction") == "worse" for c in changes)
    net, recent = movement(first, last), movement(previous, last)
    if (net < 0 and recent <= 0 and worse < DIFF_CHANGE_THRESHOLD):
        value = "improving"
    elif net > 0 and recent >= 0 and better < DIFF_CHANGE_THRESHOLD:
        value = "worse"
    elif net == recent == 0 and better == worse == 0:
        value = "stable"
    else:
        value = "mixed"
    result.update(value=value, first=first, previous=previous, last=last, better=better, worse=worse)
    return result
