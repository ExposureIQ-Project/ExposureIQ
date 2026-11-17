"""L1 scans → L2 adjacent diffs → L3 timeline → L4 bounded domain digest.

All finding identity uses host/rule/IP/port, never renumbered finding IDs.
Two subsequent observed-host absences are required for fixed/regression.
Default persistence/recent window N=3. Passive/unknown scans are excluded
from finding comparisons. More than 50 scans use weekly end-point buckets;
very long weekly timelines merge older ranges, retaining the whole span.
"""

from __future__ import annotations

import math
import copy
from datetime import datetime, timedelta

from exposureiq.ai.sanitize import compact_json, host_name, label, text
from exposureiq.diffing.pipeline import build_diff, scan_order
from exposureiq.insight.cache import cached_scan_digest
from exposureiq.insight.digest import scan_digest
from exposureiq.insight.risk import WEIGHTS, has_check_evidence, risk_score
from exposureiq.insight.verdict import history_verdict

HISTORY_MAX_CHARS = 12000
PERSISTENCE_WINDOW = 3
FIX_CONFIRMATION_SCANS = 2
WEEKLY_AFTER = 50
MAX_WEEK_BUCKETS = 40


def finding_identity(host: str, finding: dict) -> tuple:
    return host_name(host), finding.get("rule", ""), finding.get("ip", ""), finding.get("port", 0)


def _observations(scan: dict) -> dict:
    return {finding_identity(asset["host"], finding): {"host": host_name(asset["host"]),
            "rule": label(finding["rule"], 80), "severity": finding["severity"],
            "id": finding["id"]} for asset in scan["assets"] for finding in asset.get("findings", [])}


def finding_lists(scans: list[dict], window: int = PERSISTENCE_WINDOW) -> dict:
    if isinstance(window, bool) or not isinstance(window, int) or window < 2:
        raise ValueError("History window must be at least two scans.")
    scans = [s for s in scans if has_check_evidence(s)]
    empty = {k: [] for k in ("still_unfixed", "fixed", "new_recently", "regressions")}
    if not scans:
        return empty
    observations = [_observations(s) for s in scans]
    hosts = [{host_name(a["host"]) for a in s["assets"] if "findings" in a} for s in scans]
    all_keys = set().union(*(set(o) for o in observations))
    last = observations[-1]
    start_recent = max(0, len(scans) - window)
    for key in sorted(all_keys):
        present = [key in o for o in observations]
        first_seen = present.index(True)
        latest_seen = max(i for i, p in enumerate(present) if p)
        evidence = observations[latest_seen][key]
        item = {"ref": f"I:{len(empty['still_unfixed']) + len(empty['fixed']) + len(empty['new_recently']) + len(empty['regressions']) + 1}",
                **evidence}
        if len(scans) >= 2 and key in last and all(present[-min(window, len(scans)):]):
            empty["still_unfixed"].append(item)
        # Missing hosts/unknown check coverage cannot confirm a fix.
        absent_run, was_fixed, returned = 0, False, False
        for i in range(first_seen + 1, len(scans)):
            if present[i]:
                returned = returned or was_fixed
                absent_run = 0
            elif key[0] in hosts[i]:
                absent_run += 1
                was_fixed = was_fixed or absent_run >= FIX_CONFIRMATION_SCANS
            else:
                absent_run = 0
        if key not in last and absent_run >= FIX_CONFIRMATION_SCANS:
            empty["fixed"].append(item)
        if returned and key in last:
            empty["regressions"].append(item)
        elif first_seen >= start_recent and key in last:
            empty["new_recently"].append(item)
    for kind, items in empty.items():
        items.sort(key=lambda i: (-WEIGHTS[i["severity"]], i["host"], i["rule"]))
        for index, item in enumerate(items, 1):
            # Distinct references even when one issue appears in two lists.
            items[index - 1] = {**item, "ref": f"L:{kind}:{index}"}
    return empty


def _event(change: dict, pair: int, index: int) -> dict:
    payload = change.get("after") or change.get("before") or {}
    result = {"ref": f"E:{pair}:{index}", "kind": change["kind"],
              "direction": change["direction"], "host": host_name(change.get("host"))}
    for key in ("rule", "severity", "id"):
        if payload.get(key):
            result[key] = label(payload[key], 80)
    if change.get("port"):
        result["port"] = change["port"]
    return result


def _event_weight(event: dict) -> tuple:
    return (-WEIGHTS.get(event.get("severity"), 0),
            0 if event.get("direction") == "worse" else 1, event["kind"], event["host"])


def pair_digest(old: dict, new: dict, pair: int, before_old: dict | None = None) -> dict:
    diff = build_diff(old, new, before_old=before_old, rules=[])
    events = [_event(change, pair, index) for index, change in enumerate(diff["changes"], 1)]
    return {"ref": f"D:{pair}", "from": text(old["started_at"], 10), "to": text(new["started_at"], 10),
            "better": diff["summary"]["counts"]["better"], "worse": diff["summary"]["counts"]["worse"],
            "neutral": diff["summary"]["counts"]["neutral"],
            "events": sorted(events, key=_event_weight)[:5]}


def _timeline(scans: list[dict]) -> list[list]:
    rows = []
    for scan in scans:
        r = risk_score(scan)
        rows.append([text(scan["started_at"], 10), round(r["per_host"], 3),
                     r["high"], r["medium"], r["low"], r["hosts"]])
    return rows


def _thin_timeline(rows: list[list], notes: list[str]) -> list[list]:
    if len(rows) <= WEEKLY_AFTER:
        return rows
    buckets = {}
    for row in rows:
        try:
            date = datetime.fromisoformat(row[0])
            week = (date - timedelta(days=date.weekday())).date().isoformat()
        except ValueError:
            week = row[0]
        buckets.setdefault(week, []).append(row)
    grouped = list(buckets.values())
    if len(grouped) > MAX_WEEK_BUCKETS:
        size = math.ceil(len(grouped) / MAX_WEEK_BUCKETS)
        grouped = [[row for group in grouped[i:i + size] for row in group]
                   for i in range(0, len(grouped), size)]
        notes.append("Older weekly buckets merged; all date ranges retained.")
    notes.append("Weekly buckets show last observed risk/counts and included scan count, not every scan.")
    return [[bucket[0][0] + "/" + bucket[-1][0], *bucket[-1][1:], len(bucket)] for bucket in grouped]


def build_history_layers(scans: list[dict], *, digests: list[dict] | None = None,
                         window: int = PERSISTENCE_WINDOW) -> dict:
    if not scans:
        raise ValueError("No compatible saved scans for this domain.")
    scans = sorted(scans, key=scan_order)
    targets = {host_name(s.get("target")) for s in scans}
    if len(targets) != 1:
        raise ValueError("History scans must belong to one domain.")
    l1 = digests if digests is not None else [scan_digest(s) for s in scans]
    checked = [s for s in scans if has_check_evidence(s)]
    l2 = [pair_digest(checked[i - 1], checked[i], i,
                      checked[i - 2] if i >= 2 else None) for i in range(1, len(checked))]
    l3 = _timeline(scans)
    notes = ["Demo files excluded unless explicitly showing an offline demo history.",
             "Fixed means absent in subsequent observed scans, not a live verification."]
    skipped = len(scans) - len(checked)
    if skipped:
        notes.append(f"Skipped {skipped} passive-only or coverage-unknown scans for finding comparisons.")
    lists = finding_lists(checked, window)
    earlier = l2[:-5]
    older_events = [event for pair in earlier for event in pair["events"]]
    l4 = {"ref": "S:history", "header": {"domain": next(iter(targets)), "scans": len(scans),
            "compared": len(checked), "window": window, "first": l3[0][0], "last": l3[-1][0]},
          "timeline_columns": ["date", "risk_per_host", "high", "medium", "low", "hosts", "bucket_scans"],
          "timeline": _thin_timeline(l3, notes), "verdict": history_verdict(checked),
          "latest": copy.deepcopy(l1[-1]), "transitions": copy.deepcopy(l2[-5:]),
          "older": {"ref": "D:older", "pairs": len(earlier),
                    "better": sum(p["better"] for p in earlier), "worse": sum(p["worse"] for p in earlier),
                    "neutral": sum(p["neutral"] for p in earlier),
                    "events": sorted(older_events, key=_event_weight)[:5]},
          **{key: value[:6] for key, value in lists.items()},
          "list_counts": {key: len(value) for key, value in lists.items()},
          "lists_truncated": any(len(value) > 6 for value in lists.values()),
          "notes": notes, "hostile_text_seen": any(d["hostile_text_seen"] for d in l1)}
    # Only lists can grow without bound. Latest digest and the final five
    # transitions remain complete at their explicitly bounded top-five level.
    while len(compact_json(l4)) > HISTORY_MAX_CHARS:
        key = max(lists, key=lambda k: len(compact_json(l4[k])))
        if l4[key]:
            l4[key].pop()
            l4["lists_truncated"] = True
        elif l4["older"]["events"]:
            l4["older"]["events"].pop()
        elif len(l4["timeline"]) > 1:
            rows = l4["timeline"]
            l4["timeline"] = [[rows[i][0].split("/")[0] + "/" + rows[min(i + 1, len(rows) - 1)][0].split("/")[-1],
                                *rows[min(i + 1, len(rows) - 1)][1:6],
                                sum(r[6] if len(r) > 6 else 1 for r in rows[i:i + 2])]
                               for i in range(0, len(rows), 2)]
            note = "Timeline ranges merged to meet the hard budget; whole date span retained."
            if note not in notes:
                notes.append(note)
        else:
            # Host/rule labels are bounded. An unusual all-long-label history
            # still retains counts and honestly advertises shortened events.
            candidate = max(l4["transitions"], key=lambda p: len(compact_json(p)), default=None)
            if not candidate or not candidate["events"]:
                raise ValueError("History exceeds the hard digest budget.")
            candidate["events"].pop()
            note = "Long-label transitions shortened to counts and selected events for the hard budget."
            if note not in notes:
                notes.append(note)
    return {"L1": l1, "L2": l2, "L3": l3, "L4": l4, "lists": lists}


def history_digest(domain: str, results_dir="results", *, include_demo: bool = False) -> dict:
    from exposureiq.history import domain_history

    entries = domain_history(domain, results_dir, include_demo=include_demo)
    if not entries:
        raise ValueError("No compatible saved scans for this domain.")
    layers = build_history_layers([e["scan"] for e in entries],
                                  digests=[cached_scan_digest(e["path"]) for e in entries])
    return layers["L4"]


def history_facts(digest: dict) -> dict:
    """A labelled code-only projection, so AI cannot hide history sections."""
    if digest.get("ref") != "S:history":
        return {}
    pairs = [digest["older"], *digest["transitions"]]
    result = {direction: {"count": sum(pair[direction] for pair in pairs),
                         "events": [copy.deepcopy(event) for pair in pairs for event in pair["events"]
                                    if event["direction"] == direction][:5]}
              for direction in ("better", "worse")}
    result.update({key: copy.deepcopy(digest[key]) for key in
                   ("still_unfixed", "regressions", "fixed", "new_recently")})
    result.update(list_counts=copy.deepcopy(digest["list_counts"]), notes=list(digest["notes"]),
                  truncated=digest["lists_truncated"] or any(result[d]["count"] > len(result[d]["events"])
                                                            for d in ("better", "worse")))
    return result
