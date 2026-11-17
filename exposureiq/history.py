"""Read-only domain history shared by insight, TUI and the local web viewer.

The existing diff pipeline remains the owner of comparison semantics. This
module adds confined file discovery and code-derived domain browsing facts.
"""

from __future__ import annotations

from pathlib import Path

from exposureiq import storage
from exposureiq.ai.sanitize import host_name
from exposureiq.diffing.pipeline import history_group, scan_key, scan_order
from exposureiq.paths import saved_json_paths


def confined_scan_path(name: str | Path, results_dir: str | Path = "results") -> Path:
    """Only JSON files under this results root; reject traversal and symlinks."""
    root = Path(results_dir).resolve()
    candidate = Path(name)
    if ".." in candidate.parts:
        raise ValueError("Scan paths must stay under the results folder.")
    if not candidate.is_absolute():
        # Accept results/domain/file.json as well as domain/file.json.
        direct = candidate.absolute()
        candidate = direct if direct.is_relative_to(root) else root / candidate
    try:
        relative = candidate.absolute().relative_to(root)
    except ValueError:
        raise ValueError("Scan paths must stay under the results folder.") from None
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlink scan paths are not allowed.")
    if candidate.suffix.lower() != ".json" or not candidate.resolve().is_relative_to(root):
        raise ValueError("Select a JSON scan under the results folder.")
    return candidate.resolve()


def saved_entries(results_dir="results", *, include_demo: bool = False) -> list[dict]:
    """Skip invalid files and demo_ files by default. Never walk arbitrary trees."""
    from exposureiq.discovery.subdomains import normalize_domain

    found = []
    for path in saved_json_paths(results_dir):
        if path.name.lower().startswith("demo_") and not include_demo:
            continue
        try:
            safe = confined_scan_path(path, results_dir)
            scan = storage.load_scan(str(safe))
            target = normalize_domain(scan["target"])
        except (OSError, ValueError):
            continue
        if history_group(scan) != "real" and not include_demo:
            continue
        found.append({"path": str(safe), "scan": scan, "target": target})
    return sorted(found, key=lambda entry: (*scan_order(entry["scan"]), entry["path"]))


def domain_history(domain: str, results_dir="results", *, include_demo: bool = False) -> list[dict]:
    from exposureiq.discovery.subdomains import normalize_domain

    wanted = normalize_domain(domain)
    entries = [entry for entry in saved_entries(results_dir, include_demo=include_demo)
               if entry["target"] == wanted]
    if not entries:
        return []
    # A demo presentation must never pollute a real domain trend.
    group = history_group(entries[-1]["scan"])
    unique = {scan_key(e["scan"]): e for e in entries if history_group(e["scan"]) == group}
    return sorted(unique.values(), key=lambda entry: scan_order(entry["scan"]))


def trend_arrow(verdict: str) -> str:
    return {"improving": "↓", "worse": "↑", "stable": "→", "mixed": "↕",
            "not_enough_data": "·"}.get(verdict, "·")


def sparkline(values: list[float], width: int = 48) -> str:
    if not values:
        return "No comparison data"
    if len(values) > width:
        values = [values[round(i * (len(values) - 1) / (width - 1))] for i in range(width)]
    low, high = min(values), max(values)
    blocks = "▁▂▃▄▅▆▇█"
    return "".join(blocks[round((v - low) / (high - low) * 7)] if high > low else blocks[0]
                   for v in values)


def list_domains(results_dir="results", *, include_demo: bool = True) -> list[dict]:
    from exposureiq.insight.risk import has_check_evidence, risk_score
    from exposureiq.insight.verdict import history_verdict

    entries = saved_entries(results_dir, include_demo=include_demo)
    domains = {}
    for entry in entries:
        domains.setdefault(entry["target"], []).append(entry)
    result = []
    for domain, items in domains.items():
        latest = items[-1]["scan"]
        comparable = [e["scan"] for e in items if history_group(e["scan"]) == history_group(latest)]
        verdict = history_verdict(comparable)
        risk = risk_score(latest)
        result.append({"domain": host_name(domain), "scans": len(items), "last_date": latest["started_at"],
                       "latest": {k: risk[k] for k in ("high", "medium", "low", "score", "per_host", "hosts")},
                       "verdict": verdict["value"], "arrow": trend_arrow(verdict["value"]),
                       "sparkline": sparkline([risk_score(s)["per_host"] for s in comparable
                                               if has_check_evidence(s)]),
                       "demo": history_group(latest) != "real"})
    return sorted(result, key=lambda item: item["domain"])
