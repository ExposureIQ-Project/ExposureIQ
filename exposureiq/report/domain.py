"""Build an offline domain dashboard without altering any saved snapshot."""

from exposureiq.diffing import pipeline
from exposureiq.report.model import build_report

GROUP_LABELS = {
    "real": "Real scans",
    "demo-history": "Ten-scan demo story",
    "demo": "One-off demo scans",
}


def build_domain_report(scan: dict, scans: list[dict], selected_report: dict, *,
                        include_diff: bool = True) -> dict:
    """Home includes every scan; each detail view uses only its own predecessors.

    Explicit comparison options apply to the selected detail view. Home charts
    and timelines retain the complete, separately grouped domain history.
    """
    ordered = pipeline.domain_scans(scan, scans)
    rules = pipeline.noise.load_ignore_rules() if include_diff else []
    reports, groups = [], {}
    for item in ordered:
        history = pipeline.scan_history(item, ordered)
        diff = pipeline.build_history_diff(item, history, rules=rules) if include_diff else None
        report = build_report(item, diff=diff, history=history,
                              title=selected_report["title"],
                              generated_at=selected_report["generated_at"],
                              comparison_enabled=include_diff)
        report["tool_version"] = selected_report["tool_version"]
        group = pipeline.history_group(item)
        groups[group] = {"key": group, "label": GROUP_LABELS[group], "report": report}
        if pipeline.scan_key(item) == pipeline.scan_key(scan):
            report = {**selected_report, "comparison_enabled": include_diff}
        reports.append(report)
    return {
        "target": selected_report["target"],
        "selected_scan_id": selected_report["scan_id"],
        "generated_label": selected_report["generated_label"],
        "reports": reports,
        "groups": list(groups.values()),
    }
