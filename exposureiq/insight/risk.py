"""An exposure index, NOT a probability of compromise or a CVSS score.

Each recorded finding scores high=10, medium=3, low=1. A ports.*_exposed
finding adds 5, including low/medium sensitive-service rules. Total divided
by distinct discovered hosts is risk per host; zero hosts gives zero.
Missing/failed checks can lower the score, so absence is not proof of safety.
"""

from __future__ import annotations

import re

from exposureiq.ai.sanitize import host_name

WEIGHTS = {"high": 10, "medium": 3, "low": 1}
SENSITIVE_PORT_BONUS = 5
SENSITIVE_PORT_RULE = re.compile(r"^ports\.[a-z0-9_]+_exposed$")
RISK_FORMULA = "Risk = 10×high + 3×medium + low + 5×ports.*_exposed; per host = risk ÷ hosts."


def finding_score(finding: dict) -> int:
    severity = finding.get("severity")
    if severity not in WEIGHTS:
        raise ValueError("Finding severity must be high, medium or low.")
    return WEIGHTS[severity] + (
        SENSITIVE_PORT_BONUS if SENSITIVE_PORT_RULE.fullmatch(str(finding.get("rule", ""))) else 0)


def has_check_evidence(scan: dict) -> bool:
    """Conservative coverage inference without changing saved schema 0.2.

    No findings lists, or all-empty findings/technologies/ports, is passive or
    coverage-unknown. Do not turn that into evidence that issues were fixed.
    """
    assets = scan.get("assets", [])
    if scan.get("mode") == "passive" or not any("findings" in a for a in assets):
        return False
    return any(a.get("findings") or a.get("technologies") or
               any(ip.get("open_ports") for ip in a.get("ips", [])) for a in assets)


def risk_score(scan: dict) -> dict:
    if not isinstance(scan, dict) or not isinstance(scan.get("assets"), list):
        raise ValueError("Scan must have an assets list.")
    by_host = {}
    counts = dict.fromkeys(WEIGHTS, 0)
    sensitive = 0
    for asset in scan["assets"]:
        host = host_name(asset.get("host"))
        entry = by_host.setdefault(host, {"host": host, "ref": f"H:{host}", "score": 0,
                                           "high": 0, "medium": 0, "low": 0})
        for finding in asset.get("findings", []):
            score = finding_score(finding)
            severity = finding["severity"]
            entry["score"] += score
            entry[severity] += 1
            counts[severity] += 1
            sensitive += bool(SENSITIVE_PORT_RULE.fullmatch(str(finding.get("rule", ""))))
    total = sum(entry["score"] for entry in by_host.values())
    hosts = len(by_host)
    return {"score": total, "per_host": round(total / hosts, 6) if hosts else 0.0,
            "hosts": hosts, **counts, "sensitive_port_findings": sensitive,
            "by_host": sorted(by_host.values(), key=lambda item: (-item["score"], item["host"]))}
