"""Compact normalized facts. No raw banners, headers, details or recommendations.

Budget: at most 2,400 JSON characters (estimated 600 tokens). Lower-priority
groups are omitted with explicit counts; the full saved scan is not modified.
Finding IDs are per scan, not stable identifiers across a domain's history.
"""

from __future__ import annotations

import re

from exposureiq.ai.sanitize import compact_json, hostile_seen, host_name, label, text
from exposureiq.insight.risk import WEIGHTS, has_check_evidence, risk_score

SCAN_MAX_CHARS = 2400
RULE_PATTERN = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$")
ID_PATTERN = re.compile(r"^F-\d{4,}$")


def rule_title(rule: str) -> str:
    # Code-owned metadata, never a model instruction hidden in a saved title.
    from exposureiq.fingerprint.severity import RULES

    return label(RULES.get(rule, {}).get("title") or rule.replace(".", ": ").replace("_", " "), 64)


def scan_digest(scan: dict) -> dict:
    if not isinstance(scan, dict) or not isinstance(scan.get("assets"), list):
        raise ValueError("Scan must have an assets list.")
    risk = risk_score(scan)
    rules, technologies, ports, ips = {}, {}, {}, set()
    invalid = 0
    for asset in scan["assets"]:
        host = host_name(asset.get("host"))
        for finding in asset.get("findings", []):
            rule, fid = str(finding.get("rule", "")), str(finding.get("id", ""))
            if not RULE_PATTERN.fullmatch(rule) or len(rule) > 80 or not ID_PATTERN.fullmatch(fid) or len(fid) > 24:
                invalid += 1
                continue
            group = rules.setdefault(rule, {"ref": f"R:{rule}", "rule": rule,
                                            "severity": finding["severity"], "title": rule_title(rule),
                                            "_hosts": set(), "_ids": set(), "count": 0})
            group["_hosts"].add(host)
            group["_ids"].add(fid)
            group["count"] += 1
            if WEIGHTS[finding["severity"]] > WEIGHTS[group["severity"]]:
                group["severity"] = finding["severity"]
        for tech in asset.get("technologies", []):
            name, version = label(tech.get("name"), 40), label(tech.get("version"), 24)
            if not name or name == "untrusted text omitted" or version == "untrusted text omitted":
                continue
            key = (name, version)
            technologies.setdefault(key, set()).add(host)
        for ip in asset.get("ips", []):
            ips.add(ip.get("ip"))
            for port in ip.get("open_ports", []):
                key = (port["port"], label(port["protocol"], 8), label(port["service"], 30))
                ports.setdefault(key, set()).add(host)
    groups = []
    for group in rules.values():
        groups.append({k: v for k, v in group.items() if not k.startswith("_")} |
                      {"hosts": len(group["_hosts"]), "ids": sorted(group["_ids"])[:3]})
    groups.sort(key=lambda g: (-WEIGHTS[g["severity"]], -g["count"], g["rule"]))
    result = {"ref": "S:scan", "target": host_name(scan.get("target")),
              "date": text(scan.get("started_at"), 25), "hosts": risk["hosts"], "ips": len(ips),
              "risk": {k: risk[k] for k in ("score", "per_host", "high", "medium", "low")},
              "findings": groups,
              "top_hosts": risk["by_host"][:3],
              "technologies": [{"ref": f"T:{name}:{version}", "name": name, "version": version,
                                "hosts": len(hosts)} for (name, version), hosts in sorted(technologies.items())],
              "ports": [{"ref": f"P:{port}/{protocol}", "port": port, "protocol": protocol,
                         "service": service, "hosts": len(hosts)}
                        for (port, protocol, service), hosts in sorted(ports.items())],
              "notes": [], "hostile_text_seen": hostile_seen(scan)}
    if not has_check_evidence(scan):
        result["notes"].append("Passive-only or coverage-unknown; no finding comparison evidence.")
    if result["hostile_text_seen"]:
        result["notes"].append("Hostile-looking text detected and treated as untrusted data.")
    if invalid:
        result["notes"].append("Malformed finding references omitted.")
    omitted = dict(findings=0, technologies=0, ports=0, top_hosts=0)
    result["omitted"] = omitted
    while len(compact_json(result)) > SCAN_MAX_CHARS:
        for key in ("technologies", "ports", "top_hosts", "findings"):
            # Keep the most-exposed host when possible; trim it after rule groups.
            if result[key] and (key != "top_hosts" or len(result[key]) > 1):
                result[key].pop()
                omitted[key] += 1
                break
        else:
            if result["top_hosts"]:
                result["top_hosts"].pop()
                omitted["top_hosts"] += 1
            elif result["findings"]:
                result["findings"].pop()
                omitted["findings"] += 1
            else:
                raise ValueError("Scan labels exceed the digest budget.")
    return result
