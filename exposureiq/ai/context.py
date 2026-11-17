"""Code-owned chat focus, evidence selection and factual placeholders.

Only normalized, already-saved data is used. The model cannot pick a host,
alter a severity/score/verdict, or choose the order of a requested fix list.
"""

from __future__ import annotations

import copy
import re

from exposureiq.ai.fallback import latest_digest
from exposureiq.ai.glossary import requested_term
from exposureiq.ai.intents import detect_intent, normalized_intent_question, resolve_reference
from exposureiq.ai.questions import WHOLE_SCAN, is_follow_up, question_kind, referenced_finding
from exposureiq.ai.sanitize import compact_json
from exposureiq.ai.tools import MAX_TOOL_CHARS
from exposureiq.insight.digest import rule_title
from exposureiq.insight.risk import WEIGHTS, risk_score

MODES = ("simple", "technical")
SMALL_NUMBERS = ("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve")
PRIORITY_LABELS = {"high": "urgent", "medium": "important", "low": "minor"}
LIST_REQUEST = re.compile(r"\b(?:list|steps|step.by.step|fix\s+list|in\s+order|all\s+(?:priorities|fixes))\b", re.I)
SENSITIVE_ORDER = {rule: position for position, rule in enumerate((
    "ports.database_exposed", "ports.remote_desktop_exposed", "ports.smb_exposed", "ports.telnet_exposed",
    "https.not_available", "https.cert_expired", "ports.admin_interface_exposed", "ports.ftp_exposed"))}
INTENT_KINDS = {"worst_finding": "worst", "fix_how": "fix", "fix_first": "overview", "consequences": "impact",
                "effort": "timing", "who": "owner", "verify": "confirm", "opinion": "opinion"}
TERM_RULES = {"database": ("ports.database_exposed",), "remote desktop": ("ports.remote_desktop_exposed",),
              "SMB": ("ports.smb_exposed",), "Telnet": ("ports.telnet_exposed",), "FTP": ("ports.ftp_exposed",),
              "SSH": ("ports.ssh_exposed",), "certificate": ("https.cert_expired", "https.cert_expiring_soon",
              "https.cert_hostname_mismatch", "https.cert_self_signed", "https.cert_untrusted"),
              "HSTS": ("headers.missing_hsts", "headers.weak_hsts"), "CSP": ("headers.missing_csp", "headers.weak_csp")}


def number(value, mode="simple") -> str:
    return SMALL_NUMBERS[value] if mode == "simple" and isinstance(value, int) and 0 <= value < len(SMALL_NUMBERS) else str(value)


def ranked_groups(tools, *, host="") -> list[dict]:
    """Severity, sensitive-service order, then saved host score; never model rank."""
    scores = {item["host"]: item["score"] for item in risk_score(tools.scan)["by_host"]}
    groups = {}
    findings = [item for item in tools.findings if not host or item["host"] == host]
    findings.sort(key=lambda item: (-WEIGHTS[item["severity"]], SENSITIVE_ORDER.get(item["rule"], 99),
                                   -scores.get(item["host"], 0), item["rule"], item["host"], item["id"]))
    for item in findings:
        group = groups.setdefault(item["rule"], {"ref": "R:" + item["rule"], "rule": item["rule"],
                                  "severity": item["severity"], "title": rule_title(item["rule"]),
                                  "ids": [], "count": 0, "_hosts": set(), "host_score": scores.get(item["host"], 0)})
        group["count"] += 1
        group["_hosts"].add(item["host"])
        if item["id"] not in group["ids"] and len(group["ids"]) < 3:
            group["ids"].append(item["id"])
    return [{**{k: v for k, v in group.items() if k != "_hosts"}, "hosts": len(group["_hosts"])} for group in groups.values()]


def choose_context(question: str, digest: dict, tools, previous=None, *, mode=None, host="", finding_id="") -> dict:
    previous = previous or {}
    if mode is not None and mode not in MODES:
        raise ValueError("Choose simple or technical wording.")
    if host and (not isinstance(host, str) or host not in tools.hosts):
        raise ValueError("Choose a host from the selected saved scan.")
    if finding_id and (not isinstance(finding_id, str) or sum(item["id"] == finding_id for item in tools.findings) != 1):
        raise ValueError("Choose a unique finding from the selected saved scan.")
    value = normalized_intent_question(question)
    chosen_mode = mode or previous.get("mode", "simple")
    if re.search(r"\btechnical(?:ly)?\b", value, re.I):
        chosen_mode = "technical"
    elif re.search(r"\b(?:simple|plain)\s+(?:words|english)|\bsimpler\b", value, re.I):
        chosen_mode = "simple"
    kind = question_kind(value, previous_kind=previous.get("kind", ""))
    intent = detect_intent(value)
    if kind not in ("why", "incident", "unknown", "app", "scope", "severity", "risk", "coverage", "headers", "history", "unfixed"):
        kind = INTENT_KINDS.get(intent, kind)
    if intent == "which_hosts":
        kind = "host" if re.search(r"\bmost\s+exposed\b", value) else "hosts"
    term = requested_term(value)
    fid = finding_id or referenced_finding(value)
    named_hosts = [name for name in tools.hosts if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", value, re.I)]
    chosen_host = host or (named_hosts[0] if len(named_hosts) == 1 else "")
    if host and host not in tools.hosts:
        raise ValueError("Choose a host from the selected saved scan.")
    whole = bool(WHOLE_SCAN.search(value)) and not fid and not chosen_host
    continuing = is_follow_up(value) or kind in ("why", "opinion", "timing", "owner", "impact", "incident") or bool(re.search(r"\b(?:it|that|this|them|those)\b", value, re.I))
    ambiguous = ""
    explicit = bool(fid or chosen_host)
    if not fid and not chosen_host and not whole and (continuing or intent in ("fix_how", "effort", "who", "verify")):
        fid, chosen_host, ambiguous = resolve_reference(value, previous)
    if term:
        matches = [item for item in tools.findings if item["rule"] in TERM_RULES.get(term, ())]
        if matches and not explicit:
            fid, chosen_host = matches[0]["id"], matches[0]["host"]
        elif not matches and not explicit:
            fid, chosen_host = "", ""
    ranked = ranked_groups(tools, host=chosen_host)
    ranked_selection = False
    if kind != "why" and intent in ("worst_finding", "fix_first") and not LIST_REQUEST.search(value) and ranked:
        if not fid:
            candidate = ranked[0]["ids"][0]
            if sum(item["id"] == candidate for item in tools.findings) == 1:
                fid, ranked_selection = candidate, True
    if kind == "host" and not chosen_host and not fid:
        top = latest_digest(digest).get("top_hosts", [])
        chosen_host = top[0]["host"] if top else ""
    finding = next((item for item in tools.findings if item["id"] == fid), None)
    if fid and (finding is None or sum(item["id"] == fid for item in tools.findings) != 1):
        kind, chosen_host, fid = "unknown", "", ""
    elif finding:
        chosen_host = finding["host"]
    if chosen_host and not fid:
        ranked = ranked_groups(tools, host=chosen_host)
    # An unrelated explicit host must not silently reuse the previous one.
    if re.search(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\b", value, re.I) and not named_hosts and not fid:
        if kind not in ("app", "scope", "headers", "severity", "history", "risk"):
            kind, chosen_host = "unknown", ""
    return {"kind": kind, "finding_id": fid, "host": chosen_host, "mode": chosen_mode,
            "intent": intent, "ranked_groups": ranked, "ranked_selection": ranked_selection,
            "scope": "finding" if fid else "host" if chosen_host else "scan",
            "list_requested": bool(LIST_REQUEST.search(value)), "term": term, "clarification": ambiguous,
            "most_exposed": bool(chosen_host and latest_digest(digest).get("top_hosts") and chosen_host == latest_digest(digest)["top_hosts"][0]["host"])}


def add_focus_evidence(digest: dict, context: dict, tools) -> dict:
    result = copy.deepcopy(digest)
    evidence = []
    if context["host"] and context["host"] in tools.hosts:
        assets = tools.hosts[context["host"]]
        evidence.append({"type": "host", **risk_score({"assets": assets})["by_host"][0]})
    matches = [item for item in tools.findings if (item["id"] == context["finding_id"] if context["finding_id"] else item["host"] == context["host"])]
    matches.sort(key=lambda item: (-WEIGHTS[item["severity"]], item["rule"], item["id"]))
    for item in matches:
        if len(compact_json([*evidence, item])) > MAX_TOOL_CHARS:
            break
        evidence.append(copy.deepcopy(item))
    result["focus_evidence"] = evidence
    # Complete normalized rule groups and existing IDs, never raw saved details.
    # This lets the code rank evidence omitted from the small display digest.
    groups = context.get("ranked_groups", [])
    if context.get("finding_id") and not context.get("ranked_selection"):
        groups = ranked_groups_for_findings([item for item in tools.findings if item["id"] == context["finding_id"]])
    identifiers = {fid for group in groups for fid in group["ids"]}
    result["answer_evidence"] = [*copy.deepcopy(groups), *[copy.deepcopy(item) for item in tools.findings if item["id"] in identifiers]]
    result["focus_truncated"] = len(matches) > sum(item.get("type") == "finding" for item in evidence)
    return result


def ranked_groups_for_findings(findings: list[dict]) -> list[dict]:
    """Group exact already-selected evidence without scan-wide counts."""
    groups = {}
    for item in findings:
        group = groups.setdefault(item["rule"], {"ref": "R:" + item["rule"], "rule": item["rule"],
                                  "severity": item["severity"], "title": rule_title(item["rule"]),
                                  "ids": [], "count": 0, "hosts": 1})
        group["count"] += 1
        if item["id"] not in group["ids"]:
            group["ids"].append(item["id"])
        if WEIGHTS[item["severity"]] > WEIGHTS[group["severity"]]:
            group["severity"] = item["severity"]
    return sorted(groups.values(), key=lambda item: (-WEIGHTS[item["severity"]], SENSITIVE_ORDER.get(item["rule"], 99), item["rule"]))


def groups_for_answer(digest: dict, context: dict) -> list[dict]:
    if context.get("ranked_selection"):
        return copy.deepcopy(context["ranked_groups"][:1])
    if context["scope"] == "scan":
        return copy.deepcopy(context.get("ranked_groups", latest_digest(digest)["findings"]))
    if context["scope"] == "host":
        return copy.deepcopy(context["ranked_groups"])
    return ranked_groups_for_findings([item for item in digest.get("focus_evidence", []) if item.get("type") == "finding"])


def answer_plan(digest: dict, context: dict) -> dict:
    groups = groups_for_answer(digest, context)
    # Three is the presentation limit, not a claim that only three issues exist.
    priorities = (groups[:3] if context["kind"] in ("overview", "host", "why", "opinion", "impact", "finding", "fix", "worst") else [])
    refs = {"S:scan"}
    refs.update(item["ref"] for item in digest.get("focus_evidence", []))
    for group in groups:
        refs.update([group["ref"], *group["ids"][:3]])
    if context["scope"] == "scan":
        refs.update(item["ref"] for item in latest_digest(digest).get("top_hosts", []))
        if context["kind"] in ("history", "unfixed"):
            def walk(value):
                if isinstance(value, dict):
                    if isinstance(value.get("ref"), str):
                        refs.add(value["ref"])
                    for item in value.values():
                        walk(item)
                elif isinstance(value, list):
                    for item in value:
                        walk(item)
            walk(digest)
    return {**context, "priority_refs": [[item["ref"], *[fid for fid in item["ids"][:1] if fid != item["ref"]]] for item in priorities],
            "allowed_refs": sorted(refs), "groups": groups}


def fact_values(digest: dict, ref: str, index: dict, *, mode="simple") -> dict:
    item = index.get(ref, {})
    values = {}
    if ref == "S:scan":
        latest = latest_digest(digest)
        values = {"host_count": number(latest["hosts"], mode), "ip_count": number(latest["ips"], mode),
                  "risk_score": latest["risk"]["score"], "risk_per_host": latest["risk"]["per_host"],
                  **{f"{level}_count": number(latest["risk"][level], mode) for level in WEIGHTS}}
    if "host" in item:
        values["host"] = item["host"]
    if "score" in item:
        values.update(host_risk=item["score"], **{f"host_{level}_count": number(item.get(level, 0), mode) for level in WEIGHTS})
    if "rule" in item:
        hosts = item.get("hosts", 1)
        values.update(rule=item["rule"], rule_title=rule_title(item["rule"]), severity=item.get("severity", "unknown"),
                      priority_label=PRIORITY_LABELS.get(item.get("severity"), "unclassified") if mode == "simple" else item.get("severity", "unknown"),
                      hosts_affected=number(hosts, mode), affected_hosts=number(hosts, mode) + (" host" if hosts == 1 else " hosts"),
                      finding_count=number(item.get("count", 1), mode))
        if item["rule"] in ("headers.missing_hsts", "headers.weak_hsts"):
            values["hsts_max_age"] = 15552000  # Existing reviewed defensive recommendation, not a measured value.
    if "better" in item and "worse" in item:
        values.update(better_count=number(item["better"], mode), worse_count=number(item["worse"], mode))
    if ref == "V:history":
        values["verdict"] = digest["verdict"]["value"]
    if ref == "S:history" and digest.get("ref") == "S:history":
        from exposureiq.insight.history_digest import history_facts

        history = history_facts(digest)
        values.update(better_count=number(history["better"]["count"], mode),
                      worse_count=number(history["worse"]["count"], mode),
                      unfixed_count=number(history["list_counts"]["still_unfixed"], mode))
    if item.get("type") == "timeline":
        values.update(scan_date=item["date"], row_risk=item["per_host"])
    return values
