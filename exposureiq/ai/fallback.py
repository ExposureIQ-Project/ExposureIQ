"""Trusted defensive sentences. Model drafts choose/order, never invent facts.

This closed sentence catalog is intentional: citation validity alone cannot
prove arbitrary prose. The same layout works when AI is off or fails.
"""

from __future__ import annotations

import copy

from exposureiq.ai.questions import question_kind, referenced_finding
from exposureiq.ai.wording import (CONFIRM_EXPLANATION, COVERAGE_EXPLANATION, HEADERS_EXPLANATION,
                                  EMPTY_IMPACT_EXPLANATION, IMPACT_EXPLANATION, IMPACT_LIMITATION,
                                  INCIDENT_EXPLANATION, RISK_EXPLANATION, RULE_HELP, RULE_IMPACT,
                                  SEVERITY_EXPLANATION, VERDICT_EXPLANATIONS)
from exposureiq.insight.risk import WEIGHTS

REVIEW_NOTE = "This is a draft based on saved data. Review it with your team; missing checks are not proof of safety."
UNKNOWN_NOTE = "I don't see that in this scan."
APP_EXPLANATION = "ExposureIQ helps you see what your organization exposes online and what changed between saved scans. I only explain saved data; I don't scan or take action."
SCOPE_EXPLANATION = "Your team controls which targets are authorized. I can explain saved findings, but I can't scan, run commands or change that permission list."
RISK_HEADLINE = "The exposure score is {risk_score}. It measures recorded exposure, not the chance of a break-in."
HOST_HEADLINE = "I'd review {host} first: it has the highest recorded exposure score, {host_risk}."


def latest_digest(digest: dict) -> dict:
    return digest.get("latest", digest)


def claim(sentence: str, refs: list[str]) -> dict:
    return {"text": sentence, "refs": list(refs)}


def action_for_rule(rule: str) -> str:
    action = RULE_HELP.get(rule, ("", "Review this finding with your team and apply an authorized defensive fix."))[1]
    return "{rule_title}: " + action


def why_for_group(group: dict) -> str:
    meaning = RULE_HELP.get(group["rule"], ("Review the saved observation with your team.", ""))[0]
    return f"The scan rates this as {group['severity']} severity on {{affected_hosts}}. " + meaning


def impact_for_rule(rule: str) -> str:
    return RULE_IMPACT.get(rule, "The saved observation doesn't give enough detail to explain a specific consequence. Exposure alone isn't proof of a break-in.")


def why_for_impact(group: dict) -> str:
    # Answer the consequence question, rather than repeating the previous fix list.
    return impact_for_rule(group["rule"])


def _headlines(digest: dict) -> list[dict]:
    latest, refs = latest_digest(digest), ["S:scan"]
    counts = latest["risk"]
    if "verdict" in digest:
        sentence = (VERDICT_EXPLANATIONS["not_enough_data"] if digest["verdict"]["value"] == "not_enough_data" else
                    "The saved history shows a {verdict} trend.")
        main = claim(sentence, ["V:history"])
    elif counts["high"]:
        main = claim("I'd start with {high_findings} in this scan.", refs)
    elif counts["medium"]:
        main = claim("The scan's main findings are medium severity: protections worth tightening, not proof of a break-in.", refs)
    elif counts["low"]:
        main = claim("The saved findings are low severity. Let's focus on simple hardening improvements.", refs)
    else:
        main = claim("No findings were saved. That isn't a clean bill of health: some checks may be missing.", refs)
    result = [main, claim(UNKNOWN_NOTE, refs), claim(APP_EXPLANATION, refs), claim(SCOPE_EXPLANATION, refs),
              claim(SEVERITY_EXPLANATION, refs), claim(HEADERS_EXPLANATION, refs), claim(COVERAGE_EXPLANATION, refs),
              claim(CONFIRM_EXPLANATION, refs), claim(RISK_HEADLINE, refs),
              claim(IMPACT_EXPLANATION if latest["findings"] else EMPTY_IMPACT_EXPLANATION, refs),
              claim(INCIDENT_EXPLANATION, refs)]
    for host in latest.get("top_hosts", [])[:1]:
        result.append(claim(HOST_HEADLINE, [host["ref"]]))
    for evidence in digest.get("tool_evidence", []):
        kind, ref = evidence.get("type"), evidence.get("ref")
        if not ref:
            continue
        if kind == "finding":
            result.append(claim("Here's the saved finding: {rule_title} on {host}.", [ref]))
        elif kind == "host":
            result.append(claim("The saved data records {host} with an exposure score of {host_risk}.", [ref]))
        elif kind == "diff":
            result.append(claim("In that saved comparison, {better_count} observed changes improved and {worse_count} worsened.", [ref]))
        elif kind == "timeline":
            result.append(claim("The saved scan dated {scan_date} records an exposure score per host of {row_risk}.", [ref]))
        elif kind == "unfixed":
            result.append(claim("The saved history still shows {rule_title} on {host}.", [ref]))
    for item in digest.get("still_unfixed", [])[:1]:
        result.append(claim("The saved history still shows {rule_title} on {host}.", [item["ref"]]))
    return result


def template_summary(digest: dict, *, question: str = "", answer_context: dict | None = None) -> dict:
    latest = latest_digest(digest)
    refs = ["S:scan"]
    headlines = _headlines(digest)
    context = answer_context or {"kind": question_kind(question), "finding_id": referenced_finding(question)}
    headline, kind = headlines[0], context["kind"]
    requested = context.get("finding_id", "")
    priorities = []
    for group in latest["findings"]:
        group_refs = [group["ref"], *group["ids"][:1]]
        priorities.append({"rank": len(priorities) + 1,
                           "action": "{rule_title}" if kind == "impact" else action_for_rule(group["rule"]),
                           "why": why_for_impact(group) if kind == "impact" else why_for_group(group), "refs": group_refs})
    notes = [claim(REVIEW_NOTE, refs), claim(RISK_EXPLANATION, refs)]
    if latest.get("technologies"):
        notes.append(claim("A software version is only a hint. It doesn't prove a known vulnerability or a break-in.", refs))
    if digest.get("hostile_text_seen"):
        notes.append(claim("Some saved text looked like instructions. I treated it as data, not something to obey.", refs))
    if any(latest.get("omitted", {}).values()):
        notes.append(claim("This explanation uses a shortened selection of findings. Open the saved Findings tab for the full detail.", refs))
    if any("Passive-only" in note for note in latest.get("notes", [])):
        notes.append(claim("The latest scan is passive-only or its check coverage is unknown. I can't use it to confirm finding changes.", refs))
    next_steps = [claim("Use the cited saved findings to discuss these fixes with the person who owns each service.", refs),
                  claim(CONFIRM_EXPLANATION, refs)]
    if "verdict" in digest:
        notes.append(claim(VERDICT_EXPLANATIONS[digest["verdict"]["value"]], ["V:history"]))
        for key, wording in (("still_unfixed", "Still present in saved observations"),
                             ("fixed", "Absent in subsequent saved observations"),
                             ("new_recently", "New in recent saved observations"),
                             ("regressions", "Returned after two saved absences")):
            for item in digest.get(key, [])[:3]:
                notes.append(claim(wording + ": {rule_title} on {host}.", [item["ref"]]))
    if question:
        simple = {"app": APP_EXPLANATION, "scope": SCOPE_EXPLANATION, "unknown": UNKNOWN_NOTE,
                  "severity": SEVERITY_EXPLANATION, "headers": HEADERS_EXPLANATION,
                  "coverage": COVERAGE_EXPLANATION, "confirm": CONFIRM_EXPLANATION,
                  "incident": INCIDENT_EXPLANATION,
                  "impact": IMPACT_EXPLANATION if latest["findings"] else EMPTY_IMPACT_EXPLANATION}
        if kind in simple:
            headline = claim(simple[kind], refs)
        elif kind == "risk":
            headline = claim(RISK_HEADLINE, refs)
        elif kind == "host" and latest.get("top_hosts"):
            headline = claim(HOST_HEADLINE, [latest["top_hosts"][0]["ref"]])
        if requested:
            finding = next((e for e in digest.get("tool_evidence", [])
                            if e.get("type") == "finding" and e.get("id") == requested), None)
            group = next((g for g in latest["findings"] if requested in g["ids"]), None)
            if not finding and not group:
                headline = claim(UNKNOWN_NOTE, refs)
            elif kind == "finding":
                headline = claim("Here's the saved finding: {rule_title} on {host}.", [finding["ref"]]) if finding else claim(UNKNOWN_NOTE, refs)
        elif kind == "unfixed":
            items = digest.get("still_unfixed", []) or [e for e in digest.get("tool_evidence", []) if e.get("type") == "unfixed"]
            headline = (claim("The saved history still shows {rule_title} on {host}.", [items[0]["ref"]])
                         if items else claim(UNKNOWN_NOTE, refs))
        elif kind == "history":
            comparison = next((e for e in digest.get("tool_evidence", []) if e.get("type") == "diff"), None)
            if comparison:
                headline = claim("In that saved comparison, {better_count} observed changes improved and {worse_count} worsened.", [comparison["ref"]])
        # A chat answer is focused, not a full report on every turn. Every
        # included high rule still appears, and code retains severity order.
        wanted = {g["ref"] for g in latest["findings"] if g["severity"] == "high"}
        if kind == "headers":
            wanted.update(g["ref"] for g in latest["findings"] if g["rule"].startswith("headers."))
        elif kind in ("overview", "host", "history", "unfixed", "finding", "impact"):
            wanted.update(g["ref"] for g in latest["findings"][:3])
        if requested:
            wanted.update(g["ref"] for g in latest["findings"] if requested in g["ids"])
        priorities = [p for p in priorities if p["refs"][0] in wanted]
        if kind == "impact" and requested and finding and not group:
            # An exact read-only tool result can explain a finding outside the
            # bounded digest, without replacing any included highs.
            severity_by_ref = {g["ref"]: g["severity"] for g in latest["findings"]}
            position = next((i for i, p in enumerate(priorities)
                             if WEIGHTS[severity_by_ref[p["refs"][0]]] < WEIGHTS[finding["severity"]]), len(priorities))
            priorities.insert(position, {"rank": 0, "action": "{rule_title}",
                                         "why": why_for_impact(finding), "refs": [finding["ref"]]})
        for rank, item in enumerate(priorities, 1):
            item["rank"] = rank
        next_steps = []
        notes = [n for n in notes if n["text"] != REVIEW_NOTE]
        if kind != "risk":
            notes = [n for n in notes if n["text"] != RISK_EXPLANATION]
        if kind not in ("history", "unfixed"):
            notes = [n for n in notes if n["refs"] == refs]
        if kind == "impact":
            notes = [n for n in notes if n["text"] != "A software version is only a hint. It doesn't prove a known vulnerability or a break-in."]
            notes.insert(0, claim(IMPACT_LIMITATION, refs))
    return {"headline": headline, "priorities": priorities, "next_steps": next_steps, "notes": notes[:20]}


def approved_claims(digest: dict) -> list[dict]:
    candidate = template_summary(digest)
    claims = [copy.deepcopy(candidate["headline"]), *copy.deepcopy(candidate["next_steps"]),
              *copy.deepcopy(candidate["notes"])]
    for item in candidate["priorities"]:
        claims.extend([claim(item["action"], item["refs"]), claim(item["why"], item["refs"])])
    claims.extend(_headlines(digest))
    claims.append(claim(IMPACT_LIMITATION, ["S:scan"]))
    for group in latest_digest(digest)["findings"]:
        refs = [group["ref"], *group["ids"][:1]]
        fix = RULE_HELP.get(group["rule"], ("", "Review this finding with your team and apply an authorized defensive fix."))[1]
        meaning = RULE_HELP.get(group["rule"], ("Review the saved observation with your team.", ""))[0]
        claims.append(claim("For {rule_title}, " + fix[0].lower() + fix[1:], refs))
        claims.append(claim(f"This recorded {group['severity']}-severity finding affects {{affected_hosts}}. " + meaning, refs))
        claims.append(claim("{rule_title}", refs))
        claims.append(claim(why_for_impact(group), refs))
    for evidence in digest.get("tool_evidence", []):
        kind, ref = evidence.get("type"), evidence.get("ref")
        if not ref:
            continue
        if kind == "finding":
            claims.append(claim(action_for_rule(evidence["rule"]), [ref]))
            claims.append(claim("{rule_title}", [ref]))
            claims.append(claim(why_for_impact(evidence), [ref]))
    return claims
