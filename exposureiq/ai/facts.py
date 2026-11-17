"""Small code-selected facts packs shared by live phrasing and built-in chat.

No raw banners, saved recommendations or model-selected rankings enter a pack.
Guidance and effort ranges are explicitly advice, not observed scan results.
"""

from __future__ import annotations

import copy
import hashlib

from exposureiq.ai.checker import reference_index
from exposureiq.ai.context import TERM_RULES, fact_values
from exposureiq.ai.conversation import PLAIN_NAMES
from exposureiq.ai.fallback import APP_EXPLANATION, SCOPE_EXPLANATION, claim, latest_digest
from exposureiq.ai.fixes import fix_for
from exposureiq.ai.glossary import GLOSSARY
from exposureiq.ai.wording import (CONFIRM_EXPLANATION, COVERAGE_EXPLANATION, HEADERS_EXPLANATION, INCIDENT_EXPLANATION,
                                  VERDICT_EXPLANATIONS)
from exposureiq.insight.history_digest import history_facts

MAX_THEMES = 3


def selected_groups(plan: dict) -> list[dict]:
    groups = plan["groups"]
    if plan["scope"] == "finding" or plan["kind"] in ("worst", "fix") and plan.get("finding_id"):
        return copy.deepcopy(groups[:1])
    if plan["list_requested"] or plan.get("intent") == "fix_first":
        return copy.deepcopy(groups[:MAX_THEMES])
    selected, themes = [], set()
    for group in groups:
        theme = group["rule"].split(".")[0]
        if theme not in themes:
            selected.append(copy.deepcopy(group))
            themes.add(theme)
        if len(selected) == MAX_THEMES:
            break
    return selected


def build_facts_pack(digest: dict, plan: dict, *, scan_id: str, question: str) -> dict:
    """Select evidence once, before either the model or the fallback phrases it."""
    index = reference_index(digest)
    groups = selected_groups(plan)
    if plan.get("term"):
        term = plan["term"]
        groups = [group for group in groups if group["rule"] in TERM_RULES.get(term, ()) or
                  term == "security headers" and group["rule"].startswith("headers.") or
                  term == "HTTPS" and group["rule"].startswith("https.")]
    definitions = plan["kind"] in ("app", "scope", "severity", "risk", "coverage", "headers", "incident", "unknown", "history", "unfixed") or plan["kind"] == "confirm" and plan["scope"] == "scan"
    if definitions and not plan.get("term"):
        groups = []
    refs = ["S:scan"]
    if plan.get("host"):
        refs.append("H:" + plan["host"])
    if plan["kind"] == "hosts":
        refs.extend(item["ref"] for item in latest_digest(digest).get("top_hosts", [])[:MAX_THEMES])
    findings = []
    for group in groups:
        refs.extend([group["ref"], *group["ids"][:1]])
        guide = fix_for(group["rule"])
        advice = {}
        if guide:
            advice["what"] = guide["what"]
            if plan["kind"] in ("worst", "overview", "host", "hosts", "why", "finding", "impact", "opinion") or plan.get("term"):
                advice["why"] = guide["why"]
            if plan["kind"] in ("fix", "overview", "host", "why", "finding", "opinion", "worst"):
                advice["steps"] = list(guide["steps"] if plan["kind"] == "fix" else guide["steps"][:1])
            if plan["kind"] == "fix" and plan["mode"] == "technical" and guide["server_note"]:
                advice["server_note"] = guide["server_note"]
            if plan["kind"] == "timing":
                advice["effort"] = guide["effort"]
            if plan["kind"] in ("owner", "timing"):
                advice["who"] = guide["who"]
            if plan["kind"] == "confirm":
                advice.update(verify=guide["verify"], recheck=guide["recheck"])
        findings.append({"ref": group["ref"], "id": group["ids"][0], "rule": group["rule"],
                         "name": PLAIN_NAMES.get(group["rule"], "a saved protection gap"),
                         "severity": group["severity"], "hosts": group["hosts"], "count": group["count"],
                         "advice": advice})
    history = {}
    if plan["kind"] in ("history", "unfixed"):
        history = history_facts(digest)
        if "verdict" in digest:
            refs.append("V:history")
    refs = list(dict.fromkeys(ref for ref in refs if ref in index))
    values = {ref: fact_values(digest, ref, index, mode=plan["mode"]) for ref in refs}
    # Only the requested definition goes to the model, not the whole glossary.
    glossary = {plan["term"]: GLOSSARY[plan["term"]]} if plan.get("term") else {}
    seed = hashlib.sha256((str(scan_id) + "\0" + question.casefold()).encode("utf-8")).hexdigest()[:16]
    pack = {"intent": plan.get("intent", "unknown"), "kind": plan["kind"], "mode": plan["mode"],
            "focus": {key: plan[key] for key in ("host", "finding_id", "scope", "term", "most_exposed")},
            "findings": findings, "references": values, "glossary": glossary,
            "list_requested": bool(plan["list_requested"]), "ranked_list": bool(plan["list_requested"] and plan["priority_refs"]),
            "ranking": "Severity first; sensitive public services next; saved host exposure scores break remaining ties. This is fix priority, not a probability of harm.",
            "advice_limit": "Fix steps, owners and effort ranges are general defensive guidance, not measurements or proof that a fix worked.",
            "defined_terms": plan.get("defined_terms", []), "wording_seed": seed}
    if history:
        pack["history"] = {"verdict": digest.get("verdict", {}).get("value", "not_enough_data"),
                           "better": history["better"]["count"], "worse": history["worse"]["count"],
                            "list_counts": history["list_counts"]}
        # Counts in a history answer are comparison facts, not latest-scan
        # finding totals. They get a dedicated reference in this exact pack.
        from exposureiq.ai.context import number

        values["S:history"] = {"better_count": number(history["better"]["count"], plan["mode"]),
                               "worse_count": number(history["worse"]["count"], plan["mode"]),
                               "unfixed_count": number(history["list_counts"]["still_unfixed"], plan["mode"])}
        refs.append("S:history")
    # Internal checker state is not part of a scan snapshot or sent to a browser.
    plan["groups"] = groups
    plan["allowed_refs"] = refs
    plan["priority_refs"] = [[group["ref"], *[fid for fid in group["ids"][:1] if fid != group["ref"]]] for group in groups] if pack["ranked_list"] else []
    plan["list_requested"] = pack["list_requested"]
    return pack


def _ref(item):
    return list(dict.fromkeys((item["ref"], item["id"])))


def _plain_name(item):
    name = item["name"]
    return name[2:] if name.startswith("a ") else name[3:] if name.startswith("an ") else name


def built_in_answer(pack: dict) -> dict:
    """Phrase this exact pack deterministically; never fall back to a scan dump."""
    kind, groups = pack["kind"], pack["findings"]
    focus, technical = pack["focus"], pack["mode"] == "technical"
    scan_ref = ["S:scan"]
    host_ref = ["H:" + focus["host"]] if focus["host"] and "H:" + focus["host"] in pack["references"] else scan_ref
    first = groups[0] if groups else None
    refs = _ref(first) if first else host_ref
    notes, priorities, next_steps = [], [], []
    variant = int(pack["wording_seed"], 16) % 2
    headline = claim("No findings were saved. That doesn't tell us whether every relevant check ran.", scan_ref)
    if kind == "unknown":
        headline = claim("I don't see that in this scan.", scan_ref)
    elif kind == "app":
        headline = claim(APP_EXPLANATION, scan_ref)
    elif kind == "scope":
        headline = claim(SCOPE_EXPLANATION, scan_ref)
    elif kind == "severity":
        headline = claim("Severity tells your team what to fix first. Urgent means direct exposure or a broken secure website connection; important and minor mean smaller protection gaps.", scan_ref)
    elif focus["term"]:
        term, entry = next(iter(pack["glossary"].items()))
        expansion = "Server Message Block, " if term == "SMB" else ""
        headline = claim(term + (" are " if term == "security headers" else " means ") + expansion + entry["explanation"] + ".", scan_ref)
        if first:
            notes.append(claim("This scan records " + first["name"] + " on {affected_hosts}.", refs))
            notes.append(claim(first["advice"].get("why", "The service owner can review this saved observation."), refs))
        else:
            notes.append(claim("That's a definition, not evidence that this service is exposed in your scan.", scan_ref))
    elif kind == "headers":
        headline = claim(HEADERS_EXPLANATION, scan_ref)
    elif kind == "coverage":
        headline = claim(COVERAGE_EXPLANATION, scan_ref)
    elif kind == "incident":
        headline = claim(INCIDENT_EXPLANATION, scan_ref)
    elif kind == "risk":
        headline = claim("For {host}, the exposure score is {host_risk}. It measures recorded exposure, not the chance of a break-in.", host_ref) if focus["host"] else claim(
            "The exposure score is {risk_score}. It measures recorded exposure, not the chance of a break-in.", scan_ref)
    elif kind in ("history", "unfixed"):
        headline = claim(VERDICT_EXPLANATIONS[pack.get("history", {}).get("verdict", "not_enough_data")],
                         ["V:history"] if "V:history" in pack["references"] else scan_ref)
        # chat_text displays complete code-owned comparison counts once;
        # do not duplicate them as a second prose summary here.
    elif kind == "host" and focus["host"]:
        headline = claim(("{host} is the most exposed host in this saved scan, with a recorded exposure score of {host_risk}." if focus["most_exposed"] else
                          "The saved scan records {host} with an exposure score of {host_risk}.") + " The score compares saved exposure, not the chance of a break-in.", host_ref)
        if first:
            notes.append(claim(first["advice"].get("why", "Review the saved finding with its owner."), refs))
            next_steps.append(claim(first["advice"].get("steps", ["Ask the service owner to review this saved observation."])[0], refs))
    elif kind == "hosts":
        headline = claim("The selected saved scan contains {host_count} hosts.", scan_ref)
        names = [values["host"] for ref, values in pack["references"].items() if ref.startswith("H:") and "host" in values]
        if names:
            notes.extend(claim("{host} has a saved exposure score of {host_risk}.", ["H:" + name]) for name in names[:MAX_THEMES])
        else:
            notes.append(claim("Open the saved Hosts view for the complete list; this answer is not a new lookup.", scan_ref))
    elif (kind == "worst" or kind != "why" and pack["intent"] == "fix_first") and first:
        headline = claim(("The most serious saved finding is " if variant else "The worst saved finding here is ") + first["name"] + " on {affected_hosts}.", refs)
        if pack["intent"] == "fix_first":
            headline = claim("Fix " + _plain_name(first) + " first; it is an {priority_label} priority on {affected_hosts}.", refs)
        notes.append(claim("The code marks this as {priority_label} under its severity and sensitive-exposure rules. " + first["advice"].get("why", "Review this observation with its owner."), refs))
        next_steps.append(claim(first["advice"].get("steps", ["Ask the service owner to review this saved observation."])[0], refs))
    elif kind == "fix" and first:
        # The exact finding is the first ref when it has a host placeholder.
        primary = first["id"] if "host" in pack["references"].get(first["id"], {}) else first["ref"]
        refs = list(dict.fromkeys((primary, first["ref"])))
        headline = claim("For " + _plain_name(first) + (" on {host}" if "host" in pack["references"].get(primary, {}) else "") + ", use these defensive steps.", refs)
        notes.extend(claim(step, refs) for step in first["advice"].get("steps", ["Ask the service owner to review this saved observation."]))
        if technical and first["advice"].get("server_note"):
            notes.append(claim(first["advice"]["server_note"], refs))
    elif kind == "timing" and first:
        headline = claim("For " + _plain_name(first) + ", the typical effort is " + first["advice"].get("effort", "not known from this scan") + ".", refs)
        notes.extend(claim("For " + _plain_name(item) + ", the typical effort is " + item["advice"].get("effort", "not known from this scan") + ".", _ref(item)) for item in groups[1:])
        notes.append(claim("These are planning ranges, not times measured by your scan.", refs))
        next_steps.append(claim("Ask " + first["advice"].get("who", "the service owner") + " to check dependencies before giving a deadline.", refs))
    elif kind == "owner" and first:
        headline = claim("Ask " + first["advice"].get("who", "the service owner") + " to own the " + _plain_name(first) + " fix.", refs)
        notes.extend(claim("The " + _plain_name(item) + " fix usually belongs to " + item["advice"].get("who", "the service owner") + ".", _ref(item)) for item in groups[1:])
        notes.append(claim("Give them this finding and ask who still needs the affected service.", refs))
        next_steps.append(claim("Agree a safe change and a check that normal work still functions.", refs))
    elif kind == "confirm":
        if first:
            headline = claim(first["advice"].get("verify", "Ask the service owner to confirm the intended setting and normal service use."), refs)
        else:
            headline = claim(CONFIRM_EXPLANATION, scan_ref)
        from exposureiq.ai.fixes import RECHECK

        notes.append(claim(RECHECK, refs))
        next_steps.append(claim("An absent finding is useful evidence, not proof that every part of the system is safe.", refs))
    elif kind == "opinion":
        headline = claim("My honest take: " + ("keep private services private before polishing smaller website protections." if first and first["rule"].startswith("ports.") else
                         "deal with the strongest saved finding first, without treating the scan as proof of a break-in." if first else
                         "this scan doesn't contain findings we can prioritize; missing checks still aren't proof of safety."), refs)
        if first:
            notes.append(claim("That means giving " + _plain_name(first) + " practical attention, not assuming anyone got in.", refs))
            next_steps.append(claim(first["advice"].get("steps", ["Ask the service owner to review this saved observation."])[0], refs))
    elif kind == "why" and first:
        headline = claim(("{host} comes first because it has the highest recorded exposure score in the saved scan." if focus["most_exposed"] else
                          "For {host}, this saved finding deserves attention, but the score alone doesn't put it ahead of every other host.") if focus["scope"] == "host" else
                         "This is an {priority_label} saved finding, so it comes before smaller hardening gaps.", host_ref if focus["scope"] == "host" else refs)
        notes.append(claim(first["advice"].get("why", "The service owner can explain the saved observation."), refs))
        next_steps.append(claim(first["advice"].get("steps", ["Ask the service owner to review this saved observation."])[0], refs))
    elif kind == "impact":
        headline = claim("For {host}, the possible harm depends on the services recorded there and whether other protections hold.", host_ref) if focus["host"] else claim(
            "The possible harm depends on the recorded issues and on the protections around them." if first else
            "I don't have saved findings to connect to a possible consequence.", refs)
        notes.extend(claim(item["advice"].get("why", "I can't tell a specific consequence from this saved finding."), _ref(item)) for item in groups)
        if first:
            next_steps.append(claim("Have the service owner review unnecessary public access and the protections around it.", refs))
    elif kind == "finding" and first:
        refs = list(dict.fromkeys((first["id"], first["ref"])))
        headline = claim(("{rule} is recorded as {severity} severity on {host}." if technical else
                          "On {host}, this finding records " + first["name"] + "."), refs)
        notes.append(claim(first["advice"].get("what", "Ask the service owner to explain the saved observation."), refs))
        next_steps.append(claim(first["advice"].get("steps", ["Ask the service owner to review this saved observation."])[0], refs))
    elif first:
        headline = claim("The main saved concern is " + first["name"] + ". Reduce access that does not need to be public." if first["rule"].startswith("ports.") else
                         "The main saved concern is " + first["name"] + ".", refs)
        for item in groups:
            if technical:
                text = "{rule_title} is recorded as {severity} severity on {affected_hosts}."
            else:
                text = "The scan records public access to " + item["name"] + "." if item["rule"].startswith("ports.") else "The scan records " + item["name"] + "."
            step = item["advice"].get("steps", [])
            notes.append(claim(text + (" " + step[0] if step else ""), _ref(item)))
    if pack["ranked_list"]:
        # Lists and their order are application-owned in either contract.
        notes, next_steps = [], []
        for item in groups:
            guide = fix_for(item["rule"])
            priorities.append({"rank": len(priorities) + 1, "action": guide.get("steps", ("Review this saved finding with its owner.",))[1 if len(guide.get("steps", ())) > 1 else 0],
                               "why": guide.get("why", "A more specific explanation is not known."), "refs": _ref(item)})
    return {"headline": headline, "priorities": priorities, "notes": notes, "next_steps": next_steps}
