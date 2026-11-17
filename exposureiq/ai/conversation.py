"""Human-readable built-in chat replies, used only offline or after a failure.

Live models are NOT given these sentences to copy. Facts and selected evidence
still come from code. This module sends no traffic and takes no action.
"""

from __future__ import annotations

import copy
import hashlib

from exposureiq.ai.fallback import APP_EXPLANATION, SCOPE_EXPLANATION, claim, latest_digest
from exposureiq.ai.glossary import GLOSSARY, define_terms
from exposureiq.ai.wording import (CONFIRM_EXPLANATION, COVERAGE_EXPLANATION, HEADERS_EXPLANATION,
                                  INCIDENT_EXPLANATION, RULE_HELP, RULE_IMPACT, VERDICT_EXPLANATIONS)

PROOF_NOTE = "These are possible consequences, not proof that anyone broke in."
OFFLINE_NOTICE = "Offline mode: answers come from built-in explanations, not a live model."
PLAIN_NAMES = {
    "ports.database_exposed": "a database",
    "ports.remote_desktop_exposed": "remote desktop",
    "ports.smb_exposed": "SMB",
    "ports.telnet_exposed": "Telnet",
    "ports.ftp_exposed": "FTP",
    "ports.ssh_exposed": "SSH",
    "ports.admin_interface_exposed": "an administration service",
    "https.not_available": "a website without an encrypted connection",
    "https.cert_expired": "an expired website certificate",
    "https.cert_expiring_soon": "a website certificate that needs renewal soon",
    "https.cert_hostname_mismatch": "a certificate for the wrong website name",
    "https.cert_self_signed": "a self-signed website certificate",
    "https.cert_untrusted": "a website certificate browsers cannot verify",
    "headers.missing_hsts": "a missing encrypted-connection browser rule",
    "headers.weak_hsts": "a weak encrypted-connection browser rule",
    "headers.missing_csp": "a missing browser content policy",
    "headers.weak_csp": "a weak browser content policy",
    "headers.missing_x_content_type_options": "a missing file-type browser rule",
    "headers.missing_clickjacking_protection": "a missing rule against misleading page embedding",
    "headers.missing_referrer_policy": "a missing rule limiting shared page addresses",
    "headers.missing_permissions_policy": "a missing rule limiting browser features",
    "tech.server_version_disclosed": "a visible server software version",
    "tech.powered_by_disclosed": "a visible application software version",
    "tech.generator_version_disclosed": "a visible site-generator version",
}
SIMPLE_FIXES = {
    "headers.missing_hsts": "Ask the website owner to require encrypted connections once the secure connection works properly.",
    "headers.weak_hsts": "Ask the website owner to strengthen the rule requiring encrypted connections once the secure connection works properly.",
    "ports.remote_desktop_exposed": "Limit remote desktop access to approved people through a protected private connection, with strong sign-in controls.",
    "ports.telnet_exposed": "Disable Telnet and replace it with encrypted remote administration.",
    "https.cert_expired": "Ask the website owner to renew its certificate and check that automatic renewal works.",
}


def _refs(groups):
    result = []
    for item in groups:
        if item["ref"] not in result:
            result.append(item["ref"])
    for item in groups:
        for ref in item.get("ids", [])[:1]:
            if ref not in result:
                result.append(ref)
    return result[:8]


def _join(values):
    return values[0] if len(values) == 1 else ", ".join(values[:-1]) + " and " + values[-1]


def _themes(groups):
    themes = {}
    for group in groups:
        key = group["rule"].split(".")[0]
        themes.setdefault(key, []).append(group)
    return list(themes.items())[:3]


def _fix(group, technical):
    return RULE_HELP.get(group["rule"], ("", "Review this saved finding with the service owner."))[1] if technical else SIMPLE_FIXES.get(
        group["rule"], RULE_HELP.get(group["rule"], ("", "Review this saved finding with the service owner."))[1])


def _impact(group):
    value = RULE_IMPACT.get(group["rule"], "I can't tell a specific consequence from this saved finding.")
    # Put the incident-evidence limit in one conversation notice, not after
    # every service. Keep all conditions on access controls or other flaws.
    for marker in (" A reachable remote desktop port", " The open port alone", " SSH encrypts its connection;"):
        value = value.split(marker)[0]
    value = value.replace("; an expired certificate alone doesn't mean data was stolen", "")
    value = value.replace("; it doesn't by itself prove that traffic was intercepted", "")
    return value


def _overview_theme(kind, groups, technical=False):
    refs = _refs(groups)
    if technical:
        group = groups[0]
        return claim("{rule_title} is recorded as {severity} severity on {affected_hosts}. " + _fix(group, True), refs)
    if kind == "ports":
        names = _join([PLAIN_NAMES.get(group["rule"], "a sensitive service") for group in groups])
        return claim("The saved scan records public access to " + names + ". Keep services like these behind approved access controls, not open to everyone online.", refs)
    if kind == "https":
        group = groups[0]
        names = _join([PLAIN_NAMES.get(member["rule"], "a website connection issue") for member in groups])
        return claim("The saved website findings include " + names + ". " + _fix(group, False), refs)
    if kind == "headers":
        return claim("Your website also has gaps in its security headers. These browser protections are worth tightening, but do not by themselves prove a break-in.", refs)
    if kind == "tech":
        return claim("Some software version information is visible. That is a hint about the software, not proof that it has a known vulnerability.", refs)
    return claim("There is also a saved finding your team should review in the Findings view.", refs)


def fallback_chat(digest: dict, plan: dict) -> dict:
    """Return the chat JSON shape, with facts still left as code placeholders."""
    latest, groups = latest_digest(digest), plan["groups"]
    kind, technical = plan["kind"], plan["mode"] == "technical"
    scan_ref = ["S:scan"]
    host_ref = ["H:" + plan["host"]] if plan.get("host") else scan_ref
    notes, priorities, next_steps = [], [], []
    headline = claim("The main saved concerns need practical attention. Reduce access that does not need to be public.", scan_ref)
    if kind == "unknown":
        headline = claim("I don't see that in this scan.", scan_ref)
    elif kind == "app":
        headline = claim(APP_EXPLANATION, scan_ref)
    elif kind == "scope":
        headline = claim(SCOPE_EXPLANATION, scan_ref)
    elif kind == "severity":
        headline = claim("Severity tells your team what to fix first. Urgent means direct exposure or a broken secure website connection; important and minor mean smaller protection gaps.", scan_ref)
    elif plan.get("term"):
        term = plan["term"]
        entry = GLOSSARY[term]
        verb = " are " if term == "security headers" else " means "
        headline = claim(term + verb + entry["explanation"] + ". Think of it as " + entry["analogy"] + ".", scan_ref)
    elif kind == "headers":
        headline = claim(HEADERS_EXPLANATION, scan_ref)
    elif kind == "coverage":
        headline = claim(COVERAGE_EXPLANATION, scan_ref)
    elif kind == "confirm":
        headline = claim(CONFIRM_EXPLANATION, scan_ref)
    elif kind == "risk":
        headline = claim("For {host}, the exposure score is {host_risk}. It measures recorded exposure, not the chance of a break-in.", host_ref) if plan.get("host") else claim(
            "The exposure score is {risk_score}. It measures recorded exposure, not the chance of a break-in.", scan_ref)
    elif kind in ("history", "unfixed"):
        verdict = digest.get("verdict", {}).get("value", "not_enough_data")
        headline = claim(VERDICT_EXPLANATIONS[verdict], ["V:history"] if "verdict" in digest else scan_ref)
    elif kind == "incident":
        headline = claim(INCIDENT_EXPLANATION, scan_ref)
    elif kind == "timing":
        headline = claim("I can't tell how long this will take from the scan. Your team needs to check who depends on the service and how access is managed.", host_ref)
    elif kind == "owner":
        headline = claim("The person who manages the affected service should own the fix. Your network or security team can help review who should be allowed to connect.", host_ref)
    elif kind == "host" and plan.get("host"):
        headline = claim(("{host} is the most exposed host in this saved scan, with a recorded exposure score of {host_risk}." if plan["most_exposed"] else
                          "The saved scan records {host} with an exposure score of {host_risk}.") + " The score compares saved exposure, not the chance of a break-in.", host_ref)
    elif kind == "finding" and groups:
        text = ("{rule} is recorded as {severity} severity on {host}." if technical else
                "On {host}, this finding records " + PLAIN_NAMES.get(groups[0]["rule"], "a protection gap") + ".")
        refs = list(dict.fromkeys([groups[0]["ids"][0], groups[0]["ref"]]))
        headline = claim(text + " " + _fix(groups[0], technical), refs)
    elif kind == "why" and plan["scope"] == "finding" and groups:
        headline = claim("This is a {priority_label} saved finding. " + RULE_HELP.get(groups[0]["rule"], ("Review the saved observation with the service owner.", ""))[0], _refs(groups[:1]))
    elif kind == "why" and plan["scope"] == "host" and plan["most_exposed"]:
        headline = claim("{host} comes first because it has the highest recorded exposure score in the saved scan.", host_ref)
    elif kind == "why" and plan["scope"] == "host":
        headline = claim("For {host}, focus on the strongest recorded issue. The saved score alone doesn't say this host must come before every other host.", host_ref)
    elif kind == "why":
        headline = claim("Fixing the first issue reduces the most pressing exposure in the saved evidence. Smaller website improvements can follow that work." if groups else
                         "I don't have a saved finding to connect that recommendation to.", _refs(groups[:1]) or scan_ref)
    elif kind == "opinion":
        text = ("My honest take: keep private services private before polishing the smaller website protections." if any(g["rule"].startswith("ports.") for g in groups) else
                "My honest take: deal with the strongest saved finding first, without treating the scan as proof of a break-in." if groups else
                "My honest take: this scan doesn't contain findings we can prioritize. Missing checks still aren't proof that everything is safe.")
        headline = claim(text, _refs(groups[:1]) or scan_ref)
    elif kind == "impact":
        if groups and plan.get("host"):
            headline = claim("For {host}, the possible harm depends on the services recorded there and whether other protections hold.", host_ref)
        else:
            headline = claim("The possible harm depends on the recorded issues and on the protections around them." if groups else
                             "I don't have saved findings to connect to a possible consequence.", _refs(groups[:1]) or scan_ref)
    elif not groups:
        headline = claim("No findings were saved. That doesn't tell us whether every relevant check ran.", scan_ref)

    explain = kind in ("overview", "host", "why", "opinion", "impact", "finding") and groups
    if explain:
        if plan["list_requested"]:
            for refs in plan["priority_refs"]:
                group = next(item for item in groups if item["ref"] == refs[0])
                priorities.append({"rank": len(priorities) + 1, "action": _fix(group, technical),
                                   "why": _impact(group) if kind == "impact" else RULE_HELP.get(group["rule"], ("Review this saved finding with its owner.", ""))[0], "refs": refs})
        elif kind != "finding":
            for theme, members in _themes(groups):
                # Lead with one code-ranked example per theme, not every saved
                # rule joined into a report-length paragraph. Requested lists
                # above retain the full code-selected detail and priority order.
                selected = members[:1]
                if kind == "impact":
                    notes.append(claim(_impact(selected[0]), _refs(selected)))
                else:
                    notes.append(_overview_theme(theme, selected, technical))
    if kind == "impact" and groups and plan.get("include_proof_note", True):
        notes.append(claim(PROOF_NOTE, scan_ref))
    if kind not in ("unknown", "incident", "app", "scope"):
        seed = str(plan.get("wording_seed", latest.get("date", "")))
        variant = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16) % 2
        offer = ("I can turn that into a short fix list for your team.", "We can work through the first fix in plain words.")[variant]
        next_steps.append(claim(offer, host_ref))
    result = {"headline": headline, "priorities": priorities, "next_steps": next_steps, "notes": notes}
    if not technical:
        seen = set(plan.get("defined_terms", []))
        if plan.get("term"):
            seen.add(plan["term"])
        ordered = [result["headline"], *result["notes"], *result["next_steps"]]
        for item in ordered:
            item["text"], seen = define_terms(item["text"], seen=seen)
        for priority in priorities:
            for key in ("action", "why"):
                priority[key], seen = define_terms(priority[key], seen=seen)
    return copy.deepcopy(result)


def friendly_reply(kind: str) -> dict:
    text = {"greeting": "Hi! I can help explain your saved scan. What would you like to understand?",
            "thanks": "You're welcome. We can come back to the saved findings whenever you're ready.",
            "acknowledgement": "Got it. We can keep talking about this scan or look at another saved finding."}[kind]
    return {"headline": {"text": text, "refs": []}, "priorities": [], "next_steps": [], "notes": []}
