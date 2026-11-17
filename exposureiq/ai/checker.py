"""Strict report checking, plus bounded evidence/fact checks for natural chat.

Unknown references, literal numbers, incorrect severity/verdict, unsupported
sentences and missing high-rule priorities are rejected. Placeholders are
filled only after verification. This deliberately does NOT claim to solve
general semantic verification of arbitrary natural language. Conversational
checks validate refs, factual placeholders, code-selected list order and known
unsafe/unsupported patterns. They NEVER certify the truth of all model prose.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field

from exposureiq.ai.fallback import approved_claims, latest_digest
from exposureiq.ai.context import fact_values
from exposureiq.ai.sanitize import hostile_seen
from exposureiq.ai.schema import parse_output
from exposureiq.insight.digest import rule_title
from exposureiq.insight.risk import WEIGHTS
from exposureiq.ai.wording import SEVERITY_EXPLANATION

PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


@dataclass
class CheckedOutput:
    output: dict
    verified: int
    total: int
    dropped: list[dict]
    removed: list[dict] = field(default_factory=list)
    checked_numbers: int = 0

    @property
    def accepted(self) -> bool:
        return not self.dropped


def reference_index(digest: dict) -> dict:
    refs = {}

    def walk(value):
        if isinstance(value, dict):
            if isinstance(value.get("ref"), str):
                refs.setdefault(value["ref"], value)
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(digest)
    latest = latest_digest(digest)
    refs["S:scan"] = latest
    for group in latest.get("findings", []):
        for fid in group["ids"]:
            refs.setdefault(fid, group)  # Tool evidence can resolve an exact finding.
    # A chat-only facts projection is complete and may be host-scoped. It must
    # override a display digest's truncated/global group, never vice versa.
    for item in digest.get("answer_evidence", []):
        if isinstance(item, dict) and isinstance(item.get("ref"), str):
            refs[item["ref"]] = item
    return refs


def placeholder_values(digest: dict, refs: list[str]) -> dict:
    latest = latest_digest(digest)
    risk = latest["risk"]
    index = reference_index(digest)
    primary = index.get(refs[0], {})
    hosts = primary.get("hosts", 0)
    high = risk["high"]
    return {"high_count": risk["high"], "medium_count": risk["medium"], "low_count": risk["low"],
            "host_count": latest["hosts"], "ip_count": latest["ips"], "risk_score": risk["score"],
            "risk_per_host": risk["per_host"], "hosts_affected": primary.get("hosts", 0),
            "affected_hosts": f"{hosts} host" + ("" if hosts == 1 else "s"),
            "high_findings": f"{high} high-severity finding" + ("" if high == 1 else "s"),
            "host_risk": primary.get("score", 0), "host": primary.get("host", "unknown"),
            "rule": primary.get("rule", "unknown"), "rule_title": rule_title(primary.get("rule", "unknown")),
            "hsts_max_age": 15552000,
            "better_count": primary.get("better", 0), "worse_count": primary.get("worse", 0),
            "scan_date": primary.get("date", "unknown"), "row_risk": primary.get("per_host", 0),
            "verdict": digest.get("verdict", {}).get("value", "not_enough_data")}


def claim_problem(sentence: str, refs: list[str], digest: dict) -> str | None:
    index = reference_index(digest)
    if any(ref not in index for ref in refs):
        return "unknown reference"
    if hostile_seen(sentence):
        return "hostile instructions or markup"
    without_placeholders = PLACEHOLDER.sub("", sentence)
    if re.search(r"\d", without_placeholders):
        return "invented literal number or version; use code placeholders"
    placeholders = PLACEHOLDER.findall(sentence)
    if any(name not in placeholder_values(digest, refs) for name in placeholders):
        return "unknown numeric or factual placeholder"
    if "{" in PLACEHOLDER.sub("", sentence) or "}" in PLACEHOLDER.sub("", sentence):
        return "malformed placeholder"
    severities = set(re.findall(r"\b(high|medium|low)\b", sentence.lower()))
    allowed_severities = set()
    for ref in refs:
        value = index[ref]
        if value.get("severity"):
            allowed_severities.add(value["severity"])
        if "risk" in value:
            allowed_severities.update(s for s in WEIGHTS if value["risk"].get(s, 0))
    # This one reviewed sentence DEFINES all priority labels; it does not say
    # that this scan contains all three. No arbitrary prose gets this exception.
    definition = sentence == SEVERITY_EXPLANATION and refs == ["S:scan"]
    if severities - allowed_severities and not definition:
        return "severity contradicts cited data"
    verdict_words = set(re.findall(r"\b(?:improving|worse|stable|mixed|not_enough_data)\b", sentence.lower()))
    allowed = {(c["text"], tuple(c["refs"])) for c in approved_claims(digest)}
    # An approved comparison can say "got worse" without asserting that the
    # overall verdict is worse. Only uncatalogued verdict claims need this test.
    if (verdict_words and (sentence, tuple(refs)) not in allowed
            and verdict_words != {digest.get("verdict", {}).get("value")}):
        return "verdict contradicts code"
    if (sentence, tuple(refs)) not in allowed:
        return "unsupported claim; not in the code-approved sentence catalog"
    return None


def fill_sentence(sentence: str, refs: list[str], digest: dict) -> str:
    values = placeholder_values(digest, refs)
    return PLACEHOLDER.sub(lambda match: str(values[match.group(1)]), sentence)


def check_output(raw: str | dict, digest: dict) -> CheckedOutput:
    output = copy.deepcopy(parse_output(raw))
    dropped, total, verified = [], 0, 0

    def inspect(sentence, refs, path):
        nonlocal total, verified
        total += 1
        problem = claim_problem(sentence, refs, digest)
        if problem:
            dropped.append({"claim": path, "reason": problem})
            return None
        verified += 1
        return fill_sentence(sentence, refs, digest)

    headline = output["headline"]
    headline["text"] = inspect(headline["text"], headline["refs"], "headline") or "Unverified headline removed."
    kept = []
    previous_weight = float("inf")
    prioritized_rules = set()
    index = reference_index(digest)
    for priority in output["priorities"]:
        action = inspect(priority["action"], priority["refs"], f"priority {priority['rank']} action")
        why = inspect(priority["why"], priority["refs"], f"priority {priority['rank']} why")
        group = next((index[r] for r in priority["refs"] if r in index and "rule" in index[r]), {})
        weight = WEIGHTS.get(group.get("severity"), 0)
        if weight > previous_weight:
            dropped.append({"claim": "priority order", "reason": "lower severity ranked before higher severity"})
        previous_weight = weight
        if action and why:
            prioritized_rules.add(group.get("rule"))
            kept.append({**priority, "rank": len(kept) + 1, "action": action, "why": why})
    output["priorities"] = kept
    if any(g["rule"] not in prioritized_rules for g in latest_digest(digest)["findings"] if g["severity"] == "high"):
        dropped.append({"claim": "high finding coverage", "reason": "a recorded high-severity rule was omitted"})
    for key in ("next_steps", "notes"):
        kept = []
        for i, item in enumerate(output[key], 1):
            sentence = inspect(item["text"], item["refs"], f"{key} {i}")
            if sentence:
                kept.append({**item, "text": sentence})
        output[key] = kept
    return CheckedOutput(output, verified, total, dropped)


# These are defensive tripwires, not a semantic proof of arbitrary wording.
RULE_SIGNALS = {
    r"\bdatabase\b|\bstored\s+data\b": {"ports.database_exposed"},
    r"\bremote\s+desktop\b|\bRDP\b|\bcomputer.s\s+desktop\b": {"ports.remote_desktop_exposed"},
    r"\bSMB\b|\bfile.sharing\b|\bshared\s+files\b": {"ports.smb_exposed"},
    r"\bTelnet\b": {"ports.telnet_exposed"},
    r"\bFTP\b": {"ports.ftp_exposed"},
    r"\bSSH\b": {"ports.ssh_exposed", "ports.telnet_exposed"},
    r"\badministration\s+(?:page|interface|service)\b": {"ports.admin_interface_exposed", "ports.ssh_exposed", "ports.telnet_exposed"},
    r"\bHSTS\b": {"headers.missing_hsts", "headers.weak_hsts"},
    r"\bCSP\b|\bcontent\s+security\s+policy\b": {"headers.missing_csp", "headers.weak_csp", "headers.missing_clickjacking_protection"},
    r"\bsecurity\s+headers\b": {"headers.missing_hsts", "headers.weak_hsts", "headers.missing_csp", "headers.weak_csp",
        "headers.missing_x_content_type_options", "headers.missing_clickjacking_protection", "headers.missing_referrer_policy", "headers.missing_permissions_policy"},
    r"\bexpired\s+(?:website\s+)?certificate\b|\bcertificate\s+(?:has|is|already)\s+expired\b": {"https.cert_expired"},
}
RAW_FACT_COUNT = re.compile(r"\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|hundred|thousand|million)\b"
                            r"(?:\s+of\s+(?:your|the|these))?\s+(?:hosts?|servers?|sites?|pages?|findings?|ports?|accounts?|records?|days?|hours?|weeks?|seconds?)\b", re.I)
RAW_HOST_OR_RULE = re.compile(r"\b[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]+)+\b", re.I)
COMMAND_TEXT = re.compile(r"```|\b(?:curl|wget|nmap|subfinder|sudo|powershell|bash|sh)\s+(?:-|/)|"
                           r"\bexposureiq\s+(?:scan|diff|scope|run)\b|"
                          r"\b(?:run|execute|paste|type)\b.{0,30}\b(?:command|script|shell|payload)\b|"
                          r"\b(?:os\.system|subprocess|eval\(|exec\()", re.I)
ACTING_CLAIM = re.compile(r"\bI\s+(?:have|just|already|will)\b.{0,35}\b(?:scanned|scan|fixed|fix|ran|execute|contacted|changed|updated|deleted)\b|"
                          r"\bI.ve\s+(?:scanned|fixed|run|changed|updated|contacted)\b", re.I)
DAMAGE_FACT = re.compile(r"\b(?:was|were|has\s+been|have\s+been|is|are|got)\s+(?:already\s+)?(?:hacked|breached|compromised|stolen|leaked|deleted|infected)\b|"
                         r"\b(?:someone|an\s+attacker|attackers?)\s+(?:did|has|have|stole|deleted|accessed)\b|"
                         r"\b(?:will|definitely|certainly|guaranteed\s+to)\b.{0,45}\b(?:steal|lose|leak|delete|break\s+in|take\s+control|disrupt)\b", re.I)
ABSOLUTE_SAFETY = re.compile(r"\b(?:everything|every\s+(?:host|system)|all\s+(?:hosts|systems))\b.{0,30}\b(?:safe|secure|fixed)\b|"
                            r"\b(?:no\s+(?:risk|chance\s+of\s+(?:a\s+)?break.in)|guaranteed\s+safe)\b|"
                            r"\b(?:no|nothing)\b.{0,25}\b(?:needs?\s+fixing|to\s+worry\s+about)\b", re.I)
CONDITIONAL = re.compile(r"\b(?:if|may|might|could|would|depends|possible|whether|not|cannot|can't|doesn't|don't|isn't|aren't)\b", re.I)
UNSUPPORTED_SPECIFIC = re.compile(r"\bCVE\b|\bransomware\b|\b(?:customer\s+passwords?|credit.card\s+(?:details|data)|bank\s+(?:details|accounts))\b", re.I)


def _cited_rules(refs: list[str], index: dict, plan: dict) -> set[str]:
    rules = {index[ref]["rule"] for ref in refs if ref in index and "rule" in index[ref]}
    if "S:scan" in refs or (plan.get("host") and "H:" + plan["host"] in refs):
        rules.update(group["rule"] for group in plan["groups"])
    return rules


def chat_claim_problem(sentence: str, refs: list[str], digest: dict, plan: dict, index: dict | None = None) -> str | None:
    """Check bounded properties of a model paragraph, NOT its full meaning."""
    from exposureiq.ai.policy import OFFENSIVE, OFF_TOPIC, PRIVATE

    index = index or reference_index(digest)
    if any(ref not in index for ref in refs):
        return "unknown reference"
    if any(ref not in plan["allowed_refs"] for ref in refs):
        return "reference outside the code-selected answer context"
    if hostile_seen(sentence):
        return "hostile instructions or markup"
    from exposureiq.ai.fixes import RECHECK

    # One fixed, reviewed reminder is text for an authorized human, not a tool
    # action. No arbitrary command string gets this narrow exception.
    safe_reminder = plan["kind"] == "confirm" and sentence == RECHECK
    if not safe_reminder and (OFFENSIVE.search(sentence) or OFF_TOPIC.search(sentence) or PRIVATE.search(sentence) or COMMAND_TEXT.search(sentence) or ACTING_CLAIM.search(sentence)):
        return "unsafe, off-topic or acting instructions"
    plain = PLACEHOLDER.sub("", sentence)
    if re.search(r"\d", plain) or RAW_FACT_COUNT.search(plain):
        return "literal factual number or version; use code-filled placeholders"
    if RAW_HOST_OR_RULE.search(plain):
        return "literal host or rule fact; use code-filled placeholders"
    values = fact_values(digest, refs[0], index, mode=plan["mode"])
    if any(name not in values for name in PLACEHOLDER.findall(sentence)):
        return "unknown factual placeholder for the primary reference"
    if "{" in plain or "}" in plain:
        return "malformed placeholder"
    if plan["scope"] != "scan" and any(name in ("high_count", "medium_count", "low_count", "host_count", "ip_count", "risk_score", "risk_per_host") for name in PLACEHOLDER.findall(sentence)):
        return "whole-scan fact in a focused host or finding reply"
    for piece in re.split(r"(?<=[.!?])\s+", plain):
        if ABSOLUTE_SAFETY.search(piece) and not re.search(r"\b(?:not|cannot|can't|doesn't|don't|isn't|aren't)\b", piece, re.I):
            return "unsupported assurance of safety or completion"
        if DAMAGE_FACT.search(piece) and not CONDITIONAL.search(piece):
            return "unsupported observed incident or certain damage"
        if UNSUPPORTED_SPECIFIC.search(piece) and not re.search(r"\b(?:not|cannot|can't|doesn't|don't|whether)\b", piece, re.I):
            return "unsupported vulnerability or sensitive-data detail"
    rules = _cited_rules(refs, index, plan)
    definition = plan["kind"] in ("app", "scope", "severity", "headers") or bool(plan.get("term"))
    if not definition:
        for pattern, needed in RULE_SIGNALS.items():
            if re.search(pattern, plain, re.I) and not rules.intersection(needed):
                return "security explanation is not supported by the cited rule"
    allowed_severities = {index[ref]["severity"] for ref in refs if index[ref].get("severity")}
    if refs[0].startswith("H:"):
        allowed_severities.update(level for level in WEIGHTS if index[refs[0]].get(level))
    if "S:scan" in refs:
        allowed_severities.update(level for level in WEIGHTS if latest_digest(digest)["risk"].get(level))
    levels = set(re.findall(r"\b(high|medium|low)\b", plain.lower()))
    if levels - allowed_severities and not definition:
        return "severity contradicts cited data"
    labels = re.findall(r"\b(?:is|are|as|priority)\s+(?:an?\s+)?(urgent|important|minor)\b(?!\s+to\b)", plain, re.I)
    label_levels = {"urgent": "high", "important": "medium", "minor": "low"}
    if {label_levels[label.lower()] for label in labels} - allowed_severities and not definition:
        return "priority label contradicts cited data"
    if re.search(r"\bmost\s+exposed\b|\bhighest\s+(?:recorded\s+)?(?:exposure\s+)?score\b", plain, re.I):
        top = latest_digest(digest).get("top_hosts", [])
        if not top or index[refs[0]].get("host") != top[0]["host"]:
            return "most-exposed claim contradicts code-selected host"
    if re.search(r"\b(?:fix|address|prioriti[sz]e|review)\b.{0,180}\b(?:before|ahead\s+of)\b", plain, re.I):
        mentioned = []
        for pattern, needed in RULE_SIGNALS.items():
            match = re.search(pattern, plain, re.I)
            positions = [position for position, group in enumerate(plan["groups"]) if group["rule"] in needed]
            if match and positions:
                mentioned.append((match.start(), min(positions)))
        positions = [position for _, position in sorted(mentioned)]
        if positions != sorted(positions):
            return "prose priority order contradicts code-selected priorities"
    verdict_words = set(re.findall(r"\b(improving|worse|stable|mixed|not_enough_data)\b", plain.lower()))
    if verdict_words and re.search(r"\b(?:verdict|trend|overall|history)\b", plain, re.I):
        if verdict_words != {digest.get("verdict", {}).get("value")}:
            return "verdict contradicts code"
    if re.search(r"\b(?:all|every)\s+(?:your\s+)?(?:hosts?|sites?|servers?|pages?)\b", plain, re.I):
        primary = index[refs[0]]
        if primary.get("hosts") != latest_digest(digest)["hosts"]:
            return "unsupported all-hosts claim"
    return None


def check_chat_output(raw: str | dict, digest: dict, plan: dict) -> CheckedOutput:
    output, index = copy.deepcopy(parse_output(raw)), reference_index(digest)
    dropped, verified, total = [], 0, 0

    def inspect(sentence, refs, path):
        nonlocal total, verified
        total += 1
        problem = chat_claim_problem(sentence, refs, digest, plan, index)
        if problem:
            dropped.append({"claim": path, "reason": problem})
            return "Unverified wording removed."
        verified += 1
        values = fact_values(digest, refs[0], index, mode=plan["mode"])
        return PLACEHOLDER.sub(lambda match: str(values[match.group(1)]), sentence)

    headline = output["headline"]
    headline["text"] = inspect(headline["text"], headline["refs"], "headline")
    expected = plan["priority_refs"] if plan["list_requested"] else []
    if len(output["priorities"]) != len(expected):
        dropped.append({"claim": "priority selection", "reason": "chat list differs from the code-selected priorities"})
    for position, item in enumerate(output["priorities"]):
        if position >= len(expected) or item["refs"] != expected[position]:
            dropped.append({"claim": "priority order", "reason": "chat list differs from the code-selected priority order"})
        for key in ("action", "why"):
            item[key] = inspect(item[key], item["refs"], f"priority {position + 1} {key}")
    for key in ("notes", "next_steps"):
        for position, item in enumerate(output[key], 1):
            item["text"] = inspect(item["text"], item["refs"], f"{key} {position}")
    used = set(headline["refs"])
    used.update(ref for item in [*output["priorities"], *output["notes"], *output["next_steps"]] for ref in item["refs"])
    if plan["scope"] != "scan" and plan["groups"] and not used.intersection(set(plan["allowed_refs"]) - {"S:scan"}):
        dropped.append({"claim": "answer focus", "reason": "reply omitted the selected host or finding evidence"})
    return CheckedOutput(output, verified, total, dropped)


def check_model_chat_output(raw: str, digest: dict, plan: dict, pack: dict) -> CheckedOutput:
    """Plain chat first, tolerant legacy JSON too; all kept facts get checked.

    Unknown refs/numbers can remove a sentence. A partial reply is kept only
    when at least three checked sentences still answer the selected intent.
    Known unsafe instructions reject the entire reply, not just one sentence.
    Arbitrary safe-sounding prose is still NOT semantically certified.
    """
    from exposureiq.ai.plain import bind_literals, parse_tagged_output
    from exposureiq.ai.policy import OFFENSIVE, OFF_TOPIC, PRIVATE
    from exposureiq.ai.schema import SchemaError

    if hostile_seen(raw.replace("\n", " ").replace("\r", " ").replace("\t", " ")) or OFFENSIVE.search(raw) or OFF_TOPIC.search(raw) or PRIVATE.search(raw):
        raise SchemaError("The reply contained unsafe instructions or unsupported topics.")
    try:
        output = copy.deepcopy(parse_output(raw))
        structured = True
    except SchemaError:
        output, structured = parse_tagged_output(raw), False
    removed, checked_numbers = [], 0
    claims = [output["headline"], *output["notes"], *output["next_steps"]]
    kept = []
    for position, item in enumerate(claims):
        try:
            sentence, refs, count = bind_literals(item["text"], item["refs"], pack)
        except SchemaError as error:
            removed.append({"claim": "sentence " + str(position + 1), "reason": str(error)})
            continue
        kept.append({"text": sentence, "refs": refs})
        checked_numbers += count
    if not kept:
        raise SchemaError(removed[0]["reason"] if removed else "No referenced sentence survived the facts check.")
    output.update(headline=kept[0], notes=kept[1:], next_steps=[])
    if not structured and plan["list_requested"]:
        from exposureiq.ai.facts import built_in_answer

        output["priorities"] = built_in_answer(pack)["priorities"]
    for priority in output["priorities"]:
        for key in ("action", "why"):
            priority[key], priority["refs"], count = bind_literals(priority[key], priority["refs"], pack)
            checked_numbers += count
    checked = check_chat_output(output, digest, plan)
    checked.checked_numbers = checked_numbers
    checked.removed = removed
    if any(item["claim"] == "sentence 1" for item in removed):
        checked.dropped.append({"claim": "answer lead", "reason": "the answer-first sentence did not pass the saved-fact checks"})
    text = " ".join(item["text"] for item in [checked.output["headline"], *checked.output["notes"], *checked.output["next_steps"]])
    if len(text.split()) > 180:
        checked.dropped.append({"claim": "reply length", "reason": "reply exceeded the short-answer limit"})
    if removed and len(re.findall(r"[.!?](?:\s|$)", text)) < 3:
        checked.dropped.append({"claim": "partial reply", "reason": "too little checked wording remains to answer safely"})
    hints = {"worst_finding": r"\b(?:worst|most\s+(?:serious|severe)|biggest\s+(?:problem|risk))\b",
             "fix_how": r"\b(?:ask|block|restrict|allow|disable|renew|deploy|replace|set|remove|keep|test|check)\b",
             "effort": r"\b(?:minutes|hours|days|effort|planning)\b", "who": r"\b(?:IT|administrator|owner|hosting|developer)\b",
             "opinion": r"\b(?:take|think|recommend|should)\b", "verify": r"\b(?:check|confirm|compare|repeat|verify)\b"}
    hint = hints.get(pack["intent"])
    if hint and not re.search(hint, text, re.I):
        checked.dropped.append({"claim": "answer intent", "reason": "reply did not answer the code-selected kind of question"})
    return checked
