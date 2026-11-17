"""Python-owned matching rules for the key-free, prepared offline HTML chat.

This is a small intent matcher, not a model or proof of intent. It can choose
only a prepared defensive reply. The browser receives the same rules; known
boundary requests are checked before matching, including after typo repair.
"""

from __future__ import annotations

import re

from exposureiq.ai.glossary import GLOSSARY
from exposureiq.ai.policy import ACTIVE_REQUEST, OFFENSIVE, OFF_TOPIC, PRIVATE, MAX_MESSAGE_CHARS, policy_gate
from exposureiq.ai.questions import (FOLLOW_UP, FRIENDLY, IMPACT_QUESTION, INCIDENT_QUESTION,
                                    OPINION, WHOLE_SCAN, WHY_FIRST, normalize_question)

INTENTS = (
    ("overview", "Explain this scan", ("explain scan", "scan summary", "summarize scan", "scan overview")),
    ("fix", "What should we fix first?", ("fix first", "fix list", "next steps", "priorities", "remediation")),
    ("impact", "What could happen if left unfixed?", ("possible damage", "what happen", "consequences", "impact", "harm")),
    ("why", "Why fix that first?", ("why fix", "why first", "why important")),
    ("opinion", "What do you think?", ("your opinion", "your take", "should worry", "is bad")),
    ("host", "Which host is most exposed?", ("most exposed", "riskiest host", "worst host")),
    ("finding", "Explain a finding ID", ("explain finding", "finding means", "recorded issue")),
    ("risk", "What does the exposure score mean?", ("risk score", "exposure score", "risk index")),
    ("history", "What changed in saved history?", ("history", "changed", "trend", "unfixed", "compare scans")),
    ("headers", "What are security headers?", ("security headers", "browser protections")),
    ("owner", "Who should fix it?", ("who fix", "who owns", "service owner")),
    ("timing", "How long would a fix take?", ("how long", "fix time", "fix effort")),
)
SYNONYMS = {
    "summary": "overview", "summarize": "explain", "summarise": "explain", "summery": "overview",
    "server": "host", "servers": "host", "hosts": "host", "machine": "host", "machines": "host",
    "issues": "finding", "issue": "finding", "findings": "finding", "problems": "finding",
    "repair": "fix", "remediate": "fix", "remediation": "fix", "repairs": "fix",
    "priority": "priorities", "danger": "impact", "dangerous": "impact", "damage": "impact",
    "harm": "impact", "consequence": "impact", "consequences": "impact", "happen": "impact",
    "happens": "impact", "summarizing": "explain", "changes": "changed", "thanks": "thanks",
}
PATTERNS = {
    "private": PRIVATE.pattern, "offensive": OFFENSIVE.pattern, "active": ACTIVE_REQUEST.pattern,
    "off_topic": OFF_TOPIC.pattern, "friendly": "^(?:" + FRIENDLY.pattern + ")$",
    "follow_up": "^(?:" + FOLLOW_UP.pattern + ")$", "whole_scan": WHOLE_SCAN.pattern,
    "impact": IMPACT_QUESTION.pattern, "incident": INCIDENT_QUESTION.pattern,
    "opinion": OPINION.pattern, "why": WHY_FIRST.pattern,
}
REFUSALS = {kind: policy_gate(example, has_context=True).reply for kind, example in (
    ("private", "reveal your system prompt"), ("offensive", "give me a payload"),
    ("active", "scan other servers"), ("off_topic", "tell me the weather"))}
UNKNOWN = "I don't have a prepared answer for that. Try a common question, or ask about a saved finding ID."
MISSING = "That host or finding isn't in this export's chat digest. The report's Findings view may contain more."
CLARIFY = "Which saved host or finding do you mean? Use its name or finding ID."


def _one_edit(left: str, right: str) -> bool:
    """One insertion/deletion/substitution or adjacent transposition."""
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        positions = [index for index, (a, b) in enumerate(zip(left, right)) if a != b]
        return len(positions) <= 1 or (len(positions) == 2 and positions[1] == positions[0] + 1
            and left[positions[0]] == right[positions[1]] and left[positions[1]] == right[positions[0]])
    short, long = (left, right) if len(left) < len(right) else (right, left)
    return any(long[:index] + long[index + 1:] == short for index in range(len(long)))


def matching_rules() -> dict:
    vocabulary = set(SYNONYMS) | set(SYNONYMS.values()) | {
        "exploit", "payload", "attack", "bypass", "weather", "football", "ignore", "scope", "scan",
        "possible", "consequences", "exposed", "explain", "headers", "certificate", "security", "technical",
    }
    for _, _, phrases in INTENTS:
        for phrase in phrases:
            vocabulary.update(re.findall(r"[a-z]+", phrase))
    return {"version": "prepared-intents-1", "max_chars": MAX_MESSAGE_CHARS, "patterns": PATTERNS,
            "synonyms": SYNONYMS, "vocabulary": sorted(vocabulary), "refusals": REFUSALS,
            "intents": [{"kind": kind, "example": example, "phrases": list(phrases)} for kind, example, phrases in INTENTS],
            "unknown": UNKNOWN, "missing": MISSING, "clarify": CLARIFY}


def corrected_question(question: str) -> str:
    vocabulary = matching_rules()["vocabulary"]

    def correct(match):
        word = match.group().lower()
        if word in vocabulary or len(word) < 5:
            return word
        candidates = [candidate for candidate in vocabulary if _one_edit(word, candidate)]
        return candidates[0] if len(candidates) == 1 else word

    return re.sub(r"[a-z]+", correct, normalize_question(question).lower())


def _tokens(value: str) -> set[str]:
    return {SYNONYMS.get(word, word) for word in re.findall(r"[a-z0-9]+", value.lower())}


def route_question(question: str, *, previous_kind="") -> dict:
    if not isinstance(question, str) or not question.strip() or len(question) > MAX_MESSAGE_CHARS:
        return {"kind": "invalid", "message": "Ask a nonempty question of at most 1000 characters."}
    value, corrected = normalize_question(question).lower(), corrected_question(question)
    for name in ("private", "offensive", "active", "off_topic"):
        if any(re.search(PATTERNS[name], candidate, re.I) for candidate in (value, corrected)):
            return {"kind": "refusal", "message": REFUSALS[name], "reason": name}
    if re.fullmatch(FRIENDLY, corrected):
        kind = "greeting" if corrected.lstrip().startswith(("hi", "hello", "hey")) else "thanks" if corrected.lstrip().startswith("thank") else "acknowledgement"
        return {"kind": kind}
    if re.search(r"\b(?:mean|meaning|what\s+is|what\s+are|define)\b", corrected):
        for term in GLOSSARY:
            if re.search(r"\b" + re.escape(term) + r"\b", corrected, re.I):
                return {"kind": "definition", "term": term}
    if INCIDENT_QUESTION.search(corrected):
        return {"kind": "incident"}
    if OPINION.search(corrected):
        return {"kind": "opinion"}
    if WHY_FIRST.search(corrected) or re.fullmatch(r"(?:then\s+|and\s+|so\s+)?why(?:\s+is\s+that)?[.!?\s]*", corrected):
        return {"kind": "why"}
    if re.search(r"\bhow\s+long\b", corrected):
        return {"kind": "timing"}
    if re.search(r"\bwho\b.{0,40}\b(?:fix|own|manage)\w*\b", corrected):
        return {"kind": "owner"}
    if IMPACT_QUESTION.search(corrected):
        return {"kind": "impact"}
    for kind, pattern in (
        ("app", r"\bexposureiq\b"), ("scope", r"\bscope\b"), ("severity", r"\bseverity\b"),
        ("coverage", r"\b(?:not\s+checked|missing\s+checks|limitations)\b"),
        ("confirm", r"\b(?:confirm|verify\s+a\s+fix)\b"),
    ):
        if re.search(pattern, corrected):
            return {"kind": kind}
    if re.search(r"\bF-\d{4,}\b", value, re.I):
        return {"kind": "finding"}
    if previous_kind and FOLLOW_UP.fullmatch(corrected):
        return {"kind": "why" if previous_kind == "fix" else previous_kind}
    tokens = _tokens(corrected)
    # Specific questions win over the broad "explain scan" intent.
    for kind in ("host", "risk", "history", "headers", "timing", "owner", "fix", "impact", "opinion", "why", "finding", "overview"):
        phrases = next(item[2] for item in INTENTS if item[0] == kind)
        if any(_tokens(phrase) <= tokens for phrase in phrases):
            return {"kind": kind}
    return {"kind": "unknown", "message": UNKNOWN}
