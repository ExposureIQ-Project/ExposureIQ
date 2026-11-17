"""English-first question routes, not a replacement for the safety gate.

An intent is the kind of help requested, such as a fix or a definition. Only
this small vocabulary gets typo correction; hosts, IDs and safety checks do
not. The caller must run policy_gate on the original question first.
"""

from __future__ import annotations

import re
from difflib import get_close_matches

from exposureiq.ai.glossary import requested_term
from exposureiq.ai.questions import friendly_kind, normalize_question

# Earlier entries win. Synonyms are data, not another model request.
INTENTS = (
    ("worst_finding", (r"\bmost\s+bad\b", r"\bworst\b", r"\bmost\s+(?:serious|severe|dangerous)\b",
                       r"\bbiggest\s+(?:problem|issue|risk)\b", r"\b(?:top|strongest)\s+finding\b")),
    ("effort", (r"\bhow\s+long\b", r"\b(?:time|effort)\b.{0,35}\b(?:fix|take|need)\b",
                r"\b(?:minutes|hours|days)\b.{0,25}\b(?:fix|take)\b")),
    ("who", (r"\bwho\b.{0,45}\b(?:fix|own|manage|handle|responsible)\w*\b", r"\bwho\s+should\b")),
    ("verify", (r"\bhow\b.{0,50}\b(?:know|tell|check)\b.{0,30}\b(?:fixed|worked|resolved)\b",
                r"\b(?:verify|confirm|recheck|validate)\b.{0,35}\b(?:fix|change|scan)\w*\b")),
    ("fix_first", (r"\b(?:fix|do|address|deal\s+with)\b.{0,30}\bfirst\b",
                   r"\b(?:prioriti[sz]e|priorities|priority\s+order|fix\s+list)\b")),
    ("fix_how", (r"\bhow\b.{0,35}\b(?:fix|repair|resolve|remediate)\w*\b",
                 r"\bwhat\s+(?:should|can|do)\s+(?:i|we)\s+do\b", r"\b(?:fix|repair)\s+(?:it|that|this)\b")),
    ("opinion", (r"\bwhat\s+do\s+you\s+think\b", r"\byour\s+(?:take|opinion)\b",
                 r"\bshould\s+i\s+worry\b", r"\bis\s+that\s+bad\b")),
    ("consequences", (r"\bwhat\s+(?:can|could|might)\s+(?:happen|go\s+wrong)\b",
                      r"\b(?:consequences?|damage|harm|impact)\b", r"\bhow\s+(?:bad|serious)\b")),
    ("changes", (r"\b(?:changed|history|diff|trend|regression|unfixed)\b", r"\bgot\s+(?:better|worse)\b")),
    ("which_hosts", (r"\b(?:which|what)\s+(?:hosts?|servers?|sites?)\b", r"\bmost\s+exposed\b")),
    ("explain_simple", (r"\bexplain\b", r"\b(?:simple|plain)\s+(?:words|english)\b",
                        r"\b(?:overview|summari[sz]e|summary)\b", r"\bmake\s+(?:it|that)\s+simpler\b")),
)
_COMPILED = tuple((name, tuple(re.compile(p, re.I) for p in patterns)) for name, patterns in INTENTS)
_VOCABULARY = ("finding", "serious", "severe", "dangerous", "biggest", "problem", "repair", "resolve",
               "remediate", "prioritize", "priority", "consequences", "damage", "happen", "explain",
               "simple", "simpler", "technically", "certificate", "database", "history", "changed", "responsible")
_ALIASES = {"posible": "possible", "possiable": "possible", "wrost": "worst", "frist": "first",
            "fixt": "fix", "fixeded": "fixed", "smple": "simple"}


def normalized_intent_question(question: str) -> str:
    value = normalize_question(question).lower()

    def correct(match):
        word = match.group()
        if word in _ALIASES:
            return _ALIASES[word]
        if len(word) >= 6 and word not in _VOCABULARY:
            close = get_close_matches(word, _VOCABULARY, n=1, cutoff=0.88)
            if close:
                return close[0]
        return word

    # Never rewrite a token next to a dot or hyphen (host names and IDs).
    return re.sub(r"(?<![\w.-])[a-z]+(?![\w.-])", correct, value)


def detect_intent(question: str) -> str:
    if friendly_kind(question):
        return "smalltalk"
    value = normalized_intent_question(question)
    if requested_term(value):
        return "explain_term"
    for name, patterns in _COMPILED:
        if any(pattern.search(value) for pattern in patterns):
            return name
    return "unknown"


def resolve_reference(question: str, previous: dict) -> tuple[str, str, str]:
    """Return an existing finding/host or one clarification; never guess an ID."""
    value = normalized_intent_question(question)
    findings = previous.get("listed_findings") or previous.get("discussed_findings", previous.get("alternatives", []))
    findings = [ref for ref in findings if isinstance(ref, str) and ref.startswith("F-")]
    ordinal = re.search(r"\b(?:the\s+)?(first|second|third)\s+one\b", value)
    if ordinal:
        position = ("first", "second", "third").index(ordinal[1])
        if position < len(findings):
            return findings[position], "", ""
        return "", "", "Which saved finding do you mean? Use its finding ID."
    if re.search(r"\b(?:the\s+)?other\s+one\b", value):
        current = previous.get("finding_id", "") or (findings[0] if findings else "")
        others = [ref for ref in findings if ref != current]
        if len(others) == 1:
            return others[0], "", ""
        return "", "", "Which saved host or finding do you mean? You can use its name or finding ID."
    if re.search(r"\bthat\s+host\b", value):
        return "", previous.get("host", ""), ""
    # A scan-wide overview has several themes, not a single implied finding.
    return previous.get("finding_id", ""), previous.get("host", ""), ""
