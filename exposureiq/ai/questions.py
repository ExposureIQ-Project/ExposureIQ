"""Small chat presentation selectors, never proof of intent or scan evidence."""

from __future__ import annotations

import re
import unicodedata

FINDING_ID = re.compile(r"\bF-\d{4,}\b", re.I)
IMPACT_QUESTION = re.compile(
    r"\b(?:damage|harm|impact|consequences?|danger(?:ous)?|downtime|disruption)\b|"
    r"\bhow\s+(?:bad|serious)\b|\bwhat\s+(?:can|could|might)\s+(?:go\s+wrong|happen)\b|"
    r"\b(?:can|could|might|would)\b.{0,80}\b(?:affect|steal|leak|lose|loss|control|"
    r"access|disrupt|break.in|breach)\b|"
    r"\bwhat\b.{0,60}\b(?:do|cause)\b.{0,60}\b(?:if|unfixed|fixed|left)\b|"
    r"\b(?:if|when)\b.{0,60}\b(?:not|never|didn.t|don.t|isn.t|aren.t)\b.{0,25}\bfix\w*\b|"
    r"\bwhat\b.{0,40}\bhappen\b.{0,40}\b(?:left|kept|remain)\w*\b",
    re.I,
)
INCIDENT_QUESTION = re.compile(
    r"\b(?:breached|compromised|hacked)\b|"
    r"\b(?:did|has|have|was|were)\b.{0,80}\b(?:steal|stole|stolen|leaked|accessed)\b",
    re.I,
)
FOLLOW_UP = re.compile(
    r"\s*(?:(?:ok(?:ay)?|yes|right|then|and|so|please|thanks)[,\s]+)*"
    r"(?:why(?:\s+is\s+that)?|what\s+(?:does\s+that\s+mean|do\s+you\s+mean)|"
    r"(?:can|could|would)\s+you\s+(?:please\s+)?(?:explain(?:\s+(?:that|it|more))?|"
    r"say\s+(?:that|it)\s+(?:more\s+)?simply|put\s+(?:that|it)\s+in\s+simple\s+words)|"
    r"(?:explain|tell\s+me)\s+more|explain\s+(?:that|it)(?:\s+(?:more|simply))?|"
    r"put\s+(?:that|it)\s+in\s+(?:simple|plain)\s+(?:words|english)|"
    r"say\s+(?:that|it)\s+(?:more\s+)?simply|"
    r"(?:make|keep)\s+(?:that|it)\s+(?:simpler|shorter)|"
    r"(?:in\s+)?(?:simple|simpler|plain)\s+(?:words|english)|"
    r"what\s+about\s+(?:that|it|the\s+other\s+one)|go\s+on|"
    r"what\s+do\s+you\s+think|is\s+that\s+bad|should\s+I\s+worry|"
    r"how\s+long\s+would\s+that\s+take|who\s+should\s+fix\s+it|"
    r"(?:explain\s+)?technically|technical\s+(?:words|details?))\s*[.!?]*\s*",
    re.I,
)
FRIENDLY = re.compile(r"\s*(?:(?:hi|hello|hey)(?:\s+there)?|thanks?(?:\s+you)?|thank\s+you|ok(?:ay)?)[.!?]*\s*", re.I)
OPINION = re.compile(r"\b(?:what\s+do\s+you\s+think|your\s+(?:take|opinion)|should\s+I\s+worry|is\s+that\s+bad)\b", re.I)
WHY_FIRST = re.compile(r"\bwhy\b.{0,65}\b(?:fix|first|priority|prioriti|urgent|important)\w*\b", re.I)
WHOLE_SCAN = re.compile(r"\b(?:whole|entire|overall|everything|all\s+(?:hosts|findings|issues)|this\s+scan|scan\s+overview)\b", re.I)


def friendly_kind(question: str) -> str:
    value = normalize_question(question).strip().lower()
    if not FRIENDLY.fullmatch(value):
        return ""
    if value.startswith(("hi", "hello", "hey")):
        return "greeting"
    if value.startswith(("thank", "thanks")):
        return "thanks"
    return "acknowledgement"


def normalize_question(question: str) -> str:
    value = unicodedata.normalize("NFKC", question)
    return re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", value)


def is_follow_up(question: str) -> bool:
    """Only short, neutral continuations; a prior checked exchange is required."""
    return FOLLOW_UP.fullmatch(normalize_question(question)) is not None


def question_kind(question: str, *, previous_kind: str = "") -> str:
    value = normalize_question(question).lower()
    if friendly_kind(value):
        return friendly_kind(value)
    if OPINION.search(value):
        return "opinion"
    if re.search(r"\bhow\s+long\b|\b(?:time|effort)\s+(?:to|would|will)\s+fix\b", value):
        return "timing"
    if re.search(r"\bwho\b.{0,40}\b(?:fix|own|manage)\w*\b", value):
        return "owner"
    if WHY_FIRST.search(value) or (previous_kind and re.fullmatch(r"(?:then\s+|and\s+|so\s+)?why(?:\s+is\s+that)?[.!?\s]*", value)):
        return "why"
    if previous_kind and is_follow_up(question):
        return previous_kind
    if "cve" in value or "exploitability" in value:
        return "unknown"
    if INCIDENT_QUESTION.search(value):
        return "incident"
    if IMPACT_QUESTION.search(value):
        return "impact"
    if "risk" in value and not re.search(r"score|index|number|measure|calculat", value):
        return "impact"
    for kind, words in (
        ("app", ("exposureiq",)), ("scope", ("scope", "safety boundaries")),
        ("finding", ("f-",)), ("unfixed", ("unfixed",)),
        ("host", ("most exposed",)), ("severity", ("severity",)),
        ("headers", ("security headers",)),
        ("coverage", ("not checked", "wasn't checked", "missing checks", "limitations")),
        ("confirm", ("confirm", "verify a fix")), ("risk", ("risk", "exposure score")),
        ("history", ("history", "changed", "compare", "diff", "trend")),
    ):
        if any(word in value for word in words):
            return kind
    return "overview"


def referenced_finding(question: str, *, previous_id: str = "") -> str:
    value = normalize_question(question)
    requested = FINDING_ID.search(value)
    if requested:
        return requested.group().upper()
    # An explicit whole-scan request must not inherit a single finding.
    if WHOLE_SCAN.search(value):
        return ""
    if previous_id and (is_follow_up(question) or re.search(r"\b(?:it|that|this|them|those)\b", value, re.I)):
        return previous_id
    return ""
