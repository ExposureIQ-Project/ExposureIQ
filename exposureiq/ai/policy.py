"""Deterministic pre-model boundaries and a bounded per-service request rate.

This gate catches obvious requests, not every possible euphemism. Natural chat
also checks known unsafe output patterns; it does not prove arbitrary wording
safe. The hard boundary is that no acting tools or target traffic are available.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone

from exposureiq.ai.prompts import PROMPT_VERSION
from exposureiq.ai.glossary import requested_term
from exposureiq.ai.intents import detect_intent
from exposureiq.ai.questions import IMPACT_QUESTION, INCIDENT_QUESTION, WHY_FIRST, friendly_kind, is_follow_up, normalize_question

MAX_MESSAGE_CHARS = 1000
REQUESTS_PER_MINUTE = 8
RATE_WINDOW_SECONDS = 60
PRIVATE = re.compile(r"(?:reveal|show|print|repeat|leak|tell|give).{0,50}(?:system\s*prompt|your\s*prompt|api\s*key|secret|private\s*instructions)|"
                      r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|ignore\s+(?:all\s+)?(?:your\s+)?rules", re.I)
OFFENSIVE = re.compile(r"payload|reverse\s+shell|brute.?force|credential\s*dump|"
                       r"break\s*(?:in|into)|bypass\s*(?:auth|login)|"
                       r"(?:how\s+to|how\s+(?:do|does|can|could|would|should)\s+"
                       r"(?:i|we|you|someone|(?:an?|the)\s+(?:attacker|hacker))|"
                       r"steps|instructions|teach|show|write|generate).{0,60}(?:exploit|hack|attack)|"
                       r"(?:exploit|hack|attack).{0,40}(?:steps|instructions|command|code|script)|"
                       r"sql\s*injection.{0,40}(?:example|execute|command)|"
                       r"^\s*(?:please\s+)?(?:steal|exfiltrate|damage)\b|"
                       r"(?:how\s+to|how\s+(?:do|does|can|could|would|should)\s+"
                       r"(?:i|we|you|someone|(?:an?|the)\s+(?:attacker|hacker))|"
                       r"steps|instructions|teach|show|write|generate|help\s+me|"
                       r"(?:can|could|would)\s+you).{0,60}\b(?:steal|exfiltrate|cause\s+(?:damage|harm))\b|"
                       r"\bwhat\s+(?:damage|harm).{0,40}\b(?:i|we|you)\b.{0,20}\b(?:do|cause|make)\b", re.I)
OFF_TOPIC = re.compile(r"weather|recipe|cook|football|soccer|basketball|politic|election|"
                       r"write\s+(?:a\s+)?(?:poem|story|song)|movie|horoscope|stock\s*price|"
                       r"capital\s+of|meaning\s+of\s+life", re.I)
IN_SCOPE = re.compile(r"scan|exposureiq|finding|\bF-\d{4,}\b|host|domain|risk|fix|defens|harden|"
                      r"prioriti|expos|port|certificat|https|header|csp|hsts|technolog|version|"
                       r"history|diff|regression|unfixed|improv|worse|stable|mixed|verdict|trend|cve|scope|safety|"
                       r"what\s+(?:changed|got\s+better|got\s+worse)|remediat", re.I)
ACTIVE_REQUEST = re.compile(r"\b(?:scan|probe|contact|crawl|run\s+(?:a\s+)?scan)\b.{0,55}\b(?:another|other|new|these|this|the)\s+(?:hosts?|servers?|targets?|domains?)\b|"
                            r"\b(?:add|remove|change|edit|expand|update)\b.{0,35}\bscope\b|"
                            r"\b(?:scan|probe)\s+(?:https?://)?[a-z0-9][a-z0-9.-]+\.[a-z]{2,}\b", re.I)


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str = ""
    reply: str = ""


def policy_gate(question: str, *, has_context: bool = False) -> GateDecision:
    if not isinstance(question, str) or not question.strip():
        raise ValueError("Enter a nonempty question.")
    if len(question) > MAX_MESSAGE_CHARS:
        raise ValueError("Questions must be at most 1000 characters.")
    normalized = normalize_question(question)
    if PRIVATE.search(normalized):
        return GateDecision(False, "private instructions or credentials", "I can't reveal private instructions or credentials; I can explain the safety boundaries.")
    if OFFENSIVE.search(normalized):
        return GateDecision(False, "offensive request", "I can't help with attack steps or payloads; I can explain the recorded risks and defensive fixes.")
    if ACTIVE_REQUEST.search(normalized):
        return GateDecision(False, "active request", "I can't scan targets or change scope. I can explain a saved scan or discuss defensive fixes.")
    if friendly_kind(normalized):
        return GateDecision(True)
    relevant = (IN_SCOPE.search(normalized) or IMPACT_QUESTION.search(normalized)
                  or INCIDENT_QUESTION.search(normalized) or WHY_FIRST.search(normalized) or requested_term(normalized)
                  or detect_intent(normalized) in ("worst_finding", "fix_first")
                  or (has_context and detect_intent(normalized) in ("effort", "who", "verify", "opinion", "fix_how", "which_hosts"))
                  or (has_context and is_follow_up(normalized)))
    if OFF_TOPIC.search(normalized) or not relevant:
        return GateDecision(False, "off-topic request", "I can help with your saved scans, ExposureIQ and defensive fixes. Try asking what matters most or how to fix a saved finding.")
    return GateDecision(True)


class RateLimiter:
    def __init__(self, limit: int = REQUESTS_PER_MINUTE, *, clock=time.monotonic):
        self.limit, self.clock = limit, clock
        self.calls = deque()
        self.lock = threading.Lock()

    def acquire(self) -> bool:
        with self.lock:
            now = self.clock()
            while self.calls and self.calls[0] <= now - RATE_WINDOW_SECONDS:
                self.calls.popleft()
            if len(self.calls) >= self.limit:
                return False
            self.calls.append(now)
            return True


class RateLimitError(RuntimeError):
    pass


def refusal_result(decision: GateDecision, *, reason: str = "") -> dict:
    return {"draft": "AI draft", "headline": {"text": decision.reply, "refs": []},
            "priorities": [], "next_steps": [], "notes": [], "verified": 0, "total": 0,
            "dropped": [], "model": "Policy gate (no model call)", "prompt_version": PROMPT_VERSION,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "elapsed": 0,
            "source": "policy", "reason": reason or decision.reason, "cache_hit": False,
            "hostile_text_seen": False, "policy_refusal": True}
