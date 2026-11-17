"""Shared orchestration: read → group → prioritize → verify → display or fallback.

UI/CLI/web callers use this service, not the provider directly. Audit entries
stay in memory, contain the actual redacted request data and returned content,
and exclude system prompts and credentials. Disposable summary caches contain
only structured claims, never conversation or API logs.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone

from exposureiq.ai.checker import check_output
from exposureiq.ai.config import AIConfig, ConfigError, load_config, validate_config
from exposureiq.ai.fallback import template_summary
from exposureiq.ai.prompts import PROMPT_VERSION, repair_message, summary_messages
from exposureiq.ai.policy import RateLimiter, RateLimitError, policy_gate, refusal_result
from exposureiq.ai.questions import question_kind, referenced_finding
from exposureiq.ai.provider import OpenAIProvider, ProviderError, make_provider
from exposureiq.ai.sanitize import compact_json, redact
from exposureiq.ai.schema import SchemaError, parse_output
from exposureiq.insight.cache import get_cached, put_cached, summary_key
from exposureiq.insight.digest import rule_title, scan_digest
from exposureiq.insight.history_digest import history_facts

STAGES = ("Reading scan", "Grouping findings", "Prioritizing", "Verifying claims")
MAX_AUDIT_ENTRIES = 30


class NotConfigured(ConfigError):
    pass


class AIUnavailable(RuntimeError):
    """A safe error for callers that explicitly disabled template fallback."""


class AIService:
    def __init__(self, config: AIConfig | None = None, *, provider=None, use_cache: bool = True):
        self.config = config
        self.provider = provider
        self.use_cache = use_cache
        self.audit: list[dict] = []
        self._audit_lock = threading.Lock()
        self.limiter = RateLimiter()

    def _configuration(self):
        try:
            return validate_config(self.config if self.config is not None else load_config())
        except ConfigError:
            return AIConfig()

    def _log(self, messages, response, config, *, purpose="summary", dropped=None, error="", error_kind="", attempt=1):
        sent = [copy.deepcopy(m) for m in messages if m.get("role") != "system"]
        private = []
        for message in messages:
            if message.get("role") == "system":
                content = message.get("content", "")
                private += [content, redact(content), *[line.strip() for line in content.splitlines() if len(line.strip()) >= 20]]
                private += [piece.strip() for piece in re.split(r"(?<=[.!?])\s+|\n", content) if len(piece.strip()) >= 16]
        content = response.get("content", "") if isinstance(response, dict) else response
        content = content if isinstance(content, str) else ""
        safe_content = redact(content, (config.key, config.api_key, *private))
        entry = redact({"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         "purpose": purpose, "model": config.model, "prompt_version": PROMPT_VERSION,
                          "sent": sent, "received": response, "dropped": dropped or [], "error": error, "error_kind": error_kind,
                          "response_length": len(content), "response_preview": safe_content[:300],
                          "parse_error": error if error_kind in ("invalid", "empty", "incomplete") else "",
                          "attempt": attempt, "attempt_failed": bool(error)},
                       (config.key, config.api_key, *private))
        with self._audit_lock:
            self.audit.append(entry)
            del self.audit[:-MAX_AUDIT_ENTRIES]
        return entry

    def call(self, provider, messages, config, *, purpose="summary", tools=None, attempt=1):
        if isinstance(provider, OpenAIProvider):
            # Count actual HTTP attempts, including retries, across all views.
            provider.limiter = self.limiter
        elif not self.limiter.acquire():
            raise RateLimitError("AI request limit reached. Wait one minute before trying again.")
        try:
            response = provider.complete(redact(messages, (config.key, config.api_key)), tools=tools)
            if not isinstance(response.content, str) or not isinstance(response.tool_calls, list):
                raise ProviderError(kind="invalid")
        except RateLimitError:
            if getattr(provider, "attempts", 0):
                self._log(messages, "", config, purpose=purpose,
                          error="AI transport retry stopped by the shared rate limit; no extra HTTP request ran.", attempt=attempt)
            raise
        except ProviderError as error:
            # Only code-owned error categories survive, never arbitrary text
            # attached to an injected provider exception or HTTP error body.
            safe = ProviderError(kind=error.kind)
            self._log(messages, "", config, purpose=purpose, error=safe.safe_message, error_kind=safe.kind, attempt=attempt)
            raise safe from None
        except Exception:
            self._log(messages, "", config, purpose=purpose,
                        error="AI request failed; raw exceptions and credential details are suppressed.", error_kind="request", attempt=attempt)
            raise ProviderError("The configured AI request failed. No credential details are shown.") from None
        received = {"content": response.content, "tool_calls": response.tool_calls} if response.tool_calls else response.content
        entry = self._log(messages, received, config, purpose=purpose, attempt=attempt)
        entry["completion_incomplete"] = bool(getattr(response, "incomplete", False))
        entry["transport_attempts"] = getattr(provider, "attempts", 1)
        return response, entry

    def test_connection(self, config: AIConfig | None = None, *, provider=None) -> str:
        """Use the same rate limit and redacted audit as every other AI call."""
        config = validate_config(config or self._configuration(), require_ready=True)
        provider = provider or make_provider(config)
        messages = [{"role": "system", "content": "Connection check only. No scan data is included."},
                    {"role": "user", "content": 'Reply with JSON {"ready":true}.'}]
        response, entry = self.call(provider, messages, config, purpose="connection check")
        try:
            ready = json.loads(response.content) == {"ready": True} and not response.tool_calls
        except (ValueError, TypeError, RecursionError):
            ready = False
        if not ready:
            entry["error"] = "The endpoint replied, but did not confirm the expected connection-check JSON."
            entry["attempt_failed"] = True
            entry["parse_error"] = entry["error"]
            raise ProviderError(entry["error"])
        return ("Demo (offline) is ready. No network was used." if config.mode == "demo" else
                "Connection succeeded. No scan summary was sent.")

    def summary(self, scan_or_digest: dict, *, question="", progress=None, no_fallback=False) -> dict:
        start = time.monotonic()
        progress = progress or (lambda stage: None)
        progress(STAGES[0])
        if question:
            decision = policy_gate(question)
            if not decision.allowed:
                return refusal_result(decision)
        config = self._configuration()
        progress(STAGES[1])
        digest = scan_or_digest if scan_or_digest.get("ref") in ("S:scan", "S:history") else scan_digest(scan_or_digest)
        digest = redact(digest, (config.key, config.api_key))
        progress(STAGES[2])
        source, reason, model = "template", "AI is off or not configured; using a template.", "Template (no AI)"
        safe_question = redact(question, (config.key, config.api_key))
        context = {"kind": question_kind(safe_question), "finding_id": referenced_finding(safe_question)}
        messages = summary_messages(digest, question=safe_question, answer_context=context)
        raw = None
        entry = None
        if no_fallback and not config.ready and self.provider is None:
            raise NotConfigured("AI is not configured. Open AI settings or use --demo.")
        cache_id = hashlib.sha256(compact_json([digest, question, config.mode, config.base_url]).encode("utf-8")).hexdigest()
        cache_key = summary_key(cache_id, config.model, PROMPT_VERSION)
        cached = get_cached("summary", cache_key) if self.use_cache and config.ready else None
        cache_hit = False
        if cached is not None:
            try:
                raw = parse_output(cached)
                cache_hit = True
            except SchemaError:
                raw = None
        if raw is None and (config.ready or self.provider is not None):
            provider = self.provider or make_provider(config)
            model = getattr(provider, "model", config.model)
            try:
                response, entry = self.call(provider, messages, config)
                try:
                    raw = parse_summary_reply(response.content, digest)
                except SchemaError as error:
                    # Never echo malformed model output back as instructions.
                    messages = [*messages, repair_message()]
                    entry["dropped"] = [{"claim": "JSON shape", "reason": "invalid structured JSON; one repair requested"}]
                    entry["parse_error"], entry["attempt_failed"] = str(error), True
                    response, entry = self.call(provider, messages, config, purpose="JSON repair", attempt=2)
                    try:
                        raw = parse_summary_reply(response.content, digest)
                    except SchemaError as error:
                        entry["parse_error"], entry["attempt_failed"] = str(error), True
                        raise
                source, reason = config.mode if config.ready else "fake", ""
            except Exception:
                reason = "AI failed or returned invalid JSON after one repair; using the template."
                if entry is not None:
                    entry["error"] = reason
                if no_fallback:
                    raise AIUnavailable("AI failed; --no-fallback disabled the template.") from None
        elif raw is not None:
            source, reason, model = config.mode, "", config.model
        progress(STAGES[3])
        checked = check_output(raw or template_summary(digest, question=safe_question, answer_context=context), digest)
        rejected = checked.dropped
        if entry is not None:
            entry["dropped"] = copy.deepcopy(rejected)
        if rejected:
            if no_fallback:
                raise AIUnavailable("AI claims were not verified; --no-fallback disabled the template.")
            reason, source = "Unverified claims were rejected; using the code-derived template.", "template"
            checked = check_output(template_summary(digest, question=safe_question, answer_context=context), digest)
            cache_hit = False
        if not checked.accepted:
            raise ValueError("The code-derived summary failed verification.")
        if self.use_cache and source != "template" and raw is not None and not rejected and not cache_hit:
            put_cached("summary", cache_key, raw, secrets=(config.key, config.api_key))
        return {"draft": "AI draft", **checked.output, "verified": checked.verified, "total": checked.total,
                "dropped": rejected, "model": model, "prompt_version": PROMPT_VERSION,
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "elapsed": round(time.monotonic() - start, 3), "source": source, "reason": reason,
                "cache_hit": cache_hit, "hostile_text_seen": bool(digest.get("hostile_text_seen")),
                "answer_kind": context["kind"], "history": history_facts(digest)}


def result_text(result: dict) -> str:
    if result.get("verification") in ("evidence-and-facts", "built-in"):
        lines = [chat_text(result), "", reply_label(result)]
        if result.get("evidence_refs"):
            lines += ["", "Evidence: " + ", ".join(result["evidence_refs"])]
        if result.get("offline_notice"):
            lines += ["", result["offline_notice"]]
        if result.get("failure_kind") and result.get("reason"):
            lines.append("Reply status: " + result["reason"])
        lines.append(verified_footer(result))
        return "\n".join(lines)
    lines = ["AI draft", result["headline"]["text"]]
    if result.get("history"):
        facts = result["history"]
        lines += ["", "HISTORY FACTS (code, not AI)"]
        for direction in ("better", "worse"):
            section = facts[direction]
            lines += [f"{direction.upper()}: {section['count']} observed changes"]
            lines += [f"  {e.get('rule') or e['kind']} on {e['host']} [{e['ref']}]" for e in section["events"]]
            if section["count"] and not section["events"]:
                lines.append("  Detail omitted by the history budget; open the saved differences.")
        for key, title in (("still_unfixed", "STILL UNFIXED"), ("regressions", "REGRESSIONS"),
                           ("fixed", "ABSENT AFTER TWO OBSERVATIONS"), ("new_recently", "NEW RECENTLY")):
            lines.append(title + f": {facts['list_counts'].get(key, 0)}")
            lines += [f"  {i['rule']} on {i['host']} [{i['ref']}]" for i in facts[key]]
        lines += facts["notes"]
        if facts["truncated"]:
            lines.append("History lists/events are shortened; counts include omitted items.")
    lines += ["", "FIX FIRST"]
    for priority in result["priorities"]:
        lines += [f"{priority['rank']}. {priority['action']}", f"   Why: {priority['why']}",
                  "   Refs: " + ", ".join(priority["refs"])]
    lines += ["", "NEXT STEPS"] + [c["text"] + " [" + ", ".join(c["refs"]) + "]" for c in result["next_steps"]]
    lines += ["", "NOTES"] + [c["text"] + " [" + ", ".join(c["refs"]) + "]" for c in result["notes"]]
    if result["reason"]:
        lines.append(result["reason"])
    lines.append(verified_footer(result))
    return "\n".join(lines)


def verified_footer(result: dict) -> str:
    if result.get("verification") == "evidence-and-facts":
        return "Facts checked against your saved scan" if result.get("fact_check_ran") else ""
    if result.get("verification") == "built-in" or result.get("policy_refusal"):
        return ""
    model = "Checked fallback (no AI)" if result.get("source") == "template" else result["model"]
    return (f"verified {result['verified']} of {result['total']} claims · {model} · "
              f"{result['time']}")


def failure_details(error: Exception) -> tuple[str, str]:
    """Only code-owned categories reach chat, never exception/HTTP body text."""
    from exposureiq.ai.tools import ToolError

    if isinstance(error, ProviderError):
        safe = ProviderError(kind=error.kind)
        return safe.kind, safe.safe_message + " I answered from your saved scan."
    if isinstance(error, SchemaError):
        return "reply_format", "The model's reply was not in a usable format, so I answered from your saved scan."
    if isinstance(error, ToolError):
        return "tool", "The model requested an unsupported read-only tool. No extra tool ran; I answered from your saved scan."
    return "request", "The AI request failed, so I answered from your saved scan. Raw errors and credentials are hidden."


def reply_label(result: dict) -> str:
    if result.get("policy_refusal"):
        return "Safety reply · no model call"
    if result.get("source") in ("local", "remote"):
        return "Live AI · " + result.get("model", "configured model")
    return "Built-in answer"


def parse_summary_reply(raw: str, digest: dict) -> dict:
    """Try tolerant JSON, then tagged text; the summary checker stays strict."""
    try:
        return parse_output(raw)
    except SchemaError:
        from exposureiq.ai.plain import parse_tagged_output

        prose = parse_tagged_output(raw)
        # The model can supply only code-approved sentences; code owns the
        # complete ranked list, including every included high-severity rule.
        candidate = template_summary(digest)
        return {**candidate, "headline": prose["headline"], "notes": prose["notes"], "next_steps": prose["next_steps"]}


def chat_text(result: dict) -> str:
    """Friendly chat layout of checked claims and explicitly code-owned history.

    Keep the structured result/citations intact for verification and developers;
    don't repeat report headings, timestamps or internal versions in each turn.
    """
    if result.get("verification") in ("evidence-and-facts", "built-in"):
        lines = [result["headline"]["text"]]
        facts = result.get("history")
        if facts:
            from exposureiq.ai.context import number

            mode = result.get("mode", "simple")
            better = facts["better"]["count"]
            lines.append(f"From the saved comparisons, {number(better, mode)} {'change' if better == 1 else 'changes'} reduced exposure and {number(facts['worse']['count'], mode)} increased it.")
            if result.get("list_requested"):
                for key, label in (("still_unfixed", "Still present"), ("regressions", "Returned after two saved absences"),
                                   ("fixed", "Absent after two saved observations"), ("new_recently", "New recently")):
                    count = facts["list_counts"].get(key, 0)
                    detail = "; ".join(f"{rule_title(item['rule'])} on {item['host']}" for item in facts[key][:3])
                    lines.append(f"{label}: {number(count, mode)}." + (" " + detail + "." if detail else ""))
                lines.extend(facts["notes"])
            else:
                counts = facts["list_counts"]
                stayed, absent, new = (counts.get(key, 0) for key in ("still_unfixed", "fixed", "new_recently"))
                lines.append(f"{number(stayed, mode).capitalize()} {'finding stayed' if stayed == 1 else 'findings stayed'} present; {number(counts.get('regressions', 0), mode)} returned after two saved absences. "
                             f"{number(absent, mode).capitalize()} {'was' if absent == 1 else 'were'} absent in two later observations, and {number(new, mode)} {'was' if new == 1 else 'were'} new recently.")
                warning = "These are saved observations, not a live check or proof that a fix worked."
                if any(note.startswith("Skipped ") for note in facts["notes"]):
                    warning += " Some scans lacked check evidence and were left out of finding comparisons."
                if facts.get("truncated"):
                    warning += " This is a short summary; the saved history contains more detail."
                lines.append(warning)
        if result["priorities"]:
            lines += [f"{priority['rank']}. {priority['action']} {priority['why']}" for priority in result["priorities"]]
        lines += [item["text"] for item in [*result["notes"], *result["next_steps"]] if item["text"] != result["headline"]["text"]]
        if "proof_notice" in result:
            from exposureiq.ai.conversation import PROOF_NOTE

            # The model may omit or repeat this sentence. The application owns
            # its once-per-conversation display without certifying other prose.
            lines = [line.replace(PROOF_NOTE, "").strip() for line in lines]
            if result["proof_notice"]:
                lines.append(result["proof_notice"])
            lines = [line for line in lines if line]
        return "\n\n".join(lines).strip()
    lines = [result["headline"]["text"]]
    facts = result.get("history")
    if facts:
        lines += ["", "From the saved comparisons (not a live check):",
                  f"Better: {facts['better']['count']} observed changes. Worse: {facts['worse']['count']} observed changes."]
        for key, heading in (("still_unfixed", "Still present"), ("regressions", "Returned after two saved absences"),
                             ("fixed", "Absent after two saved observations"), ("new_recently", "New recently")):
            lines.append(f"{heading}: {facts['list_counts'].get(key, 0)}.")
            lines.extend(f"  {rule_title(item['rule'])} on {item['host']} [{item['ref']}]" for item in facts[key][:3])
        lines.extend(facts["notes"])
        if facts["truncated"] or any(len(facts[key]) > 3 for key in ("still_unfixed", "regressions", "fixed", "new_recently")):
            lines.append("History details are shortened here; counts include the omitted items.")
    if result["priorities"]:
        lines += ["", "What could go wrong:" if result.get("answer_kind") == "impact" else "Here's where I'd start:"]
        for priority in result["priorities"]:
            lines += [f"{priority['rank']}. {priority['action']}", priority["why"]]
            finding_refs = [ref for ref in priority["refs"] if ref.startswith("F-")]
            if finding_refs:
                lines.append("Saved finding: " + ", ".join(finding_refs))
            lines.append("")
    claims = [*result["next_steps"], *result["notes"]]
    for item in claims:
        if item["text"] != result["headline"]["text"]:
            lines.append(item["text"])
    if result.get("reason") and not result.get("policy_refusal"):
        lines += ["", result["reason"]]
    return "\n".join(lines).strip()
