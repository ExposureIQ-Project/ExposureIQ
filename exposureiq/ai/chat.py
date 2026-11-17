"""Natural, evidence-backed chat with bounded memory and read-only tools."""

from __future__ import annotations

import copy
import re
import secrets
import time
from collections import deque
from datetime import datetime, timezone

from exposureiq.ai.checker import check_chat_output, check_model_chat_output
from exposureiq.ai.context import add_focus_evidence, answer_plan, choose_context
from exposureiq.ai.conversation import OFFLINE_NOTICE, PROOF_NOTE, friendly_reply
from exposureiq.ai.facts import build_facts_pack, built_in_answer
from exposureiq.ai.glossary import define_terms
from exposureiq.ai.policy import GateDecision, RateLimitError, policy_gate, refusal_result
from exposureiq.ai.prompts import PROMPT_VERSION, chat_messages
from exposureiq.ai.provider import ProviderError, make_provider
from exposureiq.ai.questions import friendly_kind
from exposureiq.ai.sanitize import compact_json, redact
from exposureiq.ai.schema import SchemaError
from exposureiq.ai.service import AIService, AIUnavailable, NotConfigured, failure_details
from exposureiq.ai.tools import ReadOnlyTools, ToolError
from exposureiq.insight.history_digest import build_history_layers, history_facts

MEMORY_TURNS = 6  # Six messages: the last three user/assistant exchanges.


class Chat:
    def __init__(self, digest: dict, tools: ReadOnlyTools, service: AIService):
        self.digest, self.tools, self.service = digest, tools, service
        self.memory = deque(maxlen=MEMORY_TURNS)
        self.answer_context = {}
        self.proof_notice_seen = False
        self.offline_notice_seen = False
        self.defined_terms = set()
        self.retry_requests = {}

    def _built_in_reply(self, output: dict, *, kind: str) -> dict:
        return {"draft": "AI draft", **output, "verified": 0, "total": 0, "dropped": [],
                "model": "Built-in reply (no model call)", "prompt_version": PROMPT_VERSION,
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "elapsed": 0,
                "source": "built-in", "reason": "", "failure_kind": "", "verification": "built-in",
                "wording_verified": True, "checked_refs": 0, "checked_facts": 0,
                "cache_hit": False, "hostile_text_seen": False, "tool_calls": [], "history": {},
                "answer_kind": kind, "evidence_refs": [], "offline_notice": ""}

    def ask(self, question: str, *, no_fallback=False, progress=None, mode=None, host="", finding_id="", retry_id="") -> dict:
        start = time.monotonic()
        decision = policy_gate(question, has_context=bool(self.answer_context))
        if not decision.allowed:
            return refusal_result(decision)
        friendly = friendly_kind(question)
        if friendly:
            # No settings, credential, tool or provider reads for a greeting.
            return self._built_in_reply(friendly_reply(friendly), kind=friendly)
        config = self.service._configuration()
        question = redact(question, (config.key, config.api_key))
        if retry_id:
            saved = self.retry_requests.get(retry_id)
            if not saved or saved["question"] != question:
                raise ValueError("Try again is available only for this conversation's saved question.")
            context = copy.deepcopy(saved["context"])
        else:
            context = choose_context(question, self.digest, self.tools, self.answer_context,
                                     mode=mode, host=host, finding_id=finding_id)
        if context["clarification"]:
            return self._built_in_reply({"headline": {"text": context["clarification"], "refs": []},
                                        "priorities": [], "next_steps": [], "notes": []}, kind="clarification")
        digest = self.digest
        if context["kind"] in ("history", "unfixed") and digest.get("ref") != "S:history":
            digest = build_history_layers(self.tools.scans)["L4"]
        # Tool budget/evidence are per answer, never per conversation.
        self.tools.calls, self.tools.evidence = [], []
        if no_fallback and not config.ready and self.service.provider is None:
            raise NotConfigured("AI is not configured. Open AI settings or use --demo.")
        progress = progress or (lambda stage: None)
        progress("Reading your scan")
        # The code chooses all reads. No tool definitions go to a small model;
        # an unexpected tool call is rejected without reading its arguments.
        if context["kind"] in ("history", "unfixed"):
            self.tools.execute("list_unfixed" if context["kind"] == "unfixed" else "get_history", {})
        elif context["kind"] != "why" and context.get("intent") == "fix_first" and context.get("ranked_groups"):
            self.tools.execute("list_findings", {"severity": context["ranked_groups"][0]["severity"]})
        if context.get("finding_id"):
            self.tools.execute("get_finding", {"id": context["finding_id"]})
        elif context.get("host"):
            self.tools.execute("get_host", {"host": context["host"]})
        digest = redact(self.tools.augmented_digest(add_focus_evidence(digest, context, self.tools)), (config.key, config.api_key))
        plan = answer_plan(digest, context)
        plan.update(include_proof_note=not self.proof_notice_seen, defined_terms=sorted(self.defined_terms),
                    wording_seed="")
        pack = build_facts_pack(digest, plan, scan_id=self.tools.scan["scan_id"], question=question)
        candidate = built_in_answer(pack)
        model, source = "Built-in explanation (no AI)", "template"
        failure_kind, reason = "not_configured", "AI is off or not configured, so I answered from your saved scan."
        checked, entry, rejected, raw_content = None, None, [], ""
        if config.ready or self.service.provider is not None:
            try:
                provider = self.service.provider or make_provider(config)
                model = getattr(provider, "model", config.model)
                for attempt in (1, 2):
                    progress("Phrasing your answer")
                    messages = chat_messages(pack, question=question, memory=list(self.memory), repair=attempt == 2)
                    try:
                        response, entry = self.service.call(provider, messages, config,
                                                            purpose="chat" if attempt == 1 else "chat shorter retry", attempt=attempt)
                        entry["saved_reads"] = copy.deepcopy(self.tools.calls)
                    except ProviderError as error:
                        if attempt == 1 and error.kind in ("empty", "incomplete", "invalid"):
                            continue
                        raise
                    if response.tool_calls:
                        raise ToolError("A phrasing model requested a tool. No model-requested read ran.")
                    raw_content = redact(response.content, (config.key, config.api_key))
                    progress("Checking the facts")
                    try:
                        checked = check_model_chat_output(raw_content, digest, plan, pack)
                    except SchemaError as error:
                        entry["parse_error"] = str(error)
                        entry["attempt_failed"] = True
                        factual_failure = any(word in str(error) for word in ("unsafe", "number", "reference"))
                        entry["error_kind"] = "evidence" if factual_failure else "reply_format"
                        entry["dropped"] = [{"claim": "reply format", "reason": str(error)}]
                        rejected.extend(copy.deepcopy(entry["dropped"]))
                        failure_kind, reason = ("evidence", "The model's reply did not pass the saved-fact checks, so I answered from your saved scan.") if factual_failure else (
                            "reply_format", "The model's reply was not in a usable format, so I answered from your saved scan.")
                        checked = None
                        continue
                    if not checked.accepted:
                        entry["attempt_failed"] = True
                        entry["dropped"] = copy.deepcopy([*checked.dropped, *checked.removed])
                        entry["error_kind"] = "evidence"
                        rejected.extend(copy.deepcopy(entry["dropped"]))
                        failure_kind, reason = "evidence", "The model's reply did not pass the saved-fact checks, so I answered from your saved scan."
                        checked = None
                        continue
                    entry["dropped"] = copy.deepcopy(checked.removed)
                    source = "fake" if getattr(provider, "offline", False) and config.mode != "demo" else config.mode if config.ready else "fake"
                    failure_kind, reason, rejected = "", "", copy.deepcopy(checked.removed)
                    break
            except RateLimitError:
                return refusal_result(GateDecision(False, "rate limit", "Request limit reached; wait one minute before asking again."))
            except Exception as error:
                checked, source = None, "template"
                failure_kind, reason = failure_details(error)
                if entry is not None and not isinstance(error, ProviderError):
                    entry["error"], entry["error_kind"] = reason, failure_kind
                    entry["attempt_failed"] = True
        if checked is None:
            progress("Checking the facts")
            if no_fallback:
                raise AIUnavailable(reason + " --no-fallback disabled built-in replies.") from None
            checked = check_chat_output(candidate, digest, plan)
            source = "template"
        if not checked.accepted:
            raise ValueError("The built-in explanation failed evidence or safety checks.")
        # These generic definitions come from code, not another model request.
        # They introduce no new saved observations and leave factual host/rule
        # strings untouched. Both live and fallback wording get the same help.
        if context["mode"] == "simple":
            seen = set(self.defined_terms)
            for item in [checked.output["headline"], *checked.output["priorities"],
                         *checked.output["notes"], *checked.output["next_steps"]]:
                for key in (("action", "why") if "action" in item else ("text",)):
                    item[key], seen = define_terms(item[key], seen=seen)
            self.defined_terms = seen
        claims = [checked.output["headline"], *checked.output["priorities"], *checked.output["notes"], *checked.output["next_steps"]]
        refs = list(dict.fromkeys(ref for item in claims for ref in item["refs"]))
        offline = config.mode in ("off", "demo")
        offline_notice = OFFLINE_NOTICE if offline and not self.offline_notice_seen else ""
        self.offline_notice_seen |= offline
        proof_notice = PROOF_NOTE if context["kind"] == "impact" and plan["groups"] and not self.proof_notice_seen else ""
        self.proof_notice_seen |= bool(proof_notice)
        factual_tokens = re.findall(r"\{[a-z_]+\}", compact_json(candidate) if source == "template" else raw_content)
        retryable = source == "template" and config.mode in ("local", "remote") and config.ready
        retry_token = secrets.token_hex(16) if retryable else ""
        if retry_token:
            if len(self.retry_requests) >= MEMORY_TURNS:
                self.retry_requests.pop(next(iter(self.retry_requests)))
            self.retry_requests[retry_token] = {"question": question, "context": copy.deepcopy(context)}
        result = {"draft": "AI draft", **checked.output, "verified": checked.verified, "total": checked.total,
                  "dropped": rejected, "model": model, "prompt_version": PROMPT_VERSION,
                  "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "elapsed": round(time.monotonic() - start, 3), "source": source, "reason": reason,
                  "failure_kind": failure_kind, "verification": "evidence-and-facts", "wording_verified": False,
                  "checked_refs": sum(len(item["refs"]) for item in claims),
                  "checked_facts": len(factual_tokens) + checked.checked_numbers,
                  "fact_check_ran": True, "retryable": retryable, "retry_id": retry_token,
                  "review_note": "References, recorded numbers and selected priority were checked. Model-written explanations still need human review; effort ranges and fix steps are general guidance.",
                  "cache_hit": False, "hostile_text_seen": bool(digest.get("hostile_text_seen")),
                  "tool_calls": copy.deepcopy(self.tools.calls), "answer_kind": context["kind"], "answer_intent": context["intent"],
                  "answer_focus": {"host": context["host"], "finding_id": context["finding_id"], "scope": context["scope"]},
                   "mode": context["mode"], "evidence_refs": refs, "offline_notice": offline_notice,
                   "proof_notice": proof_notice, "list_requested": plan["list_requested"],
                  "history": history_facts(digest) if context["kind"] in ("history", "unfixed") else {}}
        self.memory.append({"role": "user", "content": question})
        self.memory.append({"role": "assistant", "content": compact_json(checked.output)})
        discussed = [item["id"] for item in pack["findings"] if item["id"] in refs or item["ref"] in refs]
        remembered = list(dict.fromkeys([*self.answer_context.get("discussed_findings", []), *discussed]))[-9:]
        listed = discussed if pack["ranked_list"] else self.answer_context.get("listed_findings", [])
        self.answer_context = {**context, "alternatives": discussed, "discussed_findings": remembered, "listed_findings": listed}
        return result
