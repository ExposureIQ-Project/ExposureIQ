"""One configured AI endpoint; no redirects/proxies/target tools.

60-second request timeout, one retry for timeout/5xx, bounded responses. Error
bodies and requests exceptions may contain a key: never surface or log them.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field

import requests

from exposureiq.ai.config import AIConfig, ConfigError, DEMO_MODEL, validate_config
from exposureiq.ai.policy import RateLimiter, RateLimitError
from exposureiq.ai.sanitize import compact_json, redact

TIMEOUT_SECONDS = 60
MAX_RESPONSE_BYTES = 128000
ANTHROPIC_VERSION = "2026-10-21"
SAFE_ERRORS = {
    "auth": "The AI key was rejected (401/403). Check your provider and key in AI settings.",
    "not_found": "The AI endpoint or model was not found (404). Check the base URL and model name.",
    "rate": "AI rate limit reached (429). Check the provider's retry-after guidance.",
    "unavailable": "The AI provider is unavailable (5xx), including after one retry.",
    "redirect": "AI endpoint redirects are blocked; configure the final base URL explicitly.",
    "oversize": "The AI response exceeded the size limit.",
    "invalid": "The AI endpoint returned invalid JSON or an invalid response envelope.",
    "timeout": "The AI request timed out, including after one retry. Try again later.",
    "connection": "Cannot reach the configured AI endpoint. Check the URL and connection.",
    "request": "The configured AI request failed. No credential details are shown.",
    "bad_request": "The AI endpoint rejected the request format or model options (400/422). Check the endpoint, model and API compatibility.",
    "refused": "The AI provider declined this reply. Try a saved-scan or defensive-fix question.",
    "incomplete": "The AI provider stopped before completing the reply. Try a shorter question or a model with enough output capacity.",
    "empty": "The AI endpoint returned no reply text or read-only tool call. Check the model's chat compatibility.",
}


class ProviderError(RuntimeError):
    def __init__(self, message="", *, kind="request"):
        self.kind = kind if kind in SAFE_ERRORS else "request"
        self.safe_message = SAFE_ERRORS[self.kind]
        super().__init__(message or self.safe_message)


@dataclass
class ProviderResponse:
    content: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    incomplete: bool = False


class OpenAIProvider:
    def __init__(self, config: AIConfig, session=None):
        self.config = validate_config(config, require_ready=True)
        self.model = self.config.model
        self.session = session or requests.Session()
        self.session.trust_env = False  # No netrc, proxy or ambient credentials.
        self.limiter = RateLimiter()
        self.attempts = 0

    def _request(self, messages, tools, config):
        conversational = any(message.get("role") == "system" and message.get("content", "").startswith("ExposureIQ chat: plain-text") for message in messages)
        payload = {"model": config.model, "messages": redact(messages, (config.key,)),
                    "temperature": 0.3 if conversational else 0.2, "max_tokens": 640 if conversational else 2400}
        if not conversational:
            payload["response_format"] = {"type": "json_object"}
        if config.mode == "remote" and config.provider == "OpenAI":
            # Newer OpenAI models do not accept temperature or max_tokens.
            payload.pop("temperature")
            payload["max_completion_tokens"] = payload.pop("max_tokens")
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json", "User-Agent": "ExposureIQ/0.1 advisory-AI"}
        if config.mode == "remote":
            headers["Authorization"] = "Bearer " + config.key
        return "/chat/completions", payload, headers

    def _parse_envelope(self, envelope, *, allow_partial=False):
        choice = envelope["choices"][0]
        message = choice["message"]
        if message.get("refusal") or choice.get("finish_reason") == "content_filter":
            raise ProviderError(kind="refused")
        incomplete = choice.get("finish_reason") == "length"
        if incomplete and not allow_partial:
            raise ProviderError(kind="incomplete")
        content = message.get("content") or ""
        calls = message.get("tool_calls") or []
        if not isinstance(content, str) or not isinstance(calls, list):
            raise ValueError
        if not content.strip() and not calls:
            raise ProviderError(kind="empty")
        return ProviderResponse(content, calls, incomplete)

    def complete(self, messages: list[dict], *, tools: list[dict] | None = None) -> ProviderResponse:
        config = validate_config(self.config, require_ready=True)
        suffix, payload, headers = self._request(messages, tools, config)
        allow_partial = any(message.get("role") == "system" and (message.get("content", "").startswith("ExposureIQ chat: plain-text") or
                            message.get("content", "").startswith("You are ExposureIQ's read-only defensive explanation assistant.")) for message in messages)
        self.attempts = 0
        for attempt in range(2):
            if not self.limiter.acquire():
                raise RateLimitError("AI request limit reached. Wait one minute before trying again.")
            self.attempts += 1
            response = None
            failure = None
            kind = "request"
            retry = False
            try:
                response = self.session.post(config.base_url + suffix, json=payload,
                                             headers=headers, timeout=TIMEOUT_SECONDS,
                                             allow_redirects=False, stream=True)
                code = response.status_code
                if code in (401, 403):
                    kind = "auth"
                    failure = "The AI key was rejected (401/403). Check your provider and key in AI settings."
                elif code == 404:
                    kind = "not_found"
                    failure = "The AI endpoint or model was not found (404). Check the base URL and model name."
                elif code == 429:
                    kind = "rate"
                    hint = str(response.headers.get("Retry-After", "")).strip()
                    hint = f" Retry after {int(hint)} seconds." if hint.isdigit() and len(hint) <= 6 else " Check the provider's retry-after guidance."
                    failure = "AI rate limit reached (429)." + hint
                elif code in (400, 422):
                    kind = "bad_request"
                    failure = SAFE_ERRORS[kind]
                elif 500 <= code <= 599:
                    kind = "unavailable"
                    retry = attempt == 0
                    failure = "The AI provider is unavailable (5xx), including after one retry."
                elif 300 <= code <= 399:
                    kind = "redirect"
                    failure = "AI endpoint redirects are blocked; configure the final base URL explicitly."
                elif code != 200:
                    failure = "The AI endpoint rejected the request. Check the provider, URL and model settings."
                else:
                    data = bytearray()
                    for chunk in response.iter_content(chunk_size=8192):
                        data.extend(chunk)
                        if len(data) > MAX_RESPONSE_BYTES:
                            kind = "oversize"
                            failure = "The AI response exceeded the size limit."
                            break
                    if failure is None:
                        try:
                            envelope = json.loads(bytes(data))
                            result = self._parse_envelope(envelope, allow_partial=allow_partial)
                            return ProviderResponse(redact(result.content, (config.key,)), redact(result.tool_calls, (config.key,)), result.incomplete)
                        except (ValueError, KeyError, IndexError, TypeError, AttributeError, UnicodeError, RecursionError):
                            kind = "invalid"
                            failure = "The AI endpoint returned invalid JSON or an invalid response envelope."
            except requests.Timeout:
                kind = "timeout"
                retry = attempt == 0
                failure = "The AI request timed out, including after one retry. Try again later."
            except requests.RequestException:
                kind = "connection"
                failure = "Cannot reach the configured AI endpoint. Check the URL and connection."
            finally:
                if response is not None:
                    response.close()
            if not retry:
                # Raise outside the requests exception handler: no credential
                # containing exception context escapes to callers.
                raise ProviderError(failure or "The AI request failed.", kind=kind) from None
        raise ProviderError("The AI request failed after one retry.")


class AnthropicProvider(OpenAIProvider):
    """Native Messages API over the SAME confined transport and rate limiter.

    Convert only text and our client-side read-only tool calls. Never advertise
    Anthropic server tools (web search, code execution, etc.), images or URLs.
    """

    def _request(self, messages, tools, config):
        system, turns = [], []
        for message in redact(messages, (config.key,)):
            role = message["role"]
            content = message.get("content") or ""
            if role == "system":
                system.append(content)
                continue
            blocks = []
            if role == "tool":
                role = "user"
                blocks.append({"type": "tool_result", "tool_use_id": message["tool_call_id"], "content": content})
            elif role in ("user", "assistant"):
                if content:
                    blocks.append({"type": "text", "text": content})
                for call in message.get("tool_calls", []):
                    function = call["function"]
                    blocks.append({"type": "tool_use", "id": call["id"], "name": function["name"],
                                   "input": json.loads(function["arguments"])})
            else:
                raise ProviderError(kind="invalid")
            if not blocks:
                continue
            if turns and turns[-1]["role"] == role:
                turns[-1]["content"].extend(blocks)
            else:
                turns.append({"role": role, "content": blocks})
        conversational = any(value.startswith("ExposureIQ chat: plain-text") for value in system)
        payload = {"model": config.model, "max_tokens": 640 if conversational else 2400, "system": "\n\n".join(system), "messages": turns}
        if tools:
            payload["tools"] = [{"name": tool["function"]["name"], "description": tool["function"]["description"],
                                 "input_schema": tool["function"]["parameters"]} for tool in tools]
            payload["tool_choice"] = {"type": "auto"}
        headers = {"Content-Type": "application/json", "User-Agent": "ExposureIQ/0.1 advisory-AI",
                   "anthropic-version": ANTHROPIC_VERSION}
        if config.mode == "remote":
            headers["Authorization"] = "Bearer " + config.key
        return "/messages", payload, headers

    def _parse_envelope(self, envelope, *, allow_partial=False):
        if not isinstance(envelope, dict) or envelope.get("type") != "message" or not isinstance(envelope.get("content"), list):
            raise ValueError
        incomplete = envelope.get("stop_reason") == "max_tokens"
        if incomplete and not allow_partial:
            raise ProviderError(kind="incomplete")
        if envelope.get("stop_reason") == "refusal":
            raise ProviderError(kind="refused")
        texts, calls = [], []
        for block in envelope["content"]:
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])
            elif (block.get("type") == "tool_use" and isinstance(block.get("id"), str)
                  and isinstance(block.get("name"), str) and isinstance(block.get("input"), dict)):
                calls.append({"id": block["id"], "type": "function", "function":
                              {"name": block["name"], "arguments": compact_json(block["input"])}})
            else:
                # Unsupported/server-side blocks never enter chat or its tools.
                raise ValueError
        if not texts and not calls:
            raise ProviderError(kind="empty")
        return ProviderResponse("\n".join(texts), calls, incomplete)


class FakeProvider:
    """Recorded sentence patterns + code facts, deterministic and fully offline."""
    model = DEMO_MODEL
    offline = True

    def __init__(self):
        self.calls = 0

    def complete(self, messages: list[dict], *, tools=None) -> ProviderResponse:
        self.calls += 1
        for message in reversed(messages):
            if message.get("role") == "user":
                try:
                    data = json.loads(message["content"])
                except (ValueError, KeyError, TypeError):
                    continue
                if data.get("reply_mode") == "conversation":
                    if "facts_pack" in data:
                        from exposureiq.ai.facts import built_in_answer

                        # A legacy JSON wrapper exercises the tolerant path.
                        # Separate loopback fixtures exercise plain small models.
                        return ProviderResponse(compact_json(built_in_answer(data["facts_pack"])))
                    if tools and not any(item.get("role") == "tool" for item in messages):
                        context, request = data["answer_context"], data.get("request", "")
                        latest = data["digest"].get("latest", data["digest"])
                        name, arguments = "", {}
                        scans = re.findall(r"\b(?:scan-\d{4,}|DEMO-HISTORY-\d{2})\b", request)
                        if len(scans) == 2 and any(word in request.lower() for word in ("compare", "diff")):
                            name, arguments = "get_diff", {"scan_a": scans[0], "scan_b": scans[1]}
                        elif context.get("finding_id"):
                            name, arguments = "get_finding", {"id": context["finding_id"]}
                        elif "most exposed" in request.lower() and context.get("host"):
                            name, arguments = "get_host", {"host": context["host"]}
                        elif context["kind"] == "unfixed":
                            name = "list_unfixed"
                        elif context["kind"] == "history":
                            name = "get_history"
                        elif "fix first" in request.lower():
                            severity = next((level for level in ("high", "medium", "low") if latest["risk"].get(level)), "low")
                            name, arguments = "list_findings", {"severity": severity}
                        if name:
                            return ProviderResponse(tool_calls=[{"id": "demo-tool-1", "type": "function",
                                "function": {"name": name, "arguments": compact_json(arguments)}}])
                    from exposureiq.ai.conversation import fallback_chat

                    return ProviderResponse(compact_json(fallback_chat(data["digest"], data["answer_context"])))
                if "candidate" in data:
                    if tools and not any(m.get("role") == "tool" for m in messages):
                        digest = data.get("digest", {})
                        latest = digest.get("latest", digest)
                        request = data.get("request", "")
                        requested_id = re.search(r"\bF-\d{4,}\b", request, re.I)
                        finding_id = requested_id.group().upper() if requested_id else data.get("answer_context", {}).get("finding_id", "")
                        requested_scans = re.findall(r"\b(?:scan-\d{4,}|DEMO-HISTORY-\d{2})\b", request)
                        name, arguments = "", {}
                        if len(requested_scans) == 2 and any(word in request.lower() for word in ("compare", "diff")):
                            name, arguments = "get_diff", {"scan_a": requested_scans[0], "scan_b": requested_scans[1]}
                        elif finding_id:
                            name, arguments = "get_finding", {"id": finding_id}
                        elif "most exposed" in request.lower() and latest.get("top_hosts"):
                            name, arguments = "get_host", {"host": latest["top_hosts"][0]["host"]}
                        elif "unfixed" in request.lower():
                            name = "list_unfixed"
                        elif "history" in request.lower() or "changed" in request.lower():
                            name = "get_history"
                        elif "fix first" in request.lower():
                            severity = next((s for s in ("high", "medium", "low") if latest.get("risk", {}).get(s)), "low")
                            name, arguments = "list_findings", {"severity": severity}
                        if name:
                            return ProviderResponse(tool_calls=[{"id": "demo-tool-1", "type": "function",
                              "function": {"name": name, "arguments": compact_json(arguments)}}])
                    return ProviderResponse(compact_json(copy.deepcopy(data["candidate"])))
        return ProviderResponse('{"ready":true}')


def make_provider(config: AIConfig):
    config = validate_config(config, require_ready=True)
    if config.mode == "demo":
        return FakeProvider()
    if config.mode == "remote" and config.provider == "Anthropic":
        return AnthropicProvider(config)
    return OpenAIProvider(config)


def test_connection(config: AIConfig, *, provider=None) -> str:
    config = validate_config(config, require_ready=True)
    provider = provider or make_provider(config)
    provider.complete([{"role": "system", "content": "Connection check only. No scan data is included."},
                       {"role": "user", "content": 'Reply with JSON {"ready":true}.'}])
    return "Connection succeeded. No scan summary was sent." if config.mode != "demo" else "Demo (offline) is ready. No network was used."
