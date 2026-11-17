import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from exposureiq.ai.config import AIConfig, ConfigError, confirm_remote
from exposureiq.ai.provider import ANTHROPIC_VERSION, AnthropicProvider, OpenAIProvider, ProviderError, TIMEOUT_SECONDS, make_provider
from exposureiq.ai.chat import Chat
from exposureiq.ai.tools import ReadOnlyTools, TOOL_DEFINITIONS
from exposureiq.insight.digest import scan_digest
from exposureiq.ai.policy import RateLimiter
from exposureiq.ai.service import AIService

FAKE_KEY = "FAKE-PROVIDER-KEY-ONLY-1234"


@contextmanager
def fake_server(statuses, *, body=None, retry_after=""):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                          "version": self.headers.get("anthropic-version"), "agent": self.headers.get("User-Agent"),
                          "body": json.loads(raw)})
            status = statuses[min(len(calls) - 1, len(statuses) - 1)]
            payload = body(calls) if callable(body) else body
            if payload is None:
                payload = json.dumps({"choices": [{"message": {"content": '{"ready":true}'}}]})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload.encode())))
            if retry_after:
                self.send_header("Retry-After", retry_after)
            self.end_headers()
            self.wfile.write(payload.encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("status,part", [(401, "key was rejected"), (403, "key was rejected"),
                                         (404, "model was not found"), (429, "Retry after 7 seconds"),
                                         (302, "redirects are blocked"), (400, "rejected the request")])
def test_http_error_mapping_on_loopback_and_key_never_echoed(status, part, caplog):
    with fake_server([status], body=FAKE_KEY, retry_after="7") as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", base_url=url, model="fake", api_key=FAKE_KEY), accepted=True)
        with pytest.raises(ProviderError) as error:
            OpenAIProvider(config).complete([{"role": "user", "content": "No scan data"}])
        assert part in str(error.value)
        assert FAKE_KEY not in str(error.value) + caplog.text
        assert len(calls) == 1 and calls[0]["authorization"] == "Bearer " + FAKE_KEY
        assert calls[0]["path"] == "/v1/chat/completions"


def test_exactly_one_5xx_retry_and_success():
    with fake_server([503, 200]) as (url, calls):
        provider = OpenAIProvider(AIConfig(mode="local", base_url=url, model="fake"))
        assert provider.complete([{"role": "user", "content": "check"}]).content == '{"ready":true}'
        assert len(calls) == 2
        assert all(c["authorization"] is None for c in calls)


def test_5xx_retry_exhausted_and_invalid_json_are_safe():
    with fake_server([500], body=FAKE_KEY) as (url, calls):
        with pytest.raises(ProviderError, match="after one retry"):
            OpenAIProvider(AIConfig(mode="local", base_url=url, model="fake")).complete([])
        assert len(calls) == 2
    with fake_server([200], body=FAKE_KEY) as (url, calls):
        with pytest.raises(ProviderError) as error:
            OpenAIProvider(AIConfig(mode="local", base_url=url, model="fake")).complete([])
        assert "invalid JSON" in str(error.value) and FAKE_KEY not in str(error.value)


@pytest.mark.parametrize("exception,part,expected_calls", [
    (requests.Timeout(FAKE_KEY), "timed out", 2),
    (requests.ConnectionError(FAKE_KEY), "Cannot reach", 1),
])
def test_timeout_network_error_and_transport_options(exception, part, expected_calls):
    class Session:
        calls = []

        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            raise exception

    session = Session()
    config = confirm_remote(AIConfig(mode="remote", base_url="https://ai.example.com/v1", model="fake", api_key=FAKE_KEY), accepted=True)
    with pytest.raises(ProviderError) as error:
        OpenAIProvider(config, session=session).complete([{ "role": "user", "content": FAKE_KEY}])
    assert part in str(error.value) and FAKE_KEY not in str(error.value)
    assert len(session.calls) == expected_calls and not session.trust_env
    for url, options in session.calls:
        assert url == config.base_url + "/chat/completions"
        assert options["timeout"] == TIMEOUT_SECONDS == 60
        assert options["allow_redirects"] is False
        assert FAKE_KEY not in json.dumps(options["json"])


def test_bounded_response_and_untrusted_retry_after():
    with fake_server([200], body="x" * 129000) as (url, calls):
        with pytest.raises(ProviderError, match="size limit"):
            OpenAIProvider(AIConfig(mode="local", base_url=url, model="fake")).complete([])
    with fake_server([429], retry_after=FAKE_KEY) as (url, calls):
        with pytest.raises(ProviderError) as error:
            OpenAIProvider(AIConfig(mode="local", base_url=url, model="fake")).complete([])
        assert FAKE_KEY not in str(error.value)


def test_service_rate_limit_counts_actual_http_retries(ai_scan_factory):
    with fake_server([503]) as (url, calls):
        config = AIConfig(mode="local", base_url=url, model="fake")
        provider = OpenAIProvider(config)
        service = AIService(config, provider=provider, use_cache=False)
        service.limiter = RateLimiter(limit=1)
        first = service.summary(ai_scan_factory())
        assert first["source"] == "template" and len(calls) == 1
        assert "retry stopped" in service.audit[0]["error"]
        service.summary(ai_scan_factory())
        assert len(calls) == 1 and len(service.audit) == 1


def anthropic_text(value):
    return json.dumps({"type": "message", "role": "assistant", "content": [{"type": "text", "text": value}]})


def test_openai_preset_selects_compatible_completion_parameters():
    with fake_server([200]) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="OpenAI", base_url=url,
                                         model="fake", api_key=FAKE_KEY), accepted=True)
        provider = make_provider(config)
        assert type(provider) is OpenAIProvider
        assert provider.complete([{"role": "user", "content": "check"}]).content == '{"ready":true}'
        payload = calls[0]["body"]
        assert calls[0]["path"] == "/v1/chat/completions" and calls[0]["authorization"] == "Bearer " + FAKE_KEY
        assert payload["max_completion_tokens"] == 2400 and payload["response_format"] == {"type": "json_object"}
        assert "temperature" not in payload and "max_tokens" not in payload


def test_anthropic_native_request_uses_only_configured_endpoint_and_redacted_text():
    with fake_server([200], body=anthropic_text('{"ready":true}')) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="Anthropic", base_url=url,
                                         model="fake-claude", api_key=FAKE_KEY), accepted=True)
        provider = make_provider(config)
        assert isinstance(provider, AnthropicProvider)
        response = provider.complete([{"role": "system", "content": "Private test instruction."},
                                      {"role": "user", "content": "Check " + FAKE_KEY}], tools=TOOL_DEFINITIONS)
        assert response.content == '{"ready":true}' and not response.tool_calls
        assert len(calls) == 1 and calls[0]["path"] == "/v1/messages"
        assert calls[0]["version"] == ANTHROPIC_VERSION and calls[0]["authorization"] == "Bearer " + FAKE_KEY
        assert "ExposureIQ" in calls[0]["agent"] and not provider.session.trust_env
        payload = calls[0]["body"]
        assert payload["system"] == "Private test instruction."
        assert payload["messages"][0] == {"role": "user", "content": [{"type": "text", "text": "Check [redacted]"}]}
        assert payload["max_tokens"] == 2400 and "temperature" not in payload and "response_format" not in payload
        assert {tool["name"] for tool in payload["tools"]} == {tool["function"]["name"] for tool in TOOL_DEFINITIONS}
        assert all(set(tool) == {"name", "description", "input_schema"} for tool in payload["tools"])
        assert FAKE_KEY not in json.dumps(payload)


def test_anthropic_phraser_cannot_request_extra_reads(ai_scan_factory):
    def replies(calls):
        if len(calls) == 1:
            return json.dumps({"type": "message", "content": [{"type": "tool_use", "id": "fake_tool_1",
                              "name": "get_finding", "input": {"id": "F-0001"}}]})
        blocks = calls[-1]["body"]["messages"][-1]["content"]
        update = json.loads(next(block["text"] for block in reversed(blocks) if block["type"] == "text"))
        assert update["reply_mode"] == "conversation" and "candidate" not in update
        return anthropic_text(json.dumps({"headline": {"text": "A publicly reachable database should have tighter access controls.", "refs": ["F-0001"]},
                                         "priorities": [], "notes": [], "next_steps": []}))

    with fake_server([200], body=replies) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="Anthropic", base_url=url,
                                         model="fake-claude", api_key=FAKE_KEY), accepted=True)
        service = AIService(config, use_cache=False)
        scan = ai_scan_factory()
        chat = Chat(scan_digest(scan), ReadOnlyTools(scan), service)
        result = chat.ask("Explain F-0001")
        assert result["source"] == "template" and result["verified"] == result["total"]
        assert result["wording_verified"] is False and result["failure_kind"] == "tool"
        assert len(calls) == 1 and result["tool_calls"] == [{"name": "get_finding", "arguments": {"id": "F-0001"}}]
        assert "tools" not in calls[0]["body"]
        assert all(call["path"] == "/v1/messages" for call in calls)
        assert FAKE_KEY not in json.dumps(result) + json.dumps(service.audit)


def test_anthropic_plain_chat_uses_the_same_facts_checker(ai_scan_factory):
    body = anthropic_text("A publicly reachable database should have tighter access controls. [F-0001] "
                          "Ask IT to allow only approved application systems. [F-0001]")
    with fake_server([200], body=body) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="Anthropic", base_url=url,
                                         model="fake-claude", api_key=FAKE_KEY), accepted=True)
        service = AIService(config, use_cache=False)
        scan = ai_scan_factory()
        result = Chat(scan_digest(scan), ReadOnlyTools(scan), service).ask("Explain F-0001")
        assert result["source"] == "remote" and result["fact_check_ran"] and not result["dropped"]
        assert result["wording_verified"] is False and "tighter access controls" in result["headline"]["text"]
        assert len(calls) == 1 and calls[0]["body"]["max_tokens"] == 640
        assert "tools" not in calls[0]["body"] and "response_format" not in calls[0]["body"]
        assert FAKE_KEY not in json.dumps(result) + json.dumps(service.audit)


@pytest.mark.parametrize("status,kind,expected", [(302, "redirect", 1), (401, "auth", 1), (429, "rate", 1), (503, "unavailable", 2)])
def test_anthropic_shares_safe_error_mapping_and_exact_retry_limit(status, kind, expected):
    with fake_server([status], body=FAKE_KEY) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="Anthropic", base_url=url,
                                         model="fake", api_key=FAKE_KEY), accepted=True)
        with pytest.raises(ProviderError) as error:
            make_provider(config).complete([{"role": "user", "content": "check"}])
        assert error.value.kind == kind and FAKE_KEY not in str(error.value)
        assert len(calls) == expected and all(call["path"] == "/v1/messages" for call in calls)


@pytest.mark.parametrize("block", [{"type": "server_tool_use", "name": "web_search", "input": {}},
                                   {"type": "thinking", "thinking": FAKE_KEY},
                                   {"type": "tool_use", "id": "one", "name": "get_host", "input": "wrong"}])
def test_anthropic_unsupported_blocks_fail_closed_without_display_or_server_tools(block):
    with fake_server([200], body=json.dumps({"type": "message", "content": [block]})) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="Anthropic", base_url=url,
                                         model="fake", api_key=FAKE_KEY), accepted=True)
        with pytest.raises(ProviderError) as error:
            make_provider(config).complete([{"role": "user", "content": "check"}])
        assert error.value.kind == "invalid" and FAKE_KEY not in str(error.value) and len(calls) == 1


def test_local_mode_ignores_remote_anthropic_preset_and_off_cannot_create_transport():
    provider = make_provider(AIConfig(mode="local", provider="Anthropic", base_url="http://127.0.0.1:11434/v1", model="fake"))
    assert type(provider) is OpenAIProvider
    with pytest.raises(ConfigError, match="off"):
        make_provider(AIConfig())


@pytest.mark.parametrize("envelope,kind", [
    ({"choices": [{"finish_reason": "length", "message": {"content": FAKE_KEY}}]}, "incomplete"),
    ({"choices": [{"finish_reason": "content_filter", "message": {"content": None}}]}, "refused"),
    ({"choices": [{"message": {"refusal": FAKE_KEY, "content": None}}]}, "refused"),
    ({"choices": [{"message": {"content": ""}}]}, "empty"),
    ({"type": "message", "stop_reason": "max_tokens", "content": [{"type": "text", "text": FAKE_KEY}]}, "incomplete"),
    ({"type": "message", "stop_reason": "refusal", "content": []}, "refused"),
    ({"type": "message", "content": []}, "empty"),
])
def test_provider_stop_reasons_are_safe_specific_and_do_not_trigger_retries(envelope, kind):
    with fake_server([200], body=json.dumps(envelope)) as (url, calls):
        config = confirm_remote(AIConfig(mode="remote", provider="Anthropic" if envelope.get("type") == "message" else "OpenAI",
                                         base_url=url, model="fake", api_key=FAKE_KEY), accepted=True)
        with pytest.raises(ProviderError) as error:
            make_provider(config).complete([{"role": "user", "content": "Explain saved evidence"}])
        assert error.value.kind == kind and FAKE_KEY not in str(error.value)
        assert len(calls) == 1


@pytest.mark.parametrize("status", [400, 422])
def test_bad_request_format_is_distinct_from_auth_and_connection(status):
    with fake_server([status], body=FAKE_KEY) as (url, calls):
        with pytest.raises(ProviderError) as error:
            OpenAIProvider(AIConfig(mode="local", base_url=url, model="fake")).complete([])
        assert error.value.kind == "bad_request" and "API compatibility" in str(error.value)
        assert FAKE_KEY not in str(error.value) and len(calls) == 1
