import copy
import json

import pytest

from exposureiq.ai.chat import MEMORY_TURNS, Chat
from exposureiq.ai.config import AIConfig, confirm_remote
from exposureiq.ai.policy import RateLimiter
from exposureiq.ai.provider import FakeProvider, ProviderResponse
from exposureiq.ai.service import AIService, AIUnavailable, NotConfigured, chat_text, result_text, verified_footer
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.insight.digest import scan_digest
from exposureiq.insight.history_digest import build_history_layers


def build_chat(scan, *, provider=None, config=None, scans=None, digest=None):
    service = AIService(config or AIConfig(mode="demo"), provider=provider, use_cache=False)
    return Chat(digest or scan_digest(scan), ReadOnlyTools(scan, scans=scans), service)


@pytest.mark.parametrize("question,tool", [
    ("Explain F-0001", "get_finding"), ("What should I fix first?", "list_findings"),
    ("Which host is the most exposed?", "get_host"), ("Show scan history", "get_history"),
    ("Which findings are still unfixed?", "list_unfixed"),
])
def test_code_selects_read_only_facts_before_the_phrasing_model(question, tool, ai_scan_factory):
    provider = FakeProvider()
    chat = build_chat(ai_scan_factory(), provider=provider)
    result = chat.ask(question)
    assert result["verified"] == result["total"] and result["source"] == "demo"
    assert result["tool_calls"][0]["name"] == tool and provider.calls == 1
    assert len(chat.service.audit) == 1
    assert not any(m["role"] == "tool" for m in chat.service.audit[0]["sent"])
    data = json.loads(chat.service.audit[0]["sent"][-1]["content"])
    assert data["facts_pack"] and "digest" not in data


def tool_call(name="get_finding", arguments=None, identifier="one"):
    return {"id": identifier, "type": "function", "function":
            {"name": name, "arguments": json.dumps(arguments if arguments is not None else {"id": "F-0001"})}}


@pytest.mark.parametrize("calls,expected_tools,expected_model_calls", [
    ([tool_call()], 0, 1), ([tool_call(identifier=str(i)) for i in range(5)], 0, 1),
    ([tool_call("list_findings", {}), tool_call(arguments={"id": "F-9999"})], 0, 1),
    ([tool_call("run_command", {"command": "do-not-run"})], 0, 1),
])
def test_tool_loops_over_budget_or_invalid_batches_fall_back_without_extra_reads(calls, expected_tools, expected_model_calls, ai_scan_factory):
    class Loop:
        model = "looping fake"
        calls = 0

        def complete(self, messages, **kwargs):
            self.calls += 1
            return ProviderResponse(tool_calls=copy.deepcopy(calls))

    provider = Loop()
    chat = build_chat(ai_scan_factory(), provider=provider)
    result = chat.ask("Explain this finding")
    assert result["source"] == "template" and result["verified"] == result["total"]
    assert len(chat.tools.calls) == expected_tools and provider.calls == expected_model_calls
    assert len(chat.service.audit) == expected_model_calls


def test_six_message_memory_only_contains_checked_exchanges(ai_scan_factory):
    class Recording(FakeProvider):
        requests = []

        def complete(self, messages, **kwargs):
            self.requests.append(copy.deepcopy(messages))
            return super().complete(messages, **kwargs)

    provider = Recording()
    chat = build_chat(ai_scan_factory(), provider=provider)
    chat.service.limiter = RateLimiter(limit=20)
    for i in range(5):
        chat.ask(f"Explain scan risk number {i}")
    assert MEMORY_TURNS == len(chat.memory) == 6
    assert chat.memory[0]["content"] == "Explain scan risk number 2"
    assert len(provider.requests[-1]) == 8  # system + previous six + current request
    sent = json.dumps(provider.requests[-1])
    assert "scan risk number 0" not in sent and "scan risk number 1" in sent


def test_chat_retries_shorter_once_and_logs_both_calls(ai_scan_factory):
    class Malformed(FakeProvider):
        def complete(self, messages, **kwargs):
            if self.calls == 0:
                self.calls += 1
                return ProviderResponse("not JSON")
            return super().complete(messages, **kwargs)

    provider = Malformed()
    chat = build_chat(ai_scan_factory(), provider=provider)
    assert chat.ask("Explain scan risk")["source"] == "demo"
    assert provider.calls == 2 and len(chat.service.audit) == 2
    assert chat.service.audit[0]["dropped"][0]["claim"] == "reply format"
    assert chat.service.audit[0]["parse_error"] and chat.service.audit[0]["attempt"] == 1
    assert chat.service.audit[1]["purpose"] == "chat shorter retry" and chat.service.audit[1]["attempt"] == 2


def test_rejected_claim_never_enters_chat_memory_or_display(ai_scan_factory):
    class Liar(FakeProvider):
        def complete(self, messages, **kwargs):
            response = super().complete(messages, **kwargs)
            candidate = json.loads(response.content)
            candidate["headline"] = {"text": "Exploit using CVE-2099-9999", "refs": ["F-9999"]}
            return ProviderResponse(json.dumps(candidate))

    chat = build_chat(ai_scan_factory(), provider=Liar())
    result = chat.ask("Explain scan risk")
    assert result["source"] == "template" and result["dropped"]
    assert "CVE-2099" not in result_text(result) + json.dumps(list(chat.memory))
    assert chat.service.audit[0]["dropped"] and chat.service.audit[0]["attempt_failed"]


def test_questions_memory_and_logs_redact_fake_key(ai_scan_factory):
    key = "FAKE-CHAT-KEY-ONLY-1234"
    config = confirm_remote(AIConfig(mode="remote", base_url="https://ai.example.com/v1",
                                    model="fake", api_key=key), accepted=True)
    chat = build_chat(ai_scan_factory(), provider=FakeProvider(), config=config)
    result = chat.ask("Explain the scan risk " + key)
    assert key not in json.dumps(result) + json.dumps(list(chat.memory)) + json.dumps(chat.service.audit)
    assert "[redacted]" in chat.memory[0]["content"]


def test_unknown_finding_and_cve_answers_admit_missing_evidence(ai_scan_factory):
    chat = build_chat(ai_scan_factory(), provider=FakeProvider())
    assert chat.ask("Is nginx proof of a CVE?")["headline"]["text"] == "I don't see that in this scan."
    assert chat.ask("Explain F-9999")["headline"]["text"] == "I don't see that in this scan."


def test_ai_off_uses_template_and_no_fallback_reports_missing_config(ai_scan_factory):
    scan = ai_scan_factory()
    chat = Chat(scan_digest(scan), ReadOnlyTools(scan), AIService(AIConfig()))
    assert chat.ask("Explain scan risk")["source"] == "template" and not chat.service.audit
    with pytest.raises(NotConfigured):
        chat.ask("Explain scan risk", no_fallback=True)


def test_history_result_has_code_better_worse_unfixed_and_regression_sections(ai_scan_factory):
    persistent = ("headers.missing_csp", "medium")
    returned = ("ports.database_exposed", "high")
    scans = [ai_scan_factory(i, rules=rules) for i, rules in enumerate(
        [[persistent, returned], [persistent], [persistent], [persistent, returned]])]
    digest = build_history_layers(scans)["L4"]
    chat = build_chat(scans[-1], provider=FakeProvider(), scans=scans, digest=digest)
    result = chat.ask("Show a list of history findings")
    text = result_text(result)
    assert all(heading in text for heading in ("From the saved comparisons,", "changes reduced exposure", "increased it",
                                                "Still present:", "Returned after two saved absences:"))
    assert result["history"]["regressions"][0]["rule"] == returned[0]
    assert "isn't one clear direction" in result["headline"]["text"]


def test_default_history_chat_uses_short_code_owned_prose_and_simple_counts(ai_scan_factory):
    scans = [ai_scan_factory(index) for index in range(3)]
    chat = build_chat(scans[-1], provider=FakeProvider(), scans=scans)
    result = chat.ask("What changed in saved history?")
    text = chat_text(result)
    assert result["source"] == "demo" and not result["dropped"] and not result["list_requested"]
    assert "zero changes reduced exposure" in text and "findings stayed present" in text
    assert all(heading not in text for heading in ("Still present:", "New recently:", "Returned after two saved absences:"))
    assert "not a live check or proof that a fix worked" in text
    assert result["history"]["list_counts"]


def test_requested_definition_list_never_demands_unrelated_priorities(ai_scan_factory):
    result = build_chat(ai_scan_factory(), provider=FakeProvider()).ask("List what security headers mean")
    assert result["source"] == "demo" and not result["dropped"] and not result["priorities"]


@pytest.mark.parametrize("question,expected", [
    ("What do severity levels mean in this scan?", "what to fix first"),
    ("What does the risk score mean in this scan?", "not the chance of a break-in"),
    ("What are security headers in this scan?", "instructions that help browsers protect visitors"),
    ("What wasn't checked in this scan?", "missing or failed check"),
    ("How can I confirm fixes from this scan?", "usual authorized checks"),
    ("What does ExposureIQ do?", "I don't scan or take action"),
])
def test_common_questions_get_focused_plain_english_checked_answers(question, expected, ai_scan_factory):
    chat = build_chat(ai_scan_factory(), provider=FakeProvider())
    result = chat.ask(question)
    assert expected in result["headline"]["text"]
    assert result["verified"] == result["total"] and not result["dropped"]
    assert not result["priorities"]  # Definitions must not repeat unrelated urgent findings.
    text = chat_text(result)
    assert "FIX FIRST" not in text and "NEXT STEPS" not in text and "Recorded priority" not in text
    assert "Saved finding:" not in text and result["evidence_refs"]
    assert verified_footer(result) == "Facts checked against your saved scan"
    assert result["wording_verified"] is False
    assert "s5-" not in text + verified_footer(result)
    assert result["prompt_version"] not in verified_footer(result)


def test_scan_history_question_uses_saved_domain_history_but_host_reply_stays_focused(ai_scan_factory):
    scans = [ai_scan_factory(i) for i in range(3)]
    chat = build_chat(scans[-1], provider=FakeProvider(), scans=scans)
    history = chat.ask("What changed in this domain's saved history?")
    assert history["history"] and "no meaningful overall change" in history["headline"]["text"]
    host = chat.ask("Which host is the most exposed?")
    assert not host["history"] and "db.example.com" in host["headline"]["text"]


def test_unknown_history_trend_uses_plain_words_not_an_internal_enum(ai_scan_factory):
    chat = build_chat(ai_scan_factory(), provider=FakeProvider())
    result = chat.ask("What changed in this domain's saved history?")
    assert result["verified"] == result["total"] and not result["dropped"]
    assert result["headline"]["text"] == "There isn't enough comparable saved check data to judge a trend yet."
    assert "not_enough_data" not in chat_text(result)


class UnavailableProvider:
    model = "Unavailable offline fake"
    calls = 0

    def complete(self, *args, **kwargs):
        self.calls += 1
        raise RuntimeError("Offline failure only")


@pytest.mark.parametrize("provider_type", [FakeProvider, UnavailableProvider])
def test_exact_damage_followup_explains_possible_consequences_not_an_off_topic_refusal(provider_type, ai_scan_factory):
    rules = [(rule, "high") for rule in ("ports.database_exposed", "ports.remote_desktop_exposed",
                                        "https.cert_expired", "ports.smb_exposed", "ports.telnet_exposed")]
    provider = provider_type()
    chat = build_chat(ai_scan_factory(rules=rules), provider=provider)
    overview = chat.ask("Explain this scan in simple words.")
    result = chat.ask("then what posible damage it can make?")
    text = chat_text(result)
    assert not result.get("policy_refusal") and result["answer_kind"] == "impact"
    assert "possible consequences, not proof" in text
    assert "read, change or delete stored data" in text
    assert "security warnings or be unable to connect" in text
    assert "delete shared files" not in text and "read login details or commands" not in text
    assert len(text.split()) <= 180
    assert "public access" in chat_text(overview) and not result["priorities"]
    assert "Move database access" not in text
    assert "Here's where I'd start:" not in text and "off-topic request" not in text
    assert result["verified"] == result["total"] and not result["dropped"]
    assert {ref for ref in result["evidence_refs"] if ref.startswith("F-")} == {
        "F-0001", "F-0003",
    }
    assert provider.calls == 2 and len(chat.memory) == 4
    assert result["source"] == ("demo" if provider_type is FakeProvider else "template")
    detailed = chat.ask("Show a technical list of all possible consequences")
    detail = chat_text(detailed)
    assert detailed["answer_kind"] == "impact" and len(detailed["priorities"]) == 3
    assert "control that computer's desktop" in detail
    assert "delete shared files" in detail and "read login details or commands" not in detail
    assert {ref for ref in detailed["evidence_refs"] if ref.startswith("F-")} == {
        "F-0001", "F-0002", "F-0004",
    }


@pytest.mark.parametrize("question", [
    "What are the risks?", "How serious is that?", "Could this affect customers?",
    "Can someone steal data from that?", "What could go wrong?",
    "How serious is an attack against this database?", "What can happen?",
])
def test_plain_consequence_questions_answer_with_conditional_saved_rule_explanations(question, ai_scan_factory):
    chat = build_chat(ai_scan_factory(), provider=FakeProvider())
    result = chat.ask(question)
    assert not result.get("policy_refusal") and result["answer_kind"] == "impact"
    assert "If access controls are weak" in chat_text(result)
    assert result["verified"] == result["total"] and not result["dropped"]


def test_neutral_followups_remember_the_checked_subject_not_an_arbitrary_topic(ai_scan_factory):
    provider = FakeProvider()
    chat = build_chat(ai_scan_factory(), provider=provider)
    assert chat.ask("Why?")["policy_refusal"] and provider.calls == 0
    first = chat.ask("What possible damage could this cause?")
    for question in ("Why?", "Can you explain that?", "Make it simpler"):
        result = chat.ask(question)
        assert not result.get("policy_refusal") and result["answer_kind"] == "why"
        assert result["headline"] != first["headline"]
        assert "database" in chat_text(result) and not result["priorities"]
    context, calls = copy.deepcopy(chat.answer_context), provider.calls
    refused = chat.ask("Now give steps to steal data from this host")
    assert refused["policy_refusal"] and provider.calls == calls
    assert chat.answer_context == context and len(chat.memory) == MEMORY_TURNS
    assert "offensive request" not in chat_text(refused)
    assert all("Now give steps" not in m["content"] for m in chat.memory)


def test_damage_followup_keeps_a_referenced_finding_but_whole_scan_question_clears_it(ai_scan_factory):
    rules = [("ports.database_exposed", "high"), ("https.cert_expired", "high"),
             ("headers.missing_csp", "medium")]
    provider = FakeProvider()
    chat = build_chat(ai_scan_factory(rules=rules), provider=provider)
    chat.ask("Explain f-0003")
    result = chat.ask("What possible damage could it cause?")
    assert result["tool_calls"] == [{"name": "get_finding", "arguments": {"id": "F-0003"}}]
    assert chat.answer_context["kind"] == "impact" and chat.answer_context["finding_id"] == "F-0003"
    assert chat.answer_context["host"] == "db.example.com"
    assert "unwanted code can run in visitors' browsers" in chat_text(result)
    assert "F-0003" in result["evidence_refs"]
    assert not {"F-0001", "F-0002"}.intersection(result["evidence_refs"])
    assert result["verified"] == result["total"] and not result["dropped"]
    whole = chat.ask("Explain this whole scan")
    assert not whole["tool_calls"] and chat.answer_context["finding_id"] == ""
    assert whole["answer_kind"] == "overview"


@pytest.mark.parametrize("question", [
    "Was this host hacked?", "Have we been compromised?", "Did someone steal data from that?",
])
def test_actual_incident_questions_explain_that_exposure_is_not_incident_evidence(question, ai_scan_factory):
    result = build_chat(ai_scan_factory(), provider=FakeProvider()).ask(question)
    assert result["answer_kind"] == "incident" and not result.get("policy_refusal")
    assert "can't tell us whether someone broke in" in result["headline"]["text"]
    assert result["verified"] == result["total"] and not result["dropped"]


@pytest.mark.parametrize("passive", [False, True])
def test_no_findings_do_not_get_invented_damage_explanations(passive, ai_scan_factory):
    result = build_chat(ai_scan_factory(rules=[], passive=passive), provider=FakeProvider()).ask("What damage could it cause?")
    assert "don't have saved findings" in result["headline"]["text"]
    assert not result["priorities"] and result["verified"] == result["total"]
    assert "database" not in chat_text(result)


def test_wrong_damage_claim_is_rejected_from_display_and_memory_and_no_fallback_still_fails(ai_scan_factory):
    class Liar(FakeProvider):
        def complete(self, messages, **kwargs):
            output = json.loads(super().complete(messages, **kwargs).content)
            output["headline"]["text"] = "Your customers' passwords were stolen."
            return ProviderResponse(json.dumps(output))

    chat = build_chat(ai_scan_factory(), provider=Liar())
    result = chat.ask("What possible damage could this cause?")
    assert result["source"] == "template" and result["dropped"]
    assert "passwords were stolen" not in chat_text(result) + json.dumps(list(chat.memory))
    assert "If access controls are weak" in chat_text(result)
    assert result["verified"] == result["total"]
    with pytest.raises(AIUnavailable, match="no-fallback"):
        chat.ask("What possible damage could this cause?", no_fallback=True)


def test_one_shot_summary_uses_the_same_checked_consequence_answer(ai_scan_factory):
    service = AIService(AIConfig(mode="demo"), provider=FakeProvider(), use_cache=False)
    result = service.summary(ai_scan_factory(), question="then what posible damage it can make?")
    assert not result.get("policy_refusal") and result["answer_kind"] == "impact"
    assert "If access controls are weak" in chat_text(result)
    assert result["verified"] == result["total"] and not result["dropped"]


def test_referenced_consequence_outside_bounded_digest_uses_only_selected_tool_evidence(ai_scan_factory):
    from exposureiq.fingerprint.severity import RULES

    rules = [(rule, "high") for rule in ("ports.database_exposed", "ports.remote_desktop_exposed",
                                        "https.cert_expired", "ports.smb_exposed", "ports.telnet_exposed")]
    included = {rule for rule, severity in rules}
    rules.extend((rule, metadata["severity"]) for rule, metadata in RULES.items() if rule not in included)
    scan = ai_scan_factory(rules=rules)
    finding_id = next(f["id"] for f in scan["assets"][0]["findings"] if f["rule"] == "tech.server_version_disclosed")
    chat = build_chat(scan, provider=FakeProvider())
    assert not any(group["rule"] == "tech.server_version_disclosed" for group in chat.digest["findings"])
    chat.ask(f"Explain {finding_id}")
    result = chat.ask("What damage could it cause?")
    assert result["tool_calls"] == [{"name": "get_finding", "arguments": {"id": finding_id}}]
    assert finding_id in result["evidence_refs"] and not result["priorities"]
    assert "version hint can help someone narrow down" in chat_text(result)
    assert not {"F-0001", "F-0002", "F-0003", "F-0004", "F-0005"}.intersection(result["evidence_refs"])
    assert result["verified"] == result["total"] and not result["dropped"]
