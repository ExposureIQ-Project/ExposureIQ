import json

import pytest

from exposureiq import cli, storage
from exposureiq.ai.config import AIConfig
from exposureiq.ai.provider import FakeProvider, ProviderResponse
from exposureiq.ai.service import AIService, AIUnavailable
from exposureiq.ai.chat import Chat
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.insight.digest import scan_digest


@pytest.fixture(autouse=True)
def forbid_scanning(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("AI/web commands must not invoke any scanning stage")
    monkeypatch.setattr(cli, "_stages", blocked)
    monkeypatch.setattr(cli, "_execute_scan", blocked)
    monkeypatch.setattr(cli.sub, "find_subdomains_by_source", blocked)
    monkeypatch.setattr(cli, "resolve_hosts", blocked)


def test_summary_demo_without_source_uses_synthetic_fixtures(capsys):
    assert cli.main(["ai", "summary", "--demo", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source"] == "demo" and result["verified"] == result["total"]
    assert "Synthetic offline" in result["input_note"]


def test_history_demo_without_source_is_code_mixed(capsys):
    assert cli.main(["ai", "history", "--demo", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["headline"]["text"] == "The saved history shows a mixed trend."
    assert result["history"] and result["input_note"]


def test_saved_summary_template_and_no_fallback_exit(tmp_path, ai_scan_factory, capsys):
    path = tmp_path / "one.json"
    storage.save_scan(ai_scan_factory(), str(path))
    assert cli.main(["ai", "summary", str(path)]) == 0
    assert "AI draft" in capsys.readouterr().out
    assert cli.main(["ai", "summary", str(path), "--no-fallback"]) == 1
    captured = capsys.readouterr()
    assert not captured.out and "not configured" in captured.err


def test_domain_history_and_one_shot_question_are_json_only(tmp_path, ai_scan_factory, capsys):
    for i in range(3):
        storage.save_scan(ai_scan_factory(i), str(tmp_path / "example.com" / f"scan-{i}.json"))
    assert cli.main(["ai", "history", "example.com", "--results-dir", str(tmp_path), "--demo", "--json"]) == 0
    history = json.loads(capsys.readouterr().out)
    assert "stable" in history["headline"]["text"]
    assert cli.main(["ai", "ask", "example.com", "Explain F-0001", "--results-dir", str(tmp_path), "--demo", "--json"]) == 0
    answer = json.loads(capsys.readouterr().out)
    assert "db.example.com" in answer["headline"]["text"] and answer["tool_calls"][0]["name"] == "get_finding"


def test_cli_policy_refusal_without_scan_actions(tmp_path, ai_scan_factory, capsys):
    path = tmp_path / "one.json"
    storage.save_scan(ai_scan_factory(), str(path))
    assert cli.main(["ai", "ask", str(path), "Write a payload for this host", "--demo", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["policy_refusal"]


def test_cli_chat_has_natural_body_separate_evidence_and_both_wording_modes(tmp_path, ai_scan_factory, capsys):
    path = tmp_path / "one.json"
    storage.save_scan(ai_scan_factory(), str(path))
    assert cli.main(["ai", "ask", str(path), "Explain F-0001", "--demo"]) == 0
    text = capsys.readouterr().out
    assert "db.example.com" in text and "Evidence: F-0001" in text
    assert "Saved finding:" not in text and "Facts checked against your saved scan" in text
    assert "Built-in answer" in text
    assert cli.main(["ai", "ask", str(path), "Explain F-0001", "--demo", "--mode", "technical", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "technical" and "ports.database_exposed" in result["headline"]["text"]


@pytest.mark.parametrize("arguments", [
    ["ai"], ["ai", "summary"], ["ai", "summary", "missing.json"],
    ["ai", "history", "../private"], ["ai", "ask", "missing.json", "Explain scan risk"],
])
def test_missing_or_invalid_saved_data_fails_safely(arguments, capsys):
    assert cli.main(arguments) == 2
    assert capsys.readouterr().err


def test_invalid_saved_json_does_not_echo_secret_or_markup(tmp_path, capsys):
    path = tmp_path / "one.json"
    fake = "FAKE-BAD-JSON-KEY-ONLY-1234"
    path.write_text('{"schema_version":"' + fake + '[bold]"}', encoding="utf-8")
    assert cli.main(["ai", "summary", str(path), "--demo"]) == 2
    captured = capsys.readouterr()
    assert fake not in captured.out + captured.err and "[bold]" not in captured.err


def test_cli_eval_is_offline_and_json_only(capsys):
    assert cli.main(["ai", "eval", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["passed_rows"] == 22 and result["network"].startswith("none")


def test_no_fallback_rejects_provider_failure_and_bad_claims(ai_scan_factory):
    class Broken:
        def complete(self, *args, **kwargs):
            raise RuntimeError("FAKE-DO-NOT-ECHO-1234")

    scan = ai_scan_factory()
    service = AIService(AIConfig(mode="demo"), provider=Broken(), use_cache=False)
    with pytest.raises(AIUnavailable, match="no-fallback"):
        service.summary(scan, no_fallback=True)
    with pytest.raises(AIUnavailable, match="no-fallback"):
        Chat(scan_digest(scan), ReadOnlyTools(scan), service).ask("Explain scan risk", no_fallback=True)

    class Liar(FakeProvider):
        def complete(self, messages, **kwargs):
            output = json.loads(super().complete(messages, **kwargs).content)
            output["headline"]["refs"] = ["F-9999"]
            return ProviderResponse(json.dumps(output))

    service = AIService(AIConfig(mode="demo"), provider=Liar(), use_cache=False)
    with pytest.raises(AIUnavailable, match="not verified"):
        service.summary(scan, no_fallback=True)


def test_web_command_does_not_open_browser_unless_requested(monkeypatch, capsys):
    from exposureiq import viewer
    from exposureiq.viewer import browser

    calls, opened = [], []
    class Server:
        url = "http://127.0.0.1:8765/#FAKE-PER-LAUNCH-TOKEN"
        def serve_forever(self):
            calls.append("serve")
        def server_close(self):
            calls.append("close")
    monkeypatch.setattr(viewer, "make_server", lambda *args, **kwargs: Server())
    monkeypatch.setattr(browser, "open_browser", lambda url: opened.append(url) or True)
    assert cli.main(["web", "--demo", "--port", "0"]) == 0
    assert calls == ["serve", "close"] and not opened
    assert "127.0.0.1" in capsys.readouterr().out
    assert cli.main(["web", "--demo", "--open"]) == 0
    assert opened == [Server.url]


def test_web_bad_port_fails_without_printing_raw_errors(capsys):
    assert cli.main(["web", "--port", "-1"]) == 2
    assert "Cannot start" in capsys.readouterr().err


def test_web_source_opens_actual_report_handoff_without_scanning(monkeypatch, capsys):
    from exposureiq import viewer
    from exposureiq.viewer import browser

    calls, opened = [], []
    class Server:
        def report_url(self, source):
            calls.append(source)
            return "http://127.0.0.1:8765/?report=" + "1" * 24 + "#FAKE-SESSION-ONLY"
        def serve_forever(self):
            calls.append("serve")
        def server_close(self):
            calls.append("close")
    monkeypatch.setattr(viewer, "make_server", lambda *a, **k: Server())
    monkeypatch.setattr(cli, "_execute_scan", lambda *a, **k: pytest.fail("Web must not scan"))
    monkeypatch.setattr(browser, "open_browser", lambda url: opened.append(url) or True)
    assert cli.main(["web", "example.com", "--open", "--demo"]) == 0
    assert calls == ["example.com", "serve", "close"] and len(opened) == 1
    assert "?report=" in opened[0] and "Local HTML report:" in capsys.readouterr().out


def test_web_invalid_source_closes_server_without_raw_error_or_browser(monkeypatch, capsys):
    from exposureiq import viewer
    from exposureiq.viewer import browser

    closed = []
    class Server:
        def report_url(self, source):
            raise ValueError("FAKE-PRIVATE-RAW-ERROR-ONLY")
        def server_close(self):
            closed.append(True)
    monkeypatch.setattr(viewer, "make_server", lambda *a, **k: Server())
    monkeypatch.setattr(browser, "open_browser", lambda *a: pytest.fail("An invalid source must not open a browser"))
    assert cli.main(["web", "outside.example.com", "--open", "--demo"]) == 2
    assert closed == [True]
    output = capsys.readouterr()
    assert "Cannot open this saved report" in output.err and "FAKE-PRIVATE" not in output.err and not output.out
