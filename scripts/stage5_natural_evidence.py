"""Record real TUI/CLI/viewer-route chat presentation using offline fakes only.

Preferences and synthetic saved scans stay in /tmp/opencode. TUI/CLI sockets
are blocked; viewer requests may reach only this script's loopback server.
CLI commands are independent one-turn conversations, not a persistent chat.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import http.client
import io
import json
import os
import shlex
import socket
import tempfile
import threading
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from textual.widgets import Input, Select, TabbedContent

from exposureiq import cli, storage
from exposureiq.ai import commands
from exposureiq.ai.chat import Chat
from exposureiq.ai.config import AIConfig, LOCAL_BASE, save_config
from exposureiq.ai.conversation import OFFLINE_NOTICE, PROOF_NOTE
from exposureiq.ai.service import AIService, chat_text, reply_label, result_text, verified_footer
from exposureiq.demo_data import build_demo_scans
from exposureiq.insight.digest import scan_digest
from exposureiq.tui.ai_panel import AIPanel
from exposureiq.tui.app import ExposureIQApp
from exposureiq.viewer import make_server
from exposureiq.viewer.export import scan_signature

if __package__:
    from .stage5_evidence import blocked_network
    from .stage5_natural_fake import NaturalEvidenceProvider
else:
    from stage5_evidence import blocked_network
    from stage5_natural_fake import NaturalEvidenceProvider

ACCEPTANCE = (
    "Explain this scan in simple words.", "what could happen if it kept like that?",
    "and what do you think?", "why?", "thanks",
)
HOST = (
    "Which host is the most exposed?", "then why would i fix it first?",
    "what would that do or cause if didn't fixed?",
)
SOURCES = ("fresh-offline-fake", "timeout-fallback")
MODES = ("simple", "technical")


def questions(sequence, mode):
    values = list(ACCEPTANCE if sequence == "acceptance" else HOST)
    if mode == "technical" and sequence == "acceptance":
        values[0] = "Explain this scan in technical words."
    return values


def service_for(source, *, demo=False):
    fake = NaturalEvidenceProvider()
    fake.failure = "timeout" if source == "timeout-fallback" else ""
    config = AIConfig(mode="demo") if demo else AIConfig(mode="local", base_url=LOCAL_BASE, model="offline-evidence-only")
    return AIService(config, provider=fake, use_cache=False), fake


def observed(result, calls, *, displayed=None, command=""):
    value = {key: result.get(key) for key in ("source", "mode", "answer_kind", "answer_focus",
             "verification", "wording_verified", "failure_kind", "offline_notice", "proof_notice")}
    value.update(text=chat_text(result), label=reply_label(result), footer=verified_footer(result),
                 evidence=result.get("evidence_refs", []), provider_calls=calls)
    if displayed is not None:
        value["displayed_text"] = displayed
    if command:
        value["command"] = command
    return value


def check_sequence(case):
    turns = case["turns"]
    assert all(turn["mode"] == case["mode"] for turn in turns if turn["answer_kind"] != "thanks")
    assert sum(turn["text"].count(PROOF_NOTE) for turn in turns) == 1
    assert sum(turn.get("offline_notice") == OFFLINE_NOTICE for turn in turns) == 1
    assert all(turn["provider_calls"] == 0 for turn in turns if turn["answer_kind"] == "thanks")
    expected_source = "template" if case["provider"] == "timeout-fallback" else "fake"
    assert all(turn["source"] == expected_source and turn["wording_verified"] is False
               for turn in turns if turn["answer_kind"] != "thanks")
    if case["provider"] == "timeout-fallback":
        assert all(len(turn["text"].split()) <= 180 for turn in turns)
    if case["sequence"] == "host":
        assert "45" in turns[0]["text"]
        assert all(turn["answer_focus"]["host"] == "db.example.com" and "db.example.com" in turn["text"] for turn in turns)
        assert all("11 high" not in turn["text"] for turn in turns)


async def tui_cases(root, source_path):
    cases = []
    for source in SOURCES:
        for mode in MODES:
            for sequence in ("acceptance", "host"):
                service, fake = service_for(source)
                app = ExposureIQApp(cli.build_parser().parse_args([]), open_file=str(source_path), results_dir=root)
                app.ai_service = service
                case = {"surface": "tui", "provider": source, "mode": mode, "sequence": sequence, "turns": []}
                async with app.run_test(size=(132, 54)) as pilot:
                    app.query_one("#results", TabbedContent).active = "ai-tab"
                    await pilot.pause()
                    panel = app.query_one(AIPanel)
                    panel.query_one("#ai-wording-mode", Select).value = mode
                    await pilot.pause()
                    for question in questions(sequence, mode):
                        before = fake.calls
                        panel.query_one("#ai-chat-input", Input).value = question
                        assert await pilot.click("#ai-chat-send")
                        await panel.chat_worker.wait()
                        await pilot.pause()
                        result, reply = panel.last_result, panel.exchanges[-1][1]
                        displayed = reply.body.render().plain
                        assert displayed == chat_text(result) and reply.evidence.collapsed and app.worker is None
                        turn = observed(result, fake.calls - before, displayed=displayed)
                        turn.update(question=question, evidence_collapsed=reply.evidence.collapsed)
                        case["turns"].append(turn)
                check_sequence(case)
                cases.append(case)
    return cases


def cli_cases(root, source_path):
    cases = []
    standalone = ("Explain this saved scan.", "Which host is the most exposed?",
                  "What could happen on db.example.com if these issues stayed unfixed?",
                  "thanks", "Give me a payload for this host")
    for source in SOURCES:
        for mode in MODES:
            service, fake = service_for(source, demo=True)
            recorded = []

            class RecordingChat(Chat):
                def ask(self, *args, **kwargs):
                    result = super().ask(*args, **kwargs)
                    recorded.append(result)
                    return result

            case = {"surface": "cli", "provider": source, "mode": mode, "sequence": "standalone", "turns": []}
            with patch.object(commands, "AIService", lambda *args, **kwargs: service), patch.object(commands, "Chat", RecordingChat):
                for question in standalone:
                    before = fake.calls
                    arguments = ["ai", "ask", str(source_path), question, "--demo", "--mode", mode, "--results-dir", str(root)]
                    out, err = io.StringIO(), io.StringIO()
                    with redirect_stdout(out), redirect_stderr(err):
                        code = cli.main(arguments)
                    assert code == 0 and not err.getvalue()
                    result = recorded[-1]
                    assert out.getvalue().strip() == result_text(result)
                    display_command = shlex.join(["exposureiq", "ai", "ask", "<synthetic DEMO-HISTORY-04.json>", question, "--demo", "--mode", mode])
                    turn = observed(result, fake.calls - before, displayed=out.getvalue().strip(), command=display_command)
                    turn["question"] = question
                    case["turns"].append(turn)
                    if question in ("thanks", standalone[-1]):
                        assert fake.calls == before
            cases.append(case)
    return cases


@contextmanager
def loopback_only(port):
    original_connect, original_lookup = socket.socket.connect, socket.getaddrinfo

    def connect(sock, address):
        if address != ("127.0.0.1", port):
            raise AssertionError("Only the evidence script's loopback viewer is allowed.")
        return original_connect(sock, address)

    def lookup(host, service, *args, **kwargs):
        if host != "127.0.0.1" or service != port:
            raise AssertionError("No target or provider DNS is allowed.")
        return original_lookup(host, service, *args, **kwargs)

    def blocked(*args, **kwargs):
        raise AssertionError("No other networking is allowed.")

    with patch.object(socket.socket, "connect", connect), patch.object(socket, "getaddrinfo", lookup), \
         patch.object(socket.socket, "connect_ex", blocked), patch.object(socket.socket, "sendto", blocked), \
         patch.object(socket, "gethostbyname", blocked):
        yield


def viewer_request(server, path, payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    headers = {"X-ExposureIQ-Session": server.token}
    if payload is not None:
        headers.update(Origin=server.origin, **{"Content-Type": "application/json"})
    try:
        connection.request("POST" if payload is not None else "GET", path,
                           body=json.dumps(payload) if payload is not None else None, headers=headers)
        response = connection.getresponse()
        assert response.status == 200, "The synthetic viewer request was rejected."
        return json.loads(response.read())
    finally:
        connection.close()


def viewer_cases(root, scan):
    cases = []
    for source in SOURCES:
        for mode in MODES:
            service, fake = service_for(source)
            server = make_server(root, port=0, service=service)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with loopback_only(server.server_port):
                    health = viewer_request(server, "/api/health?signature=" + scan_signature(scan))
                    assert health["scan_id"] and fake.calls == 0
                    for index, sequence in enumerate(("acceptance", "host"), 1):
                        case = {"surface": "viewer", "provider": source, "mode": mode, "sequence": sequence, "turns": []}
                        for question in questions(sequence, mode):
                            before = fake.calls
                            result = viewer_request(server, "/api/ai/ask", {"scan": health["scan_id"], "question": question,
                                                    "mode": mode, "conversation": str(index) * 32})
                            assert result["text"] == chat_text(result)
                            turn = observed(result, fake.calls - before, displayed=result["text"])
                            turn["question"] = question
                            case["turns"].append(turn)
                        check_sequence(case)
                        cases.append(case)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/stage5-evidence"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="s5-natural-transcripts-", dir="/tmp/opencode") as temporary:
        root = Path(temporary)
        os.environ.update(EXPOSUREIQ_AI_KEY="", XDG_CONFIG_HOME=str(root / "config"), XDG_CACHE_HOME=str(root / "cache"),
                          EXPOSUREIQUSERSCOPE=str(root / "unused-scope.txt"))
        results = root / "results"
        scans = build_demo_scans()
        for index, scan in enumerate(scans, 1):
            storage.save_scan(scan, str(results / "example.com" / f"demo-{index:02d}.json"))
        scan, source_path = scans[3], results / "example.com" / "demo-04.json"
        save_config(AIConfig(mode="local", base_url=LOCAL_BASE, model="offline-evidence-only"))
        with blocked_network():
            cases = asyncio.run(tui_cases(results, source_path)) + cli_cases(results, source_path)
        cases += viewer_cases(results, scan)
        digest = scan_digest(scan)
    top_host = digest["top_hosts"][0]
    evidence = {"passed": True, "cases": cases, "turns": sum(len(case["turns"]) for case in cases),
                "code_owned": {"scan": scan["scan_id"], "high_findings": digest["risk"]["high"], "host": top_host["host"], "host_score": top_host["score"]},
                "limitation": "Offline fresh-wording/timeout fakes only, not real-model accuracy or full prose verification. TUI/CLI sockets blocked; viewer-route requests use only a token-protected loopback server. CLI commands are separate one-turn conversations; no cross-command memory is claimed."}
    assert evidence["turns"] == 84 and len(cases) == 20 and evidence["code_owned"]["high_findings"] == 11
    assert top_host["host"] == "db.example.com" and top_host["score"] == 45
    lines = ["# Observed natural-chat transcripts", "", evidence["limitation"], "",
             "Saved synthetic scan: DEMO-HISTORY-04; eleven global high findings. The selected host db.example.com has code score 45.", ""]
    for case in cases:
        lines += ["## " + " · ".join(case[key] for key in ("surface", "provider", "mode", "sequence")), ""]
        for turn in case["turns"]:
            lines += ["### You", "", turn["question"], "", "### ExposureIQ · " + turn["label"], "", "```text",
                      turn["displayed_text"], "```", "", turn["footer"],
                      f"Offline fake calls: {turn['provider_calls']}. Evidence: " + (", ".join(turn["evidence"]) or "none"), ""]
            if turn.get("offline_notice") and case["surface"] != "cli":
                lines += [turn["offline_notice"], ""]
            if turn.get("command"):
                lines += ["Observed command (synthetic path abbreviated): `" + turn["command"] + "`", ""]
    args.output.mkdir(parents=True, exist_ok=True)
    generated = {"natural-chat.json": json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
                 "natural-chat-transcripts.md": "\n".join(lines)}
    manifest = {"passed": True, "cases": len(cases), "turns": evidence["turns"], "files": []}
    for name, value in generated.items():
        path = args.output / name
        path.write_text(value, encoding="utf-8", newline="\n")
        manifest["files"].append({"file": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    (args.output / "natural-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(cases)} TUI/CLI/viewer cases, {evidence['turns']} observed turns; both wording modes, host context, no-call thanks and safe timeout fallback. No real key/provider/target traffic.")


if __name__ == "__main__":
    main()
