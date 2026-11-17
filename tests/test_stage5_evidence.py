"""Check committed presentation artifacts without a browser or network."""

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree

from exposureiq.ai.evaluate import evaluation_table

EVIDENCE = Path(__file__).resolve().parents[1] / "docs" / "stage5-evidence"
SCREENSHOTS = (
    "01-home-drawer.svg", "02-masked-settings.svg", "03-remote-consent.svg",
    "04-domain-folders.svg", "05-domain-scans.svg", "06-history-summary.svg",
    "07-scan-summary.svg", "08-chat-refusal.svg", "09-ai-log.svg",
    "10-chat-thinking.svg", "11-ai-off.svg", "12-impact-follow-up.svg",
)


def test_real_svg_captures_match_manifest_and_have_no_external_resources():
    manifest = json.loads((EVIDENCE / "manifest.json").read_text(encoding="utf-8"))
    assert tuple(item["file"] for item in manifest["screenshots"]) == SCREENSHOTS
    assert {path.name for path in EVIDENCE.glob("*.svg")} == set(SCREENSHOTS)
    assert manifest["network"] == "blocked; deterministic offline fakes only"
    for item in manifest["screenshots"]:
        raw = (EVIDENCE / item["file"]).read_bytes()
        assert len(raw) == item["bytes"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]
        assert b"FAKE-EVIDENCE-KEY-ONLY-1234" not in raw
        assert b"@font-face" not in raw and b"cdnjs.cloudflare.com" not in raw
        root = ElementTree.fromstring(raw)
        words = " ".join(" ".join("".join(element.itertext()) for element in root.iter()
                                  if element.tag.endswith("}text")).split())
        assert all(expected in words for expected in item["observed_text"])
        for element in root.iter():
            assert not element.tag.endswith(("}script", "}foreignObject", "}image"))
            for name, value in element.attrib.items():
                assert not name.lower().startswith("on")
                if name.endswith("href"):
                    assert value.startswith("#")
    assert "••••" in (EVIDENCE / "02-masked-settings.svg").read_text(encoding="utf-8")


def test_saved_offline_evaluation_has_all_wrong_drafts_rejected_and_refusals_make_no_calls():
    result = json.loads((EVIDENCE / "evaluation.json").read_text(encoding="utf-8"))
    assert result["passed"] and result["passed_rows"] == len(result["rows"]) == 22
    normal = [row for row in result["rows"] if row["kind"] == "summary" and row["provider"] == "fake"]
    wrong = [row for row in result["rows"] if row["kind"] == "summary" and row["provider"] == "wrong fake"]
    refusals = [row for row in result["rows"] if row["kind"] == "policy"]
    assert len(normal) == len(wrong) == 8 and len(refusals) == 6
    assert all(row["raw_accepted"] and row["display_high_coverage"] for row in normal)
    assert all(not row["raw_accepted"] and row["source"] == "template" and row["display_high_coverage"] for row in wrong)
    assert all(row["calls"] == 0 and row["passed"] for row in refusals)
    assert (EVIDENCE / "evaluation.md").read_text(encoding="utf-8").strip() == evaluation_table(result)
    assert "not evidence of any real model" in result["limitation"]


def test_exact_damage_followup_has_a_complete_literal_offline_transcript():
    manifest = json.loads((EVIDENCE / "manifest.json").read_text(encoding="utf-8"))
    evidence = manifest["follow_up"]
    raw = (EVIDENCE / evidence["file"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == evidence["sha256"]
    assert evidence["model_calls"] == 1 and evidence["question"] == "then what posible damage it can make?"
    text = raw.decode("utf-8")
    assert evidence["question"] in text and "What could go wrong:" not in text
    assert "not proof that anyone broke in" in text and "read, change or delete stored data" in text
    assert "control the computer's desktop" in text and "an expired certificate alone doesn't mean data was stolen" in text
    assert "off-topic request" not in text and "All network sockets/DNS were blocked" in text
    assert text.count("## You") == text.count("## ExposureIQ · AI draft") == 2
    assert "saved evidence checked; wording needs review" in text and "not real-model accuracy or full prose verification" in text


def test_fresh_wording_evidence_fake_keeps_host_facts_and_unique_refs():
    from dynamic_chat_fakes import FreshFactsProvider
    from exposureiq.ai.chat import Chat
    from exposureiq.ai.config import AIConfig, LOCAL_BASE
    from exposureiq.ai.service import AIService, chat_text
    from exposureiq.ai.tools import ReadOnlyTools
    from exposureiq.demo_data import build_demo_scans
    from exposureiq.insight.digest import scan_digest

    scan, fake = build_demo_scans()[3], FreshFactsProvider()
    service = AIService(AIConfig(mode="local", base_url=LOCAL_BASE, model="offline-only"), provider=fake, use_cache=False)
    chat = Chat(scan_digest(scan), ReadOnlyTools(scan), service)
    for question in ("Which host is the most exposed?", "then why would i fix it first?", "what would that do or cause if didn't fixed?"):
        result = chat.ask(question)
        assert result["source"] == "fake" and not result["failure_kind"] and not result["dropped"]
        assert "db.example.com" in chat_text(result) and "11 high" not in chat_text(result)
        claims = [result["headline"], *result["notes"], *result["next_steps"]]
        assert all(len(claim["refs"]) == len(set(claim["refs"])) for claim in claims)


def test_natural_transcripts_cover_real_surfaces_modes_and_safe_fallbacks():
    from exposureiq.ai.conversation import OFFLINE_NOTICE, PROOF_NOTE

    manifest = json.loads((EVIDENCE / "natural-manifest.json").read_text(encoding="utf-8"))
    assert manifest["passed"] and manifest["cases"] == 20 and manifest["turns"] == 84
    for item in manifest["files"]:
        assert hashlib.sha256((EVIDENCE / item["file"]).read_bytes()).hexdigest() == item["sha256"]
    result = json.loads((EVIDENCE / "natural-chat.json").read_text(encoding="utf-8"))
    assert result["passed"] and result["turns"] == 84
    assert result["code_owned"] == {"scan": "DEMO-HISTORY-04", "high_findings": 11, "host": "db.example.com", "host_score": 45}
    assert "no cross-command memory is claimed" in result["limitation"]
    cases = result["cases"]
    assert {case["surface"] for case in cases} == {"tui", "cli", "viewer"}
    assert {case["mode"] for case in cases} == {"simple", "technical"}
    assert {case["provider"] for case in cases} == {"fresh-offline-fake", "timeout-fallback"}
    for case in cases:
        turns = case["turns"]
        if case["provider"] == "timeout-fallback":
            assert all(len(turn["text"].split()) <= 180 for turn in turns)
        assert all(turn["provider_calls"] == 0 for turn in turns if turn["answer_kind"] == "thanks" or turn["source"] == "policy")
        assert all(turn["wording_verified"] is False and "wording needs review" in turn["footer"]
                   for turn in turns if turn["verification"] == "evidence-and-facts")
        if case["surface"] != "cli":
            assert sum(turn["text"].count(PROOF_NOTE) for turn in turns) == 1
            assert sum(turn["offline_notice"] == OFFLINE_NOTICE for turn in turns) == 1
            assert all(turn["displayed_text"] == turn["text"] for turn in turns)
            if case["sequence"] == "host":
                assert "45" in turns[0]["text"]
                assert all(turn["answer_focus"]["host"] == "db.example.com" and "db.example.com" in turn["text"] for turn in turns)
            if case["surface"] == "tui":
                assert all(turn["evidence_collapsed"] for turn in turns)


def test_real_browser_evidence_includes_ready_handoff_once_only_notices_and_repeat_runs():
    live = json.loads((EVIDENCE / "export-browser-l2.json").read_text(encoding="utf-8"))
    repeat = json.loads((EVIDENCE / "export-l2-repeatability.json").read_text(encoding="utf-8"))
    assert live["passed"] and "real headless browser" in live["browser"]
    assert "code-added first-use definition and once-only disclaimer" in live["checks"]
    assert (EVIDENCE / live["screenshot"]).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert repeat["passed"] and len(repeat["runs"]) == 3 and all(run["passed"] for run in repeat["runs"])


def test_historical_live_drawer_preserves_capture_hashes_and_source_provenance():
    structure = json.loads((EVIDENCE / "live-drawer-structure.json").read_text(encoding="utf-8"))
    live = json.loads((EVIDENCE / "live-drawer-browser.json").read_text(encoding="utf-8"))
    repeats = json.loads((EVIDENCE / "live-drawer-repeatability.json").read_text(encoding="utf-8"))
    manifest = json.loads((EVIDENCE / "live-drawer-manifest.json").read_text(encoding="utf-8"))
    assert structure["prepared_replies"] == structure["inert_json_blocks"] == structure["external_assets"] == 0
    assert structure["scripts"] == 1 and structure["scans"] == 10
    assert live["passed"] and "initial Off report has no chat" in live["checks"]
    assert "open/close/Escape/focus" in live["checks"] and "mobile bounds" in live["checks"]
    assert "45" not in live["backend_down_text"]
    assert "No prepared answer was substituted" in live["backend_down_text"] or "No answer is generated here" in live["backend_down_text"]
    assert repeats["passed"] and len(repeats["runs"]) == 3 and all(run["passed"] for run in repeats["runs"])
    assert manifest["passed"]
    for item in manifest["files"]:
        raw = (EVIDENCE / item["file"]).read_bytes()
        assert len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
    # A capture's source hashes are provenance, not proof of later edits. Keep
    # historical evidence byte-for-byte intact; explicitly name replacements.
    provenance = json.loads((Path(__file__).parent / "fixtures" / "dynamic_chat" / "source-provenance.json").read_text(encoding="utf-8"))
    raw_manifest = (EVIDENCE / "live-drawer-manifest.json").read_bytes()
    assert hashlib.sha256(raw_manifest).hexdigest() == provenance["historical_manifest_sha256"]
    replacements = provenance["replaced_sources"]
    assert set(replacements) <= {item["file"] for item in manifest["sources"]}
    for item in manifest["sources"]:
        raw = (EVIDENCE.parents[1] / item["file"]).read_bytes()
        if item["file"] in replacements:
            assert replacements[item["file"]]["capture_sha256"] == item["sha256"]
            assert replacements[item["file"]]["reason"] and raw
        else:
            assert len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
