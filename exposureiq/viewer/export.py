"""Key-free report assets, size limits and legacy offline evidence helpers.

Current disk reports are scan-only. Local-server chat embeds only snapshot
identifiers and question suggestions; every answer comes from the server's
normal chat service. The older prepared helpers remain for regression evidence,
but their replies and scripts are no longer shipped in a generated report.
No helper here loads settings, calls a provider or writes a scan.
"""

from __future__ import annotations

import copy
import hashlib
import html
import json
import re
from importlib.resources import files

from exposureiq.ai.checker import check_chat_output, reference_index
from exposureiq.ai.context import MODES, add_focus_evidence, answer_plan, choose_context
from exposureiq.ai.conversation import OFFLINE_NOTICE, PROOF_NOTE, fallback_chat, friendly_reply
from exposureiq.ai.export_intents import INTENTS, CLARIFY, MISSING, matching_rules, route_question
from exposureiq.ai.glossary import GLOSSARY, define_terms
from exposureiq.ai.questions import WHOLE_SCAN, normalize_question
from exposureiq.ai.sanitize import compact_json, host_name, label, redact
from exposureiq.ai.service import chat_text
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.diffing.pipeline import domain_scans, scan_history, scan_key
from exposureiq.insight.digest import scan_digest
from exposureiq.insight.history_digest import build_history_layers, history_facts

BUNDLE_VERSION = "offline-chat-1"
LIVE_BUNDLE_VERSION = "live-chat-1"
WARN_EXPORT_BYTES = 2_000_000
MAX_EXPORT_BYTES = 10_000_000
MAX_PREPARED_FINDINGS = 24
SIZE_WARNING = "This exported page is larger than about 2 MB. It may be slow to open or share."
SHARING_WARNING = "Sharing warning: this file contains saved security findings. Share it only with people allowed to see them. No API key is included."
_FOCUSED_INTENTS = ("overview", "fix", "impact", "why", "opinion", "host", "finding", "risk", "owner", "timing")


class ExportError(ValueError):
    pass


def scan_signature(scan: dict) -> str:
    return hashlib.sha256(compact_json(scan).encode("utf-8")).hexdigest()


def view_id(scan: dict) -> str:
    # Match the report renderer's stable scan token without embedding a path.
    token = hashlib.sha256(json.dumps(scan_key(scan), ensure_ascii=False).encode("utf-8")).hexdigest()[:20]
    return "scan-" + token


def _prepared_reply(digest, context, *, intent):
    plan = answer_plan(digest, {**context, "kind": "overview" if intent == "fix" else intent,
                                "list_requested": intent == "fix"})
    plan.update(include_proof_note=False, defined_terms=list(GLOSSARY))
    checked = check_chat_output(fallback_chat(digest, plan), digest, plan)
    if not checked.accepted:
        raise ExportError("A prepared export reply failed its evidence or safety checks.")
    claims = [checked.output["headline"], *checked.output["priorities"], *checked.output["notes"], *checked.output["next_steps"]]
    refs = list(dict.fromkeys(ref for item in claims for ref in item["refs"]))
    result = {**checked.output, "verification": "evidence-and-facts", "mode": plan["mode"], "list_requested": plan["list_requested"],
              "history": history_facts(digest) if intent == "history" else {}}
    return {"text": chat_text(result), "refs": refs, "kind": intent,
            "proof_relevant": intent == "impact" and bool(plan["groups"])}


def _reference_rows(digest):
    allowed = {"ref", "rule", "severity", "host", "title", "count", "hosts", "id", "score", "date", "value"}
    return {ref: {key: value for key, value in item.items() if key in allowed and not isinstance(value, (dict, list))}
            for ref, item in reference_index(digest).items()}


def _export_digest(scan):
    digest = scan_digest(scan)
    # Port/service and software strings are unnecessary for these prepared
    # intents. Keep code-owned finding rules and counts, not copied labels.
    for key in ("ports", "technologies"):
        digest["omitted"][key] += len(digest[key])
        digest[key] = []
    return digest


def _scan_bundle(scan, scans):
    history = scan_history(scan, scans)
    tools = ReadOnlyTools(scan, scans=history)
    digest = _export_digest(scan)
    history_digest = build_history_layers(history, digests=[_export_digest(item) for item in history])["L4"]
    base = choose_context("Explain this scan", digest, tools)
    refs, replies = _reference_rows(digest), {}
    ids = [fid for group in digest["findings"] for fid in group["ids"]
           if sum(item["id"] == fid for item in tools.findings) == 1][:MAX_PREPARED_FINDINGS]
    hosts = [item["host"] for item in digest["top_hosts"]]
    focuses = {"scan": base}
    for host in hosts:
        focuses["host:" + host] = choose_context("Explain this host", digest, tools, host=host)
    for fid in ids:
        focuses["finding:" + fid] = choose_context("Explain this finding", digest, tools, finding_id=fid)
    for focus, context in focuses.items():
        replies[focus] = {}
        focused_digest = add_focus_evidence(digest, context, tools)
        refs.update(_reference_rows(focused_digest))
        for mode in MODES:
            replies[focus][mode] = {}
            intents = [item[0] for item in INTENTS] if focus == "scan" else _FOCUSED_INTENTS
            for intent in intents:
                chosen = {**context, "mode": mode}
                current = history_digest if intent == "history" else focused_digest
                refs.update(_reference_rows(current))
                # The most-exposed question selects the top host in code.
                if intent == "host" and focus == "scan" and hosts:
                    chosen = {**focuses["host:" + hosts[0]], "mode": mode}
                    current = add_focus_evidence(digest, chosen, tools)
                    refs.update(_reference_rows(current))
                if intent == "finding" and focus == "scan":
                    replies[focus][mode][intent] = {"text": "Which finding would you like explained? Use an ID from this report, such as the one in its Findings view.",
                                                       "refs": ["S:scan"], "kind": intent, "proof_relevant": False}
                else:
                    replies[focus][mode][intent] = _prepared_reply(current, chosen, intent=intent)
    common = {}
    for mode in MODES:
        common[mode] = {kind: _prepared_reply(add_focus_evidence(digest, base, tools), {**base, "mode": mode}, intent=kind)
                        for kind in ("app", "scope", "severity", "coverage", "confirm", "incident")}
    return {"scan_id": label(scan["scan_id"], 160), "date": label(scan["started_at"], 25),
            "target": host_name(scan["target"]), "signature": scan_signature(scan), "digest": digest,
            "references": refs, "replies": replies, "common": common, "hosts": hosts, "finding_ids": ids,
            "top_host": hosts[0] if hosts else "", "alternatives": [group["ids"][0] for group in digest["findings"][:3] if group["ids"]],
            "omitted_findings": max(0, len(tools.findings) - len(ids))}


def build_chat_bundle(scan: dict, scans: list[dict] | None = None) -> dict:
    ordered = domain_scans(scan, scans or [scan])
    return {"version": BUNDLE_VERSION, "default_scan": view_id(scan), "rules": matching_rules(), "glossary": GLOSSARY, "glossary_order": list(GLOSSARY),
            "offline_notice": OFFLINE_NOTICE, "proof_note": PROOF_NOTE, "sharing_warning": SHARING_WARNING,
            "friendly": {kind: friendly_reply(kind)["headline"]["text"] for kind in ("greeting", "thanks", "acknowledgement")},
            "scans": {view_id(item): _scan_bundle(item, ordered) for item in ordered}}


def build_live_chat_bundle(scan: dict, scans: list[dict] | None = None) -> dict:
    """Snapshot metadata only. The browser never selects prepared answers."""
    ordered = domain_scans(scan, scans or [scan])
    return {"version": LIVE_BUNDLE_VERSION, "default_scan": view_id(scan),
            "questions": [example for _, example, _ in INTENTS],
            "scans": {view_id(item): {"scan_id": label(item["scan_id"], 160),
                                     "date": label(item["started_at"], 25),
                                     "target": host_name(item["target"]),
                                     "signature": scan_signature(item)} for item in ordered}}


def live_report_page(scan: dict, scans: list[dict], *, ai_enabled=False, private=(), focus_scan=False) -> str:
    """Render the export's report in memory; never write a file or call AI.

    Private server strings are removed before rendering, not after hashing the
    scripts. Signatures still identify the original, already-saved snapshots.
    """
    from exposureiq.diffing.pipeline import build_history_diff
    from exposureiq.report.domain import build_domain_report
    from exposureiq.report.html import render_domain_html
    from exposureiq.report.model import build_report
    from exposureiq.report.render import _version

    safe_scan, safe_scans = redact(scan, private), redact(scans, private)
    history = scan_history(safe_scan, safe_scans)
    report = build_report(safe_scan, history=history, diff=build_history_diff(safe_scan, history))
    report["tool_version"] = _version()
    domain = build_domain_report(safe_scan, safe_scans, report)
    bundle = build_live_chat_bundle(safe_scan, safe_scans) if ai_enabled is True else None
    if bundle is not None:
        for original, safe in [(scan, safe_scan), *zip(scans, safe_scans)]:
            if view_id(safe) in bundle["scans"]:
                bundle["scans"][view_id(safe)]["signature"] = scan_signature(original)
    page, _ = check_export_size(render_domain_html(domain, chat_bundle=bundle, server_report=True,
                                                 start_view=view_id(safe_scan) if focus_scan else ""))
    return page


def embedded_json(value: dict) -> str:
    # HTML script parsing ignores JSON quotes. Escape every opening bracket of
    # an HTML tag, including </script>, before putting JSON in an inert block.
    return compact_json(value).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def chat_assets(bundle: dict) -> tuple[str, str, str, str]:
    if bundle.get("version") != LIVE_BUNDLE_VERSION:
        raise ExportError("Only local-server chat metadata can be attached to a report.")
    static = files("exposureiq.viewer").joinpath("static")
    script = static.joinpath("live-chat.js").read_text(encoding="utf-8")
    css = static.joinpath("live-chat.css").read_text(encoding="utf-8")
    markup = """<button id="export-chat-toggle" class="export-chat-toggle" type="button" hidden
  aria-label="Open AI chat" aria-controls="export-chat" aria-expanded="false" title="Open AI chat">
  <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
    <path d="M20 11.5a8 8 0 0 1-8 8H5l-4 3v-11a8 8 0 0 1 8-8h3a8 8 0 0 1 8 8Z"/>
    <path d="M7 10h8M7 14h5"/>
  </svg>
</button>
<div id="export-chat-divider" class="export-chat-divider" role="separator" tabindex="0"
  aria-label="Resize report and chat" aria-orientation="vertical" aria-valuemin="30" aria-valuemax="70" aria-valuenow="50" hidden></div>
<aside id="export-chat" class="export-chat-drawer" role="dialog" aria-modal="false"
  aria-labelledby="export-chat-title" hidden>
  <div class="export-chat-heading">
    <div><p>Saved evidence, explained</p><h2 id="export-chat-title">ExposureIQ assistant</h2></div>
    <div class="export-chat-heading-actions">
      <button id="export-chat-options-toggle" type="button" aria-controls="export-chat-options" aria-expanded="false" aria-haspopup="dialog">Chat options</button>
      <button id="export-chat-close" type="button" aria-label="Close AI chat" title="Close AI chat">&times;</button>
    </div>
  </div>
  <div id="export-chat-options" class="export-chat-settings" role="dialog" aria-label="Chat options" hidden>
    <div class="export-chat-header">
    <label>Scan <select id="export-chat-scan"></select></label>
    <label>Wording <select id="export-chat-mode"><option value="simple">Simple</option><option value="technical">Technical</option></select></label>
    </div>
    <label>Ideas to ask <select id="export-chat-common" disabled><option value="">Choose a question</option></select></label>
    <p id="export-chat-source">Checking AI settings…</p>
    <p id="export-live-status" role="status">Settings and provider keys stay on the local server.</p>
    <button id="export-live-refresh" type="button">Check settings</button>
    <button id="export-chat-clear" type="button">Clear chat</button>
  </div>
  <p id="export-chat-stage" class="export-chat-stage" role="status" aria-live="polite" hidden></p>
  <div id="export-chat-log" role="log" aria-live="polite" aria-label="Saved-data conversation">
    <p class="export-chat-empty">Ask about this saved scan, or follow up on a reply. I explain evidence and defensive fixes; I never scan or take action.</p>
  </div>
  <div id="export-chat-ideas" class="export-chat-ideas" aria-label="Suggested questions"></div>
  <div class="export-chat-compose">
    <label for="export-chat-input">Your question</label>
    <textarea id="export-chat-input" rows="2" maxlength="1000" placeholder="What matters most in this scan?" disabled></textarea>
    <div class="export-chat-actions"><span>Enter to send · Shift+Enter for a new line</span><button id="export-chat-send" type="button" disabled>Send</button></div>
    <p id="export-chat-status" role="status">No model is called until you send a question.</p>
  </div>
</aside>"""
    return markup, css, script, embedded_json(bundle)


def check_export_size(page: str) -> tuple[str, list[str]]:
    size = len(page.encode("utf-8"))
    if size > MAX_EXPORT_BYTES:
        raise ExportError("HTML export exceeds about 10 MB and was not written. Use a smaller saved history or export PDF/DOCX instead.")
    warnings = []
    if size > WARN_EXPORT_BYTES:
        warnings.append(SIZE_WARNING)
        page = page.replace('<p id="export-size-warning" hidden></p>', '<p id="export-size-warning">' + html.escape(SIZE_WARNING) + '</p>')
        if len(page.encode("utf-8")) > MAX_EXPORT_BYTES:
            raise ExportError("HTML export exceeds about 10 MB and was not written.")
    return page, warnings


def offline_answer(bundle: dict, selected: str, question: str, *, mode="simple", state: dict | None = None) -> dict:
    """Reference implementation of browser selection, for offline parity tests."""
    if selected not in bundle["scans"] or mode not in MODES:
        raise ValueError("Choose a bundled scan and simple or technical wording.")
    state = state if state is not None else {}
    row = bundle["scans"][selected]
    route = route_question(question, previous_kind=state.get("kind", ""))
    kind = route["kind"]
    base = {"source": "offline", "mode": mode, "kind": kind, "refs": [], "notice": "", "focus": state.get("focus", "scan")}
    if kind in ("refusal", "invalid", "unknown"):
        return {**base, "text": route["message"], "reason": route.get("reason", "")}
    if kind in bundle["friendly"]:
        return {**base, "text": bundle["friendly"][kind], "source": "built-in"}
    value = normalize_question(question).lower()
    if re.search(r"\btechnical(?:ly)?\b", value):
        mode = "technical"
    elif re.search(r"\b(?:simple|plain)\s+(?:words|english)|\bsimpler\b", value):
        mode = "simple"
    base["mode"] = mode
    focus = state.get("focus", "scan") if kind in ("impact", "why", "opinion", "owner", "timing", "risk") or re.fullmatch(bundle["rules"]["patterns"]["follow_up"], value, re.I) else "scan"
    fid = re.search(r"\bF-\d{4,}\b", value, re.I)
    named = [host for host in row["hosts"] if re.search(r"(?<![\w.-])" + re.escape(host) + r"(?![\w.-])", value, re.I)]
    if fid:
        focus = "finding:" + fid.group().upper()
    elif len(named) == 1:
        focus = "host:" + named[0]
    elif WHOLE_SCAN.search(value):
        focus = "scan"
    elif kind == "host":
        focus = "host:" + row["top_host"] if row["top_host"] else "scan"
    if re.search(r"\b(?:the\s+)?other\s+one\b", value):
        alternatives = state.get("alternatives", [])
        others = [item for item in alternatives if item != state.get("focus")]
        if len(others) != 1:
            return {**base, "kind": "clarification", "text": CLARIFY}
        focus = others[0]
    explicit_unknown_host = bool(re.search(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\b", value)) and not named and not fid and kind not in ("app", "scope", "headers", "history")
    if focus not in row["replies"] or explicit_unknown_host:
        return {**base, "kind": "unknown", "text": MISSING}
    if kind == "definition":
        term, entry = route["term"], GLOSSARY[route["term"]]
        text = term + (" are " if term == "security headers" else " means ") + entry["explanation"] + ". Think of it as " + entry["analogy"] + "."
        reply = {"text": text, "refs": ["S:scan"], "kind": kind, "proof_relevant": False}
        state.setdefault("defined_terms", []).append(term)
    elif kind in row["common"][mode]:
        reply = row["common"][mode][kind]
    else:
        reply = row["replies"][focus][mode].get(kind, row["replies"]["scan"][mode][kind])
    text = reply["text"]
    if reply["proof_relevant"] and not state.get("proof_notice_seen"):
        text += "\n\n" + PROOF_NOTE
        state["proof_notice_seen"] = True
    if mode == "simple":
        text, defined = define_terms(text, seen=state.get("defined_terms", []))
        state["defined_terms"] = sorted(defined)
    notice = "" if state.get("offline_notice_seen") else OFFLINE_NOTICE
    state["offline_notice_seen"] = True
    state.update(kind=kind, focus=focus, alternatives=["host:" + host for host in row["hosts"]] if kind == "host" else ["finding:" + fid for fid in row["alternatives"]])
    return {**base, "text": text, "refs": copy.deepcopy(reply["refs"]), "notice": notice, "focus": focus}
