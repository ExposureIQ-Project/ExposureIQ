"""Optional installed-Qwen trial: synthetic saved data and loopback only.

No download, settings file, credential, real target or agent action is used.
Raw model attempts stay in AIService's memory-only audit; this artifact records
only the user-visible synthetic answers and bounded outcome metadata.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from capture_transcripts import loopback_only
from dynamic_chat_fakes import ACCEPTANCE_QUESTIONS, acceptance_scan
from exposureiq.ai.chat import Chat
from exposureiq.ai.config import AIConfig
from exposureiq.ai.policy import RateLimiter
from exposureiq.ai.service import AIService, chat_text, reply_label, verified_footer
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.insight.digest import scan_digest


def main():
    loopback_only()
    wanted = "qwen2.5:3b-instruct"
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:11434/api/tags", timeout=3) as response:
            raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ValueError("Local model metadata exceeded its budget.")
            tags = json.loads(raw)
        installed = {item.get("name") for item in tags.get("models", []) if isinstance(item, dict)}
        if wanted not in installed:
            print("Requested Qwen model is not installed; no model call or download ran.")
            return
    except Exception as error:
        print("Local Ollama availability check failed (" + type(error).__name__ + "); no model call or download ran.")
        return

    scan = acceptance_scan()
    original = json.dumps(scan, sort_keys=True)
    service = AIService(AIConfig(mode="local", base_url="http://127.0.0.1:11434/v1", model=wanted), use_cache=False)
    service.limiter = RateLimiter(limit=100)
    chat = Chat(scan_digest(scan), ReadOnlyTools(scan), service)
    turns = []
    started = time.monotonic()
    for question in ACCEPTANCE_QUESTIONS:
        before = len(service.audit)
        start = time.monotonic()
        result = chat.ask(question)
        turn = {"question": question, "answer": chat_text(result), "badge": reply_label(result),
                "source": result["source"], "fallback_kind": result.get("failure_kind", ""),
                "reason": result.get("reason", ""), "facts_note": verified_footer(result),
                "focus": result.get("answer_focus", {}), "references": result.get("evidence_refs", []),
                "wording_verified": result.get("wording_verified", False), "attempts": len(service.audit) - before,
                "seconds": round(time.monotonic() - start, 2)}
        turns.append(turn)
        print(question + " -> " + turn["badge"] + f"; {turn['attempts']} attempts; {turn['seconds']}s", flush=True)
    assert json.dumps(scan, sort_keys=True) == original
    result = {"model": wanted, "provider": "installed local Ollama, OpenAI-compatible /v1",
              "network": "loopback only; non-loopback sockets and external DNS blocked",
              "scan": "acceptance_scan synthetic reserved names/IPs; no real scan used",
              "settings": "explicit temporary local config; no saved preferences or key read; no downloads",
              "limit": "One synthetic seven-question trial is not a general accuracy benchmark. Reference/number checks do not prove every model-written claim.",
              "seconds": round(time.monotonic() - started, 2), "attempts": len(service.audit),
              "live_turns": sum(turn["source"] in ("local", "remote") for turn in turns),
              "fallback_turns": sum(bool(turn["fallback_kind"]) for turn in turns), "turns": turns,
              "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                  "exposureiq/ai/chat.py", "exposureiq/ai/facts.py", "exposureiq/ai/checker.py", "exposureiq/ai/prompts.py", "exposureiq/ai/provider.py")}}
    output = Path(__file__).with_name("ollama-trial.json")
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Observed {result['live_turns']} live replies and {result['fallback_turns']} provider fallbacks; thanks made no model call.")


if __name__ == "__main__":
    main()
