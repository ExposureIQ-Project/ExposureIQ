"""Observe reply-shape and provider failures using reserved data only."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from capture_transcripts import loopback_only
from dynamic_chat_fakes import ACCEPTANCE_QUESTIONS, acceptance_scan, small_model_server
from exposureiq.ai.chat import Chat
from exposureiq.ai.config import AIConfig
from exposureiq.ai.policy import RateLimiter
from exposureiq.ai.provider import ProviderError, ProviderResponse
from exposureiq.ai.service import AIService, chat_text, reply_label, verified_footer
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.insight.digest import scan_digest


def observe(url, provider=None):
    scan = acceptance_scan()
    service = AIService(AIConfig(mode="local", base_url=url, model="synthetic-small-model"), provider=provider, use_cache=False)
    service.limiter = RateLimiter(limit=100)
    result = Chat(scan_digest(scan), ReadOnlyTools(scan), service).ask(ACCEPTANCE_QUESTIONS[0])
    # No actual request/reply log is exported; only synthetic test outcomes.
    return {"source": result["source"], "badge": reply_label(result), "fallback_kind": result["failure_kind"],
            "attempts": len(service.audit), "facts_note": verified_footer(result), "reason": result["reason"],
            "offline_notice": result["offline_notice"], "retry_available": result["retryable"],
            "answer": chat_text(result), "focus": result["answer_focus"], "wording_verified": result["wording_verified"]}


def main():
    loopback_only()
    rows = []
    for shape in ("tagged", "prose", "fences", "surrounding", "trailing_comma", "single_quotes", "truncated", "unfinished_text", "empty", "injection"):
        with small_model_server(shape) as (url, calls):
            rows.append({"case": shape, **observe(url), "loopback_requests": len(calls)})

    class SyntheticFailure:
        def __init__(self, kind):
            self.kind = kind

        def complete(self, *args, **kwargs):
            raise ProviderError(kind=self.kind)

    class WrongFact:
        def __init__(self, text):
            self.text = text

        def complete(self, *args, **kwargs):
            return ProviderResponse(self.text)

    url = "http://127.0.0.1:11434/v1"
    for kind in ("connection", "timeout", "auth", "not_found", "bad_request", "unavailable"):
        rows.append({"case": "provider_" + kind, **observe(url, SyntheticFailure(kind)), "loopback_requests": 0})
    for name, text in (("invented_number", "The worst finding is public database access on 999 hosts. [R:ports.database_exposed]"),
                       ("unknown_reference", "The worst finding is public database access. [F-9999]")):
        rows.append({"case": name, **observe(url, WrongFact(text)), "loopback_requests": 0})
    result = {"network": "loopback fakes only; external sockets and DNS blocked", "real_model_tested": False,
              "note": "Provider failures may use labelled saved-facts answers. Browser-server/auth/connection failures are separate and must never use prepared answers.",
              "rows": rows}
    output = Path(__file__).with_name("tier1-failures.json")
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Captured {len(rows)} synthetic failure/format outcomes in {output.relative_to(ROOT)}.")


if __name__ == "__main__":
    main()
