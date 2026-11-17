"""Capture synthetic Tier 1 before/after replies; never real scans or real AI.

Run from the repository with its existing virtual environment. --before-root
points at the already-preserved source snapshot; only this child process's
package search path changes. No settings, credentials or target traffic.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import sys
import threading


def loopback_only():
    connect = socket.socket.connect
    lookup = socket.getaddrinfo

    def check(address):
        if not isinstance(address, tuple) or not ipaddress.ip_address(address[0]).is_loopback:
            raise RuntimeError("Evidence capture blocks non-loopback traffic.")

    def guarded_connect(sock, address):
        check(address)
        return connect(sock, address)

    def guarded_lookup(host, *args, **kwargs):
        if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
            raise RuntimeError("Evidence capture blocks external DNS.")
        return lookup(host, *args, **kwargs)

    socket.socket.connect, socket.getaddrinfo = guarded_connect, guarded_lookup


@contextmanager
def fake_server(*, before=False):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(payload)
            if before:
                # A typical tagged prose shape that the previous strict-JSON
                # parser could not consume. This is not a Qwen accuracy trial.
                content = "Public database access deserves attention. [R:ports.database_exposed] Ask IT to restrict access. [F-0001]"
            else:
                from dynamic_chat_fakes import tagged_reply

                content = tagged_reply(json.loads(payload["messages"][-1]["content"])["facts_pack"])
            body = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": content}}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port) + "/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tests"))
    # Load only the synthetic scan constants before switching the source path.
    from dynamic_chat_fakes import ACCEPTANCE_QUESTIONS, acceptance_scan

    scan = acceptance_scan()
    if args.before_root:
        # dynamic_chat_fakes imported the after AI modules to define functions;
        # remove only those Python module-cache entries in this disposable
        # process, not any files or user work.
        for name in tuple(sys.modules):
            if name == "exposureiq.ai" or name.startswith("exposureiq.ai."):
                del sys.modules[name]
        import exposureiq

        exposureiq.__path__.insert(0, str(args.before_root / "exposureiq"))
    loopback_only()
    from exposureiq.ai.chat import Chat
    from exposureiq.ai.config import AIConfig
    from exposureiq.ai.policy import RateLimiter
    from exposureiq.ai.service import AIService, chat_text, reply_label, verified_footer
    from exposureiq.ai.tools import ReadOnlyTools
    from exposureiq.insight.digest import scan_digest

    rows = {}
    with fake_server(before=bool(args.before_root)) as (url, calls):
        for path in ("built-in", "fake-small-model-server"):
            config = AIConfig() if path == "built-in" else AIConfig(mode="local", base_url=url, model="synthetic-small-model")
            service = AIService(config, use_cache=False)
            service.limiter = RateLimiter(limit=100)
            chat = Chat(scan_digest(scan), ReadOnlyTools(scan), service)
            turns = []
            for question in ACCEPTANCE_QUESTIONS:
                result = chat.ask(question)
                turns.append({"question": question, "answer": chat_text(result), "badge": reply_label(result),
                              "facts_note": verified_footer(result), "reason": result.get("reason", ""),
                              "offline_notice": result.get("offline_notice", ""), "source": result["source"],
                              "focus": result.get("answer_focus", {}), "references": result.get("evidence_refs", []),
                              "wording_verified": result.get("wording_verified", False)})
            rows[path] = {"turns": turns, "model_calls": len(service.audit),
                          "forced_json": any("response_format" in payload for payload in calls) if path != "built-in" else False}
    artifact = {"stage": "before" if args.before_root else "after", "scan": "synthetic reserved-data fixture",
                "network": "loopback fake server only; non-loopback sockets and external DNS blocked",
                "model_limit": "No Ollama or real-model accuracy trial. The fake after server phrases the code facts deterministically.",
                "paths": rows}
    args.output.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Captured {len(ACCEPTANCE_QUESTIONS) * len(rows)} full turns in {args.output}.")
    print("No real key, provider or target used.")


if __name__ == "__main__":
    main()
