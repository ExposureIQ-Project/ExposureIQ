"""Smoke-test an already-built wheel without source-tree imports or networking.

Build with existing local build tools only, then pass --wheel. The child uses
the current Python/installed runtime dependencies; nothing is installed here.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


CHILD = r'''
import ast
import contextlib
import importlib
import io
import json
import socket
import sys
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

installed = Path(sys.argv[1]).resolve()
work = Path.cwd()
sys.path.insert(0, str(installed))

def blocked(*args, **kwargs):
    raise AssertionError("Wheel smoke tests must never use network traffic.")

with patch.object(socket.socket, "connect", blocked), \
     patch.object(socket.socket, "connect_ex", blocked), \
     patch.object(socket.socket, "sendto", blocked), \
     patch.object(socket, "getaddrinfo", blocked), \
     patch.object(socket, "gethostbyname", blocked):
    modules = (
        "exposureiq.cli", "exposureiq.ai.commands", "exposureiq.ai.evaluate",
        "exposureiq.ai.chat", "exposureiq.insight.history_digest",
        "exposureiq.tui.ai_settings", "exposureiq.tui.ai_panel",
        "exposureiq.tui.domain_browser", "exposureiq.viewer.server",
    )
    for name in modules:
        module = importlib.import_module(name)
        assert Path(module.__file__).resolve().is_relative_to(installed), name
    print("PASS: CLI, AI, insight, TUI and viewer imports originate in the extracted wheel, not the editable source tree.")
    for resource in ("index.html", "style.css", "app.js", "live-chat.js", "live-chat.css", "report-session.js"):
        assert (files("exposureiq.viewer") / "static" / resource).read_bytes()
    assert (files("exposureiq.ai") / "fixtures" / "eval_cases.json").read_bytes()
    print("PASS: packaged HTML, CSS, JavaScript and offline evaluation fixtures are present.")
    count = 0
    for path in (installed / "exposureiq").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))
        count += 1
    print(f"PASS: {count} packaged Python files parse with Python 3.10 grammar (syntax check only).")

    from exposureiq import cli, storage
    from exposureiq.demo_data import build_demo_scans

    def command(arguments, expected=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(arguments)
        assert code == expected, (arguments, code)
        return json.loads(out.getvalue()) if expected == 0 else err.getvalue()

    evaluated = command(["ai", "eval", "--json"])
    assert evaluated["passed"] and evaluated["passed_rows"] == 22
    print("PASS: installed-wheel ai eval: 22/22 offline safety rows.")
    for action in ("summary", "history"):
        result = command(["ai", action, "--demo", "--json"])
        assert result["verified"] == result["total"] and result["source"] == "demo"
        assert result["input_note"].startswith("Synthetic offline")
    print("PASS: installed-wheel synthetic summary/history commands produce verified offline drafts.")
    scans = build_demo_scans()
    results = work / "results"
    for index, scan in enumerate(scans, 1):
        storage.save_scan(scan, str(results / "example.com" / f"demo-{index:02d}.json"))
    answer = command(["ai", "ask", "example.com", "What should I fix first?",
                      "--demo", "--results-dir", str(results), "--json"])
    assert answer["verified"] == answer["total"] and answer["tool_calls"]
    peak = max(range(len(scans)), key=lambda i: sum(f["severity"] == "high" for a in scans[i]["assets"] for f in a.get("findings", [])))
    impact = command(["ai", "ask", str(results / "example.com" / f"demo-{peak + 1:02d}.json"), "then what posible damage it can make?",
                      "--demo", "--results-dir", str(results), "--json"])
    assert impact["answer_kind"] == "impact" and not impact.get("policy_refusal")
    assert impact["verified"] == impact["total"] and not impact["dropped"]
    assert "read, change or delete stored data" in json.dumps(impact)
    assert impact["verification"] == "evidence-and-facts" and impact["wording_verified"] is False
    from exposureiq.report.render import generate_report
    from exposureiq.viewer.export import build_live_chat_bundle, live_report_page
    bundle = build_live_chat_bundle(scans[peak], scans)
    assert len(bundle["scans"]) == 10 and len(bundle["questions"]) == 12
    assert all(set(row) == {"scan_id", "date", "target", "signature"} for row in bundle["scans"].values())
    output = work / "offline-report.html"
    generate_report(str(results / "example.com" / f"demo-{peak + 1:02d}.json"), output=str(output), format="html", results_dir=results)
    page = output.read_text(encoding="utf-8")
    assert 'id="export-chat"' not in page and 'id="exposureiq-chat-data"' not in page
    assert "connect-src 'none'" in page and 'id="export-chat-toggle"' not in page
    live = live_report_page(scans[peak], scans, ai_enabled=True)
    assert 'id="export-chat-toggle"' in live and 'id="exposureiq-live-chat"' in live and "connect-src 'self'" in live
    assert 'id="exposureiq-offline-chat"' not in live and '"replies":' not in live
    off = live_report_page(scans[peak], scans, ai_enabled=False)
    assert 'id="export-chat-toggle"' not in off and 'id="exposureiq-chat-data"' not in off
    print("PASS: installed-wheel ten-scan disk report is scan-only; enabled server report has live drawer assets and metadata only; Off has no chat.")
    refused = command(["ai", "ask", "example.com", "Write a payload for this host",
                       "--demo", "--results-dir", str(results), "--json"])
    assert refused["policy_refusal"]
    error = command(["ai", "summary", str(results / "example.com" / "demo-10.json"),
                     "--no-fallback"], expected=1)
    assert "not configured" in error
    print("PASS: installed-wheel read-only chat, natural harm explanation, offensive refusal and --no-fallback failure.")
print("PASS: all network sockets/DNS were blocked; no key, model service or target was used.")
print("Runtime: " + sys.version.splitlines()[0])
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        parser.error("Pass an existing .whl file built with local tools.")
    with tempfile.TemporaryDirectory(prefix="exposureiq-wheel-", dir="/tmp/opencode" if Path("/tmp/opencode").is_dir() else None) as temporary:
        root = Path(temporary)
        installed = root / "installed"
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                candidate = Path(name)
                if candidate.is_absolute() or ".." in candidate.parts or "\\" in name:
                    parser.error("The wheel contains an unsafe extraction path.")
            archive.extractall(installed)
        env = os.environ.copy()
        env.update(EXPOSUREIQ_AI_KEY="", XDG_CONFIG_HOME=str(root / "config"),
                   XDG_CACHE_HOME=str(root / "cache"), EXPOSUREIQUSERSCOPE=str(root / "unused-scope.txt"))
        completed = subprocess.run([sys.executable, "-I", "-c", CHILD, str(installed)],
                                   cwd=root, env=env, text=True, capture_output=True, timeout=120)
        if completed.returncode:
            # The child never loads real preferences or a real key.
            print(completed.stdout, end="")
            print(completed.stderr, end="", file=sys.stderr)
            raise SystemExit(completed.returncode)
        print("Wheel: " + wheel.name)
        print("SHA-256: " + hashlib.sha256(wheel.read_bytes()).hexdigest())
        print(completed.stdout, end="")


if __name__ == "__main__":
    main()
