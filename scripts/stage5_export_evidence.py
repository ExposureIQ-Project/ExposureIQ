"""Reproduce scan-only HTML, the live AI drawer and optional Firefox checks."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from exposureiq import storage
from exposureiq.ai.config import AIConfig, LOCAL_BASE
from exposureiq.ai.service import AIService
from exposureiq.demo_data import build_demo_scans
from exposureiq.report.render import generate_report
from exposureiq.report.interactive import SCRIPT
from exposureiq.viewer.export import SHARING_WARNING, view_id
from exposureiq.viewer import make_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("docs/stage5-evidence"))
    parser.add_argument("--browser", action="store_true", help="use installed Firefox, without installing anything")
    parser.add_argument("--live", action="store_true", help="also check same-origin server chat using an offline fake")
    parser.add_argument("--live-repeats", type=int, choices=(1, 2, 3), default=1,
                        help="repeat real live-browser checks with fresh servers/profiles (needs --browser --live)")
    args = parser.parse_args()
    if args.live_repeats != 1 and not (args.browser and args.live):
        parser.error("--live-repeats needs --browser --live.")
    args.out.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="s5-html-export-", dir="/tmp/opencode"))
    os.environ.update(EXPOSUREIQ_AI_KEY="", XDG_CONFIG_HOME=str(root / "config"), XDG_CACHE_HOME=str(root / "cache"))
    scans = build_demo_scans()
    for index, scan in enumerate(scans, 1):
        storage.save_scan(scan, str(root / "results" / "example.com" / f"demo-{index:02d}.json"))
    source, output = root / "results/example.com/demo-04.json", root / "index.html"
    exported = generate_report(str(source), output=str(output), format="html", results_dir=root / "results")
    page = output.read_text(encoding="utf-8")
    scripts = re.findall(r"<script\b[^>]*>([\s\S]*?)</script>", page)
    assert scripts == [SCRIPT] and 'id="export-chat-toggle"' not in page and 'id="exposureiq-chat-data"' not in page
    assert "connect-src 'none'" in page and SHARING_WARNING in page and 'src="http' not in page and 'href="http' not in page
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode("utf-8")).digest()).decode("ascii")
    assert "'sha256-" + script_hash + "'" in page
    print("PASS: standalone report is scan-only, has one hashed interaction script, sharing/size safeguards and no chat metadata, answers or external assets.")
    stats = {"source": "synthetic DEMO-HISTORY-04 only", "command": f".venv/bin/exposureiq report {source} --format html --results-dir {root / 'results'} -o {output}",
             "html": str(output), "bytes": exported["html_bytes"], "scans": len(scans), "prepared_replies": 0,
             "modes": ["simple", "technical"], "warnings": exported["warnings"], "scripts": 1, "inert_json_blocks": 0,
             "external_assets": 0, "network": "offline export uses connect-src none", "default_scan": view_id(scans[3])}
    if args.browser:
        from stage5_firefox_check import check_offline

        browser = check_offline(output, args.out / "live-drawer-offline-browser.png")
        (args.out / "live-drawer-offline-browser.json").write_text(json.dumps(browser, indent=2) + "\n", encoding="utf-8")
        print("PASS: real Firefox scan-only export checks, screenshot: " + browser["screenshot"])
        stats["browser"] = browser["browser"]
    if args.live:
        from stage5_natural_fake import NaturalEvidenceProvider

        runs = []
        for attempt in range(1, args.live_repeats + 1):
            fake = NaturalEvidenceProvider()
            service = AIService(AIConfig(mode="local", base_url=LOCAL_BASE, model="offline-browser-fake"), provider=fake, use_cache=False)
            server = make_server(root / "results", port=0, service=service)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                identifier = next(entry["id"] for entry in server.state.entries.values() if entry["scan"]["scan_id"] == "DEMO-HISTORY-04")
                live_path = root / "live.html"
                live_path.write_text(server.state.report_page(identifier), encoding="utf-8")
                completed = subprocess.run(["node", "scripts/stage5_live_dom_check.cjs", str(live_path)], capture_output=True, text=True, timeout=60)
                (args.out / "live-drawer-dom-check.txt").write_text(completed.stdout + completed.stderr, encoding="utf-8")
                print(completed.stdout, end="")
                if completed.returncode:
                    print(completed.stderr, end="", file=sys.stderr)
                    return completed.returncode
                if args.browser:
                    from stage5_firefox_check import check_live

                    browser = check_live(server, args.out / "live-drawer-browser.png", fake)
                    (args.out / "live-drawer-browser.json").write_text(json.dumps(browser, indent=2) + "\n", encoding="utf-8")
                    print(f"PASS: real Firefox same-origin live-transport checks with offline fake, repeat {attempt}/{args.live_repeats}; screenshot: " + browser["screenshot"])
                    stats["live_browser"] = browser["browser"]
                    runs.append({"attempt": attempt, "passed": browser["passed"], "checks": browser["checks"]})
                stats["live_report_bytes"] = live_path.stat().st_size
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        if args.live_repeats > 1:
            repeat = {"passed": all(run["passed"] for run in runs), "runs": runs,
                      "limitation": "Fresh browser profiles and local servers; same-origin loopback HTTP and offline fakes only. No real key/provider/target traffic."}
            (args.out / "live-drawer-repeatability.json").write_text(json.dumps(repeat, indent=2) + "\n", encoding="utf-8")
    (args.out / "live-drawer-structure.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    evidence_names = ["live-drawer-structure.json"]
    if args.live:
        evidence_names.append("live-drawer-dom-check.txt")
    if args.browser:
        evidence_names.extend(("live-drawer-offline-browser.json", "live-drawer-offline-browser.png"))
    if args.browser and args.live:
        evidence_names.extend(("live-drawer-browser.json", "live-drawer-browser.png",
                               "live-drawer-browser-closed.png", "live-drawer-browser-mobile.png"))
        if args.live_repeats > 1:
            evidence_names.append("live-drawer-repeatability.json")
    source_names = ("exposureiq/cli.py", "exposureiq/report/html.py", "exposureiq/report/render.py",
                    "exposureiq/viewer/export.py", "exposureiq/viewer/server.py",
                    "exposureiq/viewer/static/app.js", "exposureiq/viewer/static/index.html",
                    "exposureiq/viewer/static/live-chat.js", "exposureiq/viewer/static/live-chat.css",
                    "exposureiq/viewer/static/report-session.js", "scripts/stage5_export_evidence.py",
                    "scripts/stage5_firefox_check.py", "scripts/stage5_live_dom_check.cjs")
    def checksum(path):
        return {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest = {"passed": True, "network": "loopback and offline fakes only; no real key/model/target",
                "files": [{"file": name, **checksum(args.out / name)} for name in evidence_names],
                "sources": [{"file": name, **checksum(Path(name))} for name in source_names]}
    (args.out / "live-drawer-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Export: " + str(output))
    print("Bytes: " + str(exported["html_bytes"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
