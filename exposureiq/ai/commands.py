"""Plain-output AI commands. No real key is accepted as a command argument."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from exposureiq.ai.chat import Chat
from exposureiq.ai.config import AIConfig
from exposureiq.ai.evaluate import evaluation_table, run_evaluation
from exposureiq.ai.service import AIService, AIUnavailable, NotConfigured, result_text
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.history import confined_scan_path, domain_history
from exposureiq.insight.digest import scan_digest
from exposureiq.insight.history_digest import build_history_layers


def register_commands(commands):
    ai = commands.add_parser("ai", help="checked, optional explanations of saved data; never scans")
    actions = ai.add_subparsers(dest="ai_command", metavar="<command>")
    for name, description in (("summary", "summarize a saved scan or latest domain scan"),
                              ("history", "explain a code-derived domain history"),
                              ("ask", "ask one grounded saved-scan question")):
        action = actions.add_parser(name, help=description)
        action.add_argument("source", nargs=None if name == "ask" else "?", help=("saved JSON or domain" if name == "ask" else
                            "saved JSON or domain; omitted with --demo uses synthetic fixtures"))
        if name == "ask":
            action.add_argument("question", help="quoted scan/defensive question, at most 1000 characters")
            action.add_argument("--mode", choices=("simple", "technical"), default="simple", help="chat wording; default: simple")
        action.add_argument("--results-dir", default="results", help="saved-results root")
        action.add_argument("--demo", action="store_true", help="offline fake AI; includes saved demo history")
        action.add_argument("--json", action="store_true", help="structured JSON only on stdout")
        action.add_argument("--no-fallback", action="store_true", help="exit nonzero rather than use a template if AI is unavailable or rejected")
    evaluation = actions.add_parser("eval", help="run packaged fixtures with normal/wrong offline fakes; never a real model")
    evaluation.add_argument("--json", action="store_true", help="evaluation JSON only on stdout")
    evaluation.add_argument("--demo", action="store_true", help="evaluation always uses offline fakes")


def _source(source, results_dir, demo):
    from exposureiq import storage

    if source is None:
        if not demo:
            raise ValueError("Select saved data or use --demo.")
        from exposureiq.demo_data import build_demo_scans

        scans = build_demo_scans()
        return scans[-1], scans, results_dir, True, True
    if source.lower().endswith(".json"):
        candidate = Path(source)
        root = candidate.absolute().parent if results_dir == "results" and candidate.is_file() else Path(results_dir)
        path = confined_scan_path(candidate, root)
        if not path.is_file() or path.stat().st_size > 8_000_000:
            raise ValueError("Invalid saved scan.")
        scan = storage.load_scan(str(path))
        tools = ReadOnlyTools.from_scan(scan, root, include_demo=demo or str(scan["scan_id"]).startswith("DEMO-"))
        return scan, tools.scans, root, False, False
    entries = domain_history(source, results_dir, include_demo=demo)
    if not entries:
        raise ValueError("No compatible saved domain history.")
    scans = [entry["scan"] for entry in entries]
    return scans[-1], scans, results_dir, True, False


def run_ai(args) -> int:
    if args.ai_command not in ("summary", "history", "ask", "eval"):
        print("Use exposureiq ai summary, history, ask or eval.", file=sys.stderr)
        return 2
    if args.ai_command == "eval":
        result = run_evaluation()
        print(json.dumps(result, ensure_ascii=False) if args.json else evaluation_table(result))
        return 0 if result["passed"] else 1
    try:
        scan, scans, root, domain, synthetic = _source(args.source, args.results_dir, args.demo)
        service = AIService(AIConfig(mode="demo") if args.demo else None)
        if args.ai_command == "summary":
            result = service.summary(scan, no_fallback=args.no_fallback)
        elif args.ai_command == "history":
            result = service.summary(build_history_layers(scans)["L4"], no_fallback=args.no_fallback)
        else:
            digest = build_history_layers(scans)["L4"] if domain else scan_digest(scan)
            result = Chat(digest, ReadOnlyTools(scan, root, scans=scans), service).ask(args.question, no_fallback=args.no_fallback, mode=args.mode)
        if synthetic:
            result["input_note"] = "Synthetic offline ten-scan fixtures; not a real assessment."
        print(json.dumps(result, ensure_ascii=False) if args.json else result_text(result) +
              ("\n" + result["input_note"] if synthetic else ""))
        return 0
    except (NotConfigured, AIUnavailable) as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print("Cannot read saved data or question safely. Select valid JSON/domain data; questions must be 1–1000 characters. Use --demo for offline examples.", file=sys.stderr)
        return 2
    except Exception:
        print("AI answer unavailable. No raw error or credential was displayed.", file=sys.stderr)
        return 1
