"""In-memory safety demo: normalized request data, replies and checker decisions."""

from __future__ import annotations

import json

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Static


class AILogPanel(Vertical):
    DEFAULT_CSS = """
    AILogPanel { height: 1fr; }
    AILogPanel .ai-log-note { height: auto; color: $text-muted; }
    AILogPanel VerticalScroll { height: 1fr; border: round $secondary; padding: 1 2; }
    AILogPanel .ai-log-content { height: auto; }
    """

    def compose(self) -> ComposeResult:
        yield Static("AI log · memory only · last thirty calls. Credentials and private system instructions are excluded. "
                      "Received text is unverified evidence, not advice. Never act on rejected output. "
                      "Each call shows its attempt, reply length, first three hundred redacted characters and parse error.", classes="ai-log-note", markup=False)
        with VerticalScroll():
            yield Static("No AI calls in this session.", classes="ai-log-content", markup=False)

    def refresh_log(self, entries: list[dict]):
        lines = []
        for index, entry in enumerate(entries, 1):
            lines += [f"CALL {index} · {entry['purpose']} · {entry['model']} · {entry['prompt_version']} · {entry['time']}",
                      f"ATTEMPT {entry.get('attempt', 1)} · {'failed' if entry.get('attempt_failed') else 'reply checked'}",
                      f"RESPONSE LENGTH: {entry.get('response_length', 0)} characters",
                      "FIRST 300 CHARACTERS (redacted, unverified): " + entry.get("response_preview", ""),
                      "PARSE ERROR: " + (entry.get("parse_error") or "none"),
                      "SAVED READS (code-selected, not model actions): " + json.dumps(entry.get("saved_reads", []), ensure_ascii=False),
                      "SENT (question, bounded history and code facts; summaries keep a candidate; no key):",
                      json.dumps(entry["sent"], ensure_ascii=False, indent=2),
                      "RECEIVED:", json.dumps(entry["received"], ensure_ascii=False, indent=2),
                      "DROPPED AND WHY:", json.dumps(entry["dropped"], ensure_ascii=False, indent=2),
                      "ERROR: " + entry["error"], ""]
        self.query_one(".ai-log-content", Static).update(Text("\n".join(lines) or "No AI calls in this session."))
