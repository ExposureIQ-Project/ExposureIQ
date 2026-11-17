"""Chat-first safe-text AI panel. Work runs off the Textual UI thread."""

from __future__ import annotations

import copy
import time

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Button, Collapsible, ContentSwitcher, Input, Select, Static

from exposureiq.ai.chat import Chat
from exposureiq.ai.policy import MAX_MESSAGE_CHARS
from exposureiq.ai.config import AIConfig
from exposureiq.ai.service import AIService, chat_text, reply_label, verified_footer
from exposureiq.ai.sanitize import hostile_seen, redact
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.insight.digest import scan_digest
from exposureiq.insight.risk import RISK_FORMULA
from exposureiq.tui.ai_log import AILogPanel


class AIStage(Message):
    def __init__(self, stage: str, generation: int):
        super().__init__()
        self.stage, self.generation = stage, generation


class AICompleted(Message):
    def __init__(self, result: dict | None, generation: int, error: str = "", *, question="", conversation=None):
        super().__init__()
        self.result, self.error = result, error
        self.generation, self.question = generation, question
        self.conversation = conversation


class RetryAnswer(Message):
    def __init__(self, question: str, retry_id: str):
        super().__init__()
        self.question, self.retry_id = question, retry_id


class ChatMessage(Vertical):
    """Only the code-owned label is styled; the entire message body is literal."""
    DEFAULT_CSS = """
    ChatMessage { height: auto; padding: 1 2; margin-bottom: 1; background: $surface; }
    ChatMessage.user-message { border-left: solid $primary; background: $panel; margin-left: 4; }
    ChatMessage.assistant-message { border-left: solid $secondary; margin-right: 4; }
    ChatMessage .ai-speaker { height: auto; text-style: bold; margin-bottom: 1; color: $secondary; }
    ChatMessage.user-message .ai-speaker { color: $primary; }
    ChatMessage .ai-body { height: auto; color: $text; }
    ChatMessage .ai-reply-status { height: auto; color: $text-muted; margin-top: 1; }
    ChatMessage .ai-evidence { height: auto; margin-top: 1; padding: 0; border: none; }
    ChatMessage .ai-retry { height: 3; width: 14; margin-top: 1; }
    """

    def __init__(self, label: str, body: str, *, user=False, id=None):
        super().__init__(id=id, classes="user-message" if user else "assistant-message")
        self.heading = Static(label, classes="ai-speaker", markup=False)
        self.body = Static(Text(body), classes="ai-body", markup=False)
        self.status = Static(classes="ai-reply-status", markup=False)
        self.evidence_text = Static(markup=False)
        self.evidence = Collapsible(self.evidence_text, title="Evidence", collapsed=True, classes="ai-evidence")
        self.retry_button = Button("Try again", classes="ai-retry", tooltip="Ask the configured model to phrase this same saved question again.")
        self.retry_button.display = False
        self.retry_question, self.retry_id = "", ""
        self.status.display = self.evidence.display = False

    def compose(self):
        yield self.heading
        yield self.body
        yield self.status
        yield self.evidence
        yield self.retry_button

    def show_result(self, result: dict, *, question=""):
        self.heading.update(Text("ExposureIQ · " + reply_label(result)))
        self.body.update(Text(chat_text(result)))
        refs = result.get("evidence_refs", [])
        self.evidence_text.update(Text(" · ".join(refs) + ("\n" + result["review_note"] if result.get("review_note") else "")))
        self.evidence.display = bool(refs)
        status = [verified_footer(result), result.get("offline_notice", "")]
        if result.get("failure_kind"):
            status.append(result.get("reason", ""))
        self.status.update(Text("\n".join(value for value in status if value)))
        self.status.display = any(status)
        self.retry_question, self.retry_id = question, result.get("retry_id", "")
        self.retry_button.display = bool(result.get("retryable") and self.retry_id)

    @on(Button.Pressed, ".ai-retry")
    def retry(self, event: Button.Pressed):
        event.stop()
        if self.retry_id and self.retry_question:
            self.post_message(RetryAnswer(self.retry_question, self.retry_id))


MORE_QUESTIONS = (
    ("What do severity levels mean?", "What do severity levels mean in this scan?"),
    ("What does the risk score mean?", "What does the risk score mean in this scan?"),
    ("What are security headers?", "What are security headers in this scan?"),
    ("What wasn't checked?", "What wasn't checked in this scan?"),
    ("How can I confirm a fix?", "How can I confirm fixes from this scan?"),
    ("What changed in saved history?", "What changed in this domain's saved history?"),
    ("Which findings are still unfixed?", "Which findings are still unfixed in the saved history?"),
    ("What does ExposureIQ do?", "What does ExposureIQ do with my saved scans?"),
)
THINKING_FRAMES = ("[=    ]", "[ =   ]", "[  =  ]", "[   = ]", "[    =]", "[   = ]", "[  =  ]", "[ =   ]")
STAGE_LABELS = {"Policy gate passed": "Checking your question", "Prioritizing": "Putting important fixes first",
                 "Reading saved data": "Reading saved findings", "Verifying claims": "Checking the answer",
                 "Reading your scan": "Reading your scan", "Phrasing your answer": "Phrasing your answer",
                 "Checking the facts": "Checking the facts"}


class AIPanel(Vertical):
    DEFAULT_CSS = """
    AIPanel { height: 1fr; }
    AIPanel .ai-questions { height: 3; margin-bottom: 1; }
    AIPanel .ai-questions Button { width: 1fr; min-width: 0; padding: 0 1; margin-right: 1; }
    AIPanel .ai-question-menu { height: 3; margin-bottom: 1; }
    AIPanel .ai-question-menu Select { width: 1fr; }
    AIPanel .ai-question-menu Button { width: 16; min-width: 16; padding: 0 1; margin-left: 1; }
    AIPanel .ai-question-menu .ai-wording-mode { width: 18; margin-left: 1; }
    AIPanel .ai-progress { height: 1; color: $primary; }
    AIPanel .ai-result-scroll { height: 1fr; border: round $secondary; padding: 1; }
    AIPanel .ai-transcript { height: auto; }
    AIPanel .ai-intro { height: auto; color: $text-muted; }
    AIPanel .ai-verified { height: auto; color: $text-muted; }
    AIPanel .ai-formula { height: auto; color: $text-muted; }
    AIPanel ContentSwitcher { height: 1fr; }
    AIPanel .ai-view { height: 1fr; }
    AIPanel .ai-warning { height: auto; color: $warning; }
    AIPanel .ai-chat-actions { height: 3; margin-top: 1; }
    AIPanel .ai-chat-actions Input { width: 1fr; }
    AIPanel .ai-chat-actions Button { width: 10; margin-left: 1; }
    """

    def __init__(self, *, id="scan-ai", prefix="ai", history=False):
        super().__init__(id=id)
        self.prefix, self.history = prefix, history
        self.data = None
        self.last_result = None
        self.stage_history = []
        self.running = False
        self.frame = 0
        self.stage = ""
        self.generation = 0
        self.raw_scan = None
        self.history_scans = None
        self.chat = None
        self.chat_turns = []
        self.chat_worker = None
        self.enabled, self.developer_mode = False, False
        self.exchanges = []
        self.pending_reply = None
        self.thinking_started = 0.0
        self.reply_mode = "simple"

    def compose(self) -> ComposeResult:
        with Horizontal(classes="ai-questions"):
            yield Button("Explain history" if self.history else "Explain this scan", id=f"{self.prefix}-explain", variant="primary", disabled=True)
            yield Button("Fix first", id=f"{self.prefix}-fix-first", tooltip="What should I fix first?", disabled=True)
            yield Button("Most exposed host", id=f"{self.prefix}-most-exposed", tooltip="Which host is the most exposed?", disabled=True)
        with Horizontal(classes="ai-question-menu"):
            yield Select(MORE_QUESTIONS, prompt="More common questions", id=f"{self.prefix}-questions", disabled=True)
            yield Select((("Simple", "simple"), ("Technical", "technical")), value="simple", allow_blank=False,
                         id=f"{self.prefix}-wording-mode", classes="ai-wording-mode", disabled=True)
            yield Button("AI logs", id=f"{self.prefix}-log-toggle")
        yield Static(id=f"{self.prefix}-warning", classes="ai-warning", markup=False)
        with ContentSwitcher(initial=f"{self.prefix}-chat-view", id=f"{self.prefix}-views"):
            with Vertical(id=f"{self.prefix}-chat-view", classes="ai-view"):
                with VerticalScroll(classes="ai-result-scroll", id=f"{self.prefix}-chat-scroll"):
                    with Vertical(id=f"{self.prefix}-chat-transcript", classes="ai-transcript"):
                        yield Static("Ask a question above, or type your own below.\n\n"
                                     "I'll explain the saved findings in simple words. Answers are drafts for review; "
                                     "I never scan, run commands or change scope.",
                                     id=f"{self.prefix}-chat-intro", classes="ai-intro", markup=False)
                with Horizontal(classes="ai-chat-actions"):
                    yield Input(placeholder="Ask about these saved findings…", max_length=MAX_MESSAGE_CHARS,
                                 id=f"{self.prefix}-chat-input")
                    yield Button("Send", id=f"{self.prefix}-chat-send", variant="primary")
                yield Static("No question sent yet.", id=f"{self.prefix}-progress", classes="ai-progress", markup=False)
                yield Static(id=f"{self.prefix}-chat-verified", classes="ai-verified", markup=False)
            yield AILogPanel(id=f"{self.prefix}-log-view")
        yield Static(RISK_FORMULA, classes="ai-formula", markup=False)

    def on_mount(self):
        self.set_interval(0.1, self._animate_thinking)
        service = getattr(self.app, "ai_service", None) or AIService()
        self.apply_preferences(service._configuration())

    def apply_preferences(self, config: AIConfig, *, reset=False):
        if reset:
            self._clear_chat()
        self.enabled = config.mode != "off"
        self.developer_mode = config.developer_mode
        self.display = self.enabled
        self.query_one(f"#{self.prefix}-log-toggle", Button).display = self.enabled and self.developer_mode
        self.query_one(".ai-formula").display = self.developer_mode
        if not self.developer_mode:
            self.query_one(f"#{self.prefix}-views", ContentSwitcher).current = f"{self.prefix}-chat-view"
            self.query_one(f"#{self.prefix}-log-toggle", Button).label = "AI logs"
        self._controls()

    def _controls(self):
        disabled = self.running or not self.enabled or self.raw_scan is None
        for suffix in ("explain", "fix-first", "most-exposed", "chat-send"):
            self.query_one(f"#{self.prefix}-{suffix}", Button).disabled = disabled
        self.query_one(f"#{self.prefix}-chat-input", Input).disabled = disabled
        self.query_one(f"#{self.prefix}-questions", Select).disabled = disabled
        self.query_one(f"#{self.prefix}-wording-mode", Select).disabled = disabled
        for retry in self.query(".ai-retry"):
            retry.disabled = disabled

    def _clear_chat(self):
        self.generation += 1
        self.running = False
        if self.chat_worker is not None:
            self.chat_worker.cancel()
        self.chat, self.chat_turns, self.last_result, self.pending_reply = None, [], None, None
        for user, reply in self.exchanges:
            user.remove()
            reply.remove()
        self.exchanges = []
        self.query_one(f"#{self.prefix}-chat-intro").display = True
        self.query_one(f"#{self.prefix}-chat-input", Input).value = ""
        self.query_one(f"#{self.prefix}-chat-verified", Static).update("")
        self.query_one(f"#{self.prefix}-progress", Static).update("No question sent yet.")
        self.query_one(f"#{self.prefix}-views", ContentSwitcher).current = f"{self.prefix}-chat-view"
        self.query_one(f"#{self.prefix}-log-toggle", Button).label = "AI logs"

    def set_data(self, data: dict, *, scan=None, scans=None):
        self.data = copy.deepcopy(data)
        self.raw_scan = copy.deepcopy(scan or (data if "assets" in data else None))
        self.history_scans = copy.deepcopy(scans)
        self._clear_chat()
        self._controls()
        warnings = []
        if self.raw_scan and str(self.raw_scan.get("scan_id", "")).startswith("DEMO-"):
            warnings.append("Fake demonstration data — no real probes were sent.")
        if hostile_seen(data) or data.get("hostile_text_seen"):
            warnings.append("Some saved text looks like instructions. I treat it as data, never something to obey.")
        self.query_one(f"#{self.prefix}-warning", Static).update("\n".join(warnings))

    def _animate_thinking(self):
        if self.running:
            self.frame = (self.frame + 1) % len(THINKING_FRAMES)
            stage = STAGE_LABELS.get(self.stage, self.stage)
            elapsed = time.monotonic() - self.thinking_started
            self.query_one(f"#{self.prefix}-progress", Static).update(f"{THINKING_FRAMES[self.frame]} Thinking · {stage} · {elapsed:.0f}s")

    @on(AIStage)
    def on_ai_stage(self, event: AIStage):
        event.stop()
        if event.generation != self.generation:
            return
        self.stage = event.stage
        self.stage_history.append(event.stage)
        self._animate_thinking()

    @on(AICompleted)
    def on_ai_completed(self, event: AICompleted):
        event.stop()
        if event.generation != self.generation:
            return
        self.running = False
        self._controls()
        if event.conversation is not None:
            self.chat = event.conversation
        if event.result is None:
            if self.pending_reply is not None:
                self.pending_reply.heading.update("ExposureIQ · reply unavailable")
                self.pending_reply.body.update(Text(event.error))
            self.query_one(f"#{self.prefix}-progress", Static).update("Reply unavailable. You can try another question.")
            return
        self.last_result = event.result
        self._show_chat_result(event)

    def show_log(self):
        if not self.enabled or not self.developer_mode:
            return
        views = self.query_one(f"#{self.prefix}-views", ContentSwitcher)
        if views.current == f"{self.prefix}-log-view":
            views.current = f"{self.prefix}-chat-view"
            self.query_one(f"#{self.prefix}-log-toggle", Button).label = "AI logs"
            return
        views.current = f"{self.prefix}-log-view"
        self.query_one(f"#{self.prefix}-log-toggle", Button).label = "Back to chat"
        service = getattr(self.app, "ai_service", None)
        self.query_one(AILogPanel).refresh_log(service.audit if service else [])

    @on(RetryAnswer)
    def retry_answer(self, event: RetryAnswer):
        event.stop()
        self.start_chat(event.question, retry_id=event.retry_id)

    def start_chat(self, question: str, *, retry_id=""):
        service = getattr(self.app, "ai_service", None) or AIService()
        config = service._configuration()
        if self.raw_scan is None or self.running or config.mode == "off":
            return
        if not isinstance(question, str) or not question.strip() or len(question) > MAX_MESSAGE_CHARS:
            self.query_one(f"#{self.prefix}-progress", Static).update("Type a question first (up to 1000 characters).")
            return
        safe_question = redact(question.strip(), (config.key, config.api_key))
        self.query_one(f"#{self.prefix}-views", ContentSwitcher).current = f"{self.prefix}-chat-view"
        self.query_one(f"#{self.prefix}-log-toggle", Button).label = "AI logs"
        self.running, self.stage_history, self.stage = True, [], "Question sent"
        self.thinking_started = time.monotonic()
        self.generation += 1
        self._controls()
        self.query_one(f"#{self.prefix}-chat-input", Input).value = ""
        self.query_one(f"#{self.prefix}-chat-verified", Static).update("")
        self.query_one(f"#{self.prefix}-chat-intro").display = False
        user = ChatMessage("You · sent", safe_question, user=True, id=f"{self.prefix}-user-{self.generation}")
        reply = ChatMessage("ExposureIQ · thinking", "I'm checking the saved findings…", id=f"{self.prefix}-reply-{self.generation}")
        self.pending_reply = reply
        self.query_one(f"#{self.prefix}-chat-transcript", Vertical).mount(user, reply)
        self.exchanges.append((user, reply))
        if len(self.exchanges) > 3:
            old_user, old_reply = self.exchanges.pop(0)
            old_user.remove()
            old_reply.remove()
        self._animate_thinking()
        self.call_after_refresh(user.scroll_visible, top=True, animate=False)
        # Thread workers receive immutable snapshots. A stale worker can finish
        # its request, but cannot attach a conversation to newly selected data.
        self.chat_worker = self._ask(safe_question, self.generation, service, self.chat,
                                     copy.deepcopy(self.data), copy.deepcopy(self.raw_scan),
                                      copy.deepcopy(self.history_scans), getattr(self.app, "results_dir", "results"), self.reply_mode, retry_id)

    @work(thread=True, exclusive=True, group="ai-chat", exit_on_error=False)
    def _ask(self, question: str, generation: int, service: AIService, conversation, data, scan, scans, directory, mode, retry_id=""):
        try:
            if conversation is None:
                digest = data if data.get("ref") in ("S:scan", "S:history") else scan_digest(scan)
                tools = (ReadOnlyTools(scan, directory, scans=scans) if scans is not None else
                         ReadOnlyTools.from_scan(scan, directory, include_demo=str(scan.get("scan_id", "")).startswith("DEMO-")))
                conversation = Chat(digest, tools, service)
            conversation.service = service
            result = conversation.ask(question, mode=mode, retry_id=retry_id, progress=lambda stage: self.post_message(AIStage(stage, generation)))
        except ValueError:
            self.post_message(AICompleted(None, generation, "Enter a nonempty scan question of at most 1000 characters.", question=""))
        except Exception:
            self.post_message(AICompleted(None, generation, "Chat unavailable. No credential or raw error was displayed.", question=question))
        else:
            config = service._configuration()
            safe_question = redact(question, (config.key, config.api_key))
            self.post_message(AICompleted(result, generation, question=safe_question, conversation=conversation))

    def _show_chat_result(self, event: AICompleted):
        self.chat_turns.append((event.question, event.result))
        self.chat_turns = self.chat_turns[-3:]
        if self.pending_reply is not None:
            self.pending_reply.show_result(event.result, question=event.question)
        if event.result.get("mode"):
            self.reply_mode = event.result["mode"]
            with self.prevent(Select.Changed):
                self.query_one(f"#{self.prefix}-wording-mode", Select).value = self.reply_mode
        ready = "Reply ready · "
        if event.result.get("policy_refusal"):
            ready += "request declined; no AI call made."
        elif event.result.get("source") == "template":
            ready += "built-in fallback · " + event.result.get("failure_kind", "offline") + "."
        else:
            ready += f"{event.result.get('elapsed', 0):.1f}s. Review this draft with your team."
        self.query_one(f"#{self.prefix}-progress", Static).update(ready)
        self.query_one(f"#{self.prefix}-chat-verified", Static).update(Text(verified_footer(event.result)))
        if self.exchanges:
            self.call_after_refresh(self.exchanges[-1][0].scroll_visible, top=True, animate=False)

    @on(Select.Changed)
    def chosen_question(self, event: Select.Changed):
        if event.select.id == f"{self.prefix}-wording-mode" and event.value in ("simple", "technical"):
            event.stop()
            self.reply_mode = event.value
            return
        if event.select.id == f"{self.prefix}-questions" and isinstance(event.value, str):
            event.stop()
            self.start_chat(event.value)
            with self.prevent(Select.Changed):
                event.select.clear()

    @on(Input.Submitted)
    def submitted_question(self, event: Input.Submitted):
        if event.input.id == f"{self.prefix}-chat-input":
            event.stop()
            self.start_chat(event.value)

    @on(Button.Pressed)
    def clicked(self, event: Button.Pressed):
        if event.button.id == f"{self.prefix}-explain":
            event.stop()
            self.start_chat("What changed in this domain's saved history?" if self.history else "Explain this scan in simple words.")
        elif event.button.id == f"{self.prefix}-fix-first":
            event.stop()
            self.start_chat("What should I fix first?")
        elif event.button.id == f"{self.prefix}-most-exposed":
            event.stop()
            self.start_chat("Which host is the most exposed?")
        elif event.button.id == f"{self.prefix}-chat-send":
            event.stop()
            self.start_chat(self.query_one(f"#{self.prefix}-chat-input", Input).value)
        elif event.button.id == f"{self.prefix}-log-toggle":
            event.stop()
            self.show_log()
