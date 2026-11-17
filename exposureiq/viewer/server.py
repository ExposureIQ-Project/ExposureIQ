"""Small standard-library HTTP viewer, restricted to 127.0.0.1.

Only static assets and an explicit saved-data/AI route allowlist exist. Host,
Origin, a per-launch session token, body budgets and file confinement protect
against cross-site requests, DNS rebinding and arbitrary file access. There
are no credential, configuration-write, scan, scope, shell or file-write routes.
The HTML-report route renders the same saved-data page in memory only.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from exposureiq.ai.chat import Chat
from exposureiq.ai.config import AIConfig
from exposureiq.ai.sanitize import compact_json, host_name, redact, text
from exposureiq.ai.service import AIService, chat_text, reply_label, result_text, verified_footer
from exposureiq.ai.tools import ReadOnlyTools
from exposureiq.diffing.pipeline import history_group, scan_key, scan_order
from exposureiq.history import sparkline, trend_arrow
from exposureiq.insight.digest import scan_digest
from exposureiq.insight.history_digest import build_history_layers
from exposureiq.insight.risk import RISK_FORMULA, has_check_evidence, risk_score
from exposureiq.insight.verdict import history_verdict
from exposureiq.paths import saved_json_paths
from exposureiq.viewer.reader import ViewerError, read_scan

MAX_BODY_BYTES = 8192
MAX_INDEX_FILES = 500
MAX_INDEX_BYTES = 32_000_000
MAX_FINDING_ROWS = 500
MAX_CHAT_CONTEXTS = 8
MAX_PROGRESS_CONTEXTS = 32
CHAT_STAGES = ("Reading your scan", "Phrasing your answer", "Checking the facts", "Reply ready", "Reply unavailable")
SESSION_HEADER = "X-ExposureIQ-Session"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/assets/style.css": ("style.css", "text/css; charset=utf-8")}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    # Firefox can send Origin:null for native POST forms under no-referrer.
    # Same-origin keeps referrers on this exact loopback server; fragments
    # (including the session token) never enter HTTP referrer headers.
    "Referrer-Policy": "same-origin", "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin", "Cross-Origin-Opener-Policy": "same-origin",
}


def _identity(path, scan):
    return hashlib.sha256(compact_json([str(path), scan]).encode("utf-8")).hexdigest()[:24]


class ViewerState:
    def __init__(self, results_dir="results", *, service=None, demo=False):
        self.root = Path(results_dir).absolute()
        if self.root.is_symlink():
            raise ViewerError("The results root must not be a symlink.")
        self.service = service if service is not None else AIService(AIConfig(mode="demo", developer_mode=True) if demo else None)
        self.entries = {}
        self.catalog_lock = threading.Lock()
        self.ai_lock = threading.Lock()
        self.report_lock = threading.Lock()
        self.chats = {}
        self.chat_progress = {}
        self.progress_lock = threading.Lock()
        self.warning = ""
        self.refresh()

    def refresh(self):
        entries, skipped, used = {}, 0, 0
        paths = saved_json_paths(self.root)
        for path in paths[:MAX_INDEX_FILES]:
            try:
                size = path.lstat().st_size
                if used + size > MAX_INDEX_BYTES:
                    skipped += 1
                    continue
                scan, actual_size = read_scan(path, self.root, with_size=True)
                if used + actual_size > MAX_INDEX_BYTES:
                    skipped += 1
                    continue
                from exposureiq.discovery.subdomains import normalize_domain

                target = normalize_domain(scan["target"])
            except (OSError, ValueError):
                skipped += 1
                continue
            used += actual_size
            identifier = _identity(path, scan)
            entries[identifier] = {"id": identifier, "path": path, "target": target, "scan": scan}
        skipped += max(0, len(paths) - MAX_INDEX_FILES)
        warning = (f"{skipped} unreadable, unsafe or over-budget files were excluded. "
                   "The viewer indexes at most 500 files / 32 MB; scan files are never changed." if skipped else "")
        with self.catalog_lock:
            self.entries, self.warning = entries, warning

    def selected(self, identifier):
        if not isinstance(identifier, str) or len(identifier) != 24 or any(c not in "0123456789abcdef" for c in identifier):
            raise ViewerError("Select an existing scan from the viewer.")
        with self.catalog_lock:
            entry = self.entries.get(identifier)
        if entry is None:
            raise ViewerError("Saved scan is not in the viewer; refresh the domain list.")
        scan = read_scan(entry["path"], self.root)
        if _identity(entry["path"], scan) != identifier:
            raise ViewerError("Saved scan changed; refresh the domain list before reading it.")
        return scan

    def report_identifier(self, source):
        """Resolve a CLI source only against the already-confined catalog."""
        if not isinstance(source, str) or not source.strip():
            raise ViewerError("Choose a saved domain or JSON file under the results root.")
        value = source.strip()
        path = Path(value)
        if path.suffix.lower() == ".json" or "/" in value or "\\" in value:
            with self.catalog_lock:
                matches = [entry["id"] for entry in self.entries.values() if entry["path"] == path.absolute()]
            if len(matches) != 1:
                raise ViewerError("Choose an existing, safe saved JSON file under the results root.")
            identifier = matches[0]
        else:
            identifier = self.domain_entries(value)[-1]["id"]
        self.selected(identifier)  # Recheck the file before printing a handoff URL.
        return identifier

    def domain_entries(self, domain, *, selected=None):
        from exposureiq.discovery.subdomains import normalize_domain

        try:
            wanted = normalize_domain(domain)
        except (ValueError, TypeError):
            raise ViewerError("Select a valid domain from the viewer.") from None
        with self.catalog_lock:
            entries = [copy.copy(e) for e in self.entries.values() if e["target"] == wanted]
        entries.sort(key=lambda e: scan_order(e["scan"]))
        if not entries:
            raise ViewerError("No saved scans for that domain are in the viewer.")
        group = history_group(selected or entries[-1]["scan"])
        unique = {scan_key(e["scan"]): e for e in entries if history_group(e["scan"]) == group
                  and (selected is None or scan_order(e["scan"]) <= scan_order(selected))}
        return sorted(unique.values(), key=lambda e: scan_order(e["scan"]))

    def domains(self):
        self.refresh()
        with self.catalog_lock:
            targets = sorted({e["target"] for e in self.entries.values()})
        rows = []
        for target in targets:
            entries = self.domain_entries(target)
            scans = [e["scan"] for e in entries]
            risk = risk_score(scans[-1])
            verdict = history_verdict(scans)["value"]
            rows.append({"domain": target, "scans": len(scans), "date": text(scans[-1]["started_at"], 25),
                         "high": risk["high"], "medium": risk["medium"], "low": risk["low"],
                         "verdict": verdict, "arrow": trend_arrow(verdict), "demo": history_group(scans[-1]) != "real"})
        return {"domains": rows, "warning": self.warning}

    def scans(self, domain):
        entries = self.domain_entries(domain)
        scans = [self.selected(e["id"]) for e in entries]
        rows = [{"id": entry["id"], "scan_id": text(scan["scan_id"], 160), "date": text(scan["started_at"], 25),
                 "risk": {k: risk_score(scan)[k] for k in ("per_host", "high", "medium", "low", "hosts")}}
                for entry, scan in zip(entries, scans)]
        return {"domain": host_name(domain), "scans": rows[::-1], "verdict": history_verdict(scans)["value"],
                "sparkline": sparkline([risk_score(s)["per_host"] for s in scans if has_check_evidence(s)]),
                "formula": RISK_FORMULA, "note": "Code trend only. Demo/real groups stay separate. Missing checks are not proof of safety."}

    def scan_payload(self, identifier):
        scan = self.selected(identifier)
        findings = [{"id": text(f["id"], 24), "host": host_name(a["host"]), "rule": text(f["rule"], 80),
                     "severity": f["severity"], "title": text(f["title"], 160), "detail": text(f["detail"], 1000),
                     "recommendation": text(f["recommendation"], 1000)}
                    for a in scan["assets"] for f in a.get("findings", [])]
        return {"digest": scan_digest(scan), "scan_id": text(scan["scan_id"], 160),
                "findings": findings[:MAX_FINDING_ROWS], "truncated": len(findings) > MAX_FINDING_ROWS,
                "finding_count": len(findings)}

    def summary(self, payload):
        if set(payload) != {"scan"}:
            raise ViewerError("Summary requires only an existing scan ID.")
        return self.service.summary(self.selected(payload["scan"]))

    def history(self, payload):
        if set(payload) != {"domain"}:
            raise ViewerError("History summary requires only an existing domain.")
        scans = [self.selected(e["id"]) for e in self.domain_entries(payload["domain"])]
        return self.service.summary(build_history_layers(scans)["L4"])

    def ask(self, payload):
        required = set(payload) - {"mode", "host", "finding_id", "conversation", "retry_id", "progress_id"}
        if required not in ({"scan", "question"}, {"domain", "question"}):
            raise ViewerError("Chat requires a question and one selected scan or domain.")
        if "mode" in payload and payload["mode"] not in ("simple", "technical"):
            raise ViewerError("Chat wording must be simple or technical.")
        if "retry_id" in payload and (not isinstance(payload["retry_id"], str) or payload["retry_id"] and not re.fullmatch(r"[a-f0-9]{32}", payload["retry_id"])):
            raise ViewerError("Try again requires an identifier from this saved conversation.")
        conversation = payload.get("conversation", "")
        if not isinstance(conversation, str) or (conversation and not re.fullmatch(r"[a-f0-9]{32}", conversation)):
            raise ViewerError("Use a bounded, session-only conversation identifier.")
        progress_id = payload.get("progress_id", "")
        if "progress_id" in payload and (not conversation or not isinstance(progress_id, str) or not re.fullmatch(r"[a-f0-9]{32}", progress_id)):
            raise ViewerError("Live status requires a request identifier in this conversation.")

        def progress(stage, *, done=False):
            if not progress_id or stage not in CHAT_STAGES:
                return
            with self.progress_lock:
                key = (conversation, progress_id)
                if key not in self.chat_progress and len(self.chat_progress) >= MAX_PROGRESS_CONTEXTS:
                    self.chat_progress.pop(next(iter(self.chat_progress)))
                self.chat_progress[key] = {"stage": stage, "done": done}

        progress("Reading your scan")
        if "domain" in payload:
            entries = self.domain_entries(payload["domain"])
            scans = [self.selected(e["id"]) for e in entries]
            scan, digest = scans[-1], build_history_layers(scans)["L4"]
            context = "domain:" + ":".join(e["id"] for e in entries)
        else:
            scan = self.selected(payload["scan"])
            entries = self.domain_entries(scan["target"], selected=scan)
            scans = [self.selected(e["id"]) for e in entries]
            digest, context = scan_digest(scan), "scan:" + payload["scan"]
        context += ":conversation:" + conversation
        if context not in self.chats:
            if len(self.chats) >= MAX_CHAT_CONTEXTS:
                self.chats.pop(next(iter(self.chats)))
            self.chats[context] = Chat(digest, ReadOnlyTools(scan, self.root, scans=scans), self.service)
        try:
            result = self.chats[context].ask(payload["question"], mode=payload.get("mode"), progress=progress,
                                              host=payload.get("host", ""), finding_id=payload.get("finding_id", ""), retry_id=payload.get("retry_id", ""))
        except Exception:
            progress("Reply unavailable", done=True)
            raise
        progress("Reply ready", done=True)
        config = self.service._configuration()
        result["user"] = redact(payload["question"], (config.key, config.api_key))
        return result

    def progress(self, conversation, request):
        if any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value) for value in (conversation, request)):
            raise ViewerError("Use a live-status identifier from this conversation.")
        with self.progress_lock:
            result = self.chat_progress.get((conversation, request))
            if result is None:
                raise ViewerError("No live status exists for this conversation request.")
            return copy.deepcopy(result)

    def health(self, signature=""):
        from exposureiq.viewer.export import scan_signature

        if signature and not re.fullmatch(r"[a-f0-9]{64}", signature):
            raise ViewerError("Use a signature from an exported saved scan.")
        config = self.service._configuration()
        if config.mode == "off" and self.ai_lock.acquire(blocking=False):
            try:
                self.chats.clear()
                with self.progress_lock:
                    self.chat_progress.clear()
            finally:
                self.ai_lock.release()
        match = ""
        if signature:
            with self.catalog_lock:
                entries = list(self.entries.values())
            candidates = [entry for entry in entries if scan_signature(entry["scan"]) == signature]
            if len(candidates) == 1:
                scan = self.selected(candidates[0]["id"])
                if scan_signature(scan) == signature:
                    match = candidates[0]["id"]
        return {"protocol": "ExposureIQ-local-v1", "loopback": True, "mode": config.mode,
                "enabled": config.mode != "off", "ready": config.ready,
                "developer_mode": config.developer_mode, "endpoint_host": config.host,
                "model": config.model, "scan_id": match,
                "note": "Settings and provider keys stay on the local server. This check did not call a model."}

    def report_page(self, identifier, *, private=(), focus_scan=False):
        from exposureiq.viewer.export import live_report_page

        scan = self.selected(identifier)
        with self.catalog_lock:
            ids = [entry["id"] for entry in self.entries.values() if entry["target"] == scan["target"]]
        scans = [self.selected(item) for item in ids]
        config = self.service._configuration()
        return live_report_page(scan, scans, ai_enabled=config.mode != "off", private=(config.key, config.api_key, *private), focus_scan=focus_scan)


class ViewerServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, port, state):
        self.state = state
        self.token = secrets.token_urlsafe(32)
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", port), ViewerHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.expected_host = f"127.0.0.1:{self.server_port}"

    @property
    def url(self):
        # Fragments are never sent in HTTP requests or Referrer headers.
        return self.origin + "/#" + self.token

    def report_url(self, source, *, focus_scan=False):
        identifier = self.state.report_identifier(source)
        # The static page makes a same-origin native POST, so navigation never
        # puts a session token in a query or exposes a saved report without auth.
        return self.origin + "/?report=" + identifier + ("&view=scan" if focus_scan else "") + "#" + self.token

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # No raw requests, scan strings, browser tokens or provider exceptions.
        pass


class ViewerHandler(BaseHTTPRequestHandler):
    server_version = "ExposureIQ-local-viewer"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._send(code, {"error": "Request rejected."})

    def _send(self, code, body, content_type="application/json; charset=utf-8", *, csp=None):
        raw = body if isinstance(body, bytes) else compact_json(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, csp if key == "Content-Security-Policy" and csp is not None else value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _boundary(self, *, authenticated=False, write=False):
        if self.headers.get_all("Host", []) != [self.server.expected_host]:
            self._send(403, {"error": "Only this loopback viewer host is allowed."})
            return False
        origins = self.headers.get_all("Origin", [])
        if (origins and origins != [self.server.origin]) or (write and origins != [self.server.origin]):
            self._send(403, {"error": "Cross-origin requests are not allowed."})
            return False
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            self._send(403, {"error": "Cross-site requests are not allowed."})
            return False
        tokens = self.headers.get_all(SESSION_HEADER, [])
        if authenticated and (len(tokens) != 1 or not tokens[0].isascii() or not hmac.compare_digest(tokens[0], self.server.token)):
            self._send(403, {"error": "Open the full per-launch viewer URL to start a session."})
            return False
        return True

    def _route(self):
        try:
            url = urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "\\" in self.path:
                raise ValueError
            query = parse_qs(url.query, keep_blank_values=True, max_num_fields=4)
            if any(len(values) != 1 for values in query.values()):
                raise ValueError
            return url.path, {key: values[0] for key, values in query.items()}
        except ValueError:
            raise ViewerError("Invalid viewer request.") from None

    def handle_expect_100(self):
        self._send(417, {"error": "Expect/continue requests are not supported by this local viewer."})
        return False

    def do_GET(self):
        if not self._boundary():
            return
        try:
            path, query = self._route()
            handoff = (path == "/" and set(query) in ({"report"}, {"report", "view"})
                       and re.fullmatch(r"[a-f0-9]{24}", query["report"]) and query.get("view", "scan") == "scan")
            if path in STATIC and (not query or handoff):
                name, content_type = STATIC[path]
                self._send(200, (files("exposureiq.viewer") / "static" / name).read_bytes(), content_type)
                return
            if not self._boundary(authenticated=True):
                return
            state = self.server.state
            if path == "/api/domains" and not query:
                result = state.domains()
            elif path == "/api/scans" and set(query) == {"domain"}:
                result = state.scans(query["domain"])
            elif path == "/api/scan" and set(query) == {"scan"}:
                result = state.scan_payload(query["scan"])
            elif path == "/api/log" and not query:
                config = state.service._configuration()
                if config.mode == "off" or not config.developer_mode:
                    self._send(404, {"error": "AI logs are available only with AI and Developer mode enabled in terminal Settings."})
                    return
                with state.service._audit_lock:
                    result = {"entries": copy.deepcopy(state.service.audit), "note": "Memory only; last thirty AI calls. No credentials or system instructions."}
            elif path == "/api/status" and not query:
                config = state.service._configuration()
                result = {"mode": config.mode, "model": config.model, "ready": config.ready,
                          "enabled": config.mode != "off", "developer_mode": config.developer_mode,
                          "endpoint_host": config.host, "note": "Configure AI in the terminal Settings drawer. The browser never receives a key."}
            elif path == "/api/health" and set(query) in (set(), {"signature"}):
                result = state.health(query.get("signature", ""))
            elif path == "/api/ai/progress" and set(query) == {"conversation", "request"}:
                if state.service._configuration().mode == "off":
                    self._send(409, {"error": "AI is off; no live status is available."})
                    return
                result = state.progress(query["conversation"], query["request"])
            else:
                self._send(404, {"error": "No such read-only viewer route."})
                return
            config = state.service._configuration()
            self._send(200, redact(result, (config.key, config.api_key, self.server.token)))
        except ViewerError as error:
            self._send(400, {"error": str(error)})
        except Exception:
            self._send(400, {"error": "Saved data could not be read safely. No raw error was exposed."})

    def _body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") or len(lengths) != 1
                or not lengths[0].isdigit() or not 1 <= int(lengths[0]) <= MAX_BODY_BYTES):
            raise ViewerError("Use one bounded JSON request body (at most 8192 bytes).")
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ViewerError("Viewer requests must use application/json.")
        try:
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError
            return body
        except (ValueError, UnicodeError, RecursionError):
            raise ViewerError("Invalid JSON request body.") from None

    def _report_form(self):
        lengths = self.headers.get_all("Content-Length", [])
        types = self.headers.get_all("Content-Type", [])
        if (self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit()
                or not 1 <= int(lengths[0]) <= MAX_BODY_BYTES or len(types) != 1
                or types[0].split(";", 1)[0].lower() != "application/x-www-form-urlencoded"):
            raise ViewerError("Use the local viewer's bounded HTML-report form.")
        try:
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError
            form = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=3, strict_parsing=True)
            if (set(form) not in ({"scan", "session"}, {"scan", "session", "view"})
                    or any(len(values) != 1 for values in form.values()) or form.get("view", ["scan"]) != ["scan"]):
                raise ValueError
            return {key: values[0] for key, values in form.items()}
        except (ValueError, UnicodeError):
            raise ViewerError("HTML report requires one saved scan and a per-launch session.") from None

    def do_POST(self):
        if not self._boundary(write=True):
            return
        locked = report_locked = False
        state = self.server.state  # A TUI folder switch cannot change held locks.
        try:
            path, query = self._route()
            if path == "/api/report" and not query:
                # Native form navigation cannot set an HTTP session header.
                # Require the same token in its bounded body, after Host and
                # exact Origin checks. The response contains no session token.
                form = self._report_form()
                session = form["session"]
                if not session.isascii() or not hmac.compare_digest(session, self.server.token):
                    self._send(403, {"error": "Open the full per-launch viewer URL before opening a report."})
                    return
                report_locked = state.report_lock.acquire(blocking=False)
                if not report_locked:
                    self._send(409, {"error": "A saved HTML report is already being prepared. Try again shortly."})
                    return
                page = state.report_page(form["scan"], private=(self.server.token,), focus_scan=form.get("view") == "scan")
                csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
                self._send(200, page.encode("utf-8"), "text/html; charset=utf-8", csp=csp + "; frame-ancestors 'none'")
                return
            if not self._boundary(authenticated=True, write=True):
                return
            operations = {"/api/ai/summary": state.summary,
                          "/api/ai/history": state.history, "/api/ai/ask": state.ask}
            if path not in operations or query:
                self._send(404, {"error": "No such read-only AI route. No scan or scope actions exist."})
                return
            payload = self._body()
            locked = state.ai_lock.acquire(blocking=False)
            if not locked:
                self._send(409, {"error": "An AI answer is already running; wait for it to finish."})
                return
            if state.service._configuration().mode == "off":
                state.chats.clear()
                self._send(409, {"error": "AI is off. Enable Local or Remote AI in terminal Settings first."})
                return
            result = operations[path](payload)
            if state.service._configuration().mode == "off":
                state.chats.clear()
                self._send(409, {"error": "AI was turned off while the answer was running. The reply was not displayed."})
                return
            config = state.service._configuration()
            # Redact every data field before building presentation. The paragraph
            # breaks added by our renderer are safe layout, not terminal controls
            # copied from a saved string; do not flatten them into one paragraph.
            result = redact(result, (config.key, config.api_key, self.server.token))
            result["text"] = chat_text(result) if path == "/api/ai/ask" else result_text(result)
            result["footer"] = verified_footer(result)
            result["label"] = reply_label(result)
            self._send(200, result)
        except ViewerError as error:
            self._send(400, {"error": str(error)})
        except ValueError:
            self._send(400, {"error": "Use existing saved data and a nonempty scan question of at most 1000 characters."})
        except Exception:
            self._send(503, {"error": "AI answer unavailable. No raw provider error or credential was displayed."})
        finally:
            if locked:
                state.ai_lock.release()
            if report_locked:
                state.report_lock.release()

    def _method_not_allowed(self):
        if self._boundary():
            self._send(405, {"error": "Only saved-data GET and read-only POST routes exist."})

    do_HEAD = do_OPTIONS = do_PUT = do_PATCH = do_DELETE = do_TRACE = _method_not_allowed


def make_server(results_dir="results", *, port=8765, host="127.0.0.1", service=None, demo=False):
    if host != "127.0.0.1":
        raise ViewerError("The web viewer binds only to 127.0.0.1; public or LAN binding is not allowed.")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ViewerError("Choose a port between 0 and 65535.")
    return ViewerServer(port, ViewerState(results_dir, service=service, demo=demo))
