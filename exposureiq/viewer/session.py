"""One lazy, read-only daemon viewer for a terminal application's lifetime."""

from __future__ import annotations

from pathlib import Path
import threading

from exposureiq.viewer.server import ViewerState, make_server


class ViewerSession:
    def __init__(self):
        self.server = None
        self.thread = None
        self._lock = threading.Lock()
        self._closed = False

    def report_url(self, source: str, results_dir, service) -> str:
        """Choose saved data, then start/reuse the same free-port server.

        A folder switch is an explicit TUI selection, not a browser/AI route.
        Each replacement catalog retains the exact same fail-closed reader.
        """
        with self._lock:
            if self._closed:
                raise ValueError("The terminal viewer session has stopped.")
            # Do not resolve away a symlink: ViewerState must reject it.
            root = Path(results_dir).expanduser().absolute()
            if self.server is None:
                server = make_server(root, port=0, service=service)
                try:
                    url = server.report_url(source, focus_scan=True)
                    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.1),
                                              name="exposureiq-report-viewer", daemon=True)
                    thread.start()
                except Exception:
                    server.server_close()
                    raise
                self.server, self.thread = server, thread
                return url
            server = self.server
            if server.state.root != root:
                candidate = ViewerState(root, service=service)
                candidate.report_identifier(source)  # Validate before swapping.
                candidate.ai_lock = server.state.ai_lock
                candidate.report_lock = server.state.report_lock
                server.state = candidate
            else:
                self._set_service(service)
                server.state.refresh()
            return server.report_url(source, focus_scan=True)

    def _set_service(self, service) -> None:
        if self.server is not None and self.server.state.service is not service:
            self.server.state.service = service
            # Old model wording/retry contexts do not cross settings changes.
            self.server.state.chats.clear()
            with self.server.state.progress_lock:
                self.server.state.chat_progress.clear()

    def set_service(self, service) -> None:
        with self._lock:
            if not self._closed:
                self._set_service(service)

    def stop(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            server, thread = self.server, self.thread
        if server is not None:
            server.shutdown()
            server.server_close()
            if thread is not None:
                thread.join(timeout=2)
