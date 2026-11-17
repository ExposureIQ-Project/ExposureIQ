"""Quiet browser launch for an already-authorized loopback report URL.

True means a launcher accepted the request, not that a page was observed.
This helper does not render, export, scan or contact an AI provider.
"""

from __future__ import annotations

import subprocess
import sys
from urllib.parse import urlsplit
import webbrowser


def open_browser(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username is not None
                or parsed.password is not None or parsed.port is None or not 1 <= parsed.port <= 65535
                or any(ord(char) < 32 or ord(char) == 127 for char in url)):
            return False
    except (ValueError, TypeError):
        return False
    if sys.platform.startswith("linux"):
        try:
            process = subprocess.Popen(["xdg-open", url], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            try:
                if process.wait(timeout=1) == 0:
                    return True
            except subprocess.TimeoutExpired:
                return True  # Launcher is running; page success is unobserved.
        except OSError:
            pass
    try:
        return bool(webbrowser.open(url))
    except (OSError, webbrowser.Error):
        return False
