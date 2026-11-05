"""Write selected text to a local desktop clipboard without extra Python packages."""

import logging
import os
import shutil
import subprocess
import sys

log = logging.getLogger(__name__)
TIMEOUT = 3
_POWERSHELL = (
    "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new(); "
    "Set-Clipboard -Value ([Console]::In.ReadToEnd())"
)


def _commands() -> list[list[str]]:
    # On SSH, the terminal clipboard fallback reaches the client, not the server.
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return []
    candidates = []
    if sys.platform == "darwin":
        candidates.append(["pbcopy"])
    elif sys.platform == "win32":
        candidates.extend([[name, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL]
                           for name in ("powershell.exe", "pwsh")])
    elif sys.platform.startswith("linux"):
        if os.environ.get("WAYLAND_DISPLAY"):
            candidates.append(["wl-copy", "--type", "text/plain;charset=utf-8"])
        if os.environ.get("DISPLAY"):
            candidates.extend([["xclip", "-selection", "clipboard", "-in"],
                               ["xsel", "--clipboard", "--input"]])
        if os.environ.get("WSL_DISTRO_NAME"):
            candidates.append(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                               "-Command", _POWERSHELL])
    commands = []
    for name, *arguments in candidates:
        executable = shutil.which(name)
        if executable:
            commands.append([executable, *arguments])
    return commands


def copy_system_text(text: str) -> bool:
    """Return whether a native clipboard tool accepted the exact selected text."""
    if not isinstance(text, str):
        raise ValueError("clipboard text must be a string")
    if not text:
        return False  # Do not erase an existing clipboard for an empty selection.
    for command in _commands():
        try:
            # Keep text out of command arguments; clipboard owners may fork, so
            # do not wait on inherited output pipes after the parent has exited.
            subprocess.run(command, input=text, text=True, encoding="utf-8", check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT)
        except (OSError, subprocess.SubprocessError) as error:
            log.warning("Clipboard tool %s failed: %s", command[0], type(error).__name__)
        else:
            return True
    return False
