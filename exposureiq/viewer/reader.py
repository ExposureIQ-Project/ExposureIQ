"""Descriptor-relative, no-symlink reads of bounded saved JSON files."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from exposureiq import storage
from exposureiq.history import confined_scan_path

MAX_SCAN_BYTES = 8_000_000


class ViewerError(ValueError):
    """Only fixed messages may cross the HTTP boundary."""


def read_scan(path, results_dir, *, with_size=False):
    """Open each component relative to a trusted root, never follow symlinks.

    A local process replacing a directory between checking and opening cannot
    redirect this read outside the selected root. Unsupported platforms fail
    closed; the normal TUI and offline reports remain available there.
    """
    directory_fd = file_fd = None
    try:
        root = Path(results_dir).absolute()
        if root.is_symlink():
            raise ViewerError("The results root must not be a symlink.")
        safe = confined_scan_path(path, root)
        relative = safe.relative_to(root)
        if (os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW")
                or not hasattr(os, "O_DIRECTORY")):
            raise ViewerError("Secure web file reads are unavailable on this platform; use the TUI or offline reports.")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_fd = os.open(root, directory_flags)
        for part in relative.parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SCAN_BYTES:
            raise ViewerError("Saved scan is not a regular file or exceeds the web size limit.")
        with os.fdopen(file_fd, "rb") as handle:
            file_fd = None
            raw = handle.read(MAX_SCAN_BYTES + 1)
        if len(raw) > MAX_SCAN_BYTES:
            raise ViewerError("Saved scan exceeds the web size limit.")
        scan = json.loads(raw)
        storage._validate_scan(scan)
        return (scan, len(raw)) if with_size else scan
    except ViewerError:
        raise
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise ViewerError("Saved scan is unreadable, invalid or outside the selected results root.") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)
