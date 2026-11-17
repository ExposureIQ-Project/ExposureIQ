"""Private, disposable caches outside the repository. Keys contain no secrets."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from exposureiq.ai.sanitize import compact_json, redact
from exposureiq.ai.locations import outside_project

DIGEST_VERSION = "s5-digest-2"


def cache_directory() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "exposureiq"


def file_hash(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def history_hash(hashes: list[str]) -> str:
    return hashlib.sha256(compact_json(hashes).encode("utf-8")).hexdigest()


def summary_key(history: str, model: str, prompt_version: str) -> str:
    return hashlib.sha256(compact_json([history, model, prompt_version]).encode("utf-8")).hexdigest()


def _path(kind: str, key: str) -> Path:
    if kind not in ("digest", "summary") or not isinstance(key, str) or len(key) != 64 \
            or any(c not in "0123456789abcdef" for c in key):
        raise ValueError("Invalid cache key.")
    return cache_directory() / f"{DIGEST_VERSION}-{kind}-{key}.json"


def get_cached(kind: str, key: str):
    try:
        path = _path(kind, key)
        if (not outside_project(path) or path.is_symlink() or path.parent.is_symlink()
                or path.stat().st_size > 256000):
            return None
        if os.name == "posix" and (path.stat().st_mode & 0o077 or path.parent.stat().st_mode & 0o077):
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return None


def put_cached(kind: str, key: str, value, *, secrets: tuple[str, ...] = ()) -> bool:
    path = _path(kind, key)
    temporary = None
    try:
        directory = path.parent
        if not outside_project(path) or directory.is_symlink():
            return False
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        fd, name = tempfile.mkstemp(prefix=".cache-", dir=directory)
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o600)
            else:
                temporary.chmod(0o600)
            handle.write(compact_json(redact(value, secrets)) + "\n")
        os.replace(temporary, path)
        return True
    except OSError:
        return False  # Caching is optional; never break an offline summary.
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def cached_scan_digest(path: str | Path) -> dict:
    from exposureiq.insight.digest import scan_digest
    from exposureiq.storage import load_scan

    key = file_hash(path)
    value = get_cached("digest", key)
    if (isinstance(value, dict) and set(value) == {"input_hash", "value_hash", "digest"}
            and value["input_hash"] == key and isinstance(value["digest"], dict)
            and value["digest"].get("ref") == "S:scan"
            and value["value_hash"] == hashlib.sha256(compact_json(value["digest"]).encode("utf-8")).hexdigest()):
        return value["digest"]
    value = scan_digest(load_scan(str(path)))
    put_cached("digest", key, {"input_hash": key, "digest": value,
                              "value_hash": hashlib.sha256(compact_json(value).encode("utf-8")).hexdigest()})
    return value
