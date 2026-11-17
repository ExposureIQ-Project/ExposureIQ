"""Private AI preferences. Environment keys override storage, never get saved.

Remote requests require explicit consent for the configured base URL. Local
mode is loopback-only and sends no key. No caller should serialize AIConfig;
use public_config(), which returns only a masked credential state.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from exposureiq.ai.sanitize import text
from exposureiq.ai.locations import outside_project

DEMO_MODEL = "ExposureIQ demo (offline)"
LOCAL_BASE = "http://127.0.0.1:11434/v1"
PRESETS = {
    "Custom": {"url": "", "verified": False, "docs": "User-supplied OpenAI-compatible endpoint"},
    "OpenAI": {"url": "https://api.openai.com/v1", "verified": True,
               "docs": "https://platform.openai.com/docs/api-reference/chat/create", "date": "2026-11-16"},
    "Anthropic": {"url": "https://api.anthropic.com/v1", "verified": True,
                  "docs": "https://platform.claude.com/docs/en/api/overview", "date": "2026-11-16"},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1", "verified": True,
                   "docs": "https://openrouter.ai/docs/quickstart"},
    "Groq": {"url": "https://api.groq.com/openai/v1", "verified": True,
             "docs": "https://console.groq.com/docs/openai"},
    "Mistral": {"url": "https://api.mistral.ai/v1", "verified": False,
                "docs": "https://docs.mistral.ai/api/endpoint/chat (unverified: docs timed out)"},
    "Gemini (OpenAI-compatible)": {"url": "https://generativelanguage.googleapis.com/v1beta/openai",
                                  "verified": True, "docs": "https://ai.google.dev/gemini-api/docs/openai"},
}
PRESETS_VERIFIED_DATE = "2026-11-14"


class ConfigError(ValueError):
    """Only safe, fixed messages; never include supplied input or a key."""


@dataclass(frozen=True)
class AIConfig:
    mode: str = "off"
    provider: str = "Custom"
    base_url: str = ""
    model: str = ""
    api_key: str = field(default="", repr=False, compare=False)
    consent_base: str = ""
    developer_mode: bool = False

    @property
    def key(self) -> str:
        return (os.environ.get("EXPOSUREIQ_AI_KEY") or self.api_key) if self.mode == "remote" else ""

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).netloc

    @property
    def ready(self) -> bool:
        if self.mode == "demo":
            return True
        return bool(self.mode in ("local", "remote") and self.base_url and self.model
                    and (self.mode == "local" or (self.key and self.consent_base == self.base_url)))


def config_path() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "exposureiq" / "ai.json"


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_config(config: AIConfig, *, require_ready: bool = False) -> AIConfig:
    if not isinstance(config, AIConfig) or config.mode not in ("off", "remote", "local", "demo"):
        raise ConfigError("Choose off, remote, local or demo mode.")
    if config.provider not in PRESETS:
        raise ConfigError("Choose a listed provider or Custom.")
    if not isinstance(config.developer_mode, bool):
        raise ConfigError("Developer mode must be on or off.")
    if not all(isinstance(v, str) for v in (config.base_url, config.model, config.api_key, config.consent_base)):
        raise ConfigError("AI settings must be text fields.")
    if len(config.api_key) > 4096 or len(config.key) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in config.key):
        raise ConfigError("The key has an invalid format.")
    if config.mode in ("off", "demo"):
        if require_ready and config.mode == "off":
            raise ConfigError("AI is off. Choose Local or Remote in Settings.")
        return replace(config, base_url="", model=DEMO_MODEL if config.mode == "demo" else "",
                       api_key="", consent_base="")
    try:
        url = urlsplit(config.base_url.strip().rstrip("/"))
        port = url.port
    except ValueError:
        raise ConfigError("Enter a valid AI base URL.") from None
    if (url.scheme not in ("http", "https") or not url.hostname or url.username or url.password
            or url.query or url.fragment or len(config.base_url) > 500
            or any(c.isspace() or ord(c) < 32 for c in config.base_url)
            or "%" in url.netloc or "\\" in config.base_url or ".." in url.path.split("/")):
        raise ConfigError("Use an HTTP(S) base URL without credentials, query or fragment.")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("The AI base URL port is invalid.")
    if config.mode == "local" and not _loopback(url.hostname):
        raise ConfigError("Local mode must use a loopback URL. Use remote mode for other hosts.")
    if config.mode == "remote" and url.scheme != "https" and not _loopback(url.hostname):
        raise ConfigError("Remote API keys require HTTPS.")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9/_:.+@-]{0,199}", config.model):
        raise ConfigError("Enter a model name using letters, numbers, dots, slashes or hyphens.")
    netloc = url.netloc.lower()
    if url.hostname.lower() == "localhost":
        # Pin this alias to a numeric loopback address. A changed hosts/DNS
        # entry must never send a local request or an HTTP key off-machine.
        netloc = "127.0.0.1" + (f":{port}" if port is not None else "")
    base = urlunsplit((url.scheme, netloc, url.path.rstrip("/"), "", ""))
    if config.key and (config.key in base or config.key in config.model):
        raise ConfigError("Do not put a key in the URL or model name.")
    result = replace(config, base_url=base, api_key=config.api_key if config.mode == "remote" else "")
    if require_ready and not result.ready:
        raise ConfigError("AI is not configured or remote consent is missing. Open AI settings or use --demo.")
    return result


def consent_message(config: AIConfig) -> str:
    return f"Scan summaries (host names, findings) will be sent to {config.host}"


def confirm_remote(config: AIConfig, *, accepted: bool) -> AIConfig:
    config = validate_config(config)
    if config.mode != "remote" or not accepted:
        raise ConfigError("Remote data sharing was not confirmed.")
    return replace(config, consent_base=config.base_url)


def load_config() -> AIConfig:
    path = config_path()
    if not outside_project(path):
        raise ConfigError("AI settings must be outside the project. Choose a private XDG_CONFIG_HOME.")
    if not path.exists():
        return AIConfig()
    try:
        if path.is_symlink() or path.parent.is_symlink() or path.stat().st_size > 32768:
            raise ConfigError("AI settings file is unsafe or too large.")
        if os.name == "posix" and path.stat().st_mode & 0o077:
            raise ConfigError("AI settings file must be private (mode 0600).")
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {"mode", "provider", "base_url", "model", "api_key", "consent_base", "developer_mode"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ConfigError("AI settings file has an invalid format.")
        # Demo is now an explicit CLI/test fake, not a user-selectable AI mode.
        # Old preferences become Off without contacting anything or rewriting
        # the user's file just because it was read.
        if data.get("mode") == "demo":
            data = {**data, "mode": "off"}
        return validate_config(AIConfig(**data))
    except (OSError, ValueError, TypeError, UnicodeError):
        # Deliberately discard raw errors: bad JSON may contain a credential.
        raise ConfigError("Cannot read private AI settings. Check format and file permissions.") from None


def save_config(config: AIConfig) -> AIConfig:
    config = validate_config(config)
    if config.mode == "demo":
        config = validate_config(replace(config, mode="off"))
    if config.mode == "remote" and config.consent_base != config.base_url:
        raise ConfigError("Confirm remote data sharing before saving.")
    path = config_path()
    if not outside_project(path):
        raise ConfigError("AI settings must be outside the project. Choose a private XDG_CONFIG_HOME.")
    temporary = None
    try:
        if path.is_symlink() or path.parent.is_symlink():
            raise ConfigError("AI settings cannot use a symlink.")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        data = {"mode": config.mode, "provider": config.provider, "base_url": config.base_url,
                "model": config.model, "api_key": config.api_key, "consent_base": config.consent_base,
                "developer_mode": config.developer_mode}
        fd, name = tempfile.mkstemp(prefix=".ai-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o600)
            else:
                temporary.chmod(0o600)
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError:
        raise ConfigError("Cannot save private AI settings. Check folder permissions.") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return config


def mask_key(key: str) -> str:
    if not key:
        return "not set"
    return "••••" + (key[-4:] if len(key) > 8 else "")


def public_config(config: AIConfig) -> dict:
    config = validate_config(config)
    state = config.mode if config.ready or config.mode == "off" else "not set"
    return {"mode": config.mode, "provider": config.provider, "base_url": config.base_url,
            "model": text(config.model, 200), "state": state, "key_mask": mask_key(config.key),
            "env_override": bool(os.environ.get("EXPOSUREIQ_AI_KEY") and config.mode == "remote"),
            "developer_mode": config.developer_mode,
            "consent_required": config.mode == "remote" and config.consent_base != config.base_url}
