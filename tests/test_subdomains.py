"""Tests for subdomain discovery. They use fakes, so no internet and no Subfinder are needed.

Run from the project root:   python -m pytest
"""
import logging
import subprocess

import pytest
import requests

from exposureiq.discovery import subdomains as sd

REAL_FIND_SUBFINDER = sd._find_subfinder   # keep the real one for its own tests

FAKE_RECORDS = [
    {"name_value": "example.com\nwww.example.com"},
    {"name_value": "*.example.com"},
    {"name_value": "API.Example.com"},
    {"name_value": "mail.example.com\napi.example.com"},   # api is a duplicate
    {"name_value": "admin@example.com"},                   # email address, must be skipped
    {"name_value": "notexample.com"},                      # look-alike domain, must be skipped
    {"name_value": "evil.com\nshop.example.com.evil.com"}, # other domains, must be skipped
    {"name_value": "*.dev.example.com"},                   # wildcard under a subdomain
]
CRT_EXPECTED = ["api.example.com", "dev.example.com", "mail.example.com", "www.example.com"]


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    """Never really sleep, and never run a real Subfinder, unless a test asks for it."""
    monkeypatch.setattr(sd.time, "sleep", lambda s: None)
    monkeypatch.setattr(sd, "_find_subfinder", lambda: None)


# ---------------------------------------------------------------- cleaning ---
def test_extract_names_cleans_everything():
    assert sd._extract_names(FAKE_RECORDS, "example.com", include_apex=False) == CRT_EXPECTED


def test_apex_domain_only_when_asked():
    assert "example.com" in sd._extract_names(FAKE_RECORDS, "example.com", include_apex=True)
    assert "example.com" not in sd._extract_names(FAKE_RECORDS, "example.com", include_apex=False)


def test_result_is_sorted_and_unique():
    result = sd._extract_names(FAKE_RECORDS, "example.com", include_apex=False)
    assert result == sorted(set(result))


def test_ignores_broken_records():
    assert sd._extract_names([None, "text", {}, {"name_value": None}], "example.com", False) == []


def test_clean_names_from_subfinder_lines():
    lines = ["WWW.Example.com", "api.example.com", "api.example.com", "*.cdn.example.com",
             "notexample.com", "x.evil.com", "", "  ", "bad name.example.com", "a@example.com"]
    assert sd._clean_names(lines, "example.com", False) == ["api.example.com", "cdn.example.com", "www.example.com"]


@pytest.mark.parametrize("text, expected", [
    ("Example.COM", "example.com"),
    ("https://Example.com/some/path?x=1", "example.com"),
    ("example.com:8443", "example.com"),
    ("example.com.", "example.com"),
    ("*.example.com", "example.com"),
])
def test_normalize_domain(text, expected):
    assert sd._normalize_domain(text) == expected


@pytest.mark.parametrize("bad", ["", "   ", "not a domain", "localhost", "exa mple.com",
                                 "-bad.com", "--help.com", "-d.example.com", None, 123])
def test_invalid_domain_raises_value_error(bad):
    with pytest.raises(ValueError):
        sd.find_subdomains(bad)


def test_at_least_one_source_is_required():
    with pytest.raises(ValueError):
        sd.find_subdomains("example.com", use_subfinder=False, use_crtsh=False)


# ----------------------------------------------------- finding Subfinder ------
def test_find_subfinder_uses_env_variable(monkeypatch, tmp_path):
    exe = tmp_path / "my-subfinder"
    exe.write_text("")
    monkeypatch.setenv("SUBFINDER_PATH", str(exe))
    assert REAL_FIND_SUBFINDER() == str(exe)


def test_find_subfinder_uses_path(monkeypatch):
    monkeypatch.delenv("SUBFINDER_PATH", raising=False)
    monkeypatch.setattr(sd.shutil, "which", lambda name: "/usr/bin/subfinder")
    assert REAL_FIND_SUBFINDER() == "/usr/bin/subfinder"


def test_find_subfinder_uses_go_bin(monkeypatch, tmp_path):
    monkeypatch.delenv("SUBFINDER_PATH", raising=False)
    monkeypatch.setattr(sd.shutil, "which", lambda name: None)
    monkeypatch.setattr(sd.Path, "home", classmethod(lambda cls: tmp_path))
    (tmp_path / "go" / "bin").mkdir(parents=True)
    (tmp_path / "go" / "bin" / "subfinder").write_text("")
    assert REAL_FIND_SUBFINDER() == str(tmp_path / "go" / "bin" / "subfinder")


def test_find_subfinder_returns_none_when_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("SUBFINDER_PATH", raising=False)
    monkeypatch.setattr(sd.shutil, "which", lambda name: None)
    monkeypatch.setattr(sd.Path, "home", classmethod(lambda cls: tmp_path))
    assert REAL_FIND_SUBFINDER() is None


# ----------------------------------------------------- running Subfinder -----
def fake_run(stdout="", returncode=0, stderr=""):
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    run.calls = calls
    return run


def test_subfinder_command_is_safe_and_correct(monkeypatch):
    run = fake_run("a.example.com\nb.example.com\n")
    monkeypatch.setattr(sd.subprocess, "run", run)
    lines = sd._run_subfinder("example.com", "/usr/bin/subfinder", 5)
    cmd, kwargs = run.calls[0]
    assert isinstance(cmd, list) and cmd[0] == "/usr/bin/subfinder"      # a list, not a string
    assert cmd[cmd.index("-d") + 1] == "example.com"
    assert "-all" in cmd and "-silent" in cmd
    assert cmd[cmd.index("-max-time") + 1] == "5"
    assert not kwargs.get("shell")                                       # never use a shell
    assert lines == ["a.example.com", "b.example.com"]


def test_subfinder_nonzero_exit_still_uses_output(monkeypatch):
    monkeypatch.setattr(sd.subprocess, "run", fake_run("a.example.com\n", returncode=1, stderr="some source failed"))
    assert sd._run_subfinder("example.com", "x", 1) == ["a.example.com"]


def test_subfinder_timeout_keeps_partial_output(monkeypatch):
    def run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1, output=b"a.example.com\nb.example.com\n")
    monkeypatch.setattr(sd.subprocess, "run", run)
    assert sd._run_subfinder("example.com", "x", 1) == ["a.example.com", "b.example.com"]


def test_subfinder_cannot_start(monkeypatch):
    def run(cmd, **kwargs):
        raise PermissionError("not allowed")
    monkeypatch.setattr(sd.subprocess, "run", run)
    assert sd._run_subfinder("example.com", "x", 1) is None


# ----------------------------------------------------- combining sources -----
def test_uses_subfinder_and_skips_crtsh_when_subfinder_works(monkeypatch):
    monkeypatch.setattr(sd, "_find_subfinder", lambda: "/usr/bin/subfinder")
    monkeypatch.setattr(sd, "_run_subfinder", lambda d, e, m: ["www.example.com", "API.example.com", "*.cdn.example.com"])
    monkeypatch.setattr(sd, "_fetch_certificates", lambda *a: pytest.fail("crt.sh should not be called"))
    assert sd.find_subdomains("example.com") == ["api.example.com", "cdn.example.com", "www.example.com"]


def test_falls_back_to_crtsh_when_subfinder_missing(monkeypatch, caplog):
    monkeypatch.setattr(sd, "_fetch_certificates", lambda *a: FAKE_RECORDS)
    with caplog.at_level(logging.WARNING):
        assert sd.find_subdomains("example.com") == CRT_EXPECTED
    assert "Subfinder is not installed" in caplog.text


def test_falls_back_to_crtsh_when_subfinder_finds_nothing(monkeypatch):
    monkeypatch.setattr(sd, "_find_subfinder", lambda: "/usr/bin/subfinder")
    monkeypatch.setattr(sd, "_run_subfinder", lambda d, e, m: [])
    monkeypatch.setattr(sd, "_fetch_certificates", lambda *a: FAKE_RECORDS)
    assert sd.find_subdomains("example.com") == CRT_EXPECTED


def test_by_source_shows_each_source(monkeypatch):
    monkeypatch.setattr(sd, "_find_subfinder", lambda: "/usr/bin/subfinder")
    monkeypatch.setattr(sd, "_run_subfinder", lambda d, e, m: ["a.example.com"])
    result = sd.find_subdomains_by_source("example.com")
    assert result == {"subfinder": ["a.example.com"], "crtsh": []}


def test_everything_fails_returns_empty_list(monkeypatch):
    monkeypatch.setattr(sd, "_fetch_certificates", lambda *a: None)
    assert sd.find_subdomains("example.com") == []


# ----------------------------------------------------- crt.sh fallback -------
class FakeResponse:
    def __init__(self, status=200, text="[]", payload=None):
        self.status_code, self.text, self._payload = status, text, payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def test_crtsh_end_to_end(monkeypatch):
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: FakeResponse(text="x", payload=FAKE_RECORDS))
    assert sd.find_subdomains("https://Example.com/") == CRT_EXPECTED


def test_crtsh_timeout_does_not_crash_and_retries(monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise requests.Timeout("too slow")

    monkeypatch.setattr(sd.requests, "get", boom)
    assert sd.find_subdomains("example.com") == []
    assert len(calls) == 3


def test_crtsh_server_error_then_success(monkeypatch):
    answers = iter([FakeResponse(status=502), FakeResponse(text="x", payload=[{"name_value": "www.example.com"}])])
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: next(answers))
    assert sd.find_subdomains("example.com") == ["www.example.com"]


def test_crtsh_bad_json_returns_empty_list(monkeypatch):
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: FakeResponse(text="<html>oops</html>", payload=None))
    assert sd.find_subdomains("example.com") == []


def test_crtsh_empty_answer_means_no_subdomains(monkeypatch):
    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: FakeResponse(text="   "))
    assert sd.find_subdomains("example.com") == []
