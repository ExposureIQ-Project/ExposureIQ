"""Transport errors are readable by default; raw details require --verbose."""

import logging
from io import StringIO

import pytest
from rich.console import Console

from exposureiq import output


@pytest.mark.parametrize("detail, reason", [
    ("NewConnectionError([Errno 101] Network is unreachable)", "network unreachable"),
    ("NewConnectionError([Errno 111] Connection refused)", "connection refused"),
    ("NewConnectionError([Errno 113] No route to host)", "host unreachable"),
    ("ReadTimeout: request timed out", "request timed out"),
    ("NameResolutionError: name or service not known", "DNS lookup failed"),
    ("ConnectionError: failed", "connection failed"),
])
def test_network_warning_is_short_with_host_and_raw_only_when_verbose(detail, reason):
    raw = f"Request to https://example.com/ failed: {detail}"
    assert output.readable_message(raw) == f"example.com: front-page request failed ({reason})"
    assert output.readable_message(raw, verbose=True) == raw


def test_tls_message_is_not_mislabeled_as_a_front_page_failure():
    raw = "Could not connect to api.example.com:443 ([Errno 101] Network is unreachable)."
    assert output.readable_message(raw) == "api.example.com: certificate check failed (network unreachable)"


def test_ordinary_warning_is_not_replaced():
    raw = "example.com is not in scope; no checks sent"
    assert output.readable_message(raw) == raw
    assert output.readable_message("Nmap was not found; continuing without ports.") == "Nmap was not found; continuing without ports."


@pytest.mark.parametrize("verbose", [False, True])
def test_plain_logging_does_not_mutate_raw_record(verbose):
    stream = StringIO()
    handler = output.ReadableLogHandler(verbose=verbose, console=Console(file=stream, width=160, color_system=None),
                                       show_time=False, show_path=False)
    raw = "Request to https://example.com/ failed: NewConnectionError([Errno 101] Network is unreachable)"
    record = logging.LogRecord("fake", logging.WARNING, "fake.py", 1, "%s", (raw,), None)
    handler.emit(record)
    assert record.getMessage() == raw
    if verbose:
        assert "NewConnectionError" in stream.getvalue()
    else:
        assert "front-page request failed (network unreachable)" in stream.getvalue()
        assert "NewConnectionError" not in stream.getvalue()
