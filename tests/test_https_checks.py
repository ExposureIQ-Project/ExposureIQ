"""Tests for exposureiq/fingerprint/https_checks.py.

No real internet is used. The pure rules are tested with typed dicts and a fixed "now".
The network function is tested with fakes, and once against a tiny TLS server on 127.0.0.1.

Run from the project root:   python -m pytest tests/test_https_checks.py
"""

import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from exposureiq.fingerprint import https_checks as hc

NOW = "2026-10-20T00:00:00Z"        # fixed, so these tests never age


def good_info(**changes):
    # A fully valid certificate (72 days left). Tests change one thing at a time.
    info = {
        "host": "api.example.com",
        "port": 443,
        "tls_version": "TLSv1.3",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T23:59:59Z",
        "subject_cn": "api.example.com",
        "issuer": "Example CA",
        "san": ["api.example.com"],
        "verified": True,
        "verify_error": None,
    }
    info.update(changes)
    return info


def rules(findings):
    return [finding["rule"] for finding in findings]


# ------------------------------------------------------- analyze_certificate: rules --
def test_valid_certificate_gives_no_findings():
    assert hc.analyze_certificate(good_info(), NOW) == []


def test_findings_are_raw_findings_with_rule_and_detail():
    (finding,) = hc.analyze_certificate(good_info(not_after="2026-09-01T00:00:00Z"), NOW)
    assert set(finding) == {"rule", "detail"}
    assert finding["detail"] == "Certificate for api.example.com ended on 2026-09-01"


def test_expired():
    result = hc.analyze_certificate(good_info(not_after="2026-10-19T23:59:59Z"), NOW)
    assert rules(result) == ["https.cert_expired"]


def test_expiring_soon_and_the_30_day_border():
    assert rules(hc.analyze_certificate(good_info(not_after="2026-11-10T00:00:00Z"), NOW)) == [
        "https.cert_expiring_soon"
    ]
    # exactly 30 days left -> still "expiring soon"
    assert rules(hc.analyze_certificate(good_info(not_after="2026-11-19T00:00:00Z"), NOW)) == [
        "https.cert_expiring_soon"
    ]
    # 31 days left -> fine
    assert hc.analyze_certificate(good_info(not_after="2026-11-20T00:00:00Z"), NOW) == []


def test_expired_is_not_also_expiring_soon():
    result = hc.analyze_certificate(good_info(not_after="2026-10-01T00:00:00Z"), NOW)
    assert rules(result) == ["https.cert_expired"]


def test_hostname_mismatch():
    info = good_info(subject_cn="other.example.com", san=["other.example.com"],
                     verified=False, verify_error="Hostname mismatch")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_hostname_mismatch"]


def test_hostname_uses_common_name_when_there_is_no_san():
    assert hc.analyze_certificate(good_info(san=[]), NOW) == []
    info = good_info(san=[], subject_cn="other.example.com")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_hostname_mismatch"]


def test_shared_subject_key_covers_host_without_san():
    info = good_info(san=[])
    info["subject"] = info.pop("subject_cn")
    assert hc.analyze_certificate(info, NOW) == []
    info["subject"] = "other.example.com"
    result = hc.analyze_certificate(info, NOW)
    assert rules(result) == ["https.cert_hostname_mismatch"]
    assert "other.example.com" in result[0]["detail"]


def test_shared_subject_key_detects_self_signed_without_verify_error():
    info = good_info(issuer="api.example.com", verified=False, verify_error=None)
    info["subject"] = info.pop("subject_cn")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_self_signed"]


def test_subject_cn_takes_precedence_over_subject():
    info = good_info(san=[], subject="other.example.com")
    assert hc.analyze_certificate(info, NOW) == []


def test_san_wins_over_common_name():
    # The common name matches, but the SAN list does not, so the name is not covered.
    info = good_info(subject_cn="api.example.com", san=["www.example.com"])
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_hostname_mismatch"]


@pytest.mark.parametrize("host, names, covered", [
    ("a.example.com", ["*.example.com"], True),
    ("a.b.example.com", ["*.example.com"], False),   # a wildcard covers one label only
    ("example.com", ["*.example.com"], False),       # and not the bare domain
    ("example.com", ["*.example.com", "example.com"], True),
    ("A.Example.COM", ["*.example.com"], True),      # case does not matter
    ("a.example.com.", ["a.example.com"], True),     # trailing dot does not matter
    ("a.example.org", ["*.example.com"], False),
    ("evilexample.com", ["*.example.com"], False),   # the dot is part of the pattern
    ("a.example.com", ["a.*.com"], False),           # a wildcard is only valid as the first label
])
def test_wildcard_matching(host, names, covered):
    result = hc.analyze_certificate(good_info(host=host, san=names, subject_cn=names[0]), NOW)
    assert (rules(result) == []) is covered
    if not covered:
        assert rules(result) == ["https.cert_hostname_mismatch"]


def test_ip_address_host_matches_ip_san():
    info = good_info(host="203.0.113.10", san=["203.0.113.10"], subject_cn="")
    assert hc.analyze_certificate(info, NOW) == []
    info = good_info(host="203.0.113.10", san=["203.0.113.11"], subject_cn="")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_hostname_mismatch"]


def test_self_signed_when_issuer_equals_subject():
    info = good_info(issuer="api.example.com", verified=False, verify_error="something else")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_self_signed"]


@pytest.mark.parametrize("message", [
    "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate",
    "certificate verify failed: self signed certificate in certificate chain",
])
def test_self_signed_when_the_error_says_so(message):
    info = good_info(verified=False, verify_error=message)
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_self_signed"]


def test_untrusted_for_any_other_reason():
    info = good_info(verified=False, verify_error="unable to get local issuer certificate")
    result = hc.analyze_certificate(info, NOW)
    assert rules(result) == ["https.cert_untrusted"]
    assert "unable to get local issuer certificate" in result[0]["detail"]


def test_untrusted_without_an_error_text():
    assert rules(hc.analyze_certificate(good_info(verified=False), NOW)) == ["https.cert_untrusted"]


# --------------------------------------------------- analyze_certificate: no doubles --
def test_expired_and_untrusted_reports_only_expired():
    info = good_info(not_after="2026-09-01T00:00:00Z", verified=False,
                     verify_error="certificate has expired")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_expired"]


def test_expired_self_signed_reports_only_expired():
    info = good_info(not_after="2026-09-01T00:00:00Z", issuer="api.example.com",
                     verified=False, verify_error="self-signed certificate")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_expired"]


def test_hostname_mismatch_wins_over_self_signed_and_untrusted():
    info = good_info(san=["other.example.com"], subject_cn="other.example.com",
                     issuer="other.example.com", verified=False,
                     verify_error="self-signed certificate")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_hostname_mismatch"]


def test_self_signed_wins_over_untrusted():
    info = good_info(issuer="api.example.com", verified=False, verify_error="unable to get local issuer certificate")
    assert rules(hc.analyze_certificate(info, NOW)) == ["https.cert_self_signed"]


def test_every_rule_id_is_in_the_rule_list():
    allowed = {
        "https.not_available", "https.cert_expired", "https.cert_expiring_soon",
        "https.cert_hostname_mismatch", "https.cert_self_signed", "https.cert_untrusted",
        "https.old_tls_supported",
    }
    cases = [
        good_info(not_after="2026-09-01T00:00:00Z"),
        good_info(not_after="2026-11-01T00:00:00Z"),
        good_info(san=["x.example.com"], subject_cn="x.example.com"),
        good_info(issuer="api.example.com", verified=False),
        good_info(verified=False, verify_error="unable to get local issuer certificate"),
    ]
    for info in cases:
        assert set(rules(hc.analyze_certificate(info, NOW))) <= allowed


# ------------------------------------------------ analyze_certificate: odd input --
def test_default_now_is_the_current_time():
    assert hc.analyze_certificate(good_info(not_after="2000-01-01T00:00:00Z")) == [
        {"rule": "https.cert_expired", "detail": "Certificate for api.example.com ended on 2000-01-01"}
    ]


def test_time_without_z_and_with_offset_is_accepted():
    assert hc.analyze_certificate(good_info(), "2026-10-20T00:00:00+00:00") == []
    assert hc.analyze_certificate(good_info(), "2026-10-20T00:00:00") == []


def test_bad_input_raises_value_error():
    with pytest.raises(ValueError):
        hc.analyze_certificate("not a dict", NOW)
    with pytest.raises(ValueError):
        hc.analyze_certificate({"not_after": NOW}, NOW)           # no host
    with pytest.raises(ValueError):
        hc.analyze_certificate(good_info(), "yesterday")


def test_unreadable_end_date_skips_the_date_rules_and_does_not_crash():
    info = good_info(not_after="garbage")
    assert hc.analyze_certificate(info, NOW) == []
    del info["not_after"]
    assert hc.analyze_certificate(info, NOW) == []


def test_analyze_does_not_change_its_input():
    info = good_info(verified=False)
    before = dict(info)
    hc.analyze_certificate(info, NOW)
    assert info == before


# --------------------------------------------------------------------- check_https --
def fake_certificate(monkeypatch, result):
    calls = []

    def fake(host, *args, **kwargs):
        calls.append(host)
        return result

    monkeypatch.setattr(hc, "get_certificate_info", fake)
    return calls


def test_check_https_analyzes_the_certificate(monkeypatch):
    calls = fake_certificate(monkeypatch, good_info(not_after="2000-01-01T00:00:00Z"))
    assert rules(hc.check_https("api.example.com")) == ["https.cert_expired"]
    assert calls == ["api.example.com"]


def test_check_https_valid_certificate(monkeypatch):
    fake_certificate(monkeypatch, good_info(not_after="2999-01-01T00:00:00Z"))
    assert hc.check_https("api.example.com", {"scheme": "https"}) == []


def test_check_https_not_available(monkeypatch):
    fake_certificate(monkeypatch, None)
    result = hc.check_https("example.com", {"scheme": "http", "status": 200})
    assert result == [{"rule": "https.not_available",
                       "detail": "example.com answers on HTTP but not on HTTPS"}]


def test_check_https_no_tls_and_no_web_response_gives_nothing(monkeypatch):
    fake_certificate(monkeypatch, None)
    assert hc.check_https("example.com") == []
    assert hc.check_https("example.com", None) == []


def test_check_https_no_tls_but_https_response_gives_nothing(monkeypatch):
    fake_certificate(monkeypatch, None)
    assert hc.check_https("example.com", {"scheme": "https"}) == []


def test_check_https_rejects_a_bad_host():
    for bad in (None, 5, "", "  "):
        with pytest.raises(ValueError):
            hc.check_https(bad)


# ------------------------------------------------ get_certificate_info: safety --
@pytest.fixture
def no_connections(monkeypatch):
    # Any attempt to open a connection is recorded and refused.
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("a connection was attempted")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    return attempts


def test_out_of_scope_host_makes_zero_connections(monkeypatch, no_connections):
    monkeypatch.setattr(hc, "is_in_scope", lambda host: False)
    assert hc.get_certificate_info("example.com") is None
    assert no_connections == []


def test_scope_check_that_raises_fails_closed(monkeypatch, no_connections):
    def broken(host):
        raise RuntimeError("scope.txt is broken")

    monkeypatch.setattr(hc, "is_in_scope", broken)
    assert hc.get_certificate_info("example.com") is None
    assert no_connections == []


def test_check_https_out_of_scope_makes_zero_connections(monkeypatch, no_connections):
    monkeypatch.setattr(hc, "is_in_scope", lambda host: False)
    assert hc.check_https("example.com") == []
    assert no_connections == []


def test_get_certificate_info_rejects_bad_input():
    for bad in (None, 5, "", "  "):
        with pytest.raises(ValueError):
            hc.get_certificate_info(bad)
    for bad in (0, 65536, "443", True, None):
        with pytest.raises(ValueError):
            hc.get_certificate_info("example.com", port=bad)


def test_network_errors_return_none(monkeypatch):
    monkeypatch.setattr(hc, "is_in_scope", lambda host: True)
    for error in (ConnectionRefusedError("refused"), socket.timeout("timed out"),
                  socket.gaierror("no such host"), ssl.SSLError("not TLS")):
        def fail(*args, error=error, **kwargs):
            raise error

        monkeypatch.setattr(socket, "create_connection", fail)
        assert hc.get_certificate_info("example.com") is None


# ------------------------------------- get_certificate_info: local TLS server --
def make_self_signed(tmp_path, common_name="localhost", days=365):
    # Create a throw-away self-signed certificate for the local test server.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return cert_file, key_file


class TlsServer:
    # A tiny TLS server on 127.0.0.1. It only does the handshake and counts connections.
    def __init__(self, cert_file, key_file):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(cert_file), str(key_file))
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            try:
                client, _ = self.listener.accept()
            except OSError:
                continue
            self.connections += 1
            client.settimeout(2)
            try:
                with self.context.wrap_socket(client, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                client.close()      # the client refused our certificate: expected

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=2)
        self.listener.close()


def test_self_signed_server_is_read_with_the_second_handshake(tmp_path):
    cert_file, key_file = make_self_signed(tmp_path)
    with TlsServer(cert_file, key_file) as server:
        info = hc.get_certificate_info("localhost", port=server.port, timeout=3)
        connections = server.connections

    assert info is not None
    assert info["host"] == "localhost" and info["port"] == server.port
    assert info["verified"] is False
    assert info["verify_error"]
    assert info["subject_cn"] == "localhost" and info["issuer"] == "localhost"
    assert info["san"] == ["localhost"]
    assert info["tls_version"].startswith("TLSv1.")
    assert info["not_before"].endswith("Z") and info["not_after"].endswith("Z")
    assert connections <= 2                         # at most 2 connections per host
    assert rules(hc.analyze_certificate(info)) == ["https.cert_self_signed"]


def test_server_that_is_not_listening_returns_none():
    with socket.socket() as probe:                  # find a port nobody listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    assert hc.get_certificate_info("localhost", port=port, timeout=1) is None


def test_server_that_does_not_speak_tls_returns_none():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    listener.settimeout(3)
    port = listener.getsockname()[1]

    def answer_plain_text():
        try:
            client, _ = listener.accept()
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            client.close()
        except OSError:
            pass

    thread = threading.Thread(target=answer_plain_text, daemon=True)
    thread.start()
    try:
        assert hc.get_certificate_info("localhost", port=port, timeout=2) is None
    finally:
        thread.join(timeout=3)
        listener.close()
