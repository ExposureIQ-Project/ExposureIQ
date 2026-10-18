"""HTTPS and certificate checks (Stage 2, Task 3).

Three functions:

- get_certificate_info(host, port, timeout): the ONLY function here that uses the network.
- analyze_certificate(info, now):            pure, turns a certificate info dict into raw findings.
- check_https(host, response):               joins the two and also detects "HTTP only" sites.

Safety rules (same as port scanning):
- fail closed: if is_in_scope() says no (or raises), we make no connection at all;
- at most 2 connections per host, only the TLS handshake, we never send any data;
- short timeout, the socket is always closed, and a network problem never crashes us.
"""

import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from exposureiq.discovery.scope import is_in_scope

log = logging.getLogger(__name__)

# A certificate with this many days (or fewer) left is "expiring soon".
EXPIRING_SOON_DAYS = 30


# ---------------------------------------------------------------- time helpers --
def _parse_time(text: str) -> datetime:
    # Turn an ISO time such as "2026-10-20T00:00:00Z" into an aware UTC datetime.
    # Python 3.10 cannot read the trailing Z, so we replace it with +00:00.
    moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _format_time(moment: datetime) -> str:
    # Turn a datetime into an ISO UTC string that ends in Z.
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# -------------------------------------------------------- certificate parsing --
def _first_attribute(name: x509.Name, oid) -> str:
    # Return the first value of one attribute (for example the common name), or "".
    attributes = name.get_attributes_for_oid(oid)
    return str(attributes[0].value) if attributes else ""


def _certificate_dates(cert: x509.Certificate) -> tuple:
    # Newer versions of cryptography give timezone-aware dates (not_valid_after_utc).
    # Older ones give naive UTC dates, so we fall back to those.
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    return (
        cert.not_valid_before.replace(tzinfo=timezone.utc),
        cert.not_valid_after.replace(tzinfo=timezone.utc),
    )


def _subject_alt_names(cert: x509.Certificate) -> list:
    # Return the DNS names (and IP addresses) from the Subject Alternative Name extension.
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names = list(extension.value.get_values_for_type(x509.DNSName))
    names += [str(address) for address in extension.value.get_values_for_type(x509.IPAddress)]
    return names


def _build_info(host: str, port: int, der: bytes, tls_version, verified: bool, verify_error) -> dict:
    # Read a DER certificate with cryptography and build the info dict.
    cert = x509.load_der_x509_certificate(der)
    not_before, not_after = _certificate_dates(cert)

    # Prefer the issuer's common name, then its organization name.
    issuer = _first_attribute(cert.issuer, NameOID.COMMON_NAME) or _first_attribute(
        cert.issuer, NameOID.ORGANIZATION_NAME
    )
    return {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "not_before": _format_time(not_before),
        "not_after": _format_time(not_after),
        "subject_cn": _first_attribute(cert.subject, NameOID.COMMON_NAME),
        "issuer": issuer,
        "san": _subject_alt_names(cert),
        "verified": verified,
        "verify_error": verify_error,
    }


# ------------------------------------------------------------------ the network --
def _handshake(host: str, port: int, timeout: float, context: ssl.SSLContext) -> tuple:
    # Open one connection, do the TLS handshake and return (der_certificate, tls_version).
    # We never send any data. The `with` blocks always close the socket.
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            return tls_socket.getpeercert(binary_form=True), tls_socket.version()


def get_certificate_info(host: str, port: int = 443, timeout: float = 5.0) -> dict | None:
    """The only network function. Returns the certificate info dict, or None if no TLS answer."""
    # Wrong input types are a programming error, not a network problem.
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535.")

    host = host.strip()

    # Fail closed: no scope check, a "no" answer or an error all mean "do nothing".
    try:
        allowed = is_in_scope(host)
    except Exception:
        log.warning("Scope check failed for %s, skipping the HTTPS check.", host)
        return None
    if not allowed:
        log.warning("%s is not in scope, skipping the HTTPS check.", host)
        return None

    # Handshake 1: the normal, strict context (checks chain, dates and host name).
    try:
        der, tls_version = _handshake(host, port, timeout, ssl.create_default_context())
        return _build_info(host, port, der, tls_version, True, None)
    except ssl.SSLCertVerificationError as error:
        # The server speaks TLS but its certificate is not acceptable. Remember why.
        verify_error = str(error)
    except ssl.SSLError as error:
        # Some other TLS problem (for example the port does not speak TLS).
        log.warning("No usable TLS answer from %s:%s (%s).", host, port, error)
        return None
    except (OSError, ValueError) as error:
        # Refused, timed out, name not found, and so on.
        log.warning("Could not connect to %s:%s (%s).", host, port, error)
        return None

    # Handshake 2: only to READ the bad certificate. CERT_NONE means "do not verify".
    # This is safe because we send nothing and only look at the certificate.
    relaxed = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    relaxed.check_hostname = False
    relaxed.verify_mode = ssl.CERT_NONE
    try:
        der, tls_version = _handshake(host, port, timeout, relaxed)
        return _build_info(host, port, der, tls_version, False, verify_error)
    except (OSError, ValueError) as error:
        # ValueError also covers a certificate that cryptography cannot parse.
        log.warning("Could not read the certificate of %s:%s (%s).", host, port, error)
        return None


# --------------------------------------------------------------------- the rules --
def _normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _name_matches(pattern: str, host: str) -> bool:
    # Does one certificate name cover the host?
    # "*.example.com" covers "a.example.com" only: not "a.b.example.com", not "example.com".
    pattern, host = _normalize(pattern), _normalize(host)
    if pattern.startswith("*."):
        suffix = pattern[1:]                    # ".example.com"
        label = host[: -len(suffix)]            # what the * would have to match
        return host.endswith(suffix) and bool(label) and "." not in label
    return pattern == host


def _covers_host(info: dict) -> bool:
    # Names that count: the SAN list, or the common name when there is no SAN.
    names = info.get("san") or ([info["subject_cn"]] if info.get("subject_cn") else [])
    host = info["host"]
    try:
        # An IP address is compared as an address ("::1" and "0:0:0:0:0:0:0:1" are the same).
        wanted = ipaddress.ip_address(_normalize(host))
    except ValueError:
        return any(_name_matches(name, host) for name in names)
    for name in names:
        try:
            if ipaddress.ip_address(_normalize(name)) == wanted:
                return True
        except ValueError:
            continue
    return False


def _is_self_signed(info: dict) -> bool:
    issuer = (info.get("issuer") or "").strip()
    if issuer and issuer.lower() == (info.get("subject_cn") or "").strip().lower():
        return True
    error = (info.get("verify_error") or "").lower()
    # OpenSSL writes both "self-signed" and "self signed" depending on its version.
    return "self-signed" in error or "self signed" in error


def analyze_certificate(info: dict, now: str | None = None) -> list[dict]:
    """Pure. now is an ISO time like "2026-10-20T00:00:00Z" (default: current UTC time).

    Returns raw findings: [{"rule": ..., "detail": ...}].
    Only the FIRST matching of expired / hostname mismatch / self-signed / untrusted is
    reported, so one problem is never reported twice. "Expiring soon" only applies to a
    certificate that has not expired yet.
    """
    if not isinstance(info, dict):
        raise ValueError("info must be a dict.")
    if not isinstance(info.get("host"), str) or not info["host"].strip():
        raise ValueError("info['host'] must be a non-empty string.")

    try:
        current = datetime.now(timezone.utc) if now is None else _parse_time(now)
    except (ValueError, AttributeError):
        raise ValueError(f"now must be an ISO time like 2026-10-20T00:00:00Z, got {now!r}.") from None

    host = info["host"]
    findings = []

    # Dates. If the end date is missing or unreadable we skip the date rules (we cannot tell).
    expired = False
    not_after = None
    try:
        not_after = _parse_time(info["not_after"])
    except (KeyError, ValueError, AttributeError):
        log.warning("Certificate of %s has no readable end date, skipping date checks.", host)
    if not_after is not None:
        end_day = not_after.date().isoformat()
        if not_after < current:
            expired = True
            findings.append({
                "rule": "https.cert_expired",
                "detail": f"Certificate for {host} ended on {end_day}",
            })
        elif not_after - current <= timedelta(days=EXPIRING_SOON_DAYS):
            days_left = (not_after - current).days
            findings.append({
                "rule": "https.cert_expiring_soon",
                "detail": f"Certificate for {host} ends in {days_left} days (on {end_day})",
            })

    # Name / trust: report only the first problem that matches (an expired certificate
    # already counts as the problem, so we do not also call it untrusted).
    if not expired:
        if not _covers_host(info):
            names = ", ".join(info.get("san") or [info.get("subject_cn") or "no name"])
            findings.append({
                "rule": "https.cert_hostname_mismatch",
                "detail": f"Certificate for {host} does not cover this name (it is valid for: {names})",
            })
        elif _is_self_signed(info):
            findings.append({
                "rule": "https.cert_self_signed",
                "detail": f"Certificate for {host} is self-signed (issuer: {info.get('issuer') or 'unknown'})",
            })
        elif info.get("verified") is False:
            reason = info.get("verify_error") or "unknown reason"
            findings.append({
                "rule": "https.cert_untrusted",
                "detail": f"Certificate for {host} is not trusted: {reason}",
            })

    return findings


# --------------------------------------------------------------------- the check --
def check_https(host: str, response: dict | None = None) -> list[dict]:
    """get_certificate_info + analyze_certificate.

    response is the web-response dict from fetch_front_page (or None).
    """
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string.")

    info = get_certificate_info(host.strip())

    if info is None:
        # No TLS answer. If the site still answers on plain HTTP, that is a finding.
        if isinstance(response, dict) and response.get("scheme") == "http":
            return [{
                "rule": "https.not_available",
                "detail": f"{host.strip()} answers on HTTP but not on HTTPS",
            }]
        # No TLS and no web response: we cannot tell, so no finding.
        return []

    return analyze_certificate(info)
