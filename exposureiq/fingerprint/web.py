"""Safe front-page fetch (Stage 2, Hassan).

The one web request that every Stage 2 check shares. It only sends a request
to hosts that is_in_scope() accepts, reads the front page once, and returns
the "web response" dict from the shared pages (or None).
"""

import logging
import warnings
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

from exposureiq.discovery.scope import is_in_scope

logger = logging.getLogger(__name__)

USER_AGENT = "ExposureIQ/0.1 (+https://github.com/ExposureIQ-Project/ExposureIQ)"
MAX_BODY_BYTES = 100 * 1024
MAX_REDIRECTS = 3
REDIRECT_CODES = {301, 302, 303, 307, 308}
DEFAULT_PORTS = {"http": 80, "https": 443}
NETWORK_ERRORS = (RequestException, OSError, UnicodeError)


def _allowed(host: str) -> bool:
    # Fail closed: if the scope check itself breaks, the answer is "no".
    try:
        return bool(is_in_scope(host))
    except Exception as exc:
        logger.warning("Scope check failed for %s (%s); not fetching", host, exc)
        return False


def _hostname(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _build_url(scheme: str, host: str, port: int) -> str:
    netloc = host if port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return f"{scheme}://{netloc}/"


def _read_body(response) -> str:
    # Read at most MAX_BODY_BYTES, then stop (the rest is never downloaded).
    data = bytearray()
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        data.extend(chunk)
        if len(data) >= MAX_BODY_BYTES:
            break
    raw = bytes(data[:MAX_BODY_BYTES])
    encoding = getattr(response, "encoding", None) or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:  # unknown charset name
        return raw.decode("utf-8", errors="replace")


def _get_once(url: str, timeout: float) -> dict:
    # One GET, no automatic redirects. Certificate problems are Marwan's
    # check, so HTTPS is not verified here and its warning is silenced
    # for this call only.
    is_https = url.startswith("https://")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            verify=not is_https,
            stream=True,
            allow_redirects=False,
        )
    try:
        return {
            "url": url,
            "scheme": urlparse(url).scheme,
            "status": int(response.status_code),
            "headers": {k.lower(): v for k, v in response.headers.items()},
            "body": _read_body(response),
        }
    finally:
        response.close()


def _fetch_chain(url: str, timeout: float) -> dict | None:
    # Follow at most MAX_REDIRECTS redirects ourselves, checking the scope
    # of every new host first. Returns the last response we got (or None).
    result = None
    for hop in range(MAX_REDIRECTS + 1):
        try:
            result = _get_once(url, timeout)
        except NETWORK_ERRORS as exc:
            logger.warning("Request to %s failed: %s", url, exc)
            return result

        location = result["headers"].get("location")
        if result["status"] not in REDIRECT_CODES or not location:
            return result
        if hop == MAX_REDIRECTS:
            logger.warning("Too many redirects from %s; stopping", url)
            return result

        next_url = urljoin(url, location)
        next_host = _hostname(next_url)
        if urlparse(next_url).scheme not in DEFAULT_PORTS or not next_host:
            logger.warning("Redirect to %s is not http(s); not followed", next_url)
            return result
        if not _allowed(next_host):
            logger.warning("Redirect to %s is out of scope; not followed", next_host)
            return result
        url = next_url
    return result


def fetch_front_page(host: str, timeout: float = 5.0,
                     https_port: int = 443, http_port: int = 80) -> dict | None:
    """Return the web-response dict, or None if not in scope / nothing answers."""
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string")
    host = host.strip()

    # Scope check first: no request of any kind happens before this.
    if not _allowed(host):
        logger.warning("%s is not in scope; no request sent", host)
        return None

    for scheme, port in (("https", https_port), ("http", http_port)):
        url = _build_url(scheme, host, port)
        # Guard against tricks like "in-scope.com@evil.com": the URL must
        # point at exactly the host that passed the scope check.
        if _hostname(url) != host.lower():
            logger.warning("%s is not a plain host name; no request sent", host)
            return None
        result = _fetch_chain(url, timeout)
        if result is not None:
            return {"host": host, **result}

    logger.warning("No web server answered for %s", host)
    return None
