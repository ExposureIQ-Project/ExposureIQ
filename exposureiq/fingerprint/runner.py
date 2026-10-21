"""Run opt-in Stage 2 checks sequentially, only after a successful scope check.

Assets are annotated in place with the existing schema 0.2 fields. A failed host
gets empty lists and a warning, never a claim that it is safe. No crawling or
port scanning happens here; risky-port rules read already collected port data.
"""

import logging
from threading import Lock

from exposureiq.discovery.scope import is_in_scope
from exposureiq.fingerprint import severity, web
from exposureiq.fingerprint.contract import validate_raw_finding
from exposureiq.fingerprint.headers import check_security_headers
from exposureiq.fingerprint.https_checks import check_https
from exposureiq.fingerprint.risky_ports import check_risky_ports
from exposureiq.fingerprint.technology import detect_technology, technology_findings
from exposureiq.fingerprint.web import fetch_front_page

logger = logging.getLogger(__name__)
_FETCH_LOCK = Lock()


def _front_page_only(host: str) -> dict | None:
    # The existing fetcher has a redirect limit but no per-call redirect option.
    # Disable redirects during its one fetch and always restore the setting,
    # even on failure. The lock also protects simultaneous runner calls from
    # restoring this shared setting while another host is still fetching.
    with _FETCH_LOCK:
        previous = web.MAX_REDIRECTS
        try:
            web.MAX_REDIRECTS = 0
            return fetch_front_page(host)
        finally:
            web.MAX_REDIRECTS = previous


def _unique_findings(raw_findings: list) -> list[dict]:
    """Keep each distinct piece of evidence once per host, preserving order."""
    findings, seen = [], set()
    for finding in raw_findings:
        try:
            validate_raw_finding(finding)
        except ValueError as error:
            logger.warning("Invalid check result; skipping (%s)", error)
            continue
        identity = (finding["rule"], finding["detail"], finding.get("ip"), finding.get("port"))
        if identity not in seen:
            seen.add(identity)
            findings.append(finding)
    return findings


def run_checks(assets: list) -> list:
    """Return the same assets with technologies and validated final findings added.

    Out-of-scope hosts and scope errors send nothing. All host errors are caught,
    so later hosts still run. Finding IDs continue across hosts within this scan.
    Bad outer input is warned about and returns an empty list, never raises.
    """
    if not isinstance(assets, list):
        logger.warning("Checks need a list of assets; nothing checked")
        return []

    next_id = 1
    for asset in assets:
        if not isinstance(asset, dict):
            logger.warning("Skipping an asset that is not a dict")
            continue
        asset["technologies"], asset["findings"] = [], []
        host = asset.get("host")
        try:
            if not isinstance(host, str) or not host.strip():
                raise ValueError("asset host must be a non-empty string")
            # Scope FIRST, before either HTTP or TLS (or even reading port data).
            # Only a real True is accepted: unexpected scope results fail closed.
            if is_in_scope(host) is not True:
                logger.warning("%s is not in scope; no checks sent", host)
                continue

            response = _front_page_only(host)
            technologies, raw = [], []
            if response is not None:
                raw.extend(check_security_headers(response))
                technologies = detect_technology(response)
                raw.extend(technology_findings(technologies))
            # A missing web response is not a missing-header finding. TLS may
            # still answer, and the saved port data can still be analyzed offline.
            raw.extend(check_https(host, response))
            raw.extend(check_risky_ports(asset.get("ips", [])))

            findings = severity.build_findings(_unique_findings(raw), start_id=next_id)
            asset["technologies"], asset["findings"] = technologies, findings
            next_id += len(findings)
        except Exception as error:
            logger.warning("Checks failed for %s (%s); skipping this host", host, error)
    return assets
