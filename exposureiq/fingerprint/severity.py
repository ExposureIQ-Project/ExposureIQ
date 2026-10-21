"""Add plain-English priorities and recommendations to raw Stage 2 findings.

High: direct exposure of sensitive services or loss of usable HTTPS.
Medium: weakened browser protections, certificate trust, or exposed administration.
Low: information disclosure and smaller hardening gaps; not proof of a vulnerability.
Unknown or malformed findings are warned about and skipped, not saved unchecked.
"""

import logging

from exposureiq.fingerprint.contract import CHECK_BY_GROUP, validate_finding, validate_raw_finding

logger = logging.getLogger(__name__)

RULES = {
    "headers.missing_hsts": {
        "severity": "medium", "title": "Missing HTTPS-only browser policy",
        "recommendation": "Add Strict-Transport-Security with max-age of at least 15552000 after confirming HTTPS works.",
    },
    "headers.weak_hsts": {
        "severity": "medium", "title": "Weak HTTPS-only browser policy",
        "recommendation": "Set Strict-Transport-Security max-age to at least 15552000 after confirming HTTPS works.",
    },
    "headers.missing_csp": {
        "severity": "medium", "title": "Missing content security policy",
        "recommendation": "Add a Content-Security-Policy that allows only the scripts and resources the site needs.",
    },
    "headers.weak_csp": {
        "severity": "medium", "title": "Weak content security policy",
        "recommendation": "Remove unsafe-inline, unsafe-eval, and broad script wildcards from Content-Security-Policy.",
    },
    "headers.missing_x_content_type_options": {
        "severity": "low", "title": "Missing content-type protection",
        "recommendation": "Send X-Content-Type-Options: nosniff so browsers respect the declared content type.",
    },
    "headers.missing_clickjacking_protection": {
        "severity": "medium", "title": "Missing frame protection",
        "recommendation": "Set CSP frame-ancestors or X-Frame-Options to prevent unwanted framing of the site.",
    },
    "headers.missing_referrer_policy": {
        "severity": "low", "title": "Missing referrer privacy policy",
        "recommendation": "Set Referrer-Policy to strict-origin-when-cross-origin or a stricter value appropriate for the site.",
    },
    "headers.missing_permissions_policy": {
        "severity": "low", "title": "Missing browser permissions policy",
        "recommendation": "Add a Permissions-Policy that disables browser features the site does not need.",
    },
    "tech.server_version_disclosed": {
        "severity": "low", "title": "Server version disclosed",
        "recommendation": "Hide the version in the Server header and keep the server software updated.",
    },
    "tech.powered_by_disclosed": {
        "severity": "low", "title": "Application version disclosed",
        "recommendation": "Remove or reduce the X-Powered-By header and keep the application platform updated.",
    },
    "tech.generator_version_disclosed": {
        "severity": "low", "title": "Site generator version disclosed",
        "recommendation": "Remove the generator version from HTML metadata and keep the site software updated.",
    },
    "https.not_available": {
        "severity": "high", "title": "HTTPS is unavailable",
        "recommendation": "Enable HTTPS with a trusted certificate and redirect plain HTTP to HTTPS.",
    },
    "https.cert_expired": {
        "severity": "high", "title": "HTTPS certificate expired",
        "recommendation": "Renew and deploy the HTTPS certificate, then enable automatic renewal monitoring.",
    },
    "https.cert_expiring_soon": {
        "severity": "low", "title": "HTTPS certificate expires soon",
        "recommendation": "Renew the HTTPS certificate before it expires and check that automatic renewal is working.",
    },
    "https.cert_hostname_mismatch": {
        "severity": "medium", "title": "Certificate covers a different host",
        "recommendation": "Deploy a certificate whose allowed names include this exact hostname.",
    },
    "https.cert_self_signed": {
        "severity": "medium", "title": "Self-signed HTTPS certificate",
        "recommendation": "Use a certificate from a trusted certificate authority for public-facing HTTPS.",
    },
    "https.cert_untrusted": {
        "severity": "medium", "title": "HTTPS certificate is untrusted",
        "recommendation": "Deploy a trusted certificate with the complete certificate chain and verify it from a clean client.",
    },
    "ports.database_exposed": {
        "severity": "high", "title": "Database service exposed",
        "recommendation": "Restrict the database port to approved application hosts on a private network.",
    },
    "ports.remote_desktop_exposed": {
        "severity": "high", "title": "Remote desktop service exposed",
        "recommendation": "Restrict remote desktop access to an approved private network or VPN with strong authentication.",
    },
    "ports.telnet_exposed": {
        "severity": "high", "title": "Telnet service exposed",
        "recommendation": "Disable Telnet and use SSH for encrypted remote administration.",
    },
    "ports.ftp_exposed": {
        "severity": "medium", "title": "FTP service exposed",
        "recommendation": "Replace plain FTP with an encrypted file-transfer service and restrict who can connect.",
    },
    "ports.smb_exposed": {
        "severity": "high", "title": "File-sharing service exposed",
        "recommendation": "Block public access to SMB ports and allow file sharing only on approved private networks.",
    },
    "ports.ssh_exposed": {
        "severity": "low", "title": "SSH service exposed",
        "recommendation": "Allow SSH only from approved administrators and use key-based authentication with password login disabled.",
    },
    "ports.admin_interface_exposed": {
        "severity": "medium", "title": "Administrative interface exposed",
        "recommendation": "Restrict administrative interfaces to approved networks and require strong authentication.",
    },
}


def build_findings(raw_findings: list, start_id: int = 1) -> list[dict]:
    """Return validated final findings with consecutive IDs, starting at F-0001.

    Invalid function arguments raise ValueError. An unknown rule or bad individual
    finding is logged and skipped; accepted findings consume IDs without gaps.
    """
    if not isinstance(raw_findings, list):
        raise ValueError("raw_findings must be a list")
    if isinstance(start_id, bool) or not isinstance(start_id, int) or start_id < 1:
        raise ValueError("start_id must be a positive integer")

    findings = []
    for raw in raw_findings:
        try:
            validate_raw_finding(raw)
            rule = raw["rule"]
            metadata = RULES.get(rule)
            if metadata is None:
                logger.warning("Unknown finding rule %s; skipping", rule)
                continue
            finding = {
                "id": f"F-{start_id + len(findings):04d}",
                "rule": rule,
                "check": CHECK_BY_GROUP[rule.split(".", 1)[0]],
                **metadata,
                "detail": raw["detail"],
            }
            for key in ("ip", "port"):
                if key in raw:
                    finding[key] = raw[key]
            validate_finding(finding)
        except (ValueError, KeyError, TypeError) as error:
            logger.warning("Invalid finding; skipping (%s)", error)
            continue
        findings.append(finding)
    return findings
