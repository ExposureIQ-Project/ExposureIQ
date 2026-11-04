"""A repeatable ten-scan exposure story. Fake data only, never network traffic.

The story uses example.com and documentation-only IPs. Real check rules supply
severity and recommendations; the evidence is explicitly simulated, not proof
of a vulnerability, successful exploitation, or a real incident.
"""

from exposureiq import storage
from exposureiq.fingerprint.risky_ports import check_risky_ports
from exposureiq.fingerprint.severity import build_findings

DEMO_STORY = (
    "Baseline: public HTTPS sites with two routine hardening items",
    "A staging deployment adds an exposed administration page",
    "A firewall regression exposes databases, Telnet and file sharing",
    "Peak exposure: more databases and remote desktop access become public",
    "Containment starts: file sharing and some database access are blocked",
    "Remote access is restricted; the last public database still needs work",
    "Database access and certificates are fixed; browser policies remain",
    "Legacy systems are retired; one browser policy still needs hardening",
    "Temporary hosts are retired; only routine low-severity items remain",
    "Normal range: HTTPS-only inventory with one low-severity privacy item",
)

# (host, IP, first scan, last scan). Retired hosts stay absent for confirmation.
_HOSTS = (
    ("example.com", "192.0.2.10", 1, 10),
    ("www.example.com", "192.0.2.10", 1, 10),
    ("api.example.com", "192.0.2.20", 1, 10),
    ("blog.example.com", "192.0.2.30", 1, 10),
    ("staging.example.com", "198.51.100.20", 2, 8),
    ("legacy.example.com", "198.51.100.30", 3, 7),
    ("files.example.com", "198.51.100.40", 3, 8),
    ("admin.example.com", "203.0.113.20", 4, 6),
    ("db.example.com", "203.0.113.30", 4, 5),
)

# Extra public TCP services, with fixed opening and closing dates.
_PORTS = (
    ("api.example.com", 22, "ssh", 2, 7),
    ("api.example.com", 6379, "redis", 3, 5),
    ("api.example.com", 3306, "mysql", 4, 6),
    ("staging.example.com", 9090, "web-console", 2, 6),
    ("staging.example.com", 3306, "mysql", 3, 4),
    ("legacy.example.com", 80, "http", 3, 6),
    ("legacy.example.com", 23, "telnet", 3, 5),
    ("files.example.com", 21, "ftp", 3, 6),
    ("files.example.com", 445, "microsoft-ds", 3, 4),
    ("admin.example.com", 3389, "ms-wbt-server", 4, 4),
    ("admin.example.com", 5900, "vnc", 4, 5),
    ("admin.example.com", 10000, "webmin", 4, 6),
    ("db.example.com", 5432, "postgresql", 4, 5),
    ("db.example.com", 27017, "mongodb", 4, 5),
    ("db.example.com", 9200, "elasticsearch", 4, 5),
)

_WEB_FINDINGS = (
    ("example.com", "headers.missing_referrer_policy", 1, 10,
     "The sample front page omits Referrer-Policy, leaving a routine privacy hardening gap."),
    ("api.example.com", "tech.server_version_disclosed", 1, 9,
     "The sample Server header discloses nginx/{version}. A version hint alone does not prove exploitability."),
    ("api.example.com", "headers.missing_hsts", 3, 6,
     "A proxy configuration change drops Strict-Transport-Security from the sample HTTPS response."),
    ("blog.example.com", "headers.weak_csp", 4, 8,
     "The sample policy allows unsafe-inline and broad script sources. This weakens protection; no script injection was tested."),
    ("staging.example.com", "headers.missing_csp", 2, 7,
     "The staging front page has no Content-Security-Policy after a rushed deployment."),
    ("staging.example.com", "headers.missing_clickjacking_protection", 3, 6,
     "The sample response has neither frame-ancestors nor X-Frame-Options. Unwanted framing may be possible; no exploit was attempted."),
    ("legacy.example.com", "https.cert_expired", 3, 4,
     "The simulated legacy HTTPS certificate expired before scan 3 and has not yet been renewed."),
    ("legacy.example.com", "https.cert_self_signed", 5, 6,
     "An emergency self-signed certificate replaces the expired certificate; public trust still needs fixing."),
    ("admin.example.com", "https.cert_hostname_mismatch", 4, 5,
     "The simulated administration certificate covers staging.example.com, not admin.example.com."),
    ("files.example.com", "headers.missing_permissions_policy", 4, 7,
     "The sample file-transfer landing page does not restrict unused browser features."),
)

_SERVICE_RISKS = {
    "ports.database_exposed": "Unapproved clients could reach sensitive data if access controls are weak.",
    "ports.remote_desktop_exposed": "Public remote administration increases the risk of unauthorized access.",
    "ports.telnet_exposed": "Telnet does not encrypt credentials or administrative traffic.",
    "ports.ftp_exposed": "Plain FTP can disclose credentials and file contents in transit.",
    "ports.smb_exposed": "Public file sharing can expose sensitive files if permissions are weak.",
    "ports.admin_interface_exposed": "A public administration page increases exposure if authentication is weak.",
    "ports.ssh_exposed": "Restrict administration to approved networks and key-based access.",
}


def demo_assets(number: int, *, passive: bool = False, include_apex: bool = True) -> list[dict]:
    """Fresh assets for scan 1..10; every finding uses the existing rulebook."""
    if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 10:
        raise ValueError("demo scan number must be an integer from 1 to 10")
    version = "1.24.0" if number <= 6 else "1.26.2" if number <= 9 else ""
    assets, next_id = [], 1
    for host, address, first, last in _HOSTS:
        if not first <= number <= last or (host == "example.com" and not include_apex):
            continue
        ports = [] if passive or host == "db.example.com" else [
            {"port": 443, "protocol": "tcp", "service": "https"},
        ]
        if not passive:
            ports.extend({"port": port, "protocol": "tcp", "service": service}
                         for owner, port, service, start, end in _PORTS
                         if owner == host and start <= number <= end)
        ports.sort(key=lambda entry: entry["port"])
        asset = {"host": host, "ips": [{"ip": address, "open_ports": ports}],
                 "technologies": [], "findings": []}
        if not passive:
            if host != "db.example.com":
                product = "WordPress" if host == "blog.example.com" else "nginx"
                asset["technologies"] = [{"name": product,
                                          "version": version if host == "api.example.com" else "",
                                          "source": "DEMO front-page response"}]
            raw = [{"rule": rule, "detail": "DEMO: " + detail.format(version=version)}
                   for owner, rule, start, end, detail in _WEB_FINDINGS
                   if owner == host and start <= number <= end]
            for finding in check_risky_ports(asset["ips"]):
                risk = _SERVICE_RISKS.get(finding["rule"], "Review the service's public exposure.")
                raw.append({**finding, "detail": f"DEMO: {finding['detail']} {risk} "
                            "No authentication, data access or exploitation was attempted."})
            asset["findings"] = build_findings(raw, start_id=next_id)
            for finding in asset["findings"]:
                finding["title"] = "DEMO: " + finding["title"]
            next_id += len(asset["findings"])
        assets.append(asset)
    return assets


def build_demo_scans(*, passive: bool = False, include_apex: bool = True) -> list[dict]:
    """Ten deterministic, schema-valid snapshots; no randomness or clock reads."""
    scans = []
    for number in range(1, 11):
        scan = storage.build_scan("example.com", demo_assets(number, passive=passive,
                                                            include_apex=include_apex),
                                  started_at=f"2026-10-{number:02d}T10:00:00Z")
        scan["scan_id"] = f"DEMO-HISTORY-{number:02d}"
        scans.append(scan)
    return scans
