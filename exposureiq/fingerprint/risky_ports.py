
"""Identify potentially risky services in previously scanned open ports."""

import ipaddress
from collections.abc import Mapping
from typing import Any


# Each rule maps to its risky TCP ports, service aliases, and display name.
_RISKY_RULES = (
    {
        "rule": "ports.database_exposed",
        "ports": {1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017},
        "services": {
            "mysql": "MySQL",
            "postgresql": "PostgreSQL",
            "ms-sql-s": "Microsoft SQL Server",
            "oracle": "Oracle Database",
            "mongodb": "MongoDB",
            "redis": "Redis",
            "elasticsearch": "Elasticsearch",
            "memcached": "Memcached",
            "couchdb": "CouchDB",
        },
    },
    {
        "rule": "ports.remote_desktop_exposed",
        "ports": {3389, 5900, 5901, 5902},
        "services": {
            "ms-wbt-server": "Remote Desktop (RDP)",
            "rdp": "Remote Desktop (RDP)",
            "vnc": "VNC",
        },
    },
    {
        "rule": "ports.telnet_exposed",
        "ports": {23},
        "services": {"telnet": "Telnet"},
    },
    {
        "rule": "ports.ftp_exposed",
        "ports": {21},
        "services": {"ftp": "FTP"},
    },
    {
        "rule": "ports.smb_exposed",
        "ports": {139, 445},
        "services": {
            "microsoft-ds": "SMB",
            "netbios-ssn": "SMB",
            "smb": "SMB",
        },
    },
    {
        "rule": "ports.ssh_exposed",
        "ports": {22},
        "services": {"ssh": "SSH"},
    },
    {
        "rule": "ports.admin_interface_exposed",
        "ports": {2082, 2083, 2086, 2087, 5601, 8161, 8834, 9090, 10000, 15672},
        "services": {},
    },
)


def check_risky_ports(ips: list[dict]) -> list[dict]:
    """Read [{ip, open_ports}] and return raw findings, each with its IP address.

    Invalid outer input raises ValueError; malformed saved entries are ignored.
    This check uses only previously collected data and never opens a connection.
    """
    if not isinstance(ips, list):
        raise ValueError("ips must be a list")

    findings, seen = [], set()
    for entry in ips:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("ip"), str):
            continue
        ip = entry["ip"].strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        for finding in _check_open_ports(entry.get("open_ports"), ip):
            identity = (finding["rule"], ip, finding["port"])
            if identity not in seen:
                seen.add(identity)
                findings.append(finding)
    return findings


def _check_open_ports(open_ports: list[dict], ip: str) -> list[dict]:
    """Return findings for risky TCP ports in previously scanned data."""
    if not isinstance(open_ports, list):
        return []

    findings = []
    seen = set()

    for entry in open_ports:
        if not isinstance(entry, Mapping):
            continue

        port = entry.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            continue

        protocol = entry.get("protocol")
        if not isinstance(protocol, str) or protocol.lower() != "tcp":
            continue

        service = entry.get("service")
        service = service.strip().lower() if isinstance(service, str) else ""

        # Find a matching rule by port first, then by service name.
        matched_rule = None
        display_name = None

        for rule in _RISKY_RULES:
            if port in rule["ports"]:
                matched_rule = rule
                display_name = next(
                    (
                        name
                        for name in rule["services"].values()
                        if name
                    ),
                    None,
                )
                break

        # For known port matches, choose a useful display name.
        if matched_rule is not None:
            if service:
                for rule in _RISKY_RULES:
                    if service in rule["services"]:
                        display_name = rule["services"][service]
                        break
            if not display_name:
                display_name = _friendly_name(service, matched_rule, port)
        else:
            for rule in _RISKY_RULES:
                if service in rule["services"]:
                    matched_rule = rule
                    display_name = rule["services"][service]
                    break

        if matched_rule is None:
            continue

        finding_ip = ip if isinstance(ip, str) else ""
        identity = (finding_ip, port)
        if identity in seen:
            continue
        seen.add(identity)

        detail = f"{display_name} (port {port}) is open"
        finding = {
            "rule": matched_rule["rule"],
            "detail": f"{detail} on {finding_ip}" if finding_ip else detail,
            "port": port,
        }
        if finding_ip:
            finding["ip"] = finding_ip

        findings.append(finding)

    return findings


def _friendly_name(service: str, rule: dict[str, Any], port: int) -> str:
    """Choose a readable name when the scan service is missing or unfamiliar."""
    if service in rule["services"]:
        return rule["services"][service]

    names_by_port = {
        1433: "Microsoft SQL Server",
        1521: "Oracle Database",
        3306: "MySQL",
        5432: "PostgreSQL",
        5984: "CouchDB",
        6379: "Redis",
        9200: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
        3389: "Remote Desktop (RDP)",
        5900: "VNC",
        5901: "VNC",
        5902: "VNC",
        23: "Telnet",
        21: "FTP",
        139: "SMB",
        445: "SMB",
        22: "SSH",
    }
    return names_by_port.get(port, "Administrative interface")
