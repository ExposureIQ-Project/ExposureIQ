"""Fake data for demo mode:  exposureiq scan example.com --demo

Nothing here touches the network, so the whole flow can be shown and tested
anywhere. The fake IPs come from 192.0.2.0/24, a range reserved for
documentation that never belongs to a real machine.
"""

import ipaddress

_DOC_NETWORK = ipaddress.ip_network("192.0.2.0/24")


def find_subdomains(domain):
    """Return four fixed fake subdomains of `domain`."""
    return sorted(f"{name}.{domain}" for name in ("www", "api", "mail", "old"))


def resolve_hosts(hosts, **kwargs):
    """Return a fake IP per host. Hosts starting with 'dead' or 'old' are 'dead' and left out."""
    resolved = []
    for number, host in enumerate(hosts, start=1):
        if host.startswith(("dead", "old")):
            continue
        resolved.append({"host": host, "ips": [f"192.0.2.{number}"]})
    return resolved


def scan_ports(ip):
    """Return the same two fake open ports for every IP."""
    return [
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        {"port": 80, "protocol": "tcp", "service": "http"},
    ]


def is_in_scope(ip):
    """In demo mode only the documentation range counts as 'in scope'."""
    try:
        return ipaddress.ip_address(str(ip)) in _DOC_NETWORK
    except ValueError:
        return False
