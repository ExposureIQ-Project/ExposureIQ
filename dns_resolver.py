"""DNS resolution and clean-up (Stage 1, Hassan).

Takes a list of subdomain names and returns the IP addresses of each one.
Names that do not exist (or have no answer) are dropped.

    resolve_hosts(["api.example.com", "old.example.com"])
    # [{"host": "api.example.com", "ips": ["203.0.113.10"]}]

Quick test from the terminal:
    python dns_resolver.py example.com google.com github.com
"""

import sys

from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

# Seconds to wait for one DNS query before giving up on it.
DEFAULT_TIMEOUT = 4.0


def _make_resolver(timeout: float) -> dns.resolver.Resolver:
    # A resolver that can never wait longer than `timeout` seconds per query.
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _clean_hosts(hosts: list[str]) -> list[str]:
    # Normalise names (spaces, case, trailing dot), skip empty names and
    # wildcards like "*.example.com", and remove duplicates in order.
    cleaned = []
    for host in hosts:
        if not isinstance(host, str):
            continue
        name = host.strip().lower().rstrip(".")
        if not name or name.startswith("*"):
            continue
        cleaned.append(name)
    return list(dict.fromkeys(cleaned))


def _lookup(host: str, timeout: float) -> dict | None:
    # Ask DNS for the IPv4 (A) and IPv6 (AAAA) records of one host.
    # Returns None when the host has no answer, so it can be dropped.
    resolver = _make_resolver(timeout)
    ips = set()  # a set keeps the IPs unique

    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record_type)
        except dns.exception.DNSException:
            # Name does not exist, no such record, timeout... skip it.
            continue
        for record in answer:
            ips.add(record.address)

    if not ips:
        return None
    return {"host": host, "ips": sorted(ips)}


def resolve_hosts(
    hosts: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = 10,
) -> list[dict]:
    """Return [{"host": name, "ips": [unique sorted IPs]}] for each live host."""
    names = _clean_hosts(hosts)
    if not names:
        return []

    # Resolve several names at the same time; results keep the input order.
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = pool.map(lambda name: _lookup(name, timeout), names)

    # Drop hosts with no answer.
    return [result for result in results if result is not None]


if __name__ == "__main__":
    # Runs only when this file is executed directly, not when imported.
    # The names typed after the command are resolved and printed.
    names = sys.argv[1:]
    if not names:
        print("Usage: python dns_resolver.py name1 name2 ...")
        sys.exit(1)

    results = resolve_hosts(names)
    for item in results:
        print(item["host"])
        for ip in item["ips"]:
            print("   ", ip)
    print(f"\n{len(results)} of {len(_clean_hosts(names))} names resolved.")