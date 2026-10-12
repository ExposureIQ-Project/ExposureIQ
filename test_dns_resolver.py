"""Tests for resolve_hosts. Run with:  python -m unittest tests.test_dns_resolver -v

They start a tiny fake DNS server on 127.0.0.1, so no internet is needed
and the results are always the same.
"""

import socket
import threading
import time
import unittest
from unittest import mock

import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

from exposureiq.discovery import dns_resolver

# name -> {record type: [answers]}
ZONE = {
    "api.test.": {"A": ["203.0.113.10", "198.51.100.7", "203.0.113.10"],
                  "AAAA": ["2001:db8::1"]},
    "v6only.test.": {"AAAA": ["2001:db8::2"]},
    "noaaaa.test.": {"A": ["192.0.2.5"]},
}
SLOW = "slow.test."  # the server never answers this one


class FakeDNS(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            query = dns.message.from_wire(data)
            question = query.question[0]
            name = question.name.to_text().lower()
            rtype = dns.rdatatype.to_text(question.rdtype)
            if name == SLOW:
                continue  # stay silent -> client must time out
            reply = dns.message.make_response(query)
            if name not in ZONE:
                reply.set_rcode(dns.rcode.NXDOMAIN)
            else:
                for ip in ZONE[name].get(rtype, []):
                    reply.answer.append(
                        dns.rrset.from_text(name, 60, "IN", rtype, ip))
            self.sock.sendto(reply.to_wire(), addr)


class ResolveHostsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FakeDNS()
        cls.server.start()

        def fake_resolver(timeout):
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = ["127.0.0.1"]
            r.port = cls.server.port
            r.timeout = timeout
            r.lifetime = timeout
            return r

        cls.patch = mock.patch.object(dns_resolver, "_make_resolver", fake_resolver)
        cls.patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.server.sock.close()

    def test_example_from_brief(self):
        result = dns_resolver.resolve_hosts(["noaaaa.test", "old.test"])
        self.assertEqual(result, [{"host": "noaaaa.test", "ips": ["192.0.2.5"]}])

    def test_ips_unique_and_sorted_ipv4_and_ipv6(self):
        result = dns_resolver.resolve_hosts(["api.test"])
        self.assertEqual(result[0]["ips"],
                         ["198.51.100.7", "2001:db8::1", "203.0.113.10"])

    def test_ipv6_only_host_is_kept(self):
        result = dns_resolver.resolve_hosts(["v6only.test"])
        self.assertEqual(result, [{"host": "v6only.test", "ips": ["2001:db8::2"]}])

    def test_nonexistent_dropped_without_crash(self):
        self.assertEqual(dns_resolver.resolve_hosts(["nope.test"]), [])

    def test_duplicates_and_messy_names(self):
        result = dns_resolver.resolve_hosts(
            ["api.test", "API.test", " api.test. ", "", "*.test", None])
        self.assertEqual([r["host"] for r in result], ["api.test"])

    def test_empty_list(self):
        self.assertEqual(dns_resolver.resolve_hosts([]), [])

    def test_timeout_works(self):
        start = time.monotonic()
        result = dns_resolver.resolve_hosts(["slow.test"], timeout=1)
        elapsed = time.monotonic() - start
        self.assertEqual(result, [])
        self.assertLess(elapsed, 4)  # 2 queries (A + AAAA) x 1 s, plus margin

    def test_slow_name_does_not_block_others(self):
        result = dns_resolver.resolve_hosts(["slow.test", "api.test"], timeout=1)
        self.assertEqual([r["host"] for r in result], ["api.test"])

    def test_25_names_keeps_order(self):
        names = ["noaaaa.test", "api.test"] + [f"dead{i}.test" for i in range(23)]
        result = dns_resolver.resolve_hosts(names)
        self.assertEqual([r["host"] for r in result], ["noaaaa.test", "api.test"])


if __name__ == "__main__":
    unittest.main()
