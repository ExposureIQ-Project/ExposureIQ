
import unittest

from exposureiq.fingerprint.risky_ports import check_risky_ports


def ips(open_ports, ip="203.0.113.10"):
    return [{"ip": ip, "open_ports": open_ports}]


class TestCheckRiskyPorts(unittest.TestCase):
    def test_database_port(self):
        result = check_risky_ports(ips(
            [{"port": 3306, "protocol": "tcp", "service": "mysql"}],
            "203.0.113.10",
        ))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "ports.database_exposed")
        self.assertEqual(result[0]["ip"], "203.0.113.10")
        self.assertIn("MySQL (port 3306)", result[0]["detail"])

    def test_remote_desktop_port(self):
        result = check_risky_ports(ips(
            [{"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"}]
        ))
        self.assertEqual(result[0]["rule"], "ports.remote_desktop_exposed")

    def test_telnet_port(self):
        result = check_risky_ports(ips([{"port": 23, "protocol": "tcp", "service": "telnet"}]))
        self.assertEqual(result[0]["rule"], "ports.telnet_exposed")

    def test_ftp_port(self):
        result = check_risky_ports(ips([{"port": 21, "protocol": "tcp", "service": "ftp"}]))
        self.assertEqual(result[0]["rule"], "ports.ftp_exposed")

    def test_smb_port(self):
        result = check_risky_ports(ips([{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}]))
        self.assertEqual(result[0]["rule"], "ports.smb_exposed")

    def test_ssh_port(self):
        result = check_risky_ports(ips([{"port": 22, "protocol": "tcp", "service": "ssh"}]))
        self.assertEqual(result[0]["rule"], "ports.ssh_exposed")

    def test_admin_interface_port(self):
        result = check_risky_ports(ips([{"port": 5601, "protocol": "tcp", "service": "unknown"}]))
        self.assertEqual(result[0]["rule"], "ports.admin_interface_exposed")

    def test_safe_ports_are_ignored(self):
        result = check_risky_ports(ips([
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 443, "protocol": "tcp", "service": "https"},
        ]))
        self.assertEqual(result, [])

    def test_matches_service_on_unexpected_port(self):
        result = check_risky_ports(ips([{"port": 12345, "protocol": "tcp", "service": "redis"}]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "ports.database_exposed")
        self.assertEqual(result[0]["port"], 12345)

    def test_duplicate_ports_produce_one_finding(self):
        result = check_risky_ports(ips([
            {"port": 3306, "protocol": "tcp", "service": "mysql"},
            {"port": 3306, "protocol": "tcp", "service": "mysql"},
        ], "192.0.2.1"))
        self.assertEqual(len(result), 1)

    def test_udp_is_ignored(self):
        result = check_risky_ports(ips([{"port": 3306, "protocol": "udp", "service": "mysql"}]))
        self.assertEqual(result, [])

    def test_empty_or_invalid_data_does_not_crash(self):
        self.assertEqual(check_risky_ports([]), [])
        self.assertEqual(check_risky_ports(ips([])), [])
        result = check_risky_ports([
            None,
            "invalid",
            {},
            {"ip": "not an ip", "open_ports": []},
            {"ip": "203.0.113.10", "open_ports": None},
        ])
        self.assertEqual(result, [])
        result = check_risky_ports(ips([
            None,
            "invalid",
            {},
            {"port": "3306", "protocol": "tcp", "service": "mysql"},
            {"port": True, "protocol": "tcp", "service": "mysql"},
            {"port": 65536, "protocol": "tcp", "service": "mysql"},
        ]))
        self.assertEqual(result, [])

    def test_non_list_input_raises_value_error(self):
        for bad in (None, "text", 42, {}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check_risky_ports(bad)

    def test_each_finding_has_its_own_ip(self):
        ports = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
        result = check_risky_ports(ips(ports, "192.0.2.1") + ips(ports, "198.51.100.1"))
        self.assertEqual([finding["ip"] for finding in result], ["192.0.2.1", "198.51.100.1"])
        self.assertEqual(result[0]["detail"], "SSH (port 22) is open on 192.0.2.1")
        self.assertEqual(result[1]["detail"], "SSH (port 22) is open on 198.51.100.1")

    def test_duplicate_ip_entries_produce_one_finding(self):
        entry = ips([{"port": 3306, "protocol": "tcp", "service": "mysql"}])
        self.assertEqual(len(check_risky_ports(entry * 2)), 1)

    def test_ipv6_address_is_kept(self):
        result = check_risky_ports(ips([{"port": 22, "protocol": "tcp", "service": "ssh"}], "2001:db8::1"))
        self.assertEqual(result[0]["ip"], "2001:db8::1")

    def test_input_is_not_changed(self):
        import copy

        data = ips([{"port": 3306, "protocol": "tcp", "service": "mysql"}])
        before = copy.deepcopy(data)
        check_risky_ports(data)
        self.assertEqual(data, before)

    def test_risky_port_without_service_is_detected(self):
        result = check_risky_ports(ips([
            {"port": 3306, "protocol": "tcp"}
        ]))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "ports.database_exposed")
        self.assertIn("MySQL (port 3306)", result[0]["detail"])


if __name__ == "__main__":
    unittest.main()
