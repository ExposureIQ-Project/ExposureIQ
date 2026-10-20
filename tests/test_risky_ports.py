
import unittest

from exposureiq.fingerprint.risky_ports import check_risky_ports


class TestCheckRiskyPorts(unittest.TestCase):
    def test_database_port(self):
        result = check_risky_ports(
            [{"port": 3306, "protocol": "tcp", "service": "mysql"}],
            "203.0.113.10",
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "ports.database_exposed")
        self.assertEqual(result[0]["ip"], "203.0.113.10")
        self.assertIn("MySQL (port 3306)", result[0]["detail"])

    def test_remote_desktop_port(self):
        result = check_risky_ports(
            [{"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"}]
        )
        self.assertEqual(result[0]["rule"], "ports.remote_desktop_exposed")

    def test_telnet_port(self):
        result = check_risky_ports([{"port": 23, "protocol": "tcp", "service": "telnet"}])
        self.assertEqual(result[0]["rule"], "ports.telnet_exposed")

    def test_ftp_port(self):
        result = check_risky_ports([{"port": 21, "protocol": "tcp", "service": "ftp"}])
        self.assertEqual(result[0]["rule"], "ports.ftp_exposed")

    def test_smb_port(self):
        result = check_risky_ports([{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}])
        self.assertEqual(result[0]["rule"], "ports.smb_exposed")

    def test_ssh_port(self):
        result = check_risky_ports([{"port": 22, "protocol": "tcp", "service": "ssh"}])
        self.assertEqual(result[0]["rule"], "ports.ssh_exposed")

    def test_admin_interface_port(self):
        result = check_risky_ports([{"port": 5601, "protocol": "tcp", "service": "unknown"}])
        self.assertEqual(result[0]["rule"], "ports.admin_interface_exposed")

    def test_safe_ports_are_ignored(self):
        result = check_risky_ports([
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 443, "protocol": "tcp", "service": "https"},
        ])
        self.assertEqual(result, [])

    def test_matches_service_on_unexpected_port(self):
        result = check_risky_ports([{"port": 12345, "protocol": "tcp", "service": "redis"}])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "ports.database_exposed")
        self.assertEqual(result[0]["port"], 12345)

    def test_duplicate_ports_produce_one_finding(self):
        result = check_risky_ports([
            {"port": 3306, "protocol": "tcp", "service": "mysql"},
            {"port": 3306, "protocol": "tcp", "service": "mysql"},
        ], "192.0.2.1")
        self.assertEqual(len(result), 1)

    def test_udp_is_ignored(self):
        result = check_risky_ports([{"port": 3306, "protocol": "udp", "service": "mysql"}])
        self.assertEqual(result, [])

    def test_empty_or_invalid_data_does_not_crash(self):
        self.assertEqual(check_risky_ports([]), [])
        self.assertEqual(check_risky_ports(None), [])
        result = check_risky_ports([
            None,
            "invalid",
            {},
            {"port": "3306", "protocol": "tcp", "service": "mysql"},
        ])
        self.assertEqual(result, [])

    def test_ip_is_optional(self):
        result = check_risky_ports([{"port": 22, "protocol": "tcp", "service": "ssh"}])
        self.assertNotIn("ip", result[0])
        self.assertNotIn(" on ", result[0]["detail"])

    def test_risky_port_without_service_is_detected(self):
        result = check_risky_ports([
            {"port": 3306, "protocol": "tcp"}
        ])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "ports.database_exposed")
        self.assertIn("MySQL (port 3306)", result[0]["detail"])


if __name__ == "__main__":
    unittest.main()
