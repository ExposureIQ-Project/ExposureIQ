
import unittest
from unittest.mock import patch, MagicMock

from exposureiq.discovery.ports import scan_ports


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class ScanPortsTests(unittest.TestCase):

    @patch("exposureiq.discovery.ports.subprocess.run")
    def test_open_ports_sorted_and_closed_excluded(self, run):
        run.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_XML,
            stderr="",
        )

        result = scan_ports("127.0.0.1")

        self.assertEqual(result, [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 443, "protocol": "tcp", "service": "https"},
        ])

        args, kwargs = run.call_args
        self.assertEqual(kwargs["timeout"], 120)
        self.assertIn("-sT", args[0])
        self.assertIn("--top-ports", args[0])
        self.assertNotIn("-A", args[0])
        self.assertNotIn("-T5", args[0])
        self.assertNotIn("--script", args[0])

    @patch("exposureiq.discovery.ports.subprocess.run")
    def test_host_down_returns_empty_list(self, run):
        run.return_value = MagicMock(
            returncode=0,
            stdout=(
                '<nmaprun><host><status state="down"/>'
                '</host></nmaprun>'
            ),
            stderr="",
        )

        self.assertEqual(scan_ports("127.0.0.1"), [])

    @patch("exposureiq.discovery.ports.subprocess.run")
    def test_timeout_has_clear_error(self, run):
        import subprocess

        run.side_effect = subprocess.TimeoutExpired(
            cmd="nmap", timeout=120
        )

        with self.assertRaisesRegex(TimeoutError, "timed out"):
            scan_ports("127.0.0.1")

    @patch("exposureiq.discovery.ports.shutil.which", return_value=None)
    def test_missing_nmap(self, which):
        with self.assertRaisesRegex(RuntimeError, "Nmap"):
            scan_ports("127.0.0.1")

    @patch("exposureiq.discovery.ports.subprocess.run")
    def test_invalid_xml(self, run):
        run.return_value = MagicMock(
            returncode=0,
            stdout="<not-valid-xml",
            stderr="",
        )

        with self.assertRaisesRegex(RuntimeError, "XML"):
            scan_ports("127.0.0.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
