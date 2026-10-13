import unittest
from unittest.mock import patch

from exposureiq.discovery.scope import is_in_scope
from exposureiq.discovery.ports import scan_ports


class ScopeTests(unittest.TestCase):

    def test_localhost_is_allowed(self):
        self.assertTrue(is_in_scope("localhost"))
        self.assertTrue(is_in_scope("127.0.0.1"))

    def test_unlisted_targets_are_rejected(self):
        self.assertFalse(is_in_scope("192.0.2.1"))
        self.assertFalse(is_in_scope("example.com"))

    @patch("exposureiq.discovery.ports.subprocess.run")
    def test_out_of_scope_target_is_rejected_before_nmap(self, run):
        with self.assertRaisesRegex(ValueError, "not in the authorized scope"):
            scan_ports("192.0.2.1")

        run.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
