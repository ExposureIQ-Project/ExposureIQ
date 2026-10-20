"""Tests for storage.py: build_scan, save_scan and load_scan.

Run from the project root:   python -m pytest
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from exposureiq import storage

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "examples" / "scan-example.json"

ASSETS = [
    {
        "host": "api.example.com",
        "ips": [
            {
                "ip": "203.0.113.10",
                "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
            }
        ],
    },
    {"host": "dev.example.com", "ips": [{"ip": "2001:db8::2", "open_ports": []}]},
]


def make_scan():
    return storage.build_scan("example.com", copy.deepcopy(ASSETS))


class BuildScanTests(unittest.TestCase):
    def test_has_all_top_level_fields(self):
        scan = make_scan()
        self.assertEqual(
            set(scan), {"schema_version", "scan_id", "target", "started_at", "assets"}
        )
        self.assertEqual(scan["schema_version"], "0.2")
        self.assertEqual(scan["target"], "example.com")
        self.assertEqual(scan["assets"], ASSETS)

    def test_scan_id_matches_start_time_and_has_no_colons(self):
        scan = make_scan()
        self.assertNotIn(":", scan["scan_id"])
        self.assertEqual(scan["scan_id"], scan["started_at"].replace(":", "-"))
        self.assertTrue(scan["started_at"].endswith("Z"))

    def test_real_start_time_can_be_given(self):
        scan = storage.build_scan("example.com", [], started_at="2026-10-13T20:15:00Z")
        self.assertEqual(scan["started_at"], "2026-10-13T20:15:00Z")
        self.assertEqual(scan["scan_id"], "2026-10-13T20-15-00Z")

    def test_bad_start_time_is_rejected(self):
        with self.assertRaises(ValueError):
            storage.build_scan("example.com", [], started_at="  ")

    def test_target_and_assets_are_checked(self):
        for bad in ("", "   ", None, 5):
            with self.assertRaises(ValueError):
                storage.build_scan(bad, [])
        with self.assertRaises(ValueError):
            storage.build_scan("example.com", "not a list")

    def test_utc_now_is_public(self):
        self.assertTrue(storage.utc_now().endswith("Z"))


class SaveAndLoadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_save_then_load_gives_the_same_data(self):
        scan = make_scan()
        path = self.dir / "scan.json"
        storage.save_scan(scan, str(path))
        self.assertEqual(storage.load_scan(str(path)), scan)

    def test_missing_folders_are_created(self):
        path = self.dir / "results" / "deep" / "scan.json"
        storage.save_scan(make_scan(), str(path))
        self.assertTrue(path.is_file())

    def test_file_is_readable_utf8_json_with_final_newline(self):
        path = self.dir / "scan.json"
        scan = make_scan()
        scan["target"] = "bücher.example"
        storage.save_scan(scan, str(path))
        text = path.read_text(encoding="utf-8")
        self.assertIn("bücher.example", text)       # not escaped as \u00fc
        self.assertIn("\n  ", text)                 # indented
        self.assertTrue(text.endswith("\n"))

    def test_invalid_scan_is_not_written(self):
        path = self.dir / "scan.json"
        scan = make_scan()
        del scan["target"]
        with self.assertRaises(ValueError):
            storage.save_scan(scan, str(path))
        self.assertFalse(path.exists())

    def test_file_not_found_has_clear_message(self):
        with self.assertRaisesRegex(FileNotFoundError, "Scan file not found"):
            storage.load_scan(str(self.dir / "nope.json"))

    def test_broken_json_says_where(self):
        path = self.dir / "broken.json"
        path.write_text('{\n  "schema_version": "0.1",\n  "scan_id": \n}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, r"Broken JSON .* line \d+, column \d+"):
            storage.load_scan(str(path))

    def test_wrong_encoding_has_clear_message(self):
        path = self.dir / "latin1.json"
        path.write_bytes(b'{"target": "\xff\xfe"}')
        with self.assertRaisesRegex(ValueError, "Invalid UTF-8"):
            storage.load_scan(str(path))

    def test_json_that_is_not_an_object(self):
        path = self.dir / "list.json"
        path.write_text("[1, 2, 3]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "expected a JSON object"):
            storage.load_scan(str(path))


class ValidationTests(unittest.TestCase):
    def check_bad(self, change, message):
        scan = make_scan()
        change(scan)
        with self.assertRaisesRegex(ValueError, message):
            storage._validate_scan(scan)

    def test_missing_top_level_field(self):
        self.check_bad(lambda s: s.pop("assets"), "missing required fields: assets")

    def test_unsupported_schema_version(self):
        self.check_bad(lambda s: s.update(schema_version="9.9"), "Unsupported schema_version")

    def test_empty_strings_are_rejected(self):
        for field in ("scan_id", "target", "started_at"):
            self.check_bad(lambda s, f=field: s.update({f: " "}), "non-empty string")

    def test_assets_must_be_a_list(self):
        self.check_bad(lambda s: s.update(assets={}), "'assets' must be a list")

    def test_asset_needs_host_and_ips(self):
        self.check_bad(lambda s: s["assets"][0].pop("ips"), r"assets\[0\] is missing required field 'ips'")
        self.check_bad(lambda s: s["assets"][0].update(host=""), "host must be a non-empty string")

    def test_ip_entry_needs_open_ports(self):
        self.check_bad(lambda s: s["assets"][0]["ips"][0].pop("open_ports"), "missing required field 'open_ports'")

    def test_ip_must_be_a_real_ip(self):
        for bad in ("999.1.1.1", "not-an-ip", "1.2.3", "example.com"):
            self.check_bad(lambda s, b=bad: s["assets"][0]["ips"][0].update(ip=b), "not a valid IP address")

    def test_ipv6_is_accepted(self):
        storage._validate_scan(make_scan())      # the second asset uses an IPv6 address

    def test_port_numbers(self):
        for bad in (0, 65536, -1, "443", True, 1.5, None):
            self.check_bad(
                lambda s, b=bad: s["assets"][0]["ips"][0]["open_ports"][0].update(port=b),
                "port must be an integer between 1 and 65535",
            )

    def test_port_needs_protocol_and_service(self):
        self.check_bad(lambda s: s["assets"][0]["ips"][0]["open_ports"][0].pop("service"), "missing required field 'service'")
        self.check_bad(lambda s: s["assets"][0]["ips"][0]["open_ports"][0].update(protocol=""), "protocol must be a non-empty string")


TECHNOLOGIES = [
    {"name": "nginx", "version": "1.18.0", "source": "Server header"},
    {"name": "WordPress", "version": "", "source": "HTML generator tag"},   # empty version is allowed
]

FINDINGS = [
    {
        "id": "F-0001",
        "rule": "https.cert_expired",
        "check": "https",
        "severity": "high",
        "title": "Certificate has expired",
        "detail": "Certificate for api.example.com ended on 2026-09-01",
        "recommendation": "Renew the certificate and enable automatic renewal.",
    },
    {
        "id": "F-0002",
        "rule": "ports.ssh_exposed",
        "check": "risky_services",
        "severity": "low",
        "title": "SSH is open to the internet",
        "detail": "SSH (port 22) is open on 203.0.113.10",
        "recommendation": "Restrict SSH to trusted addresses.",
        "ip": "203.0.113.10",
        "port": 22,
    },
]


def make_scan_02():
    scan = make_scan()
    scan["assets"][0]["technologies"] = copy.deepcopy(TECHNOLOGIES)
    scan["assets"][0]["findings"] = copy.deepcopy(FINDINGS)
    return scan


class FormatZeroPointTwoTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def check_bad(self, change, message):
        scan = make_scan_02()
        change(scan)
        with self.assertRaisesRegex(ValueError, message):
            storage._validate_scan(scan)

    def test_supported_versions(self):
        self.assertEqual(storage.SUPPORTED_VERSIONS, {"0.1", "0.2"})

    def test_valid_02_with_findings_round_trips(self):
        scan = make_scan_02()
        path = self.dir / "scan.json"
        storage.save_scan(scan, str(path))
        loaded = storage.load_scan(str(path))
        self.assertEqual(loaded, scan)
        self.assertEqual(loaded["schema_version"], "0.2")
        self.assertEqual(len(loaded["assets"][0]["findings"]), 2)

    def test_valid_02_without_findings(self):
        scan = make_scan()                      # neither list on any asset
        self.assertEqual(scan["schema_version"], "0.2")
        storage._validate_scan(scan)
        scan["assets"][0]["technologies"] = []  # empty lists are fine too
        scan["assets"][0]["findings"] = []
        storage._validate_scan(scan)

    def test_old_01_file_still_loads(self):
        scan = make_scan()
        scan["schema_version"] = "0.1"
        path = self.dir / "old.json"
        path.write_text(json.dumps(scan), encoding="utf-8")
        self.assertEqual(storage.load_scan(str(path))["schema_version"], "0.1")
        storage.save_scan(scan, str(self.dir / "old-saved.json"))   # saving 0.1 also works

    def test_unknown_version_is_rejected(self):
        for bad in ("0.3", "1.0", None, ["0.2"]):
            self.check_bad(lambda s, b=bad: s.update(schema_version=b), "Unsupported schema_version")

    def test_bad_severity(self):
        for bad in ("critical", "HIGH", "", None, 3):
            self.check_bad(
                lambda s, b=bad: s["assets"][0]["findings"][1].update(severity=b),
                r"assets\[0\]\.findings\[1\]\.severity must be low, medium or high\.",
            )

    def test_missing_field_in_a_finding(self):
        for field in ("id", "rule", "check", "severity", "title", "detail", "recommendation"):
            self.check_bad(
                lambda s, f=field: s["assets"][0]["findings"][0].pop(f),
                rf"findings\[0\] is missing required field '{field}'",
            )

    def test_empty_or_wrong_type_text_in_a_finding(self):
        for field in ("id", "rule", "check", "title", "detail", "recommendation"):
            for bad in ("", "  ", None, 5):
                self.check_bad(
                    lambda s, f=field, b=bad: s["assets"][0]["findings"][0].update({f: b}),
                    rf"findings\[0\]\.{field} must be a non-empty string",
                )

    def test_bad_finding_ip(self):
        for bad in ("999.1.1.1", "not-an-ip", "", None, 5):
            self.check_bad(
                lambda s, b=bad: s["assets"][0]["findings"][1].update(ip=b),
                "findings.1..ip is not a valid IP address",
            )

    def test_bad_finding_port(self):
        for bad in (0, 65536, -1, "22", True, 1.5, None):
            self.check_bad(
                lambda s, b=bad: s["assets"][0]["findings"][1].update(port=b),
                "port must be an integer between 1 and 65535",
            )

    def test_ip_and_port_are_optional_in_a_finding(self):
        scan = make_scan_02()
        self.assertNotIn("ip", scan["assets"][0]["findings"][0])
        storage._validate_scan(scan)

    def test_findings_must_be_a_list_of_objects(self):
        self.check_bad(lambda s: s["assets"][0].update(findings={}), r"assets\[0\]\.findings must be a list")
        self.check_bad(lambda s: s["assets"][0].update(findings=["x"]), r"findings\[0\] must be an object")

    def test_bad_technology(self):
        self.check_bad(lambda s: s["assets"][0].update(technologies="nginx"), r"technologies must be a list")
        self.check_bad(lambda s: s["assets"][0].update(technologies=["nginx"]), r"technologies\[0\] must be an object")
        self.check_bad(lambda s: s["assets"][0]["technologies"][0].pop("source"), r"technologies\[0\] is missing required field 'source'")
        self.check_bad(lambda s: s["assets"][0]["technologies"][0].pop("version"), r"missing required field 'version'")
        for field in ("name", "source"):
            self.check_bad(lambda s, f=field: s["assets"][0]["technologies"][0].update({f: ""}), rf"technologies\[0\]\.{field} must be a non-empty string")
        for bad in (None, 1, ["1"]):
            self.check_bad(lambda s, b=bad: s["assets"][0]["technologies"][0].update(version=b), r"technologies\[0\]\.version must be a string")


class ExampleFileTests(unittest.TestCase):
    def test_example_file_is_valid(self):
        scan = storage.load_scan(str(EXAMPLE))
        self.assertEqual(scan["target"], "example.com")
        self.assertEqual(len(scan["assets"]), 2)
        self.assertEqual(scan["schema_version"], "0.2")
        self.assertEqual(len(scan["assets"][0]["technologies"]), 2)
        self.assertEqual(len(scan["assets"][0]["findings"]), 2)

    def test_example_survives_a_round_trip(self):
        scan = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "copy.json"
            storage.save_scan(scan, str(path))
            self.assertEqual(storage.load_scan(str(path)), scan)


if __name__ == "__main__":
    unittest.main()
