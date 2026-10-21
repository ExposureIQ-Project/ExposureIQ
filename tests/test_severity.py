"""Severity enrichment is pure and every result must fit the shared JSON contract."""

import copy
import socket

import pytest

from exposureiq.fingerprint.contract import CHECK_BY_GROUP, validate_finding
from exposureiq.fingerprint.severity import RULES, build_findings


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("severity enrichment must not use the network")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


@pytest.mark.parametrize("rule", sorted(RULES))
def test_every_rule_has_plain_metadata_and_produces_a_valid_finding(rule):
    metadata = RULES[rule]
    assert set(metadata) == {"severity", "title", "recommendation"}
    assert metadata["severity"] in {"low", "medium", "high"}
    assert metadata["title"].strip() and metadata["recommendation"].strip()
    (finding,) = build_findings([{"rule": rule, "detail": "Observed on example.com"}])
    validate_finding(finding)
    assert finding["check"] == CHECK_BY_GROUP[rule.split(".", 1)[0]]
    assert finding["id"] == "F-0001"
    assert finding["detail"] == "Observed on example.com"
    assert set(finding) == {"id", "rule", "check", "severity", "title", "detail", "recommendation"}


def test_preserves_optional_ip_and_port_and_does_not_mutate_input():
    raw = [{"rule": "ports.database_exposed", "detail": "MySQL is open", "ip": "203.0.113.10", "port": 3306}]
    before, rules_before = copy.deepcopy(raw), copy.deepcopy(RULES)
    (finding,) = build_findings(raw, start_id=12)
    assert finding["id"] == "F-0012"
    assert finding["ip"] == "203.0.113.10" and finding["port"] == 3306
    assert finding["severity"] == "high"
    validate_finding(finding)
    assert raw == before and RULES == rules_before


def test_ids_are_consecutive_and_allow_more_than_four_digits():
    raw = [{"rule": "headers.missing_csp", "detail": "No CSP"}] * 3
    findings = build_findings(raw, start_id=9999)
    assert [finding["id"] for finding in findings] == ["F-9999", "F-10000", "F-10001"]
    for finding in findings:
        validate_finding(finding)


def test_unknown_rules_are_skipped_with_warning_and_without_id_gaps(caplog):
    raw = [
        {"rule": "headers.future_check", "detail": "Unknown header check"},
        {"rule": "other.new_check", "detail": "Unknown group"},
        {"rule": "tech.server_version_disclosed", "detail": "nginx version is disclosed"},
    ]
    findings = build_findings(raw)
    assert len(findings) == 1 and findings[0]["id"] == "F-0001"
    assert "Unknown finding rule headers.future_check" in caplog.text
    assert "Unknown finding rule other.new_check" in caplog.text


@pytest.mark.parametrize("bad", [
    None, "text", 42, {}, {"rule": "headers.missing_csp", "detail": ""},
    {"rule": "ports.ftp_exposed", "detail": "FTP is open", "port": True},
    {"rule": "ports.ftp_exposed", "detail": "FTP is open", "ip": "bad ip"},
    {"rule": "headers.missing_csp", "detail": "No CSP", "severity": "high"},
])
def test_malformed_individual_findings_are_skipped(caplog, bad):
    findings = build_findings([bad, {"rule": "headers.missing_csp", "detail": "No CSP"}])
    assert len(findings) == 1 and findings[0]["id"] == "F-0001"
    assert "Invalid finding; skipping" in caplog.text


@pytest.mark.parametrize("bad", [None, "text", 42, {}])
def test_invalid_outer_input_raises_value_error(bad):
    with pytest.raises(ValueError, match="list"):
        build_findings(bad)


@pytest.mark.parametrize("bad", [0, -1, True, None, "1", 1.5])
def test_invalid_start_id_raises_value_error(bad):
    with pytest.raises(ValueError, match="start_id"):
        build_findings([], start_id=bad)


def test_empty_input_is_empty():
    assert build_findings([]) == []
