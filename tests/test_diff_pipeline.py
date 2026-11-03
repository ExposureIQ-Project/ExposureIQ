"""Tests for the diff pipeline, domain scan discovery, and CLI diff command."""

import json

import pytest

from exposureiq import cli, storage
from exposureiq.diffing import pipeline


def asset(host, ips=None, technologies=None, findings=None):
    return {
        "host": host,
        "ips": ips or [],
        "technologies": technologies or [],
        "findings": findings or [],
    }


def ip(address, ports=None):
    return {"ip": address, "open_ports": ports or []}


def port(number, service="https", protocol="tcp"):
    return {"port": number, "protocol": protocol, "service": service}


def finding(rule, severity="medium", title="Issue"):
    return {
        "id": "F-0001", "rule": rule, "check": "security_headers",
        "severity": severity, "title": title, "detail": "detail",
        "recommendation": "fix it",
    }


def scan(started, assets, target="example.com"):
    return storage.build_scan(target, assets, started_at=started)


def save(path, started, assets, target="example.com"):
    result = scan(started, assets, target)
    storage.save_scan(result, str(path))
    return result


def kinds(changes):
    return [change["kind"] for change in changes]


def test_build_diff_returns_changes_metadata_and_summary():
    old = scan("2026-10-01T00:00:00Z", [asset("old.example.com")])
    new = scan("2026-10-02T00:00:00Z", [asset("new.example.com")])

    diff = pipeline.build_diff(old, new, rules=[])

    assert diff["target"] == "example.com"
    assert diff["old"]["scan_id"] == old["scan_id"]
    assert diff["new"]["scan_id"] == new["scan_id"]
    assert kinds(diff["changes"]) == ["host.new", "host.removed"]
    assert diff["ignored"] == []
    assert diff["summary"]["counts"] == {
        "total": 2, "worse": 1, "better": 1, "neutral": 0,
    }
    assert diff["summary"]["headline"] == "1 thing got worse, 1 got better"


def test_build_diff_rejects_different_targets():
    old = scan("2026-10-01T00:00:00Z", [], target="example.com")
    new = scan("2026-10-02T00:00:00Z", [], target="other.com")
    with pytest.raises(ValueError, match="Targets differ"):
        pipeline.build_diff(old, new, rules=[])


def test_build_diff_rejects_invalid_scan_arguments():
    with pytest.raises(ValueError, match="dictionary"):
        pipeline.build_diff(None, {}, rules=[])
    with pytest.raises(ValueError, match="target"):
        pipeline.build_diff({"assets": []}, {"assets": []}, rules=[])


def test_removal_is_missing_without_a_third_scan():
    old = scan("2026-10-01T00:00:00Z", [asset("old.example.com")])
    new = scan("2026-10-02T00:00:00Z", [])
    diff = pipeline.build_diff(old, new, rules=[])

    (removal,) = diff["changes"]
    assert removal["status"] == "missing"
    assert any("not seen this time" in note for note in diff["notes"])


def test_removal_is_confirmed_when_missing_from_three_scans():
    before = scan("2026-09-30T00:00:00Z", [asset("old.example.com")])
    old = scan("2026-10-01T00:00:00Z", [])
    new = scan("2026-10-02T00:00:00Z", [])
    diff = pipeline.build_diff(old, new, before_old=before, rules=[])

    (removal,) = diff["changes"]
    assert removal["status"] == "confirmed"
    assert diff["notes"] == []


def test_removal_that_only_appeared_in_the_middle_scan_is_not_confirmed():
    before = scan("2026-09-30T00:00:00Z", [])
    old = scan("2026-10-01T00:00:00Z", [asset("old.example.com")])
    new = scan("2026-10-02T00:00:00Z", [])
    diff = pipeline.build_diff(old, new, before_old=before, rules=[])

    (removal,) = diff["changes"]
    assert removal["status"] == "missing"


def test_ignore_rules_split_changes_without_losing_them():
    old = scan("2026-10-01T00:00:00Z", [
        asset("www.example.com", [ip("203.0.113.1", [port(80, "http")])]),
    ])
    new = scan("2026-10-02T00:00:00Z", [
        asset("www.example.com", [ip("203.0.113.1", [port(443, "https")])]),
    ])
    rules = [{"kind": "port.*", "host": "www.example.com"}]

    diff = pipeline.build_diff(old, new, rules=rules)

    assert diff["changes"] == []
    assert kinds(diff["ignored"]) == ["port.opened", "port.closed"]
    assert any("hidden by ignore rules" in note for note in diff["notes"])


def test_diff_domain_uses_the_two_newest_scans_and_third_for_confirmation(tmp_path):
    save(tmp_path / "one.json", "2026-10-01T00:00:00Z", [asset("old.example.com")])
    save(tmp_path / "two.json", "2026-10-02T00:00:00Z", [asset("www.example.com")])
    save(tmp_path / "three.json", "2026-10-03T00:00:00Z", [asset("www.example.com")])
    save(tmp_path / "other.json", "2026-10-04T00:00:00Z", [asset("a.other.com")],
         target="other.com")

    diff = pipeline.diff_domain("https://Example.com/path", results_dir=tmp_path)

    assert diff["old"]["scan_id"] == "2026-10-02T00-00-00Z"
    assert diff["new"]["scan_id"] == "2026-10-03T00-00-00Z"
    assert kinds(diff["changes"]) == ["host.removed"]
    assert diff["changes"][0]["status"] == "confirmed"


def test_diff_domain_requires_two_scans(tmp_path):
    save(tmp_path / "one.json", "2026-10-01T00:00:00Z", [asset("www.example.com")])
    with pytest.raises(ValueError, match="at least two saved scans"):
        pipeline.diff_domain("example.com", results_dir=tmp_path)


def test_diff_domain_skips_unreadable_files(tmp_path):
    save(tmp_path / "one.json", "2026-10-01T00:00:00Z", [asset("www.example.com")])
    save(tmp_path / "two.json", "2026-10-02T00:00:00Z", [asset("www.example.com")])
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")

    diff = pipeline.diff_domain("example.com", results_dir=tmp_path)
    assert diff["summary"]["counts"]["total"] == 0


def test_cli_diff_compares_two_files_and_prints_json(tmp_path, capsys):
    old = save(tmp_path / "old.json", "2026-10-01T00:00:00Z", [asset("old.example.com")])
    new = save(tmp_path / "new.json", "2026-10-02T00:00:00Z", [asset("new.example.com")])

    code = cli.main(["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"), "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == "example.com"
    assert {item["kind"] for item in payload["changes"]} == {"host.removed", "host.new"}
    assert payload["old"]["scan_id"] == old["scan_id"]
    assert payload["new"]["scan_id"] == new["scan_id"]


def test_cli_diff_fail_on_worse(tmp_path, capsys):
    save(tmp_path / "old.json", "2026-10-01T00:00:00Z", [
        asset("www.example.com", [ip("203.0.113.1", [])]),
    ])
    save(tmp_path / "new.json", "2026-10-02T00:00:00Z", [
        asset("www.example.com", [ip("203.0.113.1", [port(22, "ssh")])]),
    ])

    code = cli.main([
        "diff", str(tmp_path / "old.json"), str(tmp_path / "new.json"),
        "--json", "--fail-on-worse",
    ])

    assert code == 1
    capsys.readouterr()


def test_cli_diff_rejects_two_non_file_arguments(tmp_path, capsys):
    code = cli.main(["diff", "example.com", "example.com"])
    assert code == 2
    assert "both must be saved scan files" in capsys.readouterr().out


def test_cli_diff_rejects_different_targets(tmp_path, capsys):
    save(tmp_path / "old.json", "2026-10-01T00:00:00Z", [], target="example.com")
    save(tmp_path / "new.json", "2026-10-02T00:00:00Z", [], target="other.com")
    code = cli.main(["diff", str(tmp_path / "old.json"), str(tmp_path / "new.json")])
    assert code == 2
    assert "Targets differ" in capsys.readouterr().out


def test_cli_diff_compares_a_domain_from_results(tmp_path, capsys):
    save(tmp_path / "one.json", "2026-10-01T00:00:00Z", [asset("old.example.com")])
    save(tmp_path / "two.json", "2026-10-02T00:00:00Z", [asset("www.example.com")])

    code = cli.main(["diff", "example.com", "--results-dir", str(tmp_path), "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == "example.com"
    assert [item["kind"] for item in payload["changes"]] == ["host.new", "host.removed"]


def test_cli_diff_domain_needs_two_scans(tmp_path, capsys):
    save(tmp_path / "one.json", "2026-10-01T00:00:00Z", [asset("www.example.com")])
    code = cli.main(["diff", "example.com", "--results-dir", str(tmp_path)])
    assert code == 2
    assert "at least two saved scans" in capsys.readouterr().out
