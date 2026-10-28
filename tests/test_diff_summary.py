
"""Tests for readable scan-difference summaries."""

import copy

from exposureiq.diffing.summary import describe_change, summarize_diff


def change(kind, direction="neutral", **extra):
    result = {
        "kind": kind,
        "direction": direction,
        "host": "www.example.com",
        "ip": None,
        "port": None,
        "before": None,
        "after": None,
        "status": "confirmed",
    }
    result.update(extra)
    return result


def test_empty_diff_returns_expected_shape():
    result = summarize_diff({"changes": []})

    assert result == {
        "headline": "No changes since the previous scan",
        "counts": {"total": 0, "worse": 0, "better": 0, "neutral": 0},
        "by_kind": {},
        "highlights": [],
        "lines": [],
    }


def test_counts_and_headline():
    diff = {
        "changes": [
            change("finding.new", "worse"),
            change("port.opened", "worse", port=443),
            change("finding.resolved", "better"),
            change("tech.new"),
        ]
    }

    result = summarize_diff(diff)

    assert result["counts"] == {
        "total": 4,
        "worse": 2,
        "better": 1,
        "neutral": 1,
    }
    assert result["headline"] == (
        "2 things got worse, 1 got better, 1 other changes"
    )


def test_by_kind_counts_each_kind():
    result = summarize_diff({
        "changes": [
            change("port.opened", "worse"),
            change("port.opened", "neutral"),
            change("host.new"),
        ]
    })

    assert result["by_kind"] == {
        "host.new": 1,
        "port.opened": 2,
    }


def test_describe_missing_removal():
    item = change(
        "host.removed",
        host="old.example.com",
        status="missing",
        before={"host": "old.example.com"},
    )

    assert describe_change(item) == "old.example.com: not seen this time"


def test_describe_open_port_with_service_and_ip():
    item = change(
        "port.opened",
        host="db.example.com",
        ip="203.0.113.20",
        port=3306,
        after={"service": "mysql"},
    )

    assert describe_change(item) == (
        "db.example.com: port 3306 (mysql) is now open on 203.0.113.20"
    )


def test_describe_technology_version_change():
    item = change(
        "tech.version_changed",
        before={"technology": "nginx", "version": "1.18.0"},
        after={"technology": "nginx", "version": "1.24.0"},
    )

    assert describe_change(item) == (
        "www.example.com: nginx changed from 1.18.0 to 1.24.0"
    )


def test_describe_finding_includes_severity_when_available():
    item = change(
        "finding.new",
        after={"title": "Missing security header", "severity": "medium"},
    )

    assert describe_change(item) == (
        "www.example.com: new finding: Missing security header (medium)"
    )


def test_optional_values_do_not_create_empty_parentheses():
    item = change("port.opened", port=443)

    message = describe_change(item)

    assert "()" not in message
    assert "None" not in message


def test_lines_are_grouped_worse_better_neutral():
    diff = {
        "changes": [
            change("tech.new", "neutral", host="neutral.example.com"),
            change("finding.resolved", "better", host="better.example.com"),
            change("port.opened", "worse", host="worse.example.com", port=443),
        ]
    }

    lines = summarize_diff(diff)["lines"]

    assert lines[0].startswith("worse.example.com:")
    assert lines[1].startswith("better.example.com:")
    assert lines[2].startswith("neutral.example.com:")


def test_sorting_is_deterministic_by_kind_then_host_and_port():
    diff = {
        "changes": [
            change("port.opened", host="z.example.com", port=443),
            change("host.new", host="z.example.com"),
            change("port.opened", host="a.example.com", port=8080),
            change("port.opened", host="a.example.com", port=80),
        ]
    }

    lines = summarize_diff(diff)["lines"]

    assert lines[0].startswith("z.example.com: new host")
    assert lines[1].startswith("a.example.com: port 80")
    assert lines[2].startswith("a.example.com: port 8080")
    assert lines[3].startswith("z.example.com: port 443")


def test_highlights_prioritize_new_findings_and_open_ports():
    diff = {
        "changes": [
            change("tech.new", "worse", host="tech.example.com"),
            change(
                "finding.new",
                "worse",
                host="low.example.com",
                after={"title": "Low issue", "severity": "low"},
            ),
            change(
                "finding.new",
                "worse",
                host="high.example.com",
                after={"title": "High issue", "severity": "high"},
            ),
            change("port.opened", "worse", host="db.example.com", port=3306),
            change("finding.resolved", "better", host="good.example.com"),
        ]
    }

    highlights = summarize_diff(diff)["highlights"]

    assert len(highlights) <= 5
    assert "High issue" in highlights[0]
    assert "Low issue" in highlights[1]
    assert "port 3306" in highlights[2]


def test_at_most_five_highlights():
    diff = {
        "changes": [
            change("port.opened", "worse", host=f"h{i}.example.com", port=80)
            for i in range(8)
        ]
    }

    assert len(summarize_diff(diff)["highlights"]) == 5


def test_summary_does_not_mutate_input():
    diff = {
        "changes": [
            change(
                "tech.version_changed",
                before={"technology": "nginx", "version": "1.18.0"},
                after={"technology": "nginx", "version": "1.24.0"},
            )
        ],
        "notes": ["sample note"],
    }
    original = copy.deepcopy(diff)

    summarize_diff(diff)

    assert diff == original
