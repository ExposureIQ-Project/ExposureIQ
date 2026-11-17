import copy
import json

import pytest

from exposureiq import storage
from exposureiq.ai.checker import check_output
from exposureiq.ai.fallback import approved_claims, template_summary
from exposureiq.ai.sanitize import compact_json
from exposureiq.ai.tools import MAX_TOOL_CHARS, ReadOnlyTools, ToolError, cap_result, parse_tool_call
from exposureiq.insight.digest import scan_digest


@pytest.mark.parametrize("name,arguments,kind", [
    ("get_finding", {"id": "F-0001"}, "finding"),
    ("list_findings", {"severity": "high"}, "finding"),
    ("get_host", {"host": "db.example.com"}, "host"),
    ("get_diff", {"scan_a": "scan-0000", "scan_b": "scan-0001"}, "diff"),
    ("get_history", {}, "timeline"), ("list_unfixed", {}, "unfixed"),
])
def test_all_six_tools_are_bounded_and_supply_checked_evidence(name, arguments, kind, ai_scan_factory):
    scans = [ai_scan_factory(0), ai_scan_factory(1)]
    tools = ReadOnlyTools(scans[-1], scans=scans)
    result = tools.execute(name, arguments)
    assert len(compact_json(result)) <= MAX_TOOL_CHARS and not result["truncated"]
    data = result["data"][0] if isinstance(result["data"], list) else result["data"]
    assert data["type"] == kind
    assert tools.calls == [{"name": name, "arguments": arguments}]
    digest = tools.augmented_digest(scan_digest(scans[-1]))
    claims = approved_claims(digest)
    evidence_claim = next(c for c in reversed(claims) if c["refs"] == [data["ref"]])
    candidate = template_summary(digest)
    candidate["notes"].append(evidence_claim)
    assert check_output(candidate, digest).accepted


@pytest.mark.parametrize("name,arguments", [
    ("run_command", {"command": "anything"}), ("get_finding", {"id": "../../secret.json"}),
    ("get_finding", {"id": "F-9999"}), ("get_finding", {"id": "F-0001", "path": "one.json"}),
    ("get_finding", {}), ("get_finding", {"id": 1}), ("get_finding", {"id": "F-0001\u0000"}),
    ("get_host", {"host": "outside.example.com"}), ("get_host", {"host": "/etc/passwd"}),
    ("get_host", {"host": "db.example.com; command"}), ("get_host", {"host": "x" * 254}),
    ("get_history", {"path": "scan-0000"}), ("list_findings", {"severity": "critical"}),
    ("list_findings", {"rule": "unknown.rule"}), ("get_diff", {"scan_a": "scan-0000", "scan_b": "../other"}),
    ("get_diff", {"scan_a": "scan-0000", "scan_b": "other-scan"}),
])
def test_invalid_tool_arguments_fail_before_any_read(name, arguments, ai_scan_factory):
    tools = ReadOnlyTools(ai_scan_factory())
    with pytest.raises(ToolError):
        tools.execute(name, arguments)
    assert not tools.calls and not tools.evidence


def test_tools_stop_at_four_calls(ai_scan_factory):
    tools = ReadOnlyTools(ai_scan_factory())
    for _ in range(4):
        tools.execute("get_finding", {"id": "F-0001"})
    with pytest.raises(ToolError, match="four"):
        tools.execute("get_history", {})
    assert len(tools.calls) == 4


def test_truncation_is_explicit_and_omitted_evidence_is_not_available(ai_scan_factory):
    scan = ai_scan_factory()
    base = scan["assets"][0]["findings"][0]
    scan["assets"][0]["findings"] = [{**base, "id": f"F-{i:04d}"} for i in range(1, 501)]
    tools = ReadOnlyTools(scan)
    result = tools.execute("list_findings", {})
    assert result["truncated"] and "truncated" in result["note"]
    assert 0 < len(result["data"]) < 500 and len(compact_json(result)) <= MAX_TOOL_CHARS
    assert all(e["id"] != "F-0500" for e in tools.evidence)
    oversized = cap_result({"text": "x" * 7000})
    assert oversized["truncated"] and oversized["data"] == []


def test_constructor_rejects_cross_domain_group_and_symlinks(tmp_path, ai_scan_factory):
    scan = ai_scan_factory()
    other = ai_scan_factory(1)
    other["target"] = "other.example.com"
    with pytest.raises(ToolError):
        ReadOnlyTools(scan, scans=[other])
    other = ai_scan_factory(1)
    other["scan_id"] = "DEMO-ONE"
    with pytest.raises(ToolError):
        ReadOnlyTools(scan, scans=[other])
    outside = tmp_path / "outside.json"
    storage.save_scan(scan, str(outside))
    root = tmp_path / "results"
    root.mkdir()
    (root / "linked.json").symlink_to(outside)
    with pytest.raises(ToolError):
        ReadOnlyTools(scan, root, entries=[{"path": root / "linked.json"}])


def test_saved_history_is_confined_sorted_and_excludes_future_scans(tmp_path, ai_scan_factory):
    root = tmp_path / "results"
    for i in range(3):
        storage.save_scan(ai_scan_factory(i), str(root / "example.com" / f"scan-{i}.json"))
    tools = ReadOnlyTools.from_scan(ai_scan_factory(1), root)
    assert list(tools.scan_map) == ["scan-0000", "scan-0001"]
    assert len(ReadOnlyTools.from_scan(ai_scan_factory(1), root, domain=True).scans) == 3
    original = copy.deepcopy(tools.scan)
    tools.execute("get_finding", {"id": "F-0001"})["data"]["rule"] = "changed"
    assert tools.scan == original


def test_duplicate_finding_and_scan_ids_are_ambiguous(ai_scan_factory):
    scan = ai_scan_factory()
    scan["assets"].append(copy.deepcopy(scan["assets"][0]))
    tools = ReadOnlyTools(scan)
    with pytest.raises(ToolError, match="ambiguous"):
        tools.execute("get_finding", {"id": "F-0001"})
    assert tools.execute("get_host", {"host": "db.example.com"})["data"]["score"] == 36
    second = ai_scan_factory(1)
    second["scan_id"] = scan["scan_id"]
    tools = ReadOnlyTools(scan, scans=[second])
    assert not tools.scan_map


@pytest.mark.parametrize("call", [None, {}, {"id": "bad/id", "function": {}},
    {"id": "a", "function": {"name": "run_command", "arguments": "{}"}},
    {"id": "a", "function": {"name": "get_history", "arguments": "[]"}},
    {"id": "a", "function": {"name": "get_history", "arguments": "x" * 2001}},
])
def test_malformed_tool_requests_do_nothing(call):
    with pytest.raises(ToolError):
        parse_tool_call(call)


def test_valid_tool_request_parses_only_fixed_shape():
    assert parse_tool_call({"id": "one", "type": "function", "function":
                            {"name": "get_finding", "arguments": json.dumps({"id": "F-0001"})}}) == (
                                "one", "get_finding", {"id": "F-0001"})
