"""Six read-only tools over validated saved data. No commands, writes or probes.

Arguments are existing IDs/names, never paths. Every disk entry is confined to
the explicitly selected results root and symlink/traversal checked before use.
Every result is bounded to 6,000 JSON characters (estimated 1,500 tokens).
"""

from __future__ import annotations

import copy
import json
import re

from exposureiq import storage
from exposureiq.ai.sanitize import compact_json, host_name, label
from exposureiq.diffing.pipeline import history_group, scan_key, scan_order
from exposureiq.history import confined_scan_path, domain_history
from exposureiq.insight.digest import rule_title, scan_digest
from exposureiq.insight.history_digest import finding_lists, pair_digest
from exposureiq.insight.risk import risk_score

MAX_TOOL_CALLS = 4
MAX_TOOL_CHARS = 6000
FINDING_ID = re.compile(r"^F-\d{4,}$")
SCAN_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$")


class ToolError(ValueError):
    pass


def _definition(name, properties, required=()):
    return {"type": "function", "function": {"name": name,
            "description": "Read normalized saved findings only. No scanning, commands or file writes.",
            "parameters": {"type": "object", "properties": properties, "required": list(required),
                           "additionalProperties": False}}}


TOOL_DEFINITIONS = [
    _definition("get_finding", {"id": {"type": "string"}}, ("id",)),
    _definition("list_findings", {"severity": {"type": "string", "enum": ["high", "medium", "low"]},
                                  "rule": {"type": "string"}, "host": {"type": "string"}}),
    _definition("get_host", {"host": {"type": "string"}}, ("host",)),
    _definition("get_diff", {"scan_a": {"type": "string"}, "scan_b": {"type": "string"}}, ("scan_a", "scan_b")),
    _definition("get_history", {}), _definition("list_unfixed", {}),
]
ARGUMENTS = {"get_finding": ({"id"}, {"id"}), "list_findings": ({"severity", "rule", "host"}, set()),
             "get_host": ({"host"}, {"host"}), "get_diff": ({"scan_a", "scan_b"}, {"scan_a", "scan_b"}),
             "get_history": (set(), set()), "list_unfixed": (set(), set())}


def cap_result(value) -> dict:
    result = {"data": value, "truncated": False, "note": ""}
    if len(compact_json(result)) <= MAX_TOOL_CHARS:
        return result
    if not isinstance(value, list):
        # All non-list tool projections are already small scan/diff digests.
        return {"data": [], "truncated": True, "note": "Tool result truncated: requested object exceeded the safe result budget."}
    kept = []
    for item in value:
        candidate = {"data": [*kept, item], "truncated": True,
                     "note": "Tool result truncated; not every matching item is included."}
        if len(compact_json(candidate)) > MAX_TOOL_CHARS:
            break
        kept.append(item)
    return {"data": kept, "truncated": True,
            "note": "Tool result truncated; not every matching item is included."}


def normalize_finding(host: str, finding: dict) -> dict:
    return {"type": "finding", "ref": finding["id"], "id": finding["id"],
            "host": host_name(host), "rule": label(finding["rule"], 80),
            "severity": finding["severity"], "title": rule_title(finding["rule"]), "hosts": 1}


class ReadOnlyTools:
    def __init__(self, scan: dict, results_dir="results", *, scans: list[dict] | None = None,
                  entries: list[dict] | None = None):
        try:
            storage._validate_scan(scan)
            for item in scans or []:
                storage._validate_scan(item)
                if (host_name(item["target"]) != host_name(scan["target"])
                        or history_group(item) != history_group(scan)):
                    raise ValueError
            for entry in entries or []:
                confined_scan_path(entry["path"], results_dir)
        except (ValueError, KeyError, TypeError):
            raise ToolError("Read-only tools require validated scans from the selected domain and history group.") from None
        self.scan, self.results_dir = copy.deepcopy(scan), results_dir
        self.findings = [normalize_finding(a["host"], f) for a in self.scan["assets"] for f in a.get("findings", [])]
        self.hosts = {}
        for asset in self.scan["assets"]:
            self.hosts.setdefault(host_name(asset["host"]), []).append(asset)
        self.rules = {f["rule"] for f in self.findings}
        self.entries = entries if entries is not None else []
        unique = {scan_key(s): copy.deepcopy(s) for s in (scans or [])}
        unique[scan_key(self.scan)] = self.scan
        self.scans = sorted(unique.values(), key=scan_order)
        grouped_ids = {}
        for item in self.scans:
            grouped_ids.setdefault(str(item["scan_id"]), []).append(item)
        # A duplicate saved ID with different dates is ambiguous, not a path.
        self.scan_map = {identifier: items[0] for identifier, items in grouped_ids.items() if len(items) == 1}
        self.evidence = []
        self.calls = []

    @classmethod
    def from_scan(cls, scan: dict, results_dir="results", *, domain=False, include_demo=False):
        from exposureiq.diffing.pipeline import history_group, scan_history

        entries = domain_history(scan["target"], results_dir, include_demo=include_demo)
        entries = [e for e in entries if history_group(e["scan"]) == history_group(scan)]
        for entry in entries:
            confined_scan_path(entry["path"], results_dir)
        all_scans = [e["scan"] for e in entries]
        scans = all_scans if domain else scan_history(scan, all_scans)
        return cls(scan, results_dir, scans=scans or [scan], entries=entries)

    def _validate(self, name: str, arguments: dict):
        if name not in ARGUMENTS or not isinstance(arguments, dict):
            raise ToolError("Unknown read-only tool or invalid arguments.")
        allowed, required = ARGUMENTS[name]
        if set(arguments) - allowed or required - set(arguments):
            raise ToolError("Tool arguments do not match its allowed fields.")
        for key, value in arguments.items():
            if not isinstance(value, str) or not value or len(value) > 253 or ".." in value or "/" in value or "\\" in value or "\x00" in value:
                raise ToolError("Use existing IDs and names, never file paths or commands.")
            if key == "id" and (not FINDING_ID.fullmatch(value) or len(value) > 24):
                raise ToolError("Use a finding ID from this scan.")
            if key == "id" and sum(f["id"] == value for f in self.findings) != 1:
                raise ToolError("Finding ID is missing or ambiguous in this scan.")
            if key == "host" and value not in self.hosts:
                raise ToolError("That host is not in this scan.")
            if key == "severity" and value not in ("high", "medium", "low"):
                raise ToolError("Severity must be high, medium or low.")
            if key == "rule" and value not in self.rules:
                raise ToolError("That rule is not in this scan.")
            if key in ("scan_a", "scan_b") and (not SCAN_ID.fullmatch(value) or value not in self.scan_map):
                raise ToolError("Use a scan ID from the selected domain history.")

    def execute(self, name: str, arguments: dict) -> dict:
        self._validate(name, arguments)
        if len(self.calls) >= MAX_TOOL_CALLS:
            raise ToolError("At most four read-only tool calls are allowed per answer.")
        self.calls.append({"name": name, "arguments": copy.deepcopy(arguments)})
        if name == "get_finding":
            matches = [f for f in self.findings if f["id"] == arguments["id"]]
            if len(matches) != 1:
                raise ToolError("Finding ID is missing or ambiguous in this scan.")
            value = matches[0]
        elif name == "list_findings":
            value = [f for f in self.findings if all(f[k] == v for k, v in arguments.items())]
        elif name == "get_host":
            assets = self.hosts[arguments["host"]]
            risk = risk_score({"assets": assets})["by_host"][0]
            value = {"type": "host", **risk, "digest": scan_digest({**self.scan, "assets": assets})}
        elif name == "get_diff":
            value = pair_digest(self.scan_map[arguments["scan_a"]], self.scan_map[arguments["scan_b"]], 1)
            suffix = arguments["scan_a"] + ":" + arguments["scan_b"]
            value["ref"], value["type"] = "D:" + suffix, "diff"
            for index, event in enumerate(value["events"], 1):
                event["ref"] = f"E:{suffix}:{index}"
        elif name == "get_history":
            value = [{"type": "timeline", "ref": f"C:{index}", "scan_id": label(s["scan_id"], 160),
                       "date": s["started_at"][:25], **{k: risk_score(s)[k]
                        for k in ("per_host", "high", "medium", "low", "hosts")}} for index, s in enumerate(self.scans, 1)]
        else:
            value = [{"type": "unfixed", **item} for item in finding_lists(self.scans)["still_unfixed"]]
        result = cap_result(value)
        self.evidence.extend(result["data"] if isinstance(result["data"], list) else [result["data"]])
        return result

    def augmented_digest(self, digest: dict) -> dict:
        result = copy.deepcopy(digest)
        result["tool_evidence"] = copy.deepcopy(self.evidence)
        return result


def parse_tool_call(call: dict) -> tuple[str, str, dict]:
    try:
        identifier = call["id"]
        function = call["function"]
        name, raw = function["name"], function["arguments"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", identifier):
            raise ValueError
        if not isinstance(name, str) or name not in ARGUMENTS or not isinstance(raw, str) or len(raw) > 2000:
            raise ValueError
        arguments = json.loads(raw)
        if not isinstance(arguments, dict):
            raise ValueError
        return identifier, name, arguments
    except (KeyError, TypeError, ValueError, RecursionError):
        raise ToolError("Invalid read-only tool request; no action was taken.") from None
