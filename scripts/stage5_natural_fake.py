"""Explicitly offline fresh-wording provider used only by evidence scripts.

This is not a real model and does not measure real-model accuracy. Report
summaries still use the strict approved fake; a few chat turns use new prose
so the evidence shows that the application no longer requires exact copies.
"""

from __future__ import annotations

import copy
import json

from exposureiq.ai.provider import FakeProvider, ProviderError, ProviderResponse
from exposureiq.ai.wording import RULE_HELP, RULE_IMPACT


class NaturalEvidenceProvider(FakeProvider):
    model = "Fresh wording (offline evidence fake)"
    offline = True

    def __init__(self):
        super().__init__()
        self.requests = []
        self.failure = ""

    def complete(self, messages, **kwargs):
        self.requests.append(copy.deepcopy(messages))
        if self.failure:
            self.calls += 1
            raise ProviderError("FAKE-RAW-ERROR-ONLY", kind=self.failure)
        response = super().complete(messages, **kwargs)
        if response.tool_calls:
            return response
        try:
            data = json.loads(messages[-1]["content"])
        except (ValueError, KeyError, TypeError):
            return response
        if not isinstance(data, dict):
            return response
        plan = data.get("answer_context", {})
        if data.get("reply_mode") != "conversation" or plan.get("list_requested"):
            return response
        kind, host = plan["kind"], plan.get("host", "")
        if kind not in ("overview", "host", "why", "impact", "opinion") or not plan["groups"]:
            return response
        primary = "H:" + host if host else "S:scan"
        headline = {
            "overview": "This saved scan points to things your team should tighten; it doesn't prove there was a break-in.",
            "host": "{host} deserves attention: its recorded exposure score is {host_risk}.",
            "why": "Reducing unnecessary public access on {host} closes a route to private services." if host else "I'd address the strongest recorded exposure first, then smaller protections. This order comes from saved observations, not a guessed chance of attack.",
            "impact": "If other access controls fail on {host}, these services could put information or normal work at risk." if host else "If other protections fail, the saved exposures could put private information or ordinary work at risk.",
            "opinion": "I'd make {host} a practical repair priority, with its owner reviewing the evidence before changing access." if host else "I'd turn this into a short repair plan with the service owners, rather than treat the scan as proof of an incident.",
        }[kind]
        notes = []
        for group in plan["groups"][:3]:
            refs = list(dict.fromkeys([group["ref"], *group["ids"][:1]]))
            meaning, _fix = RULE_HELP.get(group["rule"], ("Review this saved observation with its owner.", ""))
            if group["rule"] == "ports.database_exposed":
                meaning = "If access controls on the database are weak, someone could reach data that should stay private."
            if kind == "impact":
                meaning = {
                    "ports.database_exposed": "If access controls on the database are weak, someone could read, change or delete stored data.",
                    "ports.remote_desktop_exposed": "If a remote desktop account is compromised, someone could control the computer's desktop and disrupt normal work.",
                    "ports.telnet_exposed": "If someone can observe a Telnet connection, they could read login details or commands because the connection is not encrypted.",
                }.get(group["rule"], RULE_IMPACT.get(group["rule"], meaning))
            if plan["mode"] == "technical":
                meaning = "{rule}: " + meaning
            notes.append({"text": meaning, "refs": refs})
        if kind == "impact" and plan["mode"] == "simple":
            notes = [{"text": " ".join(note["text"] for note in notes),
                      "refs": list(dict.fromkeys(ref for note in notes for ref in note["refs"]))}]
        output = {"headline": {"text": headline, "refs": [primary]}, "priorities": [], "notes": notes,
                  "next_steps": [{"text": "Ask the service owner to review the recorded exposure and limit access that doesn't need to be public.",
                                  "refs": [plan["groups"][0]["ref"]]}]}
        return ProviderResponse(json.dumps(output))
