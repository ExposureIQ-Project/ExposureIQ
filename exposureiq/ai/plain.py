"""Bounded inline-reference parsing and literal-fact binding; no model calls.

This does not prove the meaning of arbitrary prose. It binds only exact cited
hosts/rules and typed numbers to code-owned values before the usual checker.
"""

from __future__ import annotations

import re
import unicodedata

from exposureiq.ai.context import SMALL_NUMBERS
from exposureiq.ai.schema import MAX_OUTPUT_CHARS, SchemaError, parse_output

TAGS = re.compile(r"(?:\[[^\]\n]{1,320}\]\s*)+")
TAG_VALUE = re.compile(r"\[([^\]\n]{1,320})\]")
NUMBERS = re.compile(r"(?<![\w{])(?:\d+(?:,\d{3})*(?:\.\d+)?|"
                     r"zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
                     r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|"
                     r"thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million)(?![\w}])", re.I)


def parse_tagged_output(raw: str) -> dict:
    if not isinstance(raw, str) or not raw.strip():
        raise SchemaError("The model returned no reply text.")
    if len(raw) > MAX_OUTPUT_CHARS:
        raise SchemaError("AI output exceeded the size limit.")
    raw = unicodedata.normalize("NFKC", raw).strip()
    claims, start = [], 0
    for match in TAGS.finditer(raw):
        body = raw[start:match.start()].strip()
        body = re.sub(r"^(?:[-*]\s+|\d+[.)]\s+)", "", body)
        # Accept either "Sentence. [ref]" or "Sentence [ref].".
        end = match.end()
        if end < len(raw) and raw[end] in ".!?":
            body += raw[end]
            end += 1
        if not body:
            raise SchemaError("An inline reference had no sentence to check.")
        refs = list(dict.fromkeys(TAG_VALUE.findall(match.group())))
        claims.append({"text": body, "refs": refs})
        start = end
    if not claims or raw[start:].strip():
        raise SchemaError("Each sentence needs an existing inline evidence tag.")
    return parse_output({"headline": claims[0], "notes": claims[1:], "priorities": [], "next_steps": []})


def bind_literals(sentence: str, refs: list[str], pack: dict) -> tuple[str, list[str], int]:
    """Replace only exact, typed cited facts with their checked placeholders."""
    values_by_ref = pack["references"]
    if any(ref not in values_by_ref for ref in refs):
        raise SchemaError("unknown reference or reference outside the selected facts pack")
    refs = list(refs)
    # A literal named host must bind to its own cited record, not a scan total.
    for ref in refs:
        host = values_by_ref[ref].get("host", "")
        if host and re.search(r"(?<![\w.-])" + re.escape(host) + r"(?![\w.-])", sentence, re.I):
            refs = [ref, *[other for other in refs if other != ref]]
            break
    values = values_by_ref[refs[0]]
    for field in ("host", "rule"):
        value = values.get(field)
        if isinstance(value, str) and value:
            sentence = re.sub(r"(?<![\w.-])" + re.escape(value) + r"(?![\w.-])", "{" + field + "}", sentence, flags=re.I)
    checked_numbers = 0

    def number(match):
        nonlocal checked_numbers
        token = match.group().lower()
        if token in SMALL_NUMBERS:
            numeric = SMALL_NUMBERS.index(token)
        else:
            try:
                numeric = float(token.replace(",", ""))
            except ValueError:
                raise SchemaError("invented or unsupported spelled-out number") from None
        before = sentence[max(0, match.start() - 70):match.start()].lower()
        after = sentence[match.end():match.end() + 55].lower()
        fields = []
        if refs[0] == "S:history":
            if re.match(r"\s+changes?\s+(?:reduced|improved)\b", after):
                fields = ["better_count"]
            elif re.match(r"\s+(?:changes?\s+)?(?:increased|worsened)\b", after):
                fields = ["worse_count"]
            elif re.match(r"\s+findings?\s+(?:stayed|remain)\w*\s+present\b", after):
                fields = ["unfixed_count"]
        elif re.match(r"\s+(?:affected\s+)?(?:hosts?|servers?|sites?|pages?)\b", after):
            fields = ["hosts_affected", "host_count"]
        elif re.match(r"\s+(?:(?:urgent|high|important|medium|minor|low)(?:-severity)?\s+)?(?:findings?|issues?|problems?)\b", after):
            level = re.match(r"\s+(urgent|high|important|medium|minor|low)\b", after)
            prefix = "host_" if refs[0].startswith("H:") else ""
            fields = [prefix + {"urgent": "high", "important": "medium", "minor": "low"}.get(level[1], level[1]) + "_count"] if level else ["finding_count"]
        elif re.search(r"(?:max-age\s*[=:]?\s*|duration\s+(?:of\s+)?)$", before):
            if re.search(r"\b(?:set|use|add|recommended|can)\b", sentence, re.I) and not re.search(r"\b(?:observed|current|recorded|shows)\b", sentence, re.I):
                fields = ["hsts_max_age"]
        elif re.search(r"(?:score|risk|per.host)\b.{0,25}$", before) or re.match(r"\s+(?:is\s+)?(?:the\s+)?(?:exposure\s+)?score\b", after):
            fields = ["host_risk", "risk_score", "risk_per_host"]
        elif re.match(r"\s+IP\s+addresses?\b", after, re.I):
            fields = ["ip_count"]
        for field in fields:
            value = values.get(field)
            comparable = SMALL_NUMBERS.index(value) if value in SMALL_NUMBERS else value
            try:
                equal = float(comparable) == numeric
            except (ValueError, TypeError):
                equal = False
            if equal:
                checked_numbers += 1
                return "{" + field + "}"
        raise SchemaError("literal factual number does not match its cited fact type and value")

    sentence = NUMBERS.sub(number, sentence)
    return sentence, refs, checked_numbers
