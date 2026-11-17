"""Plain definitions shared by chat prompts and built-in explanations."""

from __future__ import annotations

import re

# The definitions describe terms, not extra observations about a saved scan.
GLOSSARY = {
    "database": {"explanation": "a service that stores information", "analogy": "a digital filing cabinet"},
    "remote desktop": {"explanation": "remote access to a computer's desktop", "analogy": "using an office computer from somewhere else"},
    "SMB": {"explanation": "a file-sharing service", "analogy": "a shared office folder"},
    "Telnet": {"explanation": "an old remote-login service without encryption", "analogy": "a conversation other people on the connection may hear"},
    "FTP": {"explanation": "file transfer without encryption", "analogy": "sending files in an open envelope"},
    "SSH": {"explanation": "encrypted remote administration", "analogy": "a protected connection to a computer's controls"},
    "VPN": {"explanation": "a protected connection to a private network", "analogy": "a private entrance for approved people"},
    "HTTPS": {"explanation": "an encrypted website connection", "analogy": "a sealed envelope between a visitor and a website"},
    "certificate": {"explanation": "a website's digital identity document", "analogy": "an identity card a browser checks"},
    "security headers": {"explanation": "website instructions that help browsers protect visitors", "analogy": "safety rules given to a visitor"},
    "HSTS": {"explanation": "a browser rule to keep using encrypted website connections", "analogy": "a reminder to use the protected entrance"},
    "CSP": {"explanation": "a browser policy limiting which scripts and resources a page may use", "analogy": "a guest list for page content"},
}
TERM_ALIASES = {"RDP": "remote desktop", "TLS certificate": "certificate", "SSL certificate": "certificate"}


def requested_term(question: str) -> str:
    if not re.search(r"\b(?:mean|meaning|what\s+is|what\s+are|define|stand\s+for)\b", question, re.I):
        return ""
    term = next((term for term in GLOSSARY if re.search(r"\b" + re.escape(term) + r"\b", question, re.I)), "")
    return term or next((term for alias, term in TERM_ALIASES.items() if re.search(r"\b" + re.escape(alias) + r"\b", question, re.I)), "")


def define_terms(value: str, *, seen=()) -> tuple[str, set[str]]:
    """Expand first-use SIMPLE terms; never change host names or add observations."""
    defined = set(seen)
    for term, entry in GLOSSARY.items():
        if term in defined:
            continue
        pattern = re.compile(r"(?<![\w.-])" + re.escape(term) + r"(?![\w-]|\.[\w-])", re.I)
        if pattern.search(value):
            if entry["explanation"].lower() not in value.lower():
                value = pattern.sub(lambda match: match.group() + " (" + entry["explanation"] + ")", value, count=1)
            defined.add(term)
    return value, defined
