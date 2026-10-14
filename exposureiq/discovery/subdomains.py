"""Subdomain discovery for ExposureIQ (Stage 1, task: Subdomain discovery).

Engine: Subfinder (https://github.com/projectdiscovery/subfinder)
    A fast, passive tool that asks 50+ public sources (certificate logs, DNS
    databases, search engines, ...) for the subdomains of a domain. It never
    sends traffic to the target itself, it only reads third-party data.

Fallback: crt.sh certificate records
    If Subfinder is not installed (or finds nothing), we ask crt.sh directly, so
    the tool still works. This gives fewer results than Subfinder.

Public function (the shape the rest of the team relies on):

    find_subdomains(domain: str) -> list[str]
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# ---- Subfinder settings -----------------------------------------------------
SUBFINDER_MAX_MINUTES = 5      # stop Subfinder after this many minutes
SUBFINDER_SOURCE_TIMEOUT = 30  # seconds to wait for each source
INSTALL_HELP = "Install it from https://github.com/projectdiscovery/subfinder#installation"

# ---- crt.sh fallback settings -----------------------------------------------
CRT_URL = "https://crt.sh/"
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
HEADERS = {
    "User-Agent": "ExposureIQ/0.1 (open-source; https://github.com/ExposureIQ-Project/ExposureIQ)"
}

# A valid hostname: labels of letters/digits/hyphens separated by dots.
# It cannot start with "-", so a name can never be mistaken for a command option.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)


# =============================================================================
# Helpers: input cleaning and output cleaning
# =============================================================================
def _normalize_domain(domain: str) -> str:
    """Turn user input into a plain lowercase domain, or raise ValueError.

    "https://Example.com/path" -> "example.com"
    """
    if not isinstance(domain, str):
        raise ValueError("domain must be text, for example 'example.com'")
    d = domain.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)      # remove http:// or https://
    d = d.split("/")[0].split("?")[0].split("#")[0]   # remove path, query, fragment
    d = d.split(":")[0]                               # remove :port
    d = d.rstrip(".")                                 # remove a trailing dot
    if d.startswith("*."):
        d = d[2:]                                     # "*.example.com" -> "example.com"
    if not _HOSTNAME.match(d):
        raise ValueError(f"'{domain}' does not look like a valid domain name")
    return d


# Public name, used by the command line.
normalize_domain = _normalize_domain


def _clean_name(raw: str, domain: str, include_apex: bool):
    """Clean one raw name. Return the clean name, or None if it must be skipped."""
    name = str(raw).strip().lower()
    if name.startswith("*."):
        name = name[2:]                               # remove the wildcard prefix
    if "@" in name or " " in name or not _HOSTNAME.match(name):
        return None                                   # emails, junk, invalid names
    # ".endswith('.' + domain)" prevents "notexample.com" from matching "example.com".
    if name.endswith("." + domain):
        return name
    if name == domain and include_apex:
        return name
    return None


def _clean_names(raw_names, domain: str, include_apex: bool) -> list[str]:
    """Clean many raw names into a sorted list of unique subdomains."""
    cleaned = {_clean_name(raw, domain, include_apex) for raw in raw_names}
    cleaned.discard(None)
    return sorted(cleaned)


# =============================================================================
# Source 1: Subfinder (main engine)
# =============================================================================
def _find_subfinder():
    """Return the path to the Subfinder program, or None if it is not installed.

    Looks in this order: the SUBFINDER_PATH environment variable, the PATH, then
    ~/.local/bin (where run.sh installs it) and ~/go/bin (where 'go install' puts it).
    """
    custom = os.environ.get("SUBFINDER_PATH")
    if custom and Path(custom).is_file():
        return custom
    found = shutil.which("subfinder")
    if found:
        return found
    home = Path.home()
    for folder in (home / ".local" / "bin", home / "go" / "bin"):
        for name in ("subfinder", "subfinder.exe"):
            candidate = folder / name
            if candidate.is_file():
                return str(candidate)
    return None


def _to_text(value) -> str:
    """subprocess can give bytes or text (or None) after a timeout. Make it text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run_subfinder(domain: str, exe: str, max_minutes: int):
    """Run Subfinder and return its raw output lines, or None if it could not run.

    Security: the command is a list (no shell), and the domain has already been
    validated, so nothing from the user can be run as a command.
    """
    cmd = [
        exe,
        "-d", domain,
        "-all",                                   # use all sources (slower, finds more)
        "-silent",                                # print only the subdomains
        "-nc",                                    # no colors
        "-duc",                                   # do not check for updates
        "-timeout", str(SUBFINDER_SOURCE_TIMEOUT),
        "-max-time", str(max_minutes),
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=max_minutes * 60 + 30,        # safety net above Subfinder's own limit
        )
    except subprocess.TimeoutExpired as error:
        logger.warning("Subfinder took too long and was stopped. Using the partial results.")
        return _to_text(error.stdout).splitlines()
    except OSError as error:
        logger.warning("Could not start Subfinder: %s", error)
        return None
    if proc.returncode != 0:
        first_error = (proc.stderr or "").strip().splitlines()[:1]
        logger.warning("Subfinder exited with code %s %s", proc.returncode, first_error)
    return (proc.stdout or "").splitlines()


# =============================================================================
# Source 2: crt.sh (fallback)
# =============================================================================
def _short(error: Exception) -> str:
    """One short line for a warning, instead of a long technical message."""
    lines = str(error).splitlines() or [type(error).__name__]
    text = lines[0]
    return text if len(text) <= 90 else text[:87] + "..."


def _fetch_certificates(domain: str, timeout: int, retries: int):
    """Ask crt.sh for all certificates of a domain.

    Returns a list of records, or None if every attempt failed.
    An empty list means "crt.sh answered, but found nothing".
    """
    params = {"q": f"%.{domain}", "output": "json"}
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(CRT_URL, params=params, headers=HEADERS, timeout=timeout)
            response.raise_for_status()
            if not response.text.strip():
                return []
            records = response.json()
            if not isinstance(records, list):
                raise ValueError("unexpected answer format from crt.sh")
            return records
        except (requests.RequestException, ValueError) as error:
            logger.warning("crt.sh attempt %d/%d failed: %s", attempt, retries, _short(error))
            if attempt < retries:
                time.sleep(2 * attempt)           # wait 2 s, then 4 s, ... (be gentle)
    return None


def _extract_names(records: list, domain: str, include_apex: bool) -> list[str]:
    """Clean raw crt.sh records into a sorted list of unique subdomains."""
    raw_names = []
    for record in records:
        if isinstance(record, dict):
            # name_value can hold several names separated by new lines.
            raw_names.extend(str(record.get("name_value", "")).splitlines())
    return _clean_names(raw_names, domain, include_apex)


# =============================================================================
# Public API
# =============================================================================
def find_subdomains_by_source(
    domain: str,
    include_apex: bool = False,
    use_subfinder: bool = True,
    use_crtsh: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    subfinder_max_minutes: int = SUBFINDER_MAX_MINUTES,
) -> dict:
    """Like find_subdomains, but shows what each source found.

    Returns {"subfinder": [...], "crtsh": [...]}. A source that was not used
    or failed has an empty list.
    """
    domain = _normalize_domain(domain)
    if not (use_subfinder or use_crtsh):
        raise ValueError("enable at least one source (Subfinder or crt.sh)")
    result = {"subfinder": [], "crtsh": []}

    subfinder_ok = False
    if use_subfinder:
        exe = _find_subfinder()
        if exe is None:
            logger.warning("Subfinder is not installed, so results will be limited. %s", INSTALL_HELP)
        else:
            lines = _run_subfinder(domain, exe, subfinder_max_minutes)
            if lines is not None:
                result["subfinder"] = _clean_names(lines, domain, include_apex)
                subfinder_ok = bool(result["subfinder"])

    # Use crt.sh when Subfinder is unavailable or found nothing (or it is the only source).
    if use_crtsh and (not use_subfinder or not subfinder_ok):
        records = _fetch_certificates(domain, timeout, retries)
        if records is None:
            logger.warning("Could not get data from crt.sh for %s.", domain)
        else:
            result["crtsh"] = _extract_names(records, domain, include_apex)
    return result


def find_subdomains(
    domain: str,
    include_apex: bool = False,
    use_subfinder: bool = True,
    use_crtsh: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    subfinder_max_minutes: int = SUBFINDER_MAX_MINUTES,
) -> list[str]:
    """Return a clean, sorted list of subdomains of `domain`.

    >>> find_subdomains("example.com")          # doctest: +SKIP
    ['api.example.com', 'mail.example.com', 'www.example.com']

    - include_apex: also include "example.com" itself (off by default).
    - If a source fails, a warning is logged and the other source is used.
      If everything fails, [] is returned. It never crashes because of network
      problems or a missing Subfinder.
    - Raises ValueError only if `domain` is not a valid domain name.
    """
    by_source = find_subdomains_by_source(
        domain, include_apex, use_subfinder, use_crtsh, timeout, retries, subfinder_max_minutes
    )
    names = sorted(set(by_source["subfinder"]) | set(by_source["crtsh"]))
    logger.info("Found %d subdomains for %s", len(names), _normalize_domain(domain))
    return names


def main(argv=None) -> int:
    """Try it from the terminal:  python -m exposureiq.discovery.subdomains example.com"""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m exposureiq.discovery.subdomains")
    parser.add_argument("domain", help="the domain to search, for example example.com")
    parser.add_argument("--apex", action="store_true", help="also include the domain itself")
    parser.add_argument("--no-subfinder", action="store_true", help="skip Subfinder (use crt.sh only)")
    parser.add_argument("--minutes", type=int, default=SUBFINDER_MAX_MINUTES,
                        help="maximum minutes for Subfinder (default %(default)s)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        by_source = find_subdomains_by_source(
            args.domain, include_apex=args.apex,
            use_subfinder=not args.no_subfinder, subfinder_max_minutes=args.minutes,
        )
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    names = sorted(set(by_source["subfinder"]) | set(by_source["crtsh"]))
    for name in names:
        print(name)
    print(f"subfinder: {len(by_source['subfinder'])}  crt.sh: {len(by_source['crtsh'])}  "
          f"total unique: {len(names)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
