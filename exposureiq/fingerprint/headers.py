"""Security headers check (Stage 2, Hassan).

Pure function: takes the web-response dict from fetch_front_page and returns
raw findings (rule + detail only) for missing or weak security headers.
No network, no severity, no advice text.
"""

HSTS_MIN_AGE = 15552000  # 180 days, in seconds
WEAK_SCRIPT_SOURCES = ("'unsafe-inline'", "'unsafe-eval'", "*")
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _parse_csp(value: str) -> dict[str, list[str]]:
    # "script-src 'self' *; frame-ancestors 'none'"
    #   -> {"script-src": ["'self'", "*"], "frame-ancestors": ["'none'"]}
    directives = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def _hsts_max_age(value: str) -> int | None:
    # Returns the max-age number, or None if it is missing or not a number.
    for part in value.split(";"):
        name, _, number = part.partition("=")
        if name.strip().lower() == "max-age":
            number = number.strip().strip('"')
            return int(number) if number.isdigit() else None
    return None


def _weak_script_sources(csp: dict[str, list[str]]) -> list[str]:
    # script-src decides; default-src is used only when script-src is absent.
    sources = csp.get("script-src", csp.get("default-src", []))
    return [s for s in sources if s.lower() in WEAK_SCRIPT_SOURCES]


def check_security_headers(response: dict) -> list[dict]:
    """Return raw findings for missing or weak security headers."""
    if not isinstance(response, dict):
        raise ValueError("response must be a dict")
    if not isinstance(response.get("headers"), dict):
        raise ValueError("response['headers'] must be a dict")

    headers = {str(k).lower(): str(v) for k, v in response["headers"].items()}
    scheme = response.get("scheme")
    url = response.get("url") or f"{scheme}://{response.get('host', '')}/"
    findings = []

    def add(rule: str, detail: str) -> None:
        findings.append({"rule": rule, "detail": detail})

    csp_value = headers.get("content-security-policy")
    csp = _parse_csp(csp_value) if csp_value is not None else {}

    # HSTS is ignored by browsers over plain HTTP, so both HSTS rules
    # only apply to https pages.
    if scheme == "https":
        hsts = headers.get("strict-transport-security")
        if hsts is None:
            add("headers.missing_hsts", f"No Strict-Transport-Security header on {url}")
        else:
            max_age = _hsts_max_age(hsts)
            if max_age is None or max_age < HSTS_MIN_AGE:
                add("headers.weak_hsts",
                    f"Strict-Transport-Security max-age is missing or below "
                    f"{HSTS_MIN_AGE} seconds ({hsts}) on {url}")

    # A redirect has no page of its own, and the scan never follows it (one
    # front-page GET only). The headers below describe a page, so judging them
    # here would give false "missing" findings. The target of the redirect is
    # checked when it is scanned as its own host. HSTS above still counts.
    status = response.get("status")
    if isinstance(status, int) and status in REDIRECT_CODES and "location" in headers:
        return findings

    if csp_value is None:
        add("headers.missing_csp", f"No Content-Security-Policy header on {url}")
    else:
        weak = _weak_script_sources(csp)
        if weak:
            add("headers.weak_csp",
                f"Content-Security-Policy allows {', '.join(weak)} for scripts on {url}")

    xcto = headers.get("x-content-type-options")
    if xcto is None:
        add("headers.missing_x_content_type_options",
            f"No X-Content-Type-Options header on {url}")
    elif xcto.strip().lower() != "nosniff":
        add("headers.missing_x_content_type_options",
            f"X-Content-Type-Options is '{xcto}', expected nosniff, on {url}")

    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        add("headers.missing_clickjacking_protection",
            f"No X-Frame-Options or CSP frame-ancestors on {url}")

    if "referrer-policy" not in headers:
        add("headers.missing_referrer_policy", f"No Referrer-Policy header on {url}")

    if "permissions-policy" not in headers:
        add("headers.missing_permissions_policy",
            f"No Permissions-Policy header on {url}")

    return findings
