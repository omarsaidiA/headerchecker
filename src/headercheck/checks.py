"""Security checks. Each check reads a Response and returns the findings it detects."""

import re
from collections.abc import Callable, Iterator

from headercheck import rules
from headercheck.models import Finding, Response

Check = Callable[[Response], Iterator[Finding]]

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Split a CSP into {directive: [sources]}. Per the spec, the first occurrence wins."""
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_transport(response: Response) -> Iterator[Finding]:
    if not response.is_https:
        yield Finding(rules.PLAIN_HTTP, response.url)
        return

    hsts = response.header("strict-transport-security")
    if hsts is None:
        yield Finding(rules.HSTS_MISSING, "no Strict-Transport-Security header")
        return

    match = re.search(r'max-age\s*=\s*"?(\d+)"?', hsts, re.IGNORECASE)
    if match is None:
        yield Finding(rules.HSTS_INVALID, f"Strict-Transport-Security: {hsts}")
    elif int(match.group(1)) < HSTS_MIN_MAX_AGE:
        yield Finding(rules.HSTS_SHORT, f"max-age={match.group(1)}")


def check_csp(response: Response) -> Iterator[Finding]:
    policy = response.header("content-security-policy")
    if policy is None:
        yield Finding(rules.CSP_MISSING, "no Content-Security-Policy header")
        return

    directives = parse_csp(policy)
    # script-src falls back to default-src when it is not defined
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        yield Finding(rules.CSP_NO_SCRIPT_RESTRICTION, policy)
        return

    # Browsers ignore 'unsafe-inline' as soon as a nonce, a hash or 'strict-dynamic' is present
    neutralised = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
        for s in scripts
    )
    if "'unsafe-inline'" in scripts and not neutralised:
        yield Finding(rules.CSP_UNSAFE_INLINE, " ".join(scripts))
    if "'unsafe-eval'" in scripts:
        yield Finding(rules.CSP_UNSAFE_EVAL, " ".join(scripts))
    wildcards = sorted({"*", "http:", "https:", "data:"} & set(scripts))
    if wildcards:
        yield Finding(rules.CSP_WILDCARD_SCRIPT, f"script sources include {', '.join(wildcards)}")


def check_content_type_options(response: Response) -> Iterator[Finding]:
    value = response.header("x-content-type-options")
    if value is None or value.strip().lower() != "nosniff":
        yield Finding(rules.XCTO_MISSING, f"X-Content-Type-Options: {value or '(absent)'}")


def check_framing(response: Response) -> Iterator[Finding]:
    policy = response.header("content-security-policy")
    if policy is not None and "frame-ancestors" in parse_csp(policy):
        return
    frame_options = (response.header("x-frame-options") or "").strip().upper()
    if frame_options not in ("DENY", "SAMEORIGIN"):
        yield Finding(rules.CLICKJACKING, "no CSP frame-ancestors and no valid X-Frame-Options")


def check_referrer_policy(response: Response) -> Iterator[Finding]:
    value = response.header("referrer-policy")
    if value is None:
        yield Finding(rules.REFERRER_MISSING, "no Referrer-Policy header")
        return
    # Several comma-separated values are allowed; the browser uses the last one it supports
    effective = value.split(",")[-1].strip().lower()
    if effective in ("unsafe-url", "no-referrer-when-downgrade"):
        yield Finding(rules.REFERRER_UNSAFE, f"Referrer-Policy: {value}")


def check_version_disclosure(response: Response) -> Iterator[Finding]:
    powered_by = response.header("x-powered-by")
    if powered_by is not None:
        yield Finding(rules.VERSION_DISCLOSURE, f"X-Powered-By: {powered_by}")
    server = response.header("server")
    if server is not None and re.search(r"\d", server):
        yield Finding(rules.VERSION_DISCLOSURE, f"Server: {server}")


def check_cookies(response: Response) -> Iterator[Finding]:
    for cookie in response.header_values("set-cookie"):
        name, _, rest = cookie.partition("=")
        attributes = {
            attr.split("=", 1)[0].strip().lower(): attr.partition("=")[2].strip().lower()
            for attr in rest.split(";")[1:]
        }
        label = f"cookie '{name.strip()}'"
        secure = "secure" in attributes

        if response.is_https and not secure:
            yield Finding(rules.COOKIE_NO_SECURE, label)
        if "httponly" not in attributes:
            yield Finding(rules.COOKIE_NO_HTTPONLY, label)
        if "samesite" not in attributes:
            yield Finding(rules.COOKIE_NO_SAMESITE, label)
        elif attributes["samesite"] == "none" and not secure:
            yield Finding(rules.COOKIE_SAMESITE_NONE_INSECURE, label)


def check_cors(response: Response) -> Iterator[Finding]:
    allowed = response.header("access-control-allow-origin")
    if allowed is None:
        return
    allowed = allowed.strip()
    credentials = (response.header("access-control-allow-credentials") or "").lower() == "true"
    detail = f"Access-Control-Allow-Origin: {allowed} (credentials: {str(credentials).lower()})"

    if allowed == response.probe_origin:
        rule = rules.CORS_REFLECTED_CREDENTIALS if credentials else rules.CORS_REFLECTED
        yield Finding(rule, f"untrusted origin {response.probe_origin} accepted; {detail}")
    elif allowed == "null":
        yield Finding(rules.CORS_NULL_ORIGIN, detail)
    elif allowed == "*":
        yield Finding(
            rules.CORS_WILDCARD_CREDENTIALS if credentials else rules.CORS_WILDCARD, detail
        )


ALL_CHECKS: tuple[Check, ...] = (
    check_transport,
    check_csp,
    check_content_type_options,
    check_framing,
    check_referrer_policy,
    check_version_disclosure,
    check_cookies,
    check_cors,
)


def run_checks(response: Response) -> list[Finding]:
    """Run every check, most severe findings first."""
    findings = [finding for check in ALL_CHECKS for finding in check(response)]
    return sorted(findings, key=lambda f: f.severity, reverse=True)
