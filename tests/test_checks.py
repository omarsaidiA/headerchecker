from collections.abc import Mapping

from headercheck import checks
from headercheck.fetch import DEFAULT_PROBE_ORIGIN
from headercheck.models import Response

# Headers of a well-configured HTTPS API: the baseline every test starts from
SECURE = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def response(
    overrides: Mapping[str, str | None] | None = None,
    url: str = "https://api.example.com/",
    cookies: tuple[str, ...] = (),
) -> Response:
    headers = {**SECURE, **(overrides or {})}
    values = {name: [value] for name, value in headers.items() if value is not None}
    if cookies:
        values["set-cookie"] = list(cookies)
    return Response(url, 200, values, DEFAULT_PROBE_ORIGIN)


def ids(resp: Response) -> list[str]:
    return [finding.rule.id for finding in checks.run_checks(resp)]


def test_secure_baseline_has_no_findings() -> None:
    assert ids(response()) == []


def test_plain_http_is_reported_and_hsts_is_not_evaluated() -> None:
    assert ids(response({"strict-transport-security": None}, url="http://api.example.com/")) == [
        "PLAIN-HTTP"
    ]


def test_hsts_missing_invalid_and_short() -> None:
    assert ids(response({"strict-transport-security": None})) == ["HSTS-MISSING"]
    assert ids(response({"strict-transport-security": "includeSubDomains"})) == ["HSTS-INVALID"]
    assert ids(response({"strict-transport-security": "max-age=3600"})) == ["HSTS-SHORT"]
    assert ids(response({"strict-transport-security": 'max-age="15552000"'})) == []


def test_csp_missing_also_means_no_framing_protection() -> None:
    assert ids(response({"content-security-policy": None})) == ["CSP-MISSING", "CLICKJACKING"]


def test_x_frame_options_is_accepted_when_csp_has_no_frame_ancestors() -> None:
    overrides = {"content-security-policy": "default-src 'self'", "x-frame-options": "deny"}
    assert ids(response(overrides)) == []


def test_csp_without_script_restriction() -> None:
    assert ids(response({"content-security-policy": "frame-ancestors 'none'"})) == [
        "CSP-NO-SCRIPT-RESTRICTION"
    ]


def test_csp_weak_script_sources() -> None:
    policy = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; frame-ancestors 'none'"
    assert sorted(ids(response({"content-security-policy": policy}))) == [
        "CSP-UNSAFE-EVAL",
        "CSP-UNSAFE-INLINE",
        "CSP-WILDCARD-SCRIPT",
    ]


def test_unsafe_inline_is_ignored_when_a_nonce_is_present() -> None:
    policy = "script-src 'nonce-abc123' 'unsafe-inline'; frame-ancestors 'none'"
    assert ids(response({"content-security-policy": policy})) == []


def test_script_src_falls_back_to_default_src() -> None:
    policy = "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    assert ids(response({"content-security-policy": policy})) == ["CSP-UNSAFE-INLINE"]


def test_first_directive_wins() -> None:
    assert checks.parse_csp("script-src 'self'; script-src *") == {"script-src": ["'self'"]}


def test_content_type_options_and_referrer_policy() -> None:
    assert ids(response({"x-content-type-options": "sniff"})) == ["XCTO-MISSING"]
    assert ids(response({"referrer-policy": None})) == ["REFERRER-MISSING"]
    assert ids(response({"referrer-policy": "no-referrer, unsafe-url"})) == ["REFERRER-UNSAFE"]
    assert ids(response({"referrer-policy": "unsafe-url, strict-origin"})) == []


def test_version_disclosure() -> None:
    overrides = {"server": "Apache/2.4.58", "x-powered-by": "Express"}
    assert ids(response(overrides)) == ["VERSION-DISCLOSURE", "VERSION-DISCLOSURE"]
    assert ids(response({"server": "nginx"})) == []


def test_cookie_attributes() -> None:
    assert ids(response(cookies=("sid=1; Path=/; Secure; HttpOnly; SameSite=Lax",))) == []
    assert ids(response(cookies=("sid=1",))) == [
        "COOKIE-NO-SECURE",
        "COOKIE-NO-HTTPONLY",
        "COOKIE-NO-SAMESITE",
    ]


def test_samesite_none_requires_secure() -> None:
    plain_http = response(
        {"strict-transport-security": None},
        url="http://api.example.com/",
        cookies=("sid=1; HttpOnly; SameSite=None",),
    )
    assert ids(plain_http) == ["COOKIE-SAMESITE-NONE-INSECURE", "PLAIN-HTTP"]


def test_cors_reflected_origin_with_credentials_is_high() -> None:
    overrides = {
        "access-control-allow-origin": DEFAULT_PROBE_ORIGIN,
        "access-control-allow-credentials": "true",
    }
    findings = checks.run_checks(response(overrides))
    assert [f.rule.id for f in findings] == ["CORS-REFLECTED-CREDENTIALS"]
    assert str(findings[0].severity) == "high"


def test_cors_other_policies() -> None:
    reflected = {"access-control-allow-origin": DEFAULT_PROBE_ORIGIN}
    assert ids(response(reflected)) == ["CORS-REFLECTED"]
    assert ids(response({"access-control-allow-origin": "null"})) == ["CORS-NULL-ORIGIN"]
    assert ids(response({"access-control-allow-origin": "*"})) == ["CORS-WILDCARD"]
    wildcard_credentials = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    }
    assert ids(response(wildcard_credentials)) == ["CORS-WILDCARD-CREDENTIALS"]
    assert ids(response({"access-control-allow-origin": "https://app.example.com"})) == []


def test_findings_are_sorted_most_severe_first() -> None:
    overrides = {
        "x-content-type-options": None,
        "access-control-allow-origin": DEFAULT_PROBE_ORIGIN,
        "access-control-allow-credentials": "true",
    }
    severities = [f.severity for f in checks.run_checks(response(overrides))]
    assert severities == sorted(severities, reverse=True)
