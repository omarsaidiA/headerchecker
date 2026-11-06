"""Catalogue of every check headercheck can report.

Each rule has a stable ID (used in SARIF and for filtering), a fixed severity and a remediation
hint. Keeping them in one table makes the reports consistent and the severities easy to review.
"""

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that thresholds can be compared: ``finding.severity >= Severity.HIGH``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    remediation: str


PLAIN_HTTP = Rule(
    "PLAIN-HTTP",
    "Target is served over plain HTTP",
    Severity.LOW,
    "Serve the application over HTTPS only; HSTS and Secure cookies depend on it.",
)
HSTS_MISSING = Rule(
    "HSTS-MISSING",
    "Strict-Transport-Security header is missing",
    Severity.MEDIUM,
    "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.",
)
HSTS_INVALID = Rule(
    "HSTS-INVALID",
    "Strict-Transport-Security has no valid max-age",
    Severity.MEDIUM,
    "Set a numeric max-age directive, for example max-age=31536000.",
)
HSTS_SHORT = Rule(
    "HSTS-SHORT",
    "Strict-Transport-Security max-age is shorter than 180 days",
    Severity.LOW,
    "Use a max-age of at least 15552000 seconds (180 days); one year is the common choice.",
)
CSP_MISSING = Rule(
    "CSP-MISSING",
    "Content-Security-Policy header is missing",
    Severity.MEDIUM,
    "Define a Content-Security-Policy; for a JSON API, \"default-src 'none'; "
    "frame-ancestors 'none'\" is enough.",
)
CSP_NO_SCRIPT_RESTRICTION = Rule(
    "CSP-NO-SCRIPT-RESTRICTION",
    "Content-Security-Policy does not restrict scripts",
    Severity.MEDIUM,
    "Add a script-src or default-src directive; without one, any script source is allowed.",
)
CSP_UNSAFE_INLINE = Rule(
    "CSP-UNSAFE-INLINE",
    "Content-Security-Policy allows inline scripts",
    Severity.MEDIUM,
    "Remove 'unsafe-inline' from script-src, or use nonces or hashes instead.",
)
CSP_UNSAFE_EVAL = Rule(
    "CSP-UNSAFE-EVAL",
    "Content-Security-Policy allows eval()",
    Severity.MEDIUM,
    "Remove 'unsafe-eval' from script-src and stop building code from strings.",
)
CSP_WILDCARD_SCRIPT = Rule(
    "CSP-WILDCARD-SCRIPT",
    "Content-Security-Policy allows scripts from any host",
    Severity.MEDIUM,
    "Replace '*', 'http:', 'https:' and 'data:' in script-src with explicit trusted origins.",
)
XCTO_MISSING = Rule(
    "XCTO-MISSING",
    "X-Content-Type-Options is not set to nosniff",
    Severity.LOW,
    "Send 'X-Content-Type-Options: nosniff' so browsers do not guess content types.",
)
CLICKJACKING = Rule(
    "CLICKJACKING",
    "No protection against framing (clickjacking)",
    Severity.MEDIUM,
    "Send \"Content-Security-Policy: frame-ancestors 'none'\" (or 'X-Frame-Options: DENY').",
)
REFERRER_MISSING = Rule(
    "REFERRER-MISSING",
    "Referrer-Policy header is missing",
    Severity.LOW,
    "Send 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
)
REFERRER_UNSAFE = Rule(
    "REFERRER-UNSAFE",
    "Referrer-Policy leaks full URLs to other sites",
    Severity.LOW,
    "Avoid 'unsafe-url' and 'no-referrer-when-downgrade'; use 'strict-origin-when-cross-origin'.",
)
VERSION_DISCLOSURE = Rule(
    "VERSION-DISCLOSURE",
    "Response discloses server software or version",
    Severity.LOW,
    "Remove X-Powered-By and strip version numbers from the Server header.",
)
COOKIE_NO_SECURE = Rule(
    "COOKIE-NO-SECURE",
    "Cookie set over HTTPS without the Secure attribute",
    Severity.MEDIUM,
    "Add the Secure attribute so the cookie is never sent over plain HTTP.",
)
COOKIE_NO_HTTPONLY = Rule(
    "COOKIE-NO-HTTPONLY",
    "Cookie without the HttpOnly attribute",
    Severity.LOW,
    "Add HttpOnly unless JavaScript really needs to read the cookie (it limits XSS impact).",
)
COOKIE_NO_SAMESITE = Rule(
    "COOKIE-NO-SAMESITE",
    "Cookie without the SameSite attribute",
    Severity.LOW,
    "Add SameSite=Lax or SameSite=Strict to reduce cross-site request forgery.",
)
COOKIE_SAMESITE_NONE_INSECURE = Rule(
    "COOKIE-SAMESITE-NONE-INSECURE",
    "Cookie uses SameSite=None without Secure",
    Severity.MEDIUM,
    "SameSite=None requires Secure; browsers reject or downgrade the cookie otherwise.",
)
CORS_REFLECTED_CREDENTIALS = Rule(
    "CORS-REFLECTED-CREDENTIALS",
    "CORS reflects any origin and allows credentials",
    Severity.HIGH,
    "Allow only an explicit list of trusted origins; any site can currently read "
    "authenticated responses.",
)
CORS_REFLECTED = Rule(
    "CORS-REFLECTED",
    "CORS reflects any origin",
    Severity.MEDIUM,
    "Allow only an explicit list of trusted origins instead of echoing the Origin header.",
)
CORS_NULL_ORIGIN = Rule(
    "CORS-NULL-ORIGIN",
    "CORS allows the 'null' origin",
    Severity.MEDIUM,
    "Never allow 'null': sandboxed iframes and local files can send it.",
)
CORS_WILDCARD_CREDENTIALS = Rule(
    "CORS-WILDCARD-CREDENTIALS",
    "CORS combines a wildcard origin with credentials",
    Severity.MEDIUM,
    "Browsers reject this combination; list trusted origins explicitly if credentials are needed.",
)
CORS_WILDCARD = Rule(
    "CORS-WILDCARD",
    "CORS allows any origin (wildcard)",
    Severity.INFO,
    "Acceptable for public, unauthenticated data only; otherwise list trusted origins.",
)
