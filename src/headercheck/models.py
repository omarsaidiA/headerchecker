"""Data passed between the fetcher, the checks and the reports."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from headercheck.rules import Rule, Severity


@dataclass(frozen=True)
class Response:
    """The parts of an HTTP response the checks need.

    Header names are lower-cased. Values are lists because some headers, such as Set-Cookie,
    can legitimately appear several times.
    """

    url: str
    status: int
    headers: Mapping[str, Sequence[str]]
    probe_origin: str

    def header(self, name: str) -> str | None:
        """First value of a header, or None when it is absent."""
        values = self.headers.get(name.lower())
        return values[0] if values else None

    def header_values(self, name: str) -> Sequence[str]:
        return self.headers.get(name.lower(), ())

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")


@dataclass(frozen=True)
class Finding:
    rule: Rule
    detail: str

    @property
    def severity(self) -> Severity:
        return self.rule.severity


@dataclass
class ScanResult:
    """Outcome for one target: either a response with findings, or an error message."""

    url: str
    status: int | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
