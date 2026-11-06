"""Render scan results as text, JSON or SARIF 2.1.0."""

import json
from typing import Any

from headercheck import __version__
from headercheck.models import Finding, ScanResult
from headercheck.rules import Severity

# GitHub code scanning reads this property to rank alerts (CVSS-like scale from 0 to 10)
_SECURITY_SEVERITY = {
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}
_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_text(results: list[ScanResult]) -> str:
    lines: list[str] = []
    for result in results:
        if result.error is not None:
            lines.append(f"{result.url}\n  ERROR  {result.error}")
            continue
        lines.append(f"{result.url} (HTTP {result.status})")
        if not result.findings:
            lines.append("  no findings")
        for finding in result.findings:
            lines.append(
                f"  {str(finding.severity).upper():<6} {finding.rule.id}: {finding.rule.title}\n"
                f"         {finding.detail}\n"
                f"         fix: {finding.rule.remediation}"
            )
    return "\n".join(lines) + "\n"


def _finding_json(finding: Finding) -> dict[str, str]:
    return {
        "id": finding.rule.id,
        "severity": str(finding.severity),
        "title": finding.rule.title,
        "detail": finding.detail,
        "remediation": finding.rule.remediation,
    }


def render_json(results: list[ScanResult]) -> str:
    document = [
        {
            "url": result.url,
            "status": result.status,
            "error": result.error,
            "findings": [_finding_json(f) for f in result.findings],
        }
        for result in results
    ]
    return json.dumps(document, indent=2) + "\n"


def render_sarif(results: list[ScanResult], artifact: str | None = None) -> str:
    """SARIF for GitHub code scanning.

    Code scanning only accepts locations that are files of the repository, not URLs. When
    ``artifact`` is given (for example the API contract), every result is attached to that file
    and the scanned URL is kept in the message. Without it, the URL itself is the location.
    """
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for result in results:
        for finding in result.findings:
            rule = finding.rule
            rules.setdefault(
                rule.id,
                {
                    "id": rule.id,
                    "name": rule.id.title().replace("-", ""),
                    "shortDescription": {"text": rule.title},
                    "help": {"text": rule.remediation},
                    "properties": {
                        "security-severity": _SECURITY_SEVERITY[rule.severity],
                        "tags": ["security"],
                    },
                },
            )
            sarif_results.append(
                {
                    "ruleId": rule.id,
                    "level": _SARIF_LEVEL[rule.severity],
                    "message": {"text": f"{rule.title}: {finding.detail} (URL: {result.url})"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact or result.url},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "headercheck",
                        "version": __version__,
                        "informationUri": "https://github.com/omarsaidiA/headerchecker",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
