"""Command-line entry point."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from headercheck import __version__
from headercheck.checks import run_checks
from headercheck.fetch import DEFAULT_PROBE_ORIGIN, FetchError, fetch
from headercheck.models import ScanResult
from headercheck.report import render_json, render_sarif, render_text
from headercheck.rules import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1  # at least one finding at or above --fail-on
EXIT_ERROR = 2  # a target could not be scanned (argparse also uses 2 for usage errors)

_THRESHOLDS = {str(s): s for s in Severity}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headercheck",
        description="Audit the HTTP security headers, cookies and CORS policy of web targets.",
    )
    parser.add_argument("urls", nargs="+", metavar="URL", help="http(s) URL to scan")
    parser.add_argument(
        "-f", "--format", choices=("text", "json", "sarif"), default="text", help="report format"
    )
    parser.add_argument("-o", "--output", type=Path, help="write the report to a file")
    parser.add_argument(
        "--fail-on",
        choices=(*_THRESHOLDS, "never"),
        default="high",
        help="exit with code 1 if a finding has this severity or higher (default: high)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--origin",
        default=DEFAULT_PROBE_ORIGIN,
        help=f"untrusted Origin sent to test CORS (default: {DEFAULT_PROBE_ORIGIN})",
    )
    parser.add_argument(
        "--sarif-artifact",
        metavar="PATH",
        help="repository file to attach SARIF results to (needed by GitHub code scanning)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def scan(url: str, timeout: float, origin: str) -> ScanResult:
    try:
        response = fetch(url, timeout=timeout, probe_origin=origin)
    except FetchError as error:
        return ScanResult(url, error=str(error))
    return ScanResult(url, status=response.status, findings=run_checks(response))


def exit_code(results: list[ScanResult], fail_on: str) -> int:
    if any(r.error is not None for r in results):
        return EXIT_ERROR
    if fail_on == "never":
        return EXIT_OK
    threshold = _THRESHOLDS[fail_on]
    failed = any(f.severity >= threshold for r in results for f in r.findings)
    return EXIT_FINDINGS if failed else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    results = [scan(url, args.timeout, args.origin) for url in args.urls]

    if args.format == "json":
        report = render_json(results)
    elif args.format == "sarif":
        report = render_sarif(results, args.sarif_artifact)
    else:
        report = render_text(results)

    if args.output is not None:
        args.output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return exit_code(results, args.fail_on)
