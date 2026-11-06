import json
import socket
from pathlib import Path

import pytest

from headercheck.cli import main
from tests.conftest import LocalServer

HARDENED = [
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
]
REFLECTING_CORS = [
    ("Access-Control-Allow-Origin", "{origin}"),
    ("Access-Control-Allow-Credentials", "true"),
]


def test_hardened_target_passes(
    local_server: LocalServer, capsys: pytest.CaptureFixture[str]
) -> None:
    local_server.respond(HARDENED)
    assert main([local_server.url]) == 0
    out = capsys.readouterr().out
    # Only low findings caused by the local test server remain (plain HTTP, Python Server header)
    assert "PLAIN-HTTP" in out
    assert "CSP-MISSING" not in out


def test_reflected_cors_fails_the_scan(
    local_server: LocalServer, capsys: pytest.CaptureFixture[str]
) -> None:
    local_server.respond(HARDENED + REFLECTING_CORS)
    assert main([local_server.url, "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report[0]["status"] == 200
    assert report[0]["findings"][0]["id"] == "CORS-REFLECTED-CREDENTIALS"


def test_custom_probe_origin_is_sent(
    local_server: LocalServer, capsys: pytest.CaptureFixture[str]
) -> None:
    local_server.respond(HARDENED + REFLECTING_CORS)
    main([local_server.url, "--format", "json", "--origin", "https://attacker.example"])
    detail = json.loads(capsys.readouterr().out)[0]["findings"][0]["detail"]
    assert "https://attacker.example" in detail


def test_fail_on_threshold(local_server: LocalServer) -> None:
    local_server.respond([])  # nothing set: medium findings only
    assert main([local_server.url, "--fail-on", "high"]) == 0
    assert main([local_server.url, "--fail-on", "medium"]) == 1
    assert main([local_server.url, "--fail-on", "never"]) == 0


def test_redirects_are_not_followed(
    local_server: LocalServer, capsys: pytest.CaptureFixture[str]
) -> None:
    local_server.respond([("Location", "https://example.com/")], status=302)
    main([local_server.url, "--format", "json"])
    assert json.loads(capsys.readouterr().out)[0]["status"] == 302


def test_error_responses_are_still_checked(
    local_server: LocalServer, capsys: pytest.CaptureFixture[str]
) -> None:
    local_server.respond(HARDENED, status=401)
    assert main([local_server.url, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["status"] == 401


def test_sarif_report_written_to_file(local_server: LocalServer, tmp_path: Path) -> None:
    local_server.respond(HARDENED + REFLECTING_CORS)
    output = tmp_path / "report.sarif"
    main([local_server.url, "-f", "sarif", "-o", str(output), "--sarif-artifact", "openapi.yml"])

    run = json.loads(output.read_text(encoding="utf-8"))["runs"][0]
    assert run["tool"]["driver"]["name"] == "headercheck"
    first = run["results"][0]
    assert first["ruleId"] == "CORS-REFLECTED-CREDENTIALS"
    assert first["level"] == "error"
    location = first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert location == "openapi.yml"
    assert local_server.url in first["message"]["text"]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids


def test_sarif_location_defaults_to_the_url(
    local_server: LocalServer, capsys: pytest.CaptureFixture[str]
) -> None:
    local_server.respond([])
    main([local_server.url, "-f", "sarif"])
    result = json.loads(capsys.readouterr().out)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == local_server.url


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def test_unreachable_target_exits_with_error(capsys: pytest.CaptureFixture[str]) -> None:
    url = f"http://127.0.0.1:{_unused_port()}/"
    assert main([url, "--timeout", "2"]) == 2
    assert "ERROR" in capsys.readouterr().out


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/"])
def test_non_http_schemes_are_refused(url: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([url]) == 2
    assert "unsupported URL scheme" in capsys.readouterr().out


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("headercheck ")
