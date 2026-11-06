"""Send one GET request and capture the response headers."""

import urllib.error
import urllib.request
from collections import defaultdict
from email.message import Message
from urllib.parse import urlsplit

from headercheck import __version__
from headercheck.models import Response

DEFAULT_PROBE_ORIGIN = "https://headercheck.invalid"


class FetchError(Exception):
    """The target could not be reached or the URL is not acceptable."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report the headers of the URL that was asked for, not of wherever it redirects to."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _collect_headers(message: Message) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = defaultdict(list)
    for name, value in message.items():
        headers[name.lower()].append(value)
    return dict(headers)


def fetch(url: str, timeout: float = 10.0, probe_origin: str = DEFAULT_PROBE_ORIGIN) -> Response:
    """GET ``url`` with an Origin header, so the CORS policy can be checked in the same request."""
    # Only http(s): urllib would otherwise also open file:// and ftp:// URLs
    if urlsplit(url).scheme not in ("http", "https"):
        raise FetchError(f"unsupported URL scheme (expected http or https): {url}")

    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url,
        headers={"Origin": probe_origin, "User-Agent": f"headercheck/{__version__}"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as raw:
            return Response(url, raw.status, _collect_headers(raw.headers), probe_origin)
    except urllib.error.HTTPError as error:
        # 3xx (redirects are not followed), 4xx and 5xx still carry headers worth checking
        with error:
            return Response(url, error.code, _collect_headers(error.headers), probe_origin)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", error)
        raise FetchError(f"cannot reach {url}: {reason}") from error
