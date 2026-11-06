"""A real local HTTP server whose response headers each test can choose."""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

Headers = list[tuple[str, str]]


class _Handler(BaseHTTPRequestHandler):
    server: "_Server"

    def do_GET(self) -> None:
        self.send_response(self.server.status)
        for name, value in self.server.response_headers:
            # {origin} lets a test simulate a server that reflects the Origin header
            self.send_header(name, value.replace("{origin}", self.headers.get("Origin", "")))
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        pass


class _Server(ThreadingHTTPServer):
    status = 200
    response_headers: Headers = []  # noqa: RUF012 - overwritten per test


class LocalServer:
    def __init__(self, server: _Server) -> None:
        self._server = server
        self.url = f"http://127.0.0.1:{server.server_address[1]}/"

    def respond(self, headers: Headers, status: int = 200) -> None:
        self._server.response_headers = headers
        self._server.status = status


@pytest.fixture
def local_server() -> Iterator[LocalServer]:
    server = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LocalServer(server)
    finally:
        server.shutdown()
        server.server_close()
