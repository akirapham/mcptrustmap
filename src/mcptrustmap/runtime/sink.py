"""Egress sink — the network endpoint the sandbox routes all outbound traffic to.

A tiny HTTP server that records every request (host, method, path, headers,
body) as an EgressEvent. The oracle then checks whether a honeytoken marker
appears in any captured payload — that is the proof of exfiltration. No real
internet is reachable from the sandbox; the sink is the only route out.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

from .observe import EgressEvent


class _SinkServer(ThreadingHTTPServer):
    events: list[EgressEvent]


class _SinkHandler(BaseHTTPRequestHandler):
    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        host = (self.headers.get("Host") or self.client_address[0]).split(":")[0]
        header_blob = " ".join(f"{k}:{v}" for k, v in self.headers.items())
        payload = f"{self.command} {self.path} {header_blob} {body}"
        cast("_SinkServer", self.server).events.append(EgressEvent(host=host, payload=payload))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = _record
    do_POST = _record
    do_PUT = _record
    do_DELETE = _record
    do_PATCH = _record

    def log_message(self, format: str, *args: Any) -> None:  # silence default stderr logging
        return


class EgressSink:
    """Context-managed logging sink. Use `with EgressSink() as sink: ...`."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = _SinkServer((host, port), _SinkHandler)
        self._server.events = []
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def events(self) -> list[EgressEvent]:
        return list(self._server.events)

    def __enter__(self) -> EgressSink:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
