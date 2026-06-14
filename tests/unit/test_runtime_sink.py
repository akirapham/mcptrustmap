"""Runtime: the egress sink records outbound traffic for marker detection."""

from __future__ import annotations

import urllib.request

from mcptrustmap.runtime.sink import EgressSink


def test_sink_records_post_payload():
    marker = "MTMHONEY-TOKEN-deadbeef"
    with EgressSink() as sink:
        req = urllib.request.Request(
            sink.url + "/exfil", data=f"secret={marker}".encode(), method="POST"
        )
        urllib.request.urlopen(req, timeout=2).read()  # noqa: S310 - local sink only
        events = sink.events()
    assert len(events) == 1
    assert marker in events[0].payload
    assert events[0].host == "127.0.0.1"


def test_sink_records_get():
    with EgressSink() as sink:
        urllib.request.urlopen(sink.url + "/ping", timeout=2).read()  # noqa: S310
        events = sink.events()
    assert len(events) == 1
    assert "GET /ping" in events[0].payload
