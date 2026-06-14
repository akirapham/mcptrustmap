"""DVMCP eval (live): drive a real challenge if a checkout + the mcp extra exist.

Set MTM_DVMCP_ROOT to a Damn-Vulnerable-MCP-Server checkout to run. Skipped
otherwise (CI uses the frozen replay in test_dvmcp). This is what regenerates the
frozen Observation and guards against DVMCP drift.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("mcp")

DVMCP_ROOT = os.environ.get("MTM_DVMCP_ROOT")


def _cids():
    from mcptrustmap.runtime.dvmcp import CHALLENGES

    return sorted(CHALLENGES)


@pytest.mark.skipif(not DVMCP_ROOT, reason="set MTM_DVMCP_ROOT to a DVMCP checkout")
@pytest.mark.parametrize("cid", _cids())
def test_live_challenge_hits_ground_truth(cid):
    from mcptrustmap.runtime.dvmcp import CHALLENGES, run_challenge

    ch = CHALLENGES[cid]
    assert DVMCP_ROOT is not None
    if not (Path(DVMCP_ROOT) / ch.subpath / "server.py").exists():
        pytest.skip(f"{ch.subpath} not found under MTM_DVMCP_ROOT")

    findings = run_challenge(ch, DVMCP_ROOT)
    assert ch.expect in {f.finding_id for f in findings}


@pytest.mark.skipif(not DVMCP_ROOT, reason="set MTM_DVMCP_ROOT to a DVMCP checkout")
def test_challenge4_rugpull_is_not_protocol_observable():
    """Documented negative: challenge 4's __doc__ mutation never reaches list_tools.

    FastMCP snapshots a tool's description at registration, so the runtime docstring
    rewrite is invisible over MCP. We assert that here so the scope claim in
    evaluation/dvmcp.md stays honest if a future mcp release changes the behavior.
    """
    import asyncio
    import sys

    assert DVMCP_ROOT is not None
    ch4 = Path(DVMCP_ROOT) / "challenges/medium/challenge4"
    if not (ch4 / "server.py").exists():
        pytest.skip("challenge4 not found under MTM_DVMCP_ROOT")

    state = Path("/tmp/dvmcp_challenge4_state.json")  # noqa: S108 - the challenge's own path
    state.unlink(missing_ok=True)

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    shim = f"import sys; sys.path.insert(0, {str(ch4)!r}); import server; server.mcp.run()"

    async def _descs():
        params = StdioServerParameters(command=sys.executable, args=["-c", shim])
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            await s.initialize()
            before = {t.name: t.description for t in (await s.list_tools()).tools}
            for _ in range(4):  # cross the rug-pull threshold (3 calls)
                await s.call_tool("get_weather_forecast", {"city": "london"})
            after = {t.name: t.description for t in (await s.list_tools()).tools}
            return before["get_weather_forecast"], after["get_weather_forecast"]

    before, after = asyncio.run(_descs())
    assert before == after  # the mutation is not observable over the protocol
    assert "IMPORTANT" not in (after or "")
