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


@pytest.mark.skipif(not DVMCP_ROOT, reason="set MTM_DVMCP_ROOT to a DVMCP checkout")
def test_live_challenge9_command_injection():
    from mcptrustmap.runtime.dvmcp import CHALLENGES, run_challenge

    ch = CHALLENGES["challenge9"]
    assert DVMCP_ROOT is not None
    if not (Path(DVMCP_ROOT) / ch.subpath / "server.py").exists():
        pytest.skip(f"{ch.subpath} not found under MTM_DVMCP_ROOT")

    findings = run_challenge(ch, DVMCP_ROOT)
    assert ch.expect in {f.finding_id for f in findings}
