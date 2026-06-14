"""A controlled *benign* stdio MCP server — the negatives for precision.

Every tool is genuinely safe: pure computation, canned read-only data, and a
string transform. None executes a shell, touches the filesystem, makes a network
call, or returns seeded state. Driving it with the attacker must yield ZERO
MTM-RT findings — any finding is a false positive.

`reverse_text` deliberately reflects its input: when the attacker injects a honey
marker or an exec payload, the tool echoes a transform of it. A sound harness must
NOT call that a leak or an exec (reflection != leak/exec), so this fixture is also
the end-to-end guard for those oracle distinctions.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("controlled-benign-server")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, title="Add two numbers"))
def add_numbers(a: int, b: int) -> str:
    """Return the sum of two integers (pure computation, no side effects)."""
    return f"sum: {a + b}"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, title="Get a canned forecast"))
def get_forecast(city: str) -> str:
    """Return a fixed, public weather string for a city (no secrets, read-only)."""
    return f"Forecast for {city}: 72F, partly cloudy."


@mcp.tool(annotations=ToolAnnotations(title="Reverse a string"))
def reverse_text(text: str) -> str:
    """Return the input reversed — a transform that reflects, but never executes."""
    return f"reversed: {text[::-1]}"


if __name__ == "__main__":
    mcp.run()
