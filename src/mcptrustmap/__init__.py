"""MCPTrustMap — hybrid auditor of the authority/authorization trust boundary of MCP servers.

Three layers:
  1. a deterministic evidence layer (pure: no LLM, no network);
  2. a Claude-driven reasoning layer (candidate findings);
  3. an adversarial verification gate (anchor re-resolution + weighted judge panel).

The deterministic core alone satisfies the acceptance matrix; the LLM layer is
always reproducible in CI via recorded cassettes.
"""

__version__ = "0.1.0"
SCHEMA_VERSION = "1"

__all__ = ["__version__", "SCHEMA_VERSION"]
