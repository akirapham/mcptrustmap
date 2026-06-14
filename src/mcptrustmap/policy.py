"""Authority classes, argument roles, and severity ordering.

The vocabulary is shared by the deterministic layer (schema-declared
classification) and the LLM layer (candidates speak the same words), so facts
and candidates are directly comparable. Ported from the Agent Memory Guard
lineage/authority fork.
"""

from __future__ import annotations

# --- tool authority classes (what a tool can do) ---
AUTHORITY_CLASSES: frozenset[str] = frozenset(
    {
        "read",
        "write",
        "command_exec",
        "network",
        "filesystem",
        "credential_access",
        "database",
        "browser",
        "payment",
        "email",
        "repo_mutation",
        "cloud_mutation",
        "unknown",
    }
)

# high-authority classes weigh heavier in severity and trip MTM-HIGH-AUTHORITY-TOOL
HIGH_AUTHORITY: frozenset[str] = frozenset(
    {"command_exec", "credential_access", "payment", "cloud_mutation"}
)

# classes that represent state mutation (used by mismatch / undeclared-mutation)
MUTATING_AUTHORITY: frozenset[str] = frozenset(
    {
        "write",
        "command_exec",
        "filesystem",
        "database",
        "repo_mutation",
        "cloud_mutation",
        "payment",
        "email",
    }
)

# --- per-argument security roles ---
ARG_ROLES: frozenset[str] = frozenset(
    {
        "content",
        "target",
        "path",
        "command",
        "url",
        "recipient",
        "credential",
        "selector",
        "approval",
        "payment_destination",
        "control",
        "unknown",
    }
)

# roles that carry authority (everything except benign content/unknown)
AUTHORITY_BEARING_ROLES: frozenset[str] = ARG_ROLES - {"content", "unknown"}

# --- severity ordering (low -> high) ---
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
SEVERITIES: frozenset[str] = frozenset(SEVERITY_ORDER)

CONFIDENCES: frozenset[str] = frozenset({"high", "medium", "low"})
PROVENANCES: frozenset[str] = frozenset({"deterministic", "llm-verified"})

# OWASP MCP Top 10 (beta/v0.1) ids — every finding maps to one
OWASP_MCP_IDS: frozenset[str] = frozenset(f"MCP{n:02d}" for n in range(1, 11))


def severity_rank(severity: str) -> int:
    """Rank a severity for `--fail-on` comparison. Higher == more severe."""
    return SEVERITY_ORDER.index(severity)


def at_or_above(severity: str, threshold: str) -> bool:
    """True if `severity` is at or above `threshold`."""
    return severity_rank(severity) >= severity_rank(threshold)
