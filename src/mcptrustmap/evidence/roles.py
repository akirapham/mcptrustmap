"""Per-argument security role classification.

Deterministic and tokenization-based (split on non-alphanumerics and camelCase)
to avoid substring false positives like "profile" matching "file". Order is a
priority list: the first matching rule wins.
"""

from __future__ import annotations

import re

from ..models import ArgRecord, ToolRecord

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(name: str) -> set[str]:
    spaced = _CAMEL.sub(" ", name)
    return {t for t in _SPLIT.split(spaced.lower()) if t}


# (role, trigger-tokens). Evaluated in order; first hit wins.
_RULES: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "credential",
        frozenset(
            {
                "token",
                "secret",
                "password",
                "passwd",
                "credential",
                "credentials",
                "bearer",
                "apikey",
            }
        ),
    ),
    ("command", frozenset({"command", "cmd", "shell", "exec", "script"})),
    ("path", frozenset({"path", "file", "filepath", "filename", "dir", "directory", "folder"})),
    ("url", frozenset({"url", "uri", "endpoint", "host", "hostname", "webhook", "callback"})),
    ("payment_destination", frozenset({"amount", "account", "wallet", "iban", "payee"})),
    ("recipient", frozenset({"recipient", "email", "mailto", "phone", "sms"})),
    ("approval", frozenset({"approve", "approved", "confirm", "consent", "accept"})),
    ("control", frozenset({"mode", "action", "operation", "toggle", "flag", "enabled"})),
    ("selector", frozenset({"selector", "filter", "glob", "pattern", "where"})),
    (
        "content",
        frozenset(
            {
                "content",
                "text",
                "body",
                "message",
                "data",
                "input",
                "value",
                "prompt",
                "note",
                "query",
            }
        ),
    ),
)

_FORMAT_ROLE = {"uri": "url", "uri-reference": "url", "email": "recipient", "hostname": "url"}


def assign_role(arg: ArgRecord, input_schema: dict | None = None) -> str:
    """Classify a single argument's security role."""
    tokens = _tokens(arg.name)

    # special-case: api_key / access_key / private_key tokenize to include "key"
    if "key" in tokens and tokens & {"api", "access", "private", "secret"}:
        return "credential"

    for role, triggers in _RULES:
        if tokens & triggers:
            return role

    # json schema format as a fallback signal
    if input_schema is not None:
        spec = (input_schema.get("properties") or {}).get(arg.name) or {}
        fmt = spec.get("format")
        if isinstance(fmt, str) and fmt in _FORMAT_ROLE:
            return _FORMAT_ROLE[fmt]

    # bare "to" recipient (too short to tokenize meaningfully)
    if arg.name.lower() == "to":
        return "recipient"

    return "unknown"


def assign_roles(tool: ToolRecord) -> ToolRecord:
    """Assign roles to every argument of a tool in place; return the tool."""
    for arg in tool.arguments:
        arg.role = assign_role(arg, tool.input_schema)
    return tool
