"""Schema-declared authority classification (the *declared*, untrusted side).

Infers the authority classes a tool *claims* from its name, description,
annotations, and argument roles. This is the declared side of the
declared-vs-actual mismatch check — never treated as ground truth.
"""

from __future__ import annotations

import re

from ..models import ToolRecord

_SPLIT = re.compile(r"[^a-z0-9]+")

# keyword -> authority class (matched against name+description tokens)
_KEYWORDS: dict[str, str] = {}


def _register(cls: str, words: list[str]) -> None:
    for w in words:
        _KEYWORDS[w] = cls


_register("command_exec", ["run", "exec", "execute", "shell", "command", "spawn", "subprocess"])
_register("write", ["write", "update", "edit", "modify", "set", "save", "patch", "append"])
_register("filesystem", ["delete", "remove", "unlink", "rmdir", "mkdir", "chmod", "move", "rename"])
_register("read", ["read", "get", "list", "fetch", "view", "show", "load", "cat"])
_register("network", ["http", "request", "download", "curl", "webhook", "post", "api"])
_register("credential_access", ["secret", "credential", "token", "password", "apikey", "keychain"])
_register("database", ["sql", "query", "database", "insert", "select", "db", "mongo", "postgres"])
_register("browser", ["browser", "navigate", "click", "screenshot", "selenium", "playwright"])
_register("payment", ["pay", "payment", "charge", "transfer", "invoice", "checkout"])
_register("email", ["email", "smtp", "sendmail", "mailto"])
_register("repo_mutation", ["commit", "push", "merge", "pullrequest", "branch", "git"])
_register("cloud_mutation", ["deploy", "provision", "terraform", "kubectl", "aws", "gcloud"])

# argument role -> authority class implied
_ROLE_AUTHORITY: dict[str, str] = {
    "command": "command_exec",
    "credential": "credential_access",
    "payment_destination": "payment",
    "url": "network",
    "path": "filesystem",
    "recipient": "email",
}


def _text_tokens(tool: ToolRecord) -> set[str]:
    text = f"{tool.name} {tool.description or ''}"
    return {t for t in _SPLIT.split(text.lower()) if t}


def classify_declared_authority(tool: ToolRecord) -> list[str]:
    """Return the sorted, de-duplicated declared authority classes for a tool."""
    classes: set[str] = set()

    for token in _text_tokens(tool):
        cls = _KEYWORDS.get(token)
        if cls:
            classes.add(cls)

    for arg in tool.arguments:
        cls = _ROLE_AUTHORITY.get(arg.role)
        if cls is None:
            continue
        # an enum/pattern-constrained command or path is a selector, not free authority
        if arg.role in ("command", "path") and arg.constrained:
            continue
        classes.add(cls)

    # annotations are a (weak, untrusted) signal: destructiveHint implies write
    if tool.annotations.get("destructiveHint") is True:
        classes.add("write")

    # a tool that only reads should still surface `read` if nothing else matched
    if not classes and tool.annotations.get("readOnlyHint") is True:
        classes.add("read")

    return sorted(classes)
