"""Phase 2: per-argument role classification."""

from __future__ import annotations

import pytest

from mcptrustmap.evidence.roles import assign_role
from mcptrustmap.models import ArgRecord


def _arg(name: str) -> ArgRecord:
    return ArgRecord(name=name)


@pytest.mark.parametrize(
    "name,expected",
    [
        ("command", "command"),
        ("cmd", "command"),
        ("shell_command", "command"),
        ("path", "path"),
        ("file_path", "path"),
        ("filename", "path"),
        ("api_key", "credential"),
        ("apiKey", "credential"),
        ("access_token", "credential"),
        ("password", "credential"),
        ("secret", "credential"),
        ("url", "url"),
        ("endpoint", "url"),
        ("webhook_url", "url"),
        ("recipient", "recipient"),
        ("email", "recipient"),
        ("to", "recipient"),
        ("amount", "payment_destination"),
        ("wallet", "payment_destination"),
        ("confirm", "approval"),
        ("consent", "approval"),
        ("mode", "control"),
        ("content", "content"),
        ("text", "content"),
        ("message", "content"),
        ("query", "content"),
        ("name", "unknown"),
        ("profile", "unknown"),  # tokenization must NOT match "file" inside "profile"
        ("xyz", "unknown"),
    ],
)
def test_role_assignment(name, expected):
    assert assign_role(_arg(name)) == expected


def test_format_fallback_url():
    schema = {"properties": {"target": {"type": "string", "format": "uri"}}}
    assert assign_role(_arg("target"), schema) == "url"


def test_format_fallback_email():
    schema = {"properties": {"dest": {"type": "string", "format": "email"}}}
    assert assign_role(_arg("dest"), schema) == "recipient"
