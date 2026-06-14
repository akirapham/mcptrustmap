"""Runtime: the static->runtime declared-authority bridge."""

from __future__ import annotations

from mcptrustmap.models import ArgRecord, ToolRecord
from mcptrustmap.runtime.harness import declared_from_tools


def test_declared_map_merges_role_and_text_authority():
    fetch = ToolRecord(
        name="fetch",
        description="Fetch a URL with a key",
        arguments=[ArgRecord(name="url", role="url"), ArgRecord(name="api_key", role="credential")],
    )
    declared = declared_from_tools([fetch])["fetch"]
    # url arg -> network, credential arg -> credential_access, "fetch" verb -> read
    assert {"network", "credential_access"} <= declared["authority"]
    assert declared["read_only"] is False


def test_declared_map_extracts_readonly_hint():
    audit = ToolRecord(
        name="audit_log",
        description="Append an audit note",
        annotations={"readOnlyHint": True},
        arguments=[ArgRecord(name="note", role="content")],
    )
    declared = declared_from_tools([audit])["audit_log"]
    assert declared["read_only"] is True
    assert declared["authority"]  # "append" -> write; it claims some authority


def test_readonly_hint_with_no_other_class_surfaces_read():
    echo = ToolRecord(
        name="echo", description="echo back", annotations={"readOnlyHint": True}
    )
    assert declared_from_tools([echo])["echo"]["authority"] == {"read"}
