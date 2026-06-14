"""Phase 1: manifest parsing into validated ToolRecord[]."""

from __future__ import annotations

import json

import pytest

from mcptrustmap.errors import InputError, SchemaValidationError
from mcptrustmap.ingest.manifest import arguments_from_schema, parse_manifest


def test_vulnerable_manifest_parses(manifests_dir):
    tools = parse_manifest(manifests_dir / "vulnerable.json")
    by_name = {t.name: t for t in tools}
    assert set(by_name) == {"run_shell", "read_file", "store_credential", "echo"}

    run_shell = by_name["run_shell"]
    assert run_shell.annotations.get("readOnlyHint") is False
    (cmd_arg,) = run_shell.arguments
    assert cmd_arg.name == "command"
    assert cmd_arg.json_type == "string"
    assert cmd_arg.constrained is False
    assert cmd_arg.schema_path == "properties/command"
    assert cmd_arg.role == "unknown"  # roles assigned in Phase 2

    cred = by_name["store_credential"]
    assert {a.name for a in cred.arguments} == {"api_key", "name"}


def test_benign_manifest_constrained_arg(manifests_dir):
    tools = parse_manifest(manifests_dir / "benign.json")
    set_mode = next(t for t in tools if t.name == "set_mode")
    (arg,) = set_mode.arguments
    assert arg.name == "command"
    assert arg.constrained is True  # enum-constrained -> not a free-form command


def test_arguments_from_schema_detects_constraints():
    schema = {
        "type": "object",
        "properties": {
            "free": {"type": "string"},
            "enumed": {"type": "string", "enum": ["a", "b"]},
            "patterned": {"type": "string", "pattern": "^x"},
        },
    }
    args = {a.name: a for a in arguments_from_schema(schema)}
    assert args["free"].constrained is False
    assert args["enumed"].constrained is True
    assert args["patterned"].constrained is True


def test_no_properties_yields_no_args():
    assert arguments_from_schema({"type": "object"}) == []


def test_missing_tools_key_fails_closed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"servers": []}))
    with pytest.raises(SchemaValidationError):
        parse_manifest(bad)


def test_invalid_json_fails_closed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(InputError):
        parse_manifest(bad)
