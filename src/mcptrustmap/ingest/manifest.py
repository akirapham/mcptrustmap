"""Parse an offline `tools/list` JSON manifest into validated ToolRecord[]."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..jsonio import load_json, validate
from ..models import ArgRecord, ToolRecord

# JSON Schema keywords that constrain a value (presence => argument is constrained)
_CONSTRAINT_KEYS = frozenset(
    {"enum", "const", "pattern", "format", "minimum", "maximum", "minLength", "maxLength", "items"}
)


def arguments_from_schema(input_schema: dict[str, Any]) -> list[ArgRecord]:
    """Extract ArgRecord[] from a tool inputSchema (role assigned later, in Phase 2)."""
    props = input_schema.get("properties")
    if not isinstance(props, dict):
        return []
    args: list[ArgRecord] = []
    for name, spec in props.items():
        spec = spec if isinstance(spec, dict) else {}
        json_type = spec.get("type")
        constrained = any(k in spec for k in _CONSTRAINT_KEYS)
        args.append(
            ArgRecord(
                name=name,
                json_type=json_type if isinstance(json_type, str) else None,
                schema_path=f"properties/{name}",
                constrained=constrained,
                description=spec.get("description"),
            )
        )
    return args


def tool_from_entry(entry: dict[str, Any]) -> ToolRecord:
    input_schema = entry.get("inputSchema") or {}
    return ToolRecord(
        name=entry["name"],
        description=entry.get("description"),
        input_schema=input_schema,
        annotations=entry.get("annotations") or {},
        arguments=arguments_from_schema(input_schema),
    )


def parse_manifest(path: str | Path) -> list[ToolRecord]:
    """Load + schema-validate a manifest, return ToolRecord[]. Fails closed."""
    data = load_json(path)
    validate(data, "manifest")
    return [tool_from_entry(e) for e in data["tools"]]
