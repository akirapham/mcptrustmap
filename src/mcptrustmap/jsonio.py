"""JSON/JSONL/YAML loading + JSON Schema validation, all fail-closed.

Output is deterministic (sorted keys, fixed indent, no timestamps) so reports
re-run byte-identically and prompt prefixes stay cache-stable.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .errors import InputError, SchemaValidationError

_SCHEMA_DIR = Path(__file__).parent / "schemas"


def load_json(path: str | Path) -> Any:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {p}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {p}: {exc}") from exc


def load_yaml(path: str | Path) -> Any:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {p}: {exc}") from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InputError(f"invalid YAML in {p}: {exc}") from exc


@cache
def load_schema(name: str) -> dict[str, Any]:
    path = _SCHEMA_DIR / f"{name}.schema.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:  # pragma: no cover - packaging error
        raise InputError(f"missing schema {name!r}: {exc}") from exc


def validate(instance: Any, schema_name: str) -> None:
    """Validate `instance` against a named schema; raise on the first errors."""
    validator = Draft202012Validator(load_schema(schema_name))
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        loc = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise SchemaValidationError(
            f"{schema_name} schema violation at {loc}: {first.message}"
            + (f" (+{len(errors) - 1} more)" if len(errors) > 1 else "")
        )


def dumps(obj: Any) -> str:
    """Deterministic JSON string: sorted keys, 2-space indent, trailing newline."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(obj: Any, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(dumps(obj), encoding="utf-8")
