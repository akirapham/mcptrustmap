"""OpenAI backend for the runtime attacker — the planner is provider-agnostic.

The deterministic oracle is the contribution and the invariant; the attacker is a
swappable frontier LLM. This drives the `runtime-attack` purpose via OpenAI so the
planner can be validated/recorded with an OpenAI key. Claude stays the default for
the static reasoning + judge layers (those are not wired here). Imports openai
lazily; only ever used in `live` mode or by the cassette recorder.

JSON-object mode (not strict json_schema) is deliberate: a probe's `arguments` is a
free-form object, which OpenAI strict structured outputs disallow. The plan is
validated against our `attack_plan` schema downstream (`parse_attack_plan`), so a
malformed response still fails closed.
"""

from __future__ import annotations

import importlib
import json
from typing import Any

from .live import _attack_user
from .prompts import ATTACKER_SYSTEM

_JSON_SHAPE = (
    '\n\nReturn ONLY a JSON object of exactly this shape:\n'
    '{"probes": [{"tool": "<tool name>", "arguments": {"<arg>": <value>}, '
    '"rationale": "<one line>"}]}'
)


def openai_complete(
    _client: Any, request: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any]:  # pragma: no cover - needs OPENAI_API_KEY
    if request["purpose"] != "runtime-attack":
        raise ValueError(f"openai backend supports runtime-attack only, got {request['purpose']!r}")
    openai = importlib.import_module("openai")
    api = openai.OpenAI()
    resp = api.chat.completions.create(
        model=request["model"],
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": ATTACKER_SYSTEM + _JSON_SHAPE},
            {"role": "user", "content": _attack_user(request, context)},
        ],
    )
    return json.loads(resp.choices[0].message.content or "{}")
