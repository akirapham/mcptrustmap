"""Live Anthropic Messages calls for the reasoning + judge layers.

Only used when `--llm-mode live` (needs ANTHROPIC_API_KEY and the `[reason]`
extra). The deterministic gate (cassette replay) is what CI exercises; this path
is for periodic live evaluation and recording. Imports anthropic lazily so the
core never depends on it.
"""

from __future__ import annotations

import importlib
import json
from typing import Any

from ..jsonio import load_schema
from .prompts import ATTACKER_SYSTEM, JUDGE_SYSTEM, REASONER_SYSTEM

# strip the {candidates|verdicts} wrapper to an inline output schema
_REASON_FORMAT = {"type": "json_schema", "schema": load_schema("candidate_finding")}
_JUDGE_FORMAT = {"type": "json_schema", "schema": load_schema("verdict")}
_ATTACK_FORMAT = {"type": "json_schema", "schema": load_schema("attack_plan")}


def live_complete(
    client: Any, request: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any]:  # pragma: no cover
    anthropic = importlib.import_module("anthropic")
    api = anthropic.Anthropic()
    purpose = request["purpose"]
    if purpose == "reason":
        system, fmt, user = REASONER_SYSTEM, _REASON_FORMAT, _reason_user(request, context)
    elif purpose == "judge":
        system, fmt, user = JUDGE_SYSTEM, _JUDGE_FORMAT, _judge_user(request, context)
    elif purpose == "runtime-attack":
        system, fmt, user = ATTACKER_SYSTEM, _ATTACK_FORMAT, _attack_user(request, context)
    else:
        raise ValueError(f"unknown purpose: {purpose!r}")

    message = api.messages.create(
        model=request["model"],
        max_tokens=16000,
        thinking={"type": "adaptive"},
        output_config={"effort": "high", "format": fmt},
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = next((b.text for b in message.content if getattr(b, "type", None) == "text"), "{}")
    return json.loads(text)


def _reason_user(request: dict[str, Any], context: dict[str, Any]) -> str:  # pragma: no cover
    files = context.get("source_files", {})
    blob = "\n\n".join(f"### {rel}\n{content}" for rel, content in files.items())
    tools = json.dumps(request["tools"], indent=2)
    return f"Server: {request['server_id']}\n\nTOOLS:\n{tools}\n\nSOURCE:\n{blob}"


def _judge_user(request: dict[str, Any], context: dict[str, Any]) -> str:  # pragma: no cover
    candidate = json.dumps(request["candidate"], indent=2)
    evidence = json.dumps(context.get("anchor_facts", []), indent=2)
    return f"CANDIDATE:\n{candidate}\n\nEVIDENCE AT ANCHOR:\n{evidence}"


def _attack_user(request: dict[str, Any], context: dict[str, Any]) -> str:  # pragma: no cover
    tools = json.dumps(request["tools"], indent=2)
    arsenal = json.dumps(request["arsenal"], indent=2)
    prior = json.dumps(request.get("prior_effects", []), indent=2)
    return f"TOOLS:\n{tools}\n\nARSENAL:\n{arsenal}\n\nALREADY OBSERVED:\n{prior}"
