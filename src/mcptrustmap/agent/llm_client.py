"""LLM client abstraction with live / replay / record backends.

The *request* is a provider-agnostic dict (purpose, model, and the salient,
hash-stable inputs). `replay` keys recorded responses by a hash of that request
and raises LlmReplayMiss on an unknown one, so prompt/model drift fails CI loudly
instead of silently calling the network. `live` renders the request to an
Anthropic Messages call; `record` invokes a scripted responder to bake cassettes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..errors import LlmReplayMiss, MtmError

# Model configuration (overridable). The gate decision stays on Opus; the panel
# spans tiers in live mode. Fable 5 is deliberately not the default — its safety
# classifiers can false-positive on security tooling.
DEFAULT_MODELS: dict[str, Any] = {
    "reason": "claude-opus-4-8",
    "judge": ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5"],
    "attack": "claude-opus-4-8",
}

Responder = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


def request_hash(request: dict[str, Any]) -> str:
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class LLMClient:
    def __init__(
        self,
        mode: str = "replay",
        *,
        cassettes: dict[str, Any] | None = None,
        responder: Responder | None = None,
        models: dict[str, Any] | None = None,
    ) -> None:
        if mode not in ("live", "replay", "record"):
            raise MtmError(f"unknown llm mode: {mode!r}")
        self.mode = mode
        self.models = models or DEFAULT_MODELS
        self._cassettes = dict(cassettes or {})
        self._responder = responder
        self._recorded: dict[str, Any] = {}

    # --- constructors ---
    @classmethod
    def replay(cls, cassette_dir: str | Path, **kw: Any) -> LLMClient:
        return cls("replay", cassettes=load_cassettes(cassette_dir), **kw)

    @classmethod
    def record(cls, responder: Responder, **kw: Any) -> LLMClient:
        return cls("record", responder=responder, **kw)

    @classmethod
    def live(cls, **kw: Any) -> LLMClient:
        return cls("live", **kw)

    # --- core ---
    def complete(
        self, request: dict[str, Any], *, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        h = request_hash(request)
        if self.mode == "replay":
            entry = self._cassettes.get(h)
            if entry is None:
                raise LlmReplayMiss(
                    f"no cassette for {request.get('purpose')!r} request (hash {h}); "
                    "re-record cassettes after changing prompts/models"
                )
            return entry["response"]
        if self.mode == "record":
            assert self._responder is not None
            response = self._responder(request, context or {})
            self._recorded[h] = {"purpose": request.get("purpose"), "response": response}
            return response
        return self._live_call(request, context or {})  # pragma: no cover - needs API key

    @property
    def cassette_set_hash(self) -> str | None:
        if self.mode == "replay" and self._cassettes:
            joined = ",".join(sorted(self._cassettes))
            return hashlib.sha256(joined.encode()).hexdigest()[:16]
        return None

    def recorded(self) -> dict[str, Any]:
        return dict(self._recorded)

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(
            json.dumps(self._recorded, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _live_call(
        self, request: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:  # pragma: no cover
        from .live import live_complete

        return live_complete(self, request, context)


def load_cassettes(cassette_dir: str | Path) -> dict[str, Any]:
    """Merge every *.json cassette file under a directory into one hash->entry map."""
    merged: dict[str, Any] = {}
    directory = Path(cassette_dir)
    if not directory.exists():
        return merged
    for file in sorted(directory.glob("*.json")):
        data = json.loads(file.read_text(encoding="utf-8"))
        merged.update(data)
    return merged
