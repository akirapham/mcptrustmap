"""LLM-driven adaptive attacker — the *default* probe generator.

The LLM plans the attack (which tool, which arguments, weaponizing the honey
markers/secret, the sink URL, traversal strings, injected commands) against the
authority/authz/provenance boundary. It never decides the verdict — the
deterministic oracles do that from observed behavior. The role-based `probe_plan`
is the fallback when no LLM client is wired (CI without cassettes, or `--attacker
deterministic`).

Driven through the same `LLMClient` as the static reasoning layer: `replay` keys
plans by a hash of the salient inputs (so prompt/model drift fails CI loudly),
`record` bakes cassettes, `live` calls Claude. A captured plan replays exactly,
keeping the whole runtime path deterministic in CI.
"""

from __future__ import annotations

from typing import Any

from ..jsonio import validate
from ..models import ToolRecord
from .honey import HoneySet
from .observe import ToolEffect
from .probes import probe_plan
from .recon import SECRET_KEYWORDS, SECRET_PATHS

ATTACK_PROMPT_VERSION = "rt-attack-1"


def _tool_summaries(tools: list[ToolRecord]) -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "annotations": tool.annotations,
            "arguments": [
                {"name": arg.name, "role": arg.role, "constrained": arg.constrained}
                for arg in tool.arguments
            ],
        }
        for tool in tools
    ]


def _prior_summary(prior: list[ToolEffect] | None) -> list[dict[str, Any]]:
    """A compact, hash-stable digest of what earlier rounds already observed."""
    if not prior:
        return []
    return [
        {
            "tool": eff.tool,
            "authorities": sorted(eff.mutating_authorities()),
            "egress_hosts": sorted({e.host for e in eff.egress}),
            "responded": bool(eff.response),
        }
        for eff in prior
    ]


def build_attack_request(
    tools: list[ToolRecord],
    honey: HoneySet,
    *,
    sink_url: str,
    model: str,
    prior: list[ToolEffect] | None = None,
) -> dict[str, Any]:
    """Provider-agnostic, hash-stable request describing the attack surface + arsenal."""
    return {
        "purpose": "runtime-attack",
        "prompt_version": ATTACK_PROMPT_VERSION,
        "model": model,
        "tools": _tool_summaries(tools),
        "arsenal": {
            "honey_markers": sorted(m for m in honey.markers() if m),
            "honey_secrets": sorted(honey.secrets()),
            "sink_url": sink_url,
            "declared_root": honey.declared_root,
            "exec_payload": honey.exec_payload,
            "exec_tag": honey.exec_tag,
            "exec_factors": list(honey.exec_factors),
            "secret_paths": list(SECRET_PATHS),
            "secret_keywords": list(SECRET_KEYWORDS),
        },
        "prior_effects": _prior_summary(prior),
    }


def parse_attack_plan(
    payload: dict[str, Any], known_tools: set[str]
) -> list[tuple[str, dict[str, Any]]]:
    """Validate a plan and keep only probes that name a real tool."""
    validate(payload, "attack_plan")
    return [
        (probe["tool"], dict(probe["arguments"]))
        for probe in payload["probes"]
        if probe["tool"] in known_tools
    ]


class LLMAttacker:
    """Plans probes via an LLMClient; falls back to deterministic probes if absent."""

    def __init__(self, client: Any | None = None) -> None:
        self.client = client

    def plan(
        self,
        tools: list[ToolRecord],
        honey: HoneySet,
        *,
        sink_url: str,
        prior: list[ToolEffect] | None = None,
    ) -> list[tuple[str, dict[str, Any]]]:
        if self.client is None:
            return probe_plan(tools, honey, sink_url=sink_url)
        model = self.client.models.get("attack", "claude-opus-4-8")
        request = build_attack_request(tools, honey, sink_url=sink_url, model=model, prior=prior)
        response = self.client.complete(request, context={"tools": tools, "honey": honey})
        plan = parse_attack_plan(response, {t.name for t in tools})
        # An empty or all-unknown plan still gets the deterministic floor, so a
        # degenerate LLM response never silently skips the whole surface.
        return plan or probe_plan(tools, honey, sink_url=sink_url)
