#!/usr/bin/env python
"""Record real LLM attack plans for the in-scope DVMCP challenges (maintainer tool).

Runs each wired challenge with the LLM attacker in *live* mode, so Claude itself
plans the probes; the request/response is captured into a cassette and the
resulting Observation is re-frozen. Each plan must actually trip the ground-truth
finding — otherwise the run fails loudly. Afterwards CI can prove "the model did
it" with no key (replay the cassette) and no DVMCP checkout (replay the frozen
observation).

The attacker is provider-agnostic (the verdict is the deterministic oracle, not the
model). Provider + model are auto-selected from the available key, or forced via env:

    # Claude (default if ANTHROPIC_API_KEY set):
    MTM_DVMCP_ROOT=/path/to/dvmcp uv run python scripts/record_attack_cassettes.py
    # OpenAI:
    MTM_ATTACK_PROVIDER=openai MTM_ATTACK_MODEL=gpt-4o \
        MTM_DVMCP_ROOT=/path/to/dvmcp uv run python scripts/record_attack_cassettes.py

Prereqs: a DVMCP checkout, the `mcp` extra, and the chosen provider's key + SDK.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcptrustmap.agent.live import live_complete  # noqa: E402
from mcptrustmap.agent.llm_client import DEFAULT_MODELS, LLMClient  # noqa: E402
from mcptrustmap.agent.openai_live import openai_complete  # noqa: E402
from mcptrustmap.audit import dedupe  # noqa: E402
from mcptrustmap.runtime.attacker import LLMAttacker  # noqa: E402
from mcptrustmap.runtime.dvmcp import CHALLENGES, capture_challenge  # noqa: E402
from mcptrustmap.runtime.oracles import run_oracles  # noqa: E402

OBS_DIR = ROOT / "tests" / "fixtures" / "observations"
CASSETTE = ROOT / "tests" / "cassettes" / "dvmcp_attack.json"
_DEFAULT_MODEL = {"anthropic": "claude-opus-4-8", "openai": "gpt-4o"}


def _pick_provider() -> tuple[str, str] | None:
    forced = os.environ.get("MTM_ATTACK_PROVIDER")
    if forced:
        provider = forced
    elif os.environ.get("ANTHROPIC_API_KEY"):
        provider = "anthropic"
    elif os.environ.get("OPENAI_API_KEY"):
        provider = "openai"
    else:
        return None
    return provider, os.environ.get("MTM_ATTACK_MODEL") or _DEFAULT_MODEL[provider]


def main() -> int:
    dvmcp_root = os.environ.get("MTM_DVMCP_ROOT")
    if not dvmcp_root:
        print("set MTM_DVMCP_ROOT to a DVMCP checkout", file=sys.stderr)
        return 2
    picked = _pick_provider()
    if picked is None:
        print("set ANTHROPIC_API_KEY or OPENAI_API_KEY for the planner", file=sys.stderr)
        return 2
    provider, model = picked

    def responder(request, context):
        # record mode + a live-calling responder = live-and-record: the plan the
        # model returns is stored in the cassette, keyed by the (port-stable) hash.
        if provider == "openai":
            return openai_complete(None, request, context)
        return live_complete(None, request, context)

    print(f"recording with provider={provider} model={model}")
    client = LLMClient.record(responder, models={**DEFAULT_MODELS, "attack": model})
    attacker = LLMAttacker(client)

    for cid in sorted(CHALLENGES):
        ch = CHALLENGES[cid]
        if not (Path(dvmcp_root) / ch.subpath / "server.py").exists():
            print(f"skip {cid}: not in checkout")
            continue
        observation, honey = capture_challenge(ch, dvmcp_root, attacker=attacker)
        findings = dedupe(run_oracles(f"dvmcp:{cid}", observation, honey, declared=ch.declared))
        ids = {f.finding_id for f in findings}
        if ch.expect not in ids:
            print(f"FAIL {cid}: Claude's plan did not trip {ch.expect} (got {sorted(ids)})")
            return 1
        out = OBS_DIR / f"dvmcp_{cid}.json"
        out.write_text(json.dumps(observation.to_dict(), indent=2, sort_keys=True) + "\n")
        print(f"ok {cid}: {ch.expect} via Claude's own plan -> re-froze {out.name}")

    client.save(CASSETTE)
    print(f"wrote {len(client.recorded())} attack cassette(s) -> {CASSETTE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
