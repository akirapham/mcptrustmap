# MCPTrustMap

**Status:** v0.1 implemented — deterministic core + Claude reasoning layer + adversarial verification gate; release gate green (lint, type, 182 tests, replayable CI). **v0.2 (in progress):** a runtime pentest harness — Docker/stdio sandbox + honeytokens + egress sink + LLM-driven attacker + deterministic observed oracles — base built and proven end-to-end (`pentest` CLI; freeze/replay), with **command injection (RCE) proven on a real third-party benchmark (DVMCP challenge 9)**.
**Working name:** MCPTrustMap (`mcptrustmap`)
**Type:** applied-research security tool — **hybrid** (deterministic evidence + Claude reasoning + adversarial verification)

## Quickstart

```bash
uv sync --all-groups

# audit a server (offline manifest + optional source), deterministic + LLM-verified
uv run mcptrustmap audit --manifest examples/manifests/vulnerable.json \
    --source examples/servers/vulnerable-mcp --out build/report.json
uv run mcptrustmap report render build/report.json --format md      # or sarif

# the cross-language hybrid path (gate-verified, from recorded cassettes)
uv run mcptrustmap audit --manifest examples/manifests/js-vulnerable.json \
    --source examples/servers/js-vulnerable --reason --llm-mode replay

# inventory servers across clients; batch a corpus; list the finding registry
uv run mcptrustmap discover --client all --config-root examples/configs
uv run mcptrustmap corpus run --dir examples/corpus
uv run mcptrustmap findings list

# expose `audit` as an MCP tool a frontier agent can call
uv run mcptrustmap serve --transport stdio

# v0.2 runtime pentest: replay a frozen sandbox run, or drive a live server
uv run mcptrustmap pentest --replay tests/fixtures/observations/controlled_vuln.json \
    --manifest tests/fixtures/manifests/controlled_vuln.tools.json \
    --seed e2e --declared-root /honey --fail-on high
# live backends (need the [mcp] extra): --local-command "python server.py", or --image vuln/srv
```

The deterministic core needs no API key and no network; the Claude reasoning
layer runs from recorded cassettes in CI (`--llm-mode replay`) and against the
live API (`--llm-mode live`, needs the `[reason]` extra + `ANTHROPIC_API_KEY`).

MCPTrustMap audits the **authority and authorization trust boundary** of Model Context Protocol (MCP) servers and their tools. Given an MCP server (live, or an offline tool manifest + optional source), it answers:

> What servers are configured across my clients, what authority can each tool exercise, which argument fills which security role, does a tool's *declared* authority match its *actual* authority, is the server's auth wired safely (token passthrough, confused deputy, scope creep, missing consent), is any tool *poisoned*, and does it over-share context — all mapped to the OWASP MCP Top 10?

It is the third leg of a coherent agent-security portfolio:

| Leg | Project | Boundary |
| --- | --- | --- |
| Memory / context | Agent Memory Guard lineage fork | provenance + use-time memory authority |
| Harness / evidence | SecureAHE | coding-agent harness evidence trust |
| **Tool protocol** | **MCPTrustMap** | **tool capability + authorization trust** |

## Hybrid by design

MCPTrustMap is not a pure static scanner and not an "ask-an-LLM" tool. It is a **hybrid** of three cooperating layers:

1. **Deterministic evidence layer** — pure Python, no LLM, no network. Parses client configs, tool manifests, JSON Schemas, server source (Python `ast` + generic lexical), and OAuth config into an **evidence graph** of facts, each pinned to a concrete anchor (`file:line`, `schema-path`, `config-key`). Everything reproducible lives here.
2. **Claude-driven reasoning layer** — an agent (Messages API + client-side, repo-scoped file tools) reads the server source and tool descriptions to produce *candidate findings* for the judgment calls determinism can't settle: cross-language authority, semantic tool poisoning, declared-vs-actual reasoning, scope-vs-need. Every candidate must cite a concrete anchor.
3. **Adversarial verification gate** — every candidate is re-checked twice: its anchor must re-resolve against the deterministic evidence graph, **and** an independent Claude judge panel (perspective-diverse, prompted to refute) must fail to kill it. Survive both, or be dropped. This is the generator–verifier / LLM-as-judge pattern: the LLM proposes, determinism + an adversarial panel dispose.

The payoff: deterministic findings are reproducible by construction; LLM findings get the reach to handle any language and genuinely semantic poisoning, but can never enter a report without a fact a human can re-check by hand.

## What makes this distinctive (not "another MCP scanner")

A deep-research review (2026-06-14, adversarially verified) established the landscape. MCPTrustMap builds the **full** scanner surface — config inventory, tool/schema poisoning, supply-chain, shadow servers — to parity with the field, and adds the layer the field lacks:

- **The crowded part (built fully, credited):** deterministic config inventory and tool/schema-poisoning detection are also done by **AgentAuditKit** (offline AST+regex, 26 poisoning rules), **MCP-Scan / Snyk Agent Scan** (poisoning, rug-pulls, shadowing, prompt injection), and **apisec mcp-audit** (multi-client inventory, coarse 4-tier capability risk). We build these as first-class features and credit prior art in the report — coverage parity is table stakes.
- **The under-served part (our distinctive contribution):** **per-tool authority taxonomy**, **per-argument role classification**, **declared-vs-actual authority mismatch**, and **authorization anti-pattern auditing** (token passthrough, confused deputy, scope minimization, consent). Snyk Agent Scan (the hybrid successor to mcp-scan) targets the same MCP-authority threat class, but — like apisec mcp-audit (coarse capability tiers) and AgentAuditKit — **publishes no benchmark, precision, or recall**. So two things distinguish MCPTrustMap: **(1)** the transparent, anchored, gate-verified authority/authz analysis itself, and **(2)** a **published labeled benchmark with measured precision/recall and judge-vs-human agreement** — which no surveyed MCP security tool ships. The hybrid architecture makes (1) tractable across languages (the LLM layer reasons about authority where `ast` can't reach, and the gate keeps it honest); the published metrics make (2) the credibility moat.

So MCPTrustMap ships the whole map, and **leads** on the authority/authorization layer — reusing the per-argument-role authority primitive proven in the Agent Memory Guard fork and applying it to MCP tools.

## Grounding (sources)

- **OWASP MCP Top 10** (`MCP01`–`MCP10:2025`) — a *real but beta/v0.1 Incubator* project; cite as emerging, not finalized. Items: MCP01 Token Mismanagement, MCP02 Scope Creep, MCP03 Tool Poisoning, MCP04 Supply Chain, MCP05 Command Injection, MCP06 Intent-Flow Subversion, MCP07 Authn/Authz, MCP08 Audit/Telemetry, MCP09 Shadow Servers, MCP10 Context Over-Sharing. (`owasp.org/www-project-mcp-top-10`)
- **MCP security best practices** (official spec) — documents every authorization anti-pattern we target at MUST level: confused deputy, token-passthrough (forbidden), exact redirect-URI match, per-client consent, scope minimization, correlation-ID logging. *Caveat:* the redirect-URI/consent MUSTs apply specifically to **proxy / OAuth servers**, and logging is scoped to scope-elevation — not blanket telemetry. (`modelcontextprotocol.io/docs/tutorials/security/security_best_practices`)
- **Tool annotations are untrusted** — a server may declare `readOnlyHint: true` and still mutate state; clients MUST treat annotations as untrusted unless from a trusted server. This is the central feasibility constraint and the source of our most novel check (declared-vs-actual mismatch). (`blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations`, `modelcontextprotocol.io/specification/2025-06-18/server/tools`)
- **Anthropic Claude API** (for the reasoning + gate layers) — Messages API + tool use (manual agentic loop with client-side repo tools), structured outputs, prompt caching; `claude-opus-4-8` for reasoning and the gate decision, `claude-sonnet-4-6`/`claude-haiku-4-5` for panel breadth. `claude-fable-5` is deliberately avoided as the default (its safety classifiers can false-positive on security tooling). Model IDs are configurable.
- **LLM-as-judge reliability research** — single LLM judges show position, self-enhancement, and self-inconsistency biases (MT-Bench and judge-bias studies); weighted verifier ensembles beat naive averaging (Weaver); vulnerability benchmarks suffer label-quality problems. This grounds the gate design: the **deterministic anchor is primary**, the LLM panel is a **weighted, diverse-tier secondary check**, and credibility rests on a **hand-authored oracle + measured judge-vs-human agreement**, not on trusting the model. (Deployment is likewise grounded: standalone scanners dominate the field — Snyk Agent Scan, apisec — and Semgrep ships its scanner *as an MCP server*, the precedent for our `serve` entrypoint.)

## In scope (v0.1) — all first-class, nothing deferred

- **Multi-client config inventory** (Claude Desktop, Cursor, Windsurf, VS Code/Cline, generic stdio/URL) with **shadow-server** and **supply-chain** detection.
- **Tool / schema poisoning** detection — deterministic markers (hidden instructions, unicode obfuscation, name spoofing, tool shadowing) **plus** LLM semantic judgment, gate-verified.
- Per-tool **authority classification** and per-argument **role classification**.
- **Declared-vs-actual authority mismatch** — Python `ast`-grounded and cross-language LLM-reasoned (gate-verified).
- **Authorization anti-pattern** audit (token passthrough, confused deputy, scope creep, missing consent, lax redirect-URI, static client id, missing scope-elevation telemetry).
- **Context over-sharing** audit (resources/prompts exposed without scoping).
- **Evidence reports** in **JSON, Markdown, and SARIF** (all first-class), finding IDs mapped to OWASP MCP Top 10.
- **Batch / corpus mode** and an **empirical-study harness** that runs the tooling over real servers and reports prevalence.
- **Live MCP ingestion** via the official MCP SDK.
- **Claude reasoning layer** with an **adversarial verification gate**, and **record/replay cassettes** so the agent layer runs deterministically in CI.
- A **thin MCP-server entrypoint** (`mcptrustmap serve`) exposing `audit` as an MCP tool a frontier agent can call before connecting to a server — a real distribution pattern, not a gimmick (Semgrep ships its scanner as an MCP server the same way).
- A **published labeled benchmark** (acceptance corpus + held-out recall + measured precision/recall + judge-vs-human agreement) — the credibility artifact none of the comparable MCP tools provide.

## Out of scope for v0.1

- Runtime/dynamic interception or live exploitation (analysis, not attack).
- Claiming to "secure MCP," to fully assess authority from schema alone, or coverage of the *finalized* OWASP MCP Top 10 (it is beta).
- Treating LLM judgment as ground truth — it is anchored to deterministic facts and adversarially gated, never trusted on its own.
- Supporting every client — v0.1 targets Claude Desktop, Cursor, Windsurf, VS Code/Cline, and a generic stdio/URL config.

## Roadmap shape (layers within v0.1, then beyond)

```
Layer 1  Tool                → the hybrid auditor (this plan, v0.1)
Layer 2  + research framing  → OWASP-MCP mapping + crafted benchmark (same repo, v0.1)
Layer 3  + empirical study   → run over real MCP servers, report prevalence (same repo, v0.1)
```

All three layers land in v0.1: the tool is built **with the study in mind** (batch mode + machine-readable output from day one), and the study harness (`study run`) plus a prevalence writeup ship with it. Post-v0.1 work (more clients, runtime analysis, CI integrations) is genuinely later.

## Primary artifacts

- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) — product target, threat model + OWASP mapping, hybrid architecture, the Claude reasoning/gate layers pinned to the current API, framework reuse, schemas, CLI, code structure, build-order phases.
- [ACCEPTANCE_CRITERIA.md](ACCEPTANCE_CRITERIA.md) — binding definition of done per feature, finding families, the LLM-layer + gate criteria, reports.
- [TEST_PLAN.md](TEST_PLAN.md) — validation layers, fixtures, cassette strategy, metrics, release gates, exact commands.

## Implementation status

v0.1 is built and the [TEST_PLAN](TEST_PLAN.md) release gate is green. The
deterministic evidence + detector core (ingestion → evidence graph →
deterministic findings → validated report) is the backbone; the Claude reasoning
layer and verification gate sit on top and are reproducible in CI via recorded
cassettes. Live MCP connection, SARIF, the agent layer, the MCP-server
entrypoint, and the empirical-study harness all ship in v0.1 — and the
deterministic core alone satisfies the acceptance matrix, so the tool degrades
safely with the LLM layer disabled (`--no-reason`). Source layout and the
12-phase build are documented in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
