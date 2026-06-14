# MCPTrustMap — Implementation Plan

**Status:** implementation specification (binding once approved)
**Date:** 2026-06-14
**Tool:** `mcptrustmap`
**Architecture:** hybrid — deterministic evidence layer + Claude-driven reasoning layer + adversarial verification gate

## 1. Product target

MCPTrustMap is a **hybrid agentic auditor** for the **authority and authorization trust boundary** of MCP servers — built to the full scope of the original pitch (config inventory, tool/schema poisoning, authority/authz, over-sharing, SARIF, live connection, empirical study), with the authority/authorization layer as its distinctive contribution.

"Hybrid" means three cooperating layers, in order:

1. a **deterministic evidence layer** — pure-Python, no LLM, no network: it parses client configs, tool manifests, JSON Schemas, server source (Python `ast` + generic lexical), and OAuth config into an **evidence graph** of facts, each pinned to a concrete anchor (`file:line`, `schema-path`, or `config-key`). Everything reproducible lives here.
2. a **Claude-driven reasoning layer** — an agent that reads the server source and tool descriptions to produce *candidate findings* for the judgment-heavy questions determinism can't fully settle (cross-language authority, semantic tool/schema poisoning, declared-vs-actual reasoning, scope-vs-need). Every candidate must cite a concrete evidence anchor.
3. an **adversarial verification gate** — every candidate finding is re-checked two ways: (a) its cited anchor must re-resolve against the deterministic evidence graph, and (b) an independent Claude judge panel, prompted to refute, must fail to kill it. A candidate survives only if its anchor resolves **and** the panel does not refute it. This is the generator–verifier / LLM-as-judge pattern.

v0.1 ships, as first-class features (nothing deferred):

- **multi-client config inventory** (Claude Desktop, Cursor, Windsurf, VS Code/Cline, generic stdio/URL) with shadow-server and supply-chain detection,
- **tool/schema poisoning** detection (deterministic markers + LLM semantic judgment, gate-verified),
- per-tool **authority classification** and per-argument **role classification**,
- **declared-vs-actual** authority mismatch (Python `ast`-grounded + cross-language LLM, gate-verified),
- **authorization anti-pattern** audit (token passthrough, confused deputy, scope creep, consent, redirect-URI, client-id, scope-elevation telemetry),
- **context over-sharing** audit,
- a **findings registry** mapped to the OWASP MCP Top 10 (beta/v0.1),
- **evidence reports** in **JSON, Markdown, and SARIF** (all first-class),
- **single-server and batch/corpus** modes,
- **live MCP ingestion** via the official MCP SDK,
- a **thin MCP-server entrypoint** (`mcptrustmap serve`) exposing `audit` as an MCP tool a frontier agent can call before connecting to a server (Semgrep-MCP precedent — a real distribution pattern, not a gimmick),
- an **empirical-study harness** that runs the corpus tooling over real-world servers and reports prevalence,
- a **published labeled benchmark** with measured precision/recall and judge-vs-human agreement — which no surveyed MCP security tool currently ships.

The v0.1 claim is narrow and defensible:

> MCPTrustMap classifies the authority each MCP tool can exercise and the security role of each argument, detects when a tool's declared authority contradicts its actual authority, audits MCP authorization anti-patterns and tool poisoning, and inventories servers across clients — producing evidence-backed findings mapped to the OWASP MCP Top 10 (beta). Deterministic findings are reproducible by construction; every LLM-derived finding is anchored to a concrete source/schema fact and survives an adversarial verification gate or is dropped.

## 2. Threat model and OWASP MCP Top 10 mapping

The boundary: an agent connects to MCP servers and lets tools act on its behalf. The questions per server/tool: *what servers are even configured, what can each tool do, what untrusted input steers that authority, does a tool's self-description match reality, is its auth wired safely, and does it leak context?*

Audited dimensions → finding families → OWASP MCP Top 10 (beta). The **layer** column records which layer produces each family — deterministic (D), LLM-reasoned + gate-verified (L), or both (D+L):

| Dimension | Finding family (prefix `MTM-`) | OWASP MCP | Layer |
| --- | --- | --- | --- |
| **Authority taxonomy** (per tool) | `MTM-UNDECLARED-MUTATION`, `MTM-HIGH-AUTHORITY-TOOL` | MCP02, MCP07 | D+L |
| **Argument roles** (per arg) | `MTM-UNCONSTRAINED-COMMAND-ARG`, `MTM-UNCONSTRAINED-PATH-ARG`, `MTM-CREDENTIAL-ARG-EXPOSED` | MCP05, MCP07 | D |
| **Declared-vs-actual mismatch** *(core novelty)* | `MTM-AUTHORITY-MISMATCH` | MCP02, MCP03, MCP07 | D+L |
| **Authorization anti-patterns** | `MTM-TOKEN-PASSTHROUGH`, `MTM-CONFUSED-DEPUTY`, `MTM-SCOPE-CREEP`, `MTM-MISSING-CONSENT`, `MTM-LAX-REDIRECT-URI`, `MTM-STATIC-CLIENT-ID` | MCP01, MCP02, MCP07 | D+L |
| **Audit/telemetry** | `MTM-MISSING-SCOPE-ELEVATION-LOG` | MCP08 | D+L |
| **Context over-sharing** | `MTM-CONTEXT-OVERSHARING`, `MTM-UNSCOPED-RESOURCE` | MCP10 | D+L |
| **Tool / schema poisoning** (first-class) | `MTM-TOOL-POISONING` (sub-types: hidden-instruction, name-spoofing, unicode-obfuscation, tool-shadowing) | MCP03, MCP06 | D+L |
| **Inventory / shadow servers** (first-class) | `MTM-SHADOW-SERVER`, `MTM-CROSS-ORIGIN-COLLISION` | MCP09 | D |
| **Supply chain** (first-class) | `MTM-UNPINNED-SERVER-PACKAGE`, `MTM-UNTRUSTED-SERVER-SOURCE` | MCP04 | D |

Positioning note: every dimension is built fully and competitively. The **authority / argument-role / declared-vs-actual / authorization** rows remain the *distinctive* contribution (no surveyed competitor classifies per-tool authority, per-argument roles, or audits declared-vs-actual mismatch and authz anti-patterns — see [README](README.md)); the inventory and poisoning rows are built to parity with AgentAuditKit/MCP-Scan and credited, not skipped. We never claim coverage of the *finalized* Top 10 — it is beta.

Honest caveats baked into rules (from the grounding):
- Redirect-URI exact-match and per-client consent are MUSTs **for proxy/OAuth servers** → those rules only fire when OAuth/proxy config is present; otherwise `not_applicable`.
- Audit-telemetry MUST is scoped to **scope-elevation events**, not blanket logging → the finding is `MTM-MISSING-SCOPE-ELEVATION-LOG`, not "no telemetry".
- Tool annotations are untrusted → authority is never trusted from the schema alone; the schema is the *declared* side of the mismatch check.
- LLM judgment never stands alone → an LLM finding without a re-resolvable deterministic anchor is dropped by the gate, never reported.

## 3. Authority and role model (reused from the Agent Memory Guard fork)

The per-argument role + minimum-authority model is proven in the AMG lineage/authority fork and ports directly. It is shared by the deterministic layer (schema-declared classification) and the LLM layer (the agent emits findings in the same vocabulary, so candidates and deterministic facts are directly comparable).

**Tool authority classes** (what a tool can do): `read`, `write`, `command_exec`, `network`, `filesystem`, `credential_access`, `database`, `browser`, `payment`, `email`, `repo_mutation`, `cloud_mutation`, `unknown`. Each has a default severity weight; `command_exec`, `credential_access`, `payment`, `cloud_mutation` are high-authority.

**Argument roles** (security role an argument plays): `content`, `target`, `path`, `command`, `url`, `recipient`, `credential`, `selector`, `approval`, `payment_destination`, `control`, `unknown`. `content` is benign; the rest are authority-bearing (mirrors the AMG authority gate).

**Authority sources for a tool** (in increasing trust):
1. `schema_declared` — name, description, `inputSchema`, annotations (`readOnlyHint`, `destructiveHint`, …). *Untrusted.*
2. `source_inferred` — analysis of the server's command/source (what the tool actually calls). Two sub-sources: **`ast`** (Python, deterministic, line-accurate) and **`llm`** (cross-language reasoning, gate-verified, anchored to `file:line`).
3. `operator_asserted` — an optional policy file where the operator states intended authority (acts as ground truth for mismatch).

The **mismatch** finding fires when `source_inferred` authority exceeds `schema_declared` (e.g., `readOnlyHint: true` but `os.remove` present), or when either exceeds `operator_asserted`. For Python the inference is `ast`-grounded (high confidence); for other languages it is LLM-reasoned and only survives if the gate re-resolves the cited line.

## 4. Architecture and code structure

Principles: deterministic **pure-core** separated from **I/O** and from **LLM**; schema-validated boundaries; a single **findings registry** as source of truth; reports validated before emission; every LLM finding anchored to a deterministic fact and gated; the LLM client is an abstraction with live and record/replay backends so the agent layer is testable without network or API key.

```text
tools-impl/mcptrustmap/
  README.md  IMPLEMENTATION_PLAN.md  ACCEPTANCE_CRITERIA.md  TEST_PLAN.md
  pyproject.toml
  src/mcptrustmap/
    __init__.py
    cli.py                 # single entry point: `mcptrustmap`
    errors.py              # MtmError / SchemaValidationError / LlmReplayMiss
    jsonio.py              # JSON/JSONL/YAML load + JSON Schema validation
    models.py              # dataclasses: ServerRecord, ToolRecord, ArgRecord, Finding, CandidateFinding, Verdict
    findings.py            # finding-ID registry: id -> {owasp, spec_ref, severity, title, recommendation}
    policy.py              # authority classes, argument roles, severities, decisions
    # --- ingestion (I/O boundary) ---
    ingest/
      __init__.py
      discovery.py         # multi-client config inventory -> ServerRecord[] (first-class)
      manifest.py          # offline tools/list JSON -> ToolRecord[]
      connect.py           # live MCP ingestion via official MCP SDK (first-class; transcripts recorded for tests)
    # --- deterministic evidence layer (pure: no LLM, no network) ---
    evidence/
      __init__.py
      graph.py             # EvidenceGraph: facts keyed by anchor (file:line / schema-path / config-key)
      authority.py         # schema-declared authority classification
      roles.py             # per-argument role classification
      source/
        __init__.py
        python_ast.py      # Python authority facts via stdlib `ast` (line-accurate)
        generic_regex.py   # non-Python lexical facts (curated patterns)
      oauth.py             # OAuth / proxy config facts
      poisoning.py         # deterministic poisoning markers (hidden-instruction / unicode / name-spoof / shadowing)
      inventory.py         # shadow-server / allow-list / supply-chain facts
    # --- deterministic detectors (consume the evidence graph) ---
    detect/
      __init__.py
      arguments.py         # MTM-UNCONSTRAINED-*-ARG, MTM-CREDENTIAL-ARG-EXPOSED
      mismatch.py          # MTM-AUTHORITY-MISMATCH / -UNDECLARED-MUTATION (ast-grounded path)
      authz.py             # token passthrough / confused deputy / scope creep / consent / redirect / client-id
      oversharing.py       # context over-sharing (config/schema-grounded)
      poisoning.py         # deterministic poisoning findings
      inventory.py         # shadow-server / cross-origin-collision / supply-chain findings
    # --- LLM / agent reasoning layer ---
    agent/
      __init__.py
      llm_client.py        # LLMClient: `live` (anthropic SDK) | `replay` (cassette) backends; request-hash keying
      caching.py           # prompt-cache prefix assembly (frozen system + tools + server source)
      tools.py             # client-side repo-scoped tools: read_file / list_dir / grep / get_tool_source / get_evidence
      reasoner.py          # generator: drives Claude to emit CandidateFinding[] (cross-lang authority, poisoning, scope-vs-need)
      prompts.py           # system prompts + per-task instructions (frozen, cache-stable)
    # --- adversarial verification gate ---
    verify/
      __init__.py
      anchor.py            # re-resolve a candidate's evidence anchor against the EvidenceGraph
      judge.py             # adversarial Claude judge panel (perspective-diverse, default-refute, majority vote)
      gate.py              # anchor + panel -> survive/drop; confidence assignment
    # --- orchestration & output ---
    audit.py               # orchestrator: ingest -> evidence -> deterministic detectors + agent candidates -> gate -> Finding[]
    corpus.py              # batch/corpus mode over a directory -> aggregate
    study.py               # empirical-study harness (run corpus over real servers -> prevalence + adjudicated precision/agreement)
    serve.py               # thin MCP-server entrypoint: exposes `audit` as an MCP tool (official MCP SDK, server side)
    report.py              # build / validate / render: JSON + Markdown + SARIF (all first-class)
    schemas/               # *.schema.json (server, tool, finding, candidate_finding, verdict, report, sarif_subset, policy, corpus_summary, study_summary)
  tests/
    unit/                  # one module per analyzer + registry + schemas + report + gate logic
    acceptance/            # full flows + CLI + serve entrypoint + fixture corpus + acceptance-matrix (LLM via replay cassettes)
    heldout/               # held-out fixtures (labels NOT used to tune detectors) — scored once at release for recall
    gate_redteam/          # known-false candidates (hallucinated anchors, plausible-but-wrong) the gate MUST kill
    cassettes/             # recorded Claude request/response pairs for deterministic agent-layer tests
    live/                  # opt-in live-API eval (not part of the release gate)
  examples/
    configs/               # sample client configs (Claude Desktop/Cursor/Windsurf/VS Code-Cline/generic)
    manifests/             # sample tools/list outputs (benign + vulnerable)
    servers/               # synthetic MCP server sources (Python + a non-Python server, vulnerable + benign)
    policies/              # operator authority-assertion examples
    allowlists/            # operator server allow-lists (for shadow-server detection)
    corpus/                # fixture corpus for batch mode + the acceptance gate
  evaluation/              # generated benchmark + study summaries (runtime outputs go to gitignored build/)
  scripts/
    check_acceptance_matrix.py
    record_cassettes.py    # re-record agent-layer cassettes against the live API (maintainer tool)
```

## 5. The hybrid pipeline (end to end)

```
ingest ─▶ evidence layer ─▶ deterministic detectors ─┐
              │                                       ├─▶ merge ─▶ report (JSON / MD / SARIF)
              └─▶ agent reasoner ─▶ verification gate ┘
                  (CandidateFinding[])   (anchor re-resolve + judge panel)
```

1. **Ingest.** `discovery.py` / `manifest.py` / `connect.py` produce `ServerRecord[]` + `ToolRecord[]` (+ `source_path`).
2. **Evidence.** `evidence/*` build an `EvidenceGraph`: every fact (a dangerous call at `file:line`, an unconstrained arg at a `schema-path`, an OAuth field at a `config-key`, a poisoning marker, a shadow-server) carries its anchor. This layer is pure and byte-reproducible.
3. **Deterministic detectors.** `detect/*` consume the graph and emit `Finding[]` for everything determinism settles exactly (unconstrained args, `ast`-grounded mismatch, OAuth anti-patterns from config, shadow/supply-chain, lexical poisoning). These are `confidence: high`, `provenance: deterministic`.
4. **Agent reasoner.** `agent/reasoner.py` drives Claude (Messages API + client-side repo tools, manual loop) over the judgment-heavy questions: cross-language authority, semantic poisoning, declared-vs-actual across languages, scope-vs-need. It emits `CandidateFinding[]`, each carrying a `claimed_anchor` (`file:line` or `schema-path`) and a rationale.
5. **Verification gate.** For each candidate, `verify/anchor.py` checks the `claimed_anchor` resolves in the `EvidenceGraph` (the line exists and contains the claimed construct; the schema-path exists). If it resolves, `verify/judge.py` runs an adversarial panel; majority refute → drop. Survivors become `Finding[]` with `provenance: llm-verified` and a confidence set from the panel margin.
6. **Merge & report.** Deterministic + gate-survived findings are merged (dedup by `(finding_id, anchor)`), then `report.py` validates and renders JSON + Markdown + SARIF.

## 6. The Claude reasoning + verification layers (pinned to current API)

These choices are pinned to the Anthropic API/SDK as of 2026-06-14; verify exact bindings against the `claude-api` skill / SDK repos at implementation time.

**Surface — Messages API + tool use (manual agentic loop), NOT Managed Agents.** The server source is a *local* repo and the audit must be deterministic and cassette-testable. Managed Agents runs the loop and tool execution in an Anthropic-hosted cloud container — wrong for a local repo and for byte-stable CI. We host the loop with `client.messages.create(...)` and supply **client-side tools** (`read_file`, `list_dir`, `grep`, `get_tool_source`, `get_evidence`) scoped to the repo root, so every file read is on our side, sandboxed, and recordable. The manual loop (over the SDK tool runner) is chosen for control: we capture every tool call as evidence, enforce the gate, and record/replay.

**Models.**
- *Reasoning / generator and the gate decision:* **`claude-opus-4-8`** (adaptive thinking, `output_config.effort: "high"`). This is the documented default for capable reasoning and is the security-critical path — we do not downgrade it for cost.
- *Verification-panel breadth:* the gate decision stays on `claude-opus-4-8`; additional perspective-diverse votes may use **`claude-sonnet-4-6`** and **`claude-haiku-4-5`** to widen the panel cheaply. All model IDs are config (`mcptrustmap.toml`), never hard-coded in detectors.
- *Explicitly avoid `claude-fable-5` as the default.* Its safety classifiers target cybersecurity content and can false-positive on security tooling (returning `stop_reason: "refusal"`) — a poor fit for an MCP security auditor. If a maintainer opts into Fable 5, the client must enable server-side fallbacks (`betas: ["server-side-fallback-2026-06-01"]`, `fallbacks: [{"model": "claude-opus-4-8"}]`) and handle `stop_reason == "refusal"` before reading content.

**Structured findings.** Candidates and verdicts are forced to validate against checked-in JSON Schemas (`candidate_finding.schema.json`, `verdict.schema.json`):
- the reasoner emits each candidate via a `strict: true` `emit_finding` tool **and/or** `client.messages.parse()` with a Pydantic model mirroring the schema (recommended — the SDK validates and returns typed objects);
- the judge returns its verdict via `output_config={"format": {"type": "json_schema", "schema": ...}}`.
- Schema constraints the API doesn't enforce (numeric/string bounds) are validated client-side by `jsonio.py`. Structured outputs are supported on Opus 4.8 / Sonnet 4.6 / Haiku 4.5 and are incompatible with citations and prefill (we use neither).

**Prompt caching.** The agent reads the same server source across many per-tool / per-finding calls, so caching is load-bearing. Prefix order is fixed `tools → system → server source`, all frozen, with a `cache_control: {type: "ephemeral"}` breakpoint on the last source block; the volatile per-tool question goes *after* the breakpoint. `caching.py` serializes deterministically (`sort_keys=True`, no timestamps/UUIDs in the prefix) to avoid silent invalidation, and asserts `usage.cache_read_input_tokens > 0` on the second call. Verifier calls reuse the generator's exact prefix (fork pattern) so they read the cache the generator wrote; for fan-out we send one verifier, await first token, then fire the rest. An audit run may pre-warm with a `max_tokens: 0` request and use `ttl: "1h"` for large servers. Min cacheable prefix on Opus 4.8 is 4096 tokens.

**Verification gate (anchor-primary + weighted judge panel).** The gate has two stages, and the *deterministic* stage is primary. **Stage 1 — anchor re-resolution (`anchor.py`, non-LLM):** a candidate whose `claimed_anchor` doesn't re-resolve against the evidence graph is dropped before any judge call. This is the strongest verifier precisely because it is *not* an LLM. **Stage 2 — weighted judge panel (`judge.py`):** N verifiers (default N=3) each with a *distinct lens* and a default-refute instruction — *source lens* ("does the cited `file:line` actually perform the claimed authority? default to refuted if unconfirmed"), *declaration lens* ("is the declared annotation/schema genuinely contradicted?"), *mapping lens* ("is the OWASP mapping and `not_applicable` gating correct?"). The panel verdict is a **weighted** combination (anchor-confirmation + lens reliability), **not a flat majority** — the research is clear that naively averaging weak LLM verifiers underperforms weighted aggregation.

*Self-enhancement-bias mitigation (load-bearing).* A Claude judge scoring Claude-generated candidates is biased to confirm them (a documented self-enhancement bias). We counter it four ways: (1) the non-LLM anchor stage is primary; (2) the panel spans **diverse model tiers** (`claude-opus-4-8` + `claude-sonnet-4-6` + `claude-haiku-4-5`) rather than one model judging itself; (3) the refute-default prompt; (4) a measured **judge-vs-human agreement** metric reported at release (§11). *Determinism note:* Opus 4.8 exposes no `temperature` knob (adaptive thinking), so we do not pin sampling — CI determinism comes from cassette replay, and the gate's *decision* is reproducible because the deterministic anchor stage, not the sampled panel, is decisive. The server-side `advisor_20260301` tool is a possible single-second-opinion alternative, but the explicit weighted panel is more controllable and is the default.

**Record / replay for deterministic CI.** `llm_client.py` exposes one interface with two backends. `live` calls the `anthropic` SDK. `replay` loads recorded responses keyed by a stable hash of the canonicalized request (model + system + tools + messages + params) and raises `LlmReplayMiss` on an unknown request, so a drift in prompts fails loudly instead of silently calling the network. Cassettes are recorded with **vcrpy / pytest-recording** at the httpx layer (the SDK uses httpx), with `x-api-key` scrubbed via `filter_headers`; `scripts/record_cassettes.py` re-records against the live API when prompts change. Acceptance and unit tests run on `replay` (no key, no network); a separate opt-in `tests/live/` eval runs against the API periodically to catch model drift. The gate's *logic* (anchor-must-resolve, majority-refute-kills) is unit-tested with synthetic candidates and stubbed verdicts, so gate correctness is verified independently of any model.

## 7. Framework / library reuse (do not hand-roll)

| Need | Reuse | Why |
| --- | --- | --- |
| MCP protocol / live `tools/list` | **official MCP Python SDK (`mcp`)** | never hand-roll JSON-RPC/MCP; used in `connect.py` |
| Claude reasoning + judging | **`anthropic` Python SDK** | official SDK; Messages API + tool use, structured outputs, prompt caching |
| Record / replay of API calls | **vcrpy / pytest-recording** (httpx layer) | deterministic agent-layer CI without network/key |
| Schema validation | `jsonschema` (Draft 2020-12) | proven boundary validation (as in AMG) |
| Structured-output models | `pydantic` | typed candidate/verdict models for `messages.parse()` |
| Config/policy parsing | `PyYAML` + stdlib `json` | client configs are JSON; policies/allow-lists YAML |
| Python source authority inference | stdlib **`ast`** | deterministic, line-accurate static analysis |
| Non-Python source inference | curated `re` patterns + the LLM layer | `ast` doesn't apply; lexical facts anchor LLM reasoning |
| SARIF output | `sarif-om` (or a checked-in SARIF 2.1.0 subset schema) | first-class report format for CI/code-scanning ingestion |
| Toolchain | `uv`, `ruff`, `ty`, `pytest` | identical to the AMG fork; fast, typed, reproducible |
| Architecture patterns | **ported from the AMG fork** | findings registry, schema-validated reports, deterministic detectors, role/authority model, fixture-driven acceptance |

The **deterministic evidence + detector layers never import the MCP SDK or `anthropic`**: they consume plain records and a local source tree, so all reproducible analysis runs offline. `connect.py` and `agent/*` are adapters at the edges.

## 8. Core data models (schemas live in `schemas/`)

**ServerRecord** — `server_id`, `client` (claude_desktop|cursor|windsurf|vscode_cline|generic), `transport` (stdio|http|sse), `command`/`args`/`env` or `url`, `package?` (npx/uvx/pip spec, for supply-chain), `source_path?`, `oauth?` (client_id, redirect_uris, scopes, is_proxy), `tools[]`, `resources[]?`, `prompts[]?`.

**ToolRecord** — `name`, `description`, `input_schema`, `annotations` (`read_only_hint?`, `destructive_hint?`, …), `arguments[]`, `declared_authority[]` (classes), `inferred_authority[]?` (with `sub_source: ast|llm`), `source_symbol?`.

**ArgRecord** — `name`, `json_type`, `role` (assigned), `constrained` (enum/pattern/format present?), `evidence` (schema-path).

**EvidenceFact** — `anchor` (`{kind: file_line|schema_path|config_key, ref: str}`), `kind` (call|arg|oauth_field|poison_marker|inventory), `detail`, `language?`. The graph is the shared substrate the gate re-resolves against.

**CandidateFinding** — `finding_id`, `server_id`, `tool?`, `argument?`, `claimed_anchor`, `rationale`, `proposed_severity`, `proposed_owasp`. Produced only by the LLM layer; never reported directly.

**Verdict** — `candidate_ref`, `lens`, `refuted` (bool), `reason`, `anchor_confirmed` (bool). One per judge vote.

**Finding** — `finding_id`, `severity` (critical|high|medium|low|info), `owasp` (MCP0x), `spec_ref?`, `title`, `server_id`, `tool?`, `argument?`, `evidence` (resolved anchor: schema path, source line, config key), `recommendation`, `confidence` (high|medium|low), `provenance` (deterministic|llm-verified), `status` (reproduced|not_applicable). `not_applicable` is recorded but not counted as a finding.

**Report** — `report_id`, `tool_version`, `target` (server_id or corpus id), `findings[]`, `summary` (counts by severity + by OWASP + by provenance), `inventory` (servers/tools counted), `security_claims[]`, `reproducibility` (deterministic-core + cassette-hash for the agent layer).

**StudySummary** — corpus-level prevalence: per-OWASP / per-finding rates across the real-server corpus, with the corpus manifest hash and run metadata.

## 9. CLI surface

Single entry point `mcptrustmap`. Returns non-zero on schema-validation failure, invalid input, or (optionally) when findings exceed a `--fail-on` severity. The reasoning layer is opt-in per run via `--reason` (default on; `--no-reason` gives a deterministic-only audit) and `--llm-mode live|replay` (tests use `replay`).

```text
mcptrustmap --help
mcptrustmap discover --client all --out build/servers.json                # multi-client inventory
mcptrustmap audit --manifest examples/manifests/vulnerable.json --source examples/servers/vulnerable-mcp \
                  --policy examples/policies/intended.yml --allowlist examples/allowlists/ops.yml \
                  --reason --llm-mode replay --out build/reports/audit.json
mcptrustmap audit --server-record build/servers.json#server_id --no-reason --out build/reports/audit.json
mcptrustmap audit --connect --transport stdio --command "python server.py" --out ...   # live ingestion
mcptrustmap corpus run --dir examples/corpus --out build/evaluation/summary.json        # batch mode
mcptrustmap study run --dir corpus/real --out build/evaluation/study.json                # empirical study
mcptrustmap report validate build/reports/audit.json
mcptrustmap report render build/reports/audit.json --format md   --out build/reports/audit.md
mcptrustmap report render build/reports/audit.json --format sarif --out build/reports/audit.sarif
mcptrustmap serve --transport stdio                                                      # expose `audit` as an MCP tool for a host agent
mcptrustmap findings list                                                                # registry + OWASP map
```

Offline `audit` (manifest [+source] [+policy] [+allowlist]) with `--llm-mode replay` is the deterministic path used by all acceptance tests. `--connect` (live MCP) and `--llm-mode live` are exercised by opt-in tests, never the gate.

## 10. Implementation phases (build order, not a cut line — everything below lands in v0.1)

Phases are sequencing only. Nothing here is deferred past v0.1; the release gate covers all of it.

**Phase 0 — Scaffold.** pyproject (uv/ruff/ty/pytest/jsonschema/pyyaml/pydantic/anthropic/mcp/vcrpy), package skeleton, `cli.py` with the full argparse surface, empty schemas, `llm_client.py` with the `replay` backend stubbed. *Exit:* `mcptrustmap --help` works; format/lint/typecheck/empty tests pass.

**Phase 1 — Ingestion (first-class, multi-client).** `manifest.py`, `discovery.py` for Claude Desktop / Cursor / Windsurf / VS Code-Cline / generic, schemas, `models.py`. *Exit:* a fixture manifest and each client config parse to validated records; unknown/missing fields fail closed.

**Phase 2 — Evidence layer + authority/role classification.** `evidence/graph.py`, `evidence/authority.py`, `evidence/roles.py`, `evidence/source/python_ast.py`, `evidence/oauth.py`, `policy.py`; `detect/arguments.py`. *Exit:* the evidence graph is populated with anchored facts; command/path/credential args are correctly roled and unconstrained ones flagged; benign content args are not.

**Phase 3 — Declared-vs-actual mismatch (deterministic path).** `detect/mismatch.py` over `ast` facts. *Exit:* a `readOnlyHint: true` tool whose Python source calls `os.remove` is flagged with the source line; a faithfully-declared tool is not.

**Phase 4 — Authorization anti-patterns + over-sharing (deterministic).** `detect/authz.py`, `detect/oversharing.py`, each gated to applicable config. *Exit:* a proxy forwarding the token / using a wildcard redirect is flagged; a no-OAuth server yields `not_applicable`; an unscoped resource is flagged, a scoped one is not.

**Phase 5 — Inventory, supply-chain, and deterministic poisoning (first-class).** `evidence/poisoning.py`, `evidence/inventory.py`, `detect/poisoning.py`, `detect/inventory.py`. *Exit:* a server absent from the allow-list → `MTM-SHADOW-SERVER`; an unpinned `npx`/`uvx` package → `MTM-UNPINNED-SERVER-PACKAGE`; a hidden-instruction / unicode-obfuscated / name-spoofing description → `MTM-TOOL-POISONING`; benign descriptions are clean.

**Phase 6 — LLM reasoning layer.** `agent/llm_client.py` (both backends), `agent/caching.py`, `agent/tools.py`, `agent/reasoner.py`, `agent/prompts.py`, candidate schema. Cassettes recorded for the fixture servers. *Exit:* on a non-Python fixture server, the reasoner emits anchored `CandidateFinding[]` (cross-language authority + semantic poisoning) under `--llm-mode replay`; prompt drift raises `LlmReplayMiss`.

**Phase 7 — Verification gate.** `verify/anchor.py` (primary, non-LLM), `verify/judge.py` (weighted diverse-tier panel), `verify/gate.py`, verdict schema, and the `tests/gate_redteam/` suite. *Exit:* a candidate with a real anchor and a non-refuting panel survives as `llm-verified`; a candidate with a bogus anchor is dropped pre-judge; a candidate the weighted panel refutes is dropped; the gate red-team (hallucinated anchors, plausible-but-wrong claims) is killed in full; gate logic unit tests pass with stubbed verdicts.

**Phase 8 — Findings registry + report engine (JSON / MD / SARIF).** `findings.py`, `report.py`, fail-closed validation, SARIF emission. *Exit:* a report validates; tampering (unknown id, missing evidence, claim without a fixture) fails validation; Markdown and SARIF render; SARIF validates against the SARIF subset schema.

**Phase 9 — Corpus / batch mode + acceptance matrix + held-out recall.** `corpus.py`, `scripts/check_acceptance_matrix.py`, per-finding TP/FP/FN, and a `tests/heldout/` set whose labels are not used to tune detectors. *Exit:* the fixture corpus runs; every required family has a positive fixture and a benign control; the acceptance matrix passes; the held-out set is scored once and its **recall** recorded and reported (not build-gating); the [TEST_PLAN](TEST_PLAN.md) release-gate block is green.

**Phase 10 — Live MCP ingestion.** `connect.py` over the official MCP SDK; recorded server transcripts for tests. *Exit:* `--connect` ingests a live stdio fixture server to the same `ToolRecord[]` as the offline manifest; the offline and live records match on the fixture.

**Phase 11 — Empirical study + agreement metric.** `study.py` + a curated real-server corpus + manual adjudication of a sampled subset + a prevalence writeup (`evaluation/study.md`). *Exit:* `study run` over the real corpus produces a validated `StudySummary`; a hand-adjudicated sample yields a measured precision on real data and a **judge-vs-human agreement** figure (% / κ); prevalence is reported as a convenience-sample lower bound; the study uses only the v0.1 tool.

**Phase 12 — MCP-server entrypoint.** `serve.py`: a thin MCP server (official MCP SDK, server side) exposing `audit` as an MCP tool a host frontier agent can call before connecting to a target server (Semgrep-MCP precedent). It wraps the same core — no new analysis logic. *Exit:* `mcptrustmap serve` starts over stdio; a test MCP client lists and calls the `audit` tool and receives a schema-valid report identical to the CLI's for that input.

## 11. Determinism, reproducibility, and how the LLM layer stays honest

The reproducibility contract has two tiers:

1. **Deterministic tier (the backbone).** The evidence layer and `detect/*` are pure functions over checked-in inputs. A reviewer clones, runs the fixtures, and gets byte-identical findings (modulo latency). All `confidence: high`, `provenance: deterministic` findings live here. This tier alone satisfies the acceptance matrix's required families.

2. **LLM tier (made reproducible by construction).** The agent + gate are non-deterministic at the API, so CI runs them on **recorded cassettes** (`--llm-mode replay`): identical inputs → identical gated findings, no network, no key. Beyond replay, two structural guarantees keep the tier auditable: (a) every surviving LLM finding carries a `claimed_anchor` that re-resolved against the deterministic graph, so a human can confirm each one by hand against the source; (b) the gate's decision logic is unit-tested independently of any model. A separate opt-in `tests/live/` eval runs against the real API to detect model drift, and is never part of the release gate.

**The oracle is hand-authored, never the model.** Each fixture's `expected.json` (authored from the threat, not derived from a recording) is the authoritative outcome; cassettes supply *inputs only*, so re-recording can never silently bless a regression. And because no public labeled MCP-security benchmark exists, MCPTrustMap ships its own: the acceptance corpus, a held-out recall figure, and a **judge-vs-human agreement** figure measured on a hand-adjudicated sample are the credibility keystone — no surveyed MCP tool publishes any of them.

No wall-clock timestamps are embedded in reports (reproducibility); latency lives only in corpus/study metrics. The report's `reproducibility` block records the deterministic-core version and the cassette-set hash used for the agent layer.

## 12. Non-goals and claim limits

MCPTrustMap may claim: it inventoried servers across clients; it classified authority/roles; it detected declared-vs-actual mismatches and named authz anti-patterns and tool poisoning on fixtures and on a real-server corpus; every LLM-derived finding was anchored to a concrete fact and survived adversarial verification; it mapped findings to OWASP MCP Top 10 (beta) and MCP-spec MUSTs; it emits JSON/Markdown/SARIF; it published a labeled benchmark with measured precision/recall and judge-vs-human agreement — which the comparable MCP tools (Snyk Agent Scan, apisec mcp-audit) do not. It must **not** claim: it secures MCP; it determines a tool's true authority from schema alone; it covers the *finalized* OWASP MCP Top 10; that LLM judgment is ground truth (it is gated and anchored, not trusted). Security claims are bounded to validated fixture families and the documented study corpus (see [ACCEPTANCE_CRITERIA](ACCEPTANCE_CRITERIA.md)).
