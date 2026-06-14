# MCPTrustMap — Acceptance Criteria

**Status:** binding acceptance specification for v0.1
**Date:** 2026-06-14

## 1. Global definition of done

v0.1 is accepted only when **all** required criteria below hold:

- The **deterministic core** (evidence layer + `detect/*`) runs **offline** and **byte-reproducibly** on checked-in fixtures (no network, MCP server, API key, or LLM). It alone satisfies the acceptance matrix's required families, so the tool degrades safely under `--no-reason`.
- The **LLM reasoning layer + verification gate** run **deterministically in CI via recorded cassettes** (`--llm-mode replay`): identical inputs → identical gated findings, no network, no key.
- Every reported finding is **schema-validated** and carries `owasp` (MCP0x), an evidence reference, a recommendation, a confidence, and a `provenance` (`deterministic` | `llm-verified`).
- Every **LLM-verified** finding carries a `claimed_anchor` that **re-resolved** against the deterministic evidence graph; a finding whose anchor does not resolve is never reported.
- Every finding family has at least one **positive fixture** and a **benign negative control** that does not trip it.
- Rules that depend on context (OAuth/proxy, Python source, allow-list present) emit `not_applicable` when context is absent — never a false finding.
- Every security claim is limited to a validated fixture family or the documented study corpus; the tool never claims to "secure MCP," to determine true authority from schema alone, to cover the *finalized* OWASP MCP Top 10 (it is beta), or that LLM judgment is ground truth.
- Reports render in **JSON, Markdown, and SARIF**, each validating against its schema.
- The [TEST_PLAN](TEST_PLAN.md) release-gate command block is reproducible from the documented commands.

## 2. CLI acceptance

- `mcptrustmap --help` and every subcommand `--help` exit 0.
- Invalid input paths, malformed manifests/configs, and schema violations exit non-zero.
- `audit` supports `--manifest [+--source +--policy +--allowlist]`, `--server-record`, and `--connect`; `--reason`/`--no-reason`; `--llm-mode live|replay`; `--out` writes machine-readable JSON.
- `report render --format json|md|sarif` produces each format.
- `serve` starts a thin MCP server (stdio) exposing `audit` as an MCP tool; a test MCP client can list and call it and receives the same schema-valid report the CLI produces for that input.
- `--fail-on <severity>` makes the process exit non-zero when a finding at/above that severity exists (CI use).
- Under `--llm-mode replay`, an unknown LLM request raises a clear `LlmReplayMiss` and exits non-zero (prompt drift fails loud, never silently calls the network).
- Commands write only to `--out`/explicit paths.

## 3. Ingestion acceptance (Phase 1, 10)

- A `tools/list` JSON manifest parses to validated `ToolRecord[]` (name, description, input_schema, annotations, arguments).
- Each of Claude Desktop, Cursor, Windsurf, VS Code/Cline, and a generic stdio/URL config parses to validated `ServerRecord[]` (transport, command/args/env or url, package spec if present, oauth if present).
- Missing required fields or unknown transports fail closed (non-zero, clear error).
- A server with no `source_path` still audits (source-dependent rules degrade to `confidence: low`, `not_applicable`, or hand off to the LLM layer, documented per rule).
- **Live ingestion:** `audit --connect` over a stdio fixture server yields the same `ToolRecord[]` as the offline manifest for that server (offline/live parity on the fixture). The live path is exercised by opt-in tests, never the release gate.

## 4. Authority & role classification acceptance (Phase 2)

| Finding ID | Required trigger | OWASP | Evidence required |
| --- | --- | --- | --- |
| `MTM-HIGH-AUTHORITY-TOOL` | A tool's declared authority includes a high-authority class (command_exec / credential_access / payment / cloud_mutation) | MCP02/07 | tool name, declared classes |
| `MTM-UNCONSTRAINED-COMMAND-ARG` | An argument is roled `command` and lacks enum/pattern/allow-list constraint | MCP05/07 | argument name, schema path |
| `MTM-UNCONSTRAINED-PATH-ARG` | An argument is roled `path` and is unconstrained (no root confinement / pattern) | MCP05/07 | argument name, schema path |
| `MTM-CREDENTIAL-ARG-EXPOSED` | An argument is roled `credential` and accepted as a free-form tool input | MCP01/07 | argument name |

- Argument roles are assigned deterministically by name + description + json type + format (e.g. `cmd`/`command`→command; `path`/`file`/`dir`→path; `token`/`api_key`/`password`→credential; `to`/`recipient`/`email`→recipient; `url`/`endpoint`→url; `amount`/`account`→payment_destination).
- **Negative controls:** a tool whose only arguments are `content`/`query`/`text` (role `content`) produces no authority/role finding; a `command` argument constrained by an enum is not flagged.

## 5. Declared-vs-actual mismatch acceptance (Phase 3, 6, 7) — core novelty

| Finding ID | Required trigger | OWASP | Evidence required | Provenance |
| --- | --- | --- | --- | --- |
| `MTM-AUTHORITY-MISMATCH` | Inferred authority exceeds declared (e.g. `readOnlyHint: true` but source calls `os.remove`/`subprocess`) | MCP02/03/07 | declared vs inferred classes, **source file:line** | `deterministic` (Python `ast`) or `llm-verified` (other languages) |
| `MTM-UNDECLARED-MUTATION` | A tool with no write/destructive declaration performs a mutation in source | MCP03/07 | source symbol + line | as above |

- **Python path (deterministic):** stdlib `ast` produces line-accurate evidence; the finding is `provenance: deterministic`, `confidence: high`.
- **Cross-language path (LLM-verified):** for JS/TS/Go/etc. the reasoning layer proposes the mismatch with a `claimed_anchor` (`file:line`); it is reported **only if** the gate re-resolves that line against the evidence graph **and** the judge panel does not refute it. Reported as `provenance: llm-verified` with confidence from the panel margin.
- **Negative controls:** a tool that faithfully declares its authority (declared ⊇ inferred) yields no mismatch; a read-only tool whose source only reads yields none; an LLM-proposed mismatch whose cited line does not contain the claimed call is **dropped by the gate** (must be demonstrated by a fixture).
- If no source is provided, mismatch rules are `not_applicable` (recorded, not counted).

## 6. Authorization anti-pattern acceptance (Phase 4)

| Finding ID | Required trigger | OWASP | Applies only when |
| --- | --- | --- | --- |
| `MTM-TOKEN-PASSTHROUGH` | Server forwards the incoming client token to an upstream API instead of minting its own | MCP01/07 | OAuth/proxy config or source evidence present |
| `MTM-CONFUSED-DEPUTY` | Static client ID + dynamically-registered redirect without per-client consent | MCP07 | OAuth proxy server |
| `MTM-SCOPE-CREEP` | Requested OAuth scopes exceed what the exposed tools require | MCP02 | OAuth config present |
| `MTM-MISSING-CONSENT` | Proxy server forwards consent without obtaining its own per-client consent | MCP07 | OAuth proxy server |
| `MTM-LAX-REDIRECT-URI` | Redirect URI matched by prefix/wildcard rather than exact string | MCP07 | OAuth config present |
| `MTM-STATIC-CLIENT-ID` | A single static client ID shared across clients | MCP07 | OAuth config present |
| `MTM-MISSING-SCOPE-ELEVATION-LOG` | No audit log emitted on a scope-elevation/authorization decision | MCP08 | server performs authorization |

- Each rule records the precise spec MUST it maps to and degrades to `not_applicable` (not a finding) when its context is absent. This encodes the grounding caveat that consent/redirect MUSTs apply to **proxy/OAuth** servers and telemetry is scoped to **scope-elevation**.
- `MTM-SCOPE-CREEP` may be deterministic (declared scopes vs declared tool needs) or LLM-verified (scopes vs *reasoned* tool needs across source); the LLM path is gated and anchored to the scope config + the tool source lines it cites.
- **Negative control:** a plain stdio server with no OAuth produces zero authz findings (all `not_applicable`).

## 7. Context over-sharing acceptance (Phase 4)

| Finding ID | Required trigger | OWASP |
| --- | --- | --- |
| `MTM-CONTEXT-OVERSHARING` | A tool/resource returns broad context (whole files/dirs, env, full DB rows) without task/tenant scoping | MCP10 |
| `MTM-UNSCOPED-RESOURCE` | A resource is exposed without session/tenant scoping or access control | MCP10 |

- **Negative control:** a resource scoped to a session/tenant, or a tool returning a single scoped record, is not flagged.

## 8. Tool / schema poisoning acceptance (Phase 5, 6, 7) — first-class

| Finding ID | Required trigger | OWASP | Provenance |
| --- | --- | --- | --- |
| `MTM-TOOL-POISONING` (sub-type `hidden-instruction`) | Description/schema contains hidden or imperative instructions aimed at the agent | MCP03/06 | `deterministic` (marker) and/or `llm-verified` (semantic) |
| `MTM-TOOL-POISONING` (sub-type `unicode-obfuscation`) | Homoglyph / zero-width / bidi obfuscation in name or description | MCP03 | `deterministic` |
| `MTM-TOOL-POISONING` (sub-type `name-spoofing`) | Tool name impersonates a well-known/trusted tool | MCP03/06 | `deterministic` and/or `llm-verified` |
| `MTM-TOOL-POISONING` (sub-type `tool-shadowing`) | A tool's description references or redefines the behavior of another tool/server | MCP06 | `llm-verified` (anchored to both descriptions) |

- The deterministic layer fires on lexical/structural markers (high precision, language-agnostic). The LLM layer adds semantic judgment (is this *actually* a hidden instruction vs a legitimate description?) and only survives the gate when anchored to a specific `schema-path`/`file:line` and not refuted by the panel.
- The report **credits AgentAuditKit / MCP-Scan** as established tools in this class while presenting MCPTrustMap's coverage as first-class parity, not a stub.
- **Negative controls:** a benign tool description with imperative phrasing that is legitimately about its own function is not flagged; an LLM-proposed poisoning finding whose cited text doesn't contain the claimed construct is dropped by the gate.

## 9. Inventory, shadow-server & supply-chain acceptance (Phase 1, 5) — first-class

| Finding ID | Required trigger | OWASP |
| --- | --- | --- |
| `MTM-SHADOW-SERVER` | A configured server not present in an operator allow-list | MCP09 |
| `MTM-CROSS-ORIGIN-COLLISION` | Two servers expose tools with colliding names (shadowing surface) | MCP09/06 |
| `MTM-UNPINNED-SERVER-PACKAGE` | A server launched via an unpinned `npx`/`uvx`/`pip` spec (no version/hash) | MCP04 |
| `MTM-UNTRUSTED-SERVER-SOURCE` | A server launched from an untrusted/unverifiable source (arbitrary URL, non-registry) | MCP04 |

- Shadow-server requires an allow-list to be provided; absent one, the rule is `not_applicable` (recorded). Supply-chain rules are deterministic over the parsed launch spec.
- **Negative controls:** a server present in the allow-list is not flagged; a pinned package (`pkg@1.2.3` / hash) is not flagged; uniquely-named tools across servers produce no collision.

## 10. LLM reasoning-layer acceptance (Phase 6)

- Under `--llm-mode replay`, the reasoner emits `CandidateFinding[]` for the fixture servers that validate against `candidate_finding.schema.json`; each candidate carries a `claimed_anchor` and a rationale.
- The reasoner uses **client-side, repo-scoped** tools only (`read_file`/`list_dir`/`grep`/`get_tool_source`/`get_evidence`); it cannot read outside the declared repo root (path-escape attempts are rejected and tested).
- Structured output is enforced (a `strict` `emit_finding` tool and/or `messages.parse()`); a candidate that fails schema validation is rejected, not coerced.
- Prompt-cache reuse is demonstrated: the second per-tool call on the same server reports `usage.cache_read_input_tokens > 0` in the recorded transcripts.
- Cassette hygiene: no `x-api-key`/auth header appears in any checked-in cassette.

## 11. Verification-gate acceptance (Phase 7)

- The gate is **anchor-primary**: Stage 1 re-resolves the candidate's `claimed_anchor` against the evidence graph (non-LLM); only survivors reach Stage 2, the **weighted** judge panel. The panel verdict is a weighted aggregation (anchor-confirmation + lens reliability), **not a flat majority** — naive averaging of weak LLM verifiers is known to underperform.
- The panel is **perspective-diverse across both lenses and model tiers** (≥3 votes spanning source/declaration/mapping lenses, drawn from `claude-opus-4-8` + `claude-sonnet-4-6` + `claude-haiku-4-5`) and **default-refute**, to counter self-enhancement bias (a Claude judge favoring Claude-generated candidates).
- The gate's logic is unit-tested **independently of any model** with synthetic candidates and stubbed verdicts: anchor-resolves + non-refuting weighted panel → survive; bogus anchor → dropped pre-judge; refuting panel → dropped.
- A **gate red-team suite** of known-false candidates (hallucinated anchors, plausible-but-wrong claims) must be **killed in full** — this measures the gate's discriminative power, not just its plumbing.
- On the fixtures: at least one LLM candidate **survives** (becomes an `llm-verified` finding), at least one is **dropped for a non-resolving anchor**, and at least one is **dropped by the panel** — each demonstrated by a fixture.
- A surviving finding's `evidence` is the *resolved* anchor (file:line / schema-path), not the LLM's prose.
- A measured **judge-vs-human agreement** figure (§15) is reported; the gate decision is computed from the recorded verdicts deterministically (CI determinism comes from cassette replay, since Opus 4.8 exposes no temperature knob).

## 12. Report acceptance (Phase 8)

- JSON report validates against `report.schema.json`; Markdown renders from the same data; SARIF renders and validates against the checked-in SARIF 2.1.0 subset schema.
- Every finding includes: `finding_id` (known to the registry), `severity` (known), `owasp` (MCP01–MCP10), `spec_ref` (when applicable), evidence ref(s), recommendation, confidence, `provenance`, status.
- The report validator fails closed on: unknown finding ID, unknown severity, unknown OWASP id, missing evidence, an `llm-verified` finding whose anchor did not resolve, a `security_claims` entry not backed by a passing fixture family, or `not_applicable` entries miscounted as findings.
- Summary includes counts by severity, by OWASP MCP item, **and by provenance** (deterministic vs llm-verified), plus an inventory count (servers/tools audited).

## 13. Corpus / batch acceptance (Phase 9)

- `corpus run` over a directory produces: total servers/tools, per-OWASP / per-finding / per-provenance counts, per-server pass/fail, median & p95 latency, and a stable machine-readable summary that itself validates as a report.
- Re-running on the same fixtures (`--llm-mode replay`) yields identical findings (determinism), modulo latency.

## 14. Benchmark / acceptance-matrix (Phase 9)

- A fixture matrix lists each required finding family with an expected positive fixture and a benign control.
- Required families (must each pass): `MTM-AUTHORITY-MISMATCH`, `MTM-UNCONSTRAINED-COMMAND-ARG`, `MTM-UNCONSTRAINED-PATH-ARG`, `MTM-CREDENTIAL-ARG-EXPOSED`, `MTM-HIGH-AUTHORITY-TOOL`, `MTM-TOKEN-PASSTHROUGH`, `MTM-CONFUSED-DEPUTY`, `MTM-SCOPE-CREEP`, `MTM-LAX-REDIRECT-URI`, `MTM-CONTEXT-OVERSHARING`, `MTM-TOOL-POISONING`, `MTM-SHADOW-SERVER`, `MTM-UNPINNED-SERVER-PACKAGE`.
- The matrix must include at least one **`llm-verified`** required family (a cross-language `MTM-AUTHORITY-MISMATCH` and/or a semantic `MTM-TOOL-POISONING`) proving the hybrid path end-to-end.
- `scripts/check_acceptance_matrix.py` exits non-zero unless every required family has a passing positive fixture and zero false positives on benign controls.
- Metrics reported per family: TP / FP / FN, confidence distribution, and provenance.
- A **held-out fixture set** (labels not used to tune detectors) is scored once at release and its **recall** recorded and reported (not build-gating, but published) — recall, not just precision, because false negatives are the documented weak spot of LLM detection.

## 15. Empirical-study acceptance (Phase 11)

- `study run` over a curated real-server corpus produces a `StudySummary` that validates against `study_summary.schema.json`: per-OWASP / per-finding prevalence, the corpus manifest hash, and run metadata.
- The study uses **only the shipped v0.1 tool** (no bespoke one-off analysis code).
- A **hand-adjudicated sample** of the study's findings yields a **measured precision on real data** and a **judge-vs-human agreement** figure (% agreement and/or Cohen's κ between the gate panel and the human label); both are reported in `evaluation/study.md`.
- A written prevalence report (`evaluation/study.md`) accompanies the summary, states the corpus size and selection method, and bounds its claims (a convenience sample, not a census).
- Study claims are clearly separated from tool-capability claims and never over-generalized to "the MCP ecosystem."

## 16. MCP-server entrypoint acceptance (Phase 12)

- `mcptrustmap serve` starts a thin MCP server over stdio (official MCP SDK, server side) exposing a single `audit` tool whose input is a server reference (manifest/source/connect) and whose output is a schema-valid report.
- A test MCP client can `tools/list` and `tools/call` the `audit` tool and receive the **same** report the CLI would produce for that input — the wrapper adds no analysis and no findings of its own.
- The entrypoint reuses the deterministic core + gate unchanged; `--reason`/`--llm-mode` semantics are honored via tool arguments; the server never writes outside its working area.

## 17. Security-claim acceptance

The tool may claim, per validated fixture family and the documented study corpus: it inventoried servers across clients; it classified tool authority and argument roles; it detected declared-vs-actual authority mismatch (deterministically for Python, gate-verified for other languages); it flagged specific MCP authorization anti-patterns and tool poisoning; it mapped findings to OWASP MCP Top 10 (beta) and MCP-spec MUSTs; every LLM-derived finding was anchored to a concrete fact and survived adversarial verification; it published a labeled benchmark with measured precision/recall and judge-vs-human agreement, which the comparable MCP tools (Snyk Agent Scan, apisec mcp-audit) do not. It must not claim: it secures MCP; it determines true authority from schema; it covers the finalized OWASP MCP Top 10; that LLM judgment is ground truth; or that the study generalizes to the whole ecosystem. Every report names the inspected OWASP MCP Top 10 maturity (**beta/v0.1**).

## 18. Documentation acceptance

- README states scope, non-goals, the hybrid architecture, the differentiation (vs AgentAuditKit/MCP-Scan/apisec), and the grounding sources (incl. the Claude API choices).
- The implementation plan lists modules, schemas, the Claude reasoning/gate design pinned to the current API, phases, CLI, and framework reuse.
- The test plan gives exact commands, the cassette strategy, and release gates.
- The OWASP MCP Top 10 is cited as beta wherever referenced.
