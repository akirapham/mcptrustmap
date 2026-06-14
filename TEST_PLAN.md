# MCPTrustMap — Test & Validation Plan

**Status:** validation specification for v0.1
**Date:** 2026-06-14

## 1. Principle

v0.1 is validated in **two reproducible tiers**:

1. **Deterministic tier** — the evidence layer and `detect/*` are pure functions over checked-in inputs. A reviewer clones the repo, installs deps, runs the fixtures, and reproduces byte-identical findings — no network, MCP server, API key, or LLM.
2. **LLM tier** — the reasoning layer and verification gate run against **recorded cassettes** (`--llm-mode replay`): identical inputs → identical gated findings, no network, no key. The gate's *logic* is additionally unit-tested with stubbed verdicts, independently of any model. Each fixture's hand-authored `expected.json` is the authoritative oracle — a cassette supplies inputs only, so re-recording can never silently bless a regression.

Validation must prove five things:

1. The tool works as software (static checks + unit tests).
2. Its detectors fire on the threats they target and stay quiet on benign controls (acceptance fixtures).
3. Its **LLM-derived findings are anchored and gated** — every one re-resolves against the deterministic evidence graph and survives an adversarial panel, or is dropped.
4. Its claims are bounded to validated fixture families and a documented study corpus, with evidence (report + matrix audit).
5. Its **gate is credible, not self-confirming** — the hand-authored `expected.json` is the oracle, a gate red-team of known-false candidates is killed in full, and a measured judge-vs-human agreement figure is reported.

## 2. Release-gate command block

```bash
cd tools-impl/mcptrustmap
uv sync --all-groups
uv run ruff format --check .
uv run ruff check .
uv run ty check src
uv run pytest tests/unit -q
uv run pytest tests/acceptance -q                      # LLM layer via replay cassettes (no key, no network)
uv run mcptrustmap findings list
uv run mcptrustmap discover --client all --config-root examples/configs --out build/servers.json
uv run mcptrustmap audit --manifest examples/manifests/vulnerable.json \
    --source examples/servers/vulnerable-mcp --policy examples/policies/intended.yml \
    --allowlist examples/allowlists/ops.yml --reason --llm-mode replay \
    --out build/reports/vulnerable-audit.json
uv run mcptrustmap report validate build/reports/vulnerable-audit.json
uv run mcptrustmap report render build/reports/vulnerable-audit.json --format md    --out build/reports/vulnerable-audit.md
uv run mcptrustmap report render build/reports/vulnerable-audit.json --format sarif --out build/reports/vulnerable-audit.sarif
uv run mcptrustmap corpus run --dir examples/corpus --llm-mode replay --out build/evaluation/summary.json
uv run mcptrustmap report validate build/evaluation/summary.json
uv run python scripts/check_acceptance_matrix.py build/evaluation/summary.json
uv run pytest tests/gate_redteam -q                                                      # the gate kills known-false candidates in full
uv run mcptrustmap serve --transport stdio --self-test                                   # MCP server starts; `audit` tool lists + returns a valid report
uv run mcptrustmap corpus run --dir tests/heldout --llm-mode replay --out build/evaluation/heldout.json  # held-out recall (reported, not build-gating)
```

The optional **live** paths are validated separately and are **not** part of the gate:

```bash
# Live MCP ingestion (opt-in)
uv run mcptrustmap audit --connect --transport stdio \
    --command "python examples/servers/vulnerable-mcp/server.py" --no-reason --out build/reports/live.json
# Live-API LLM eval (opt-in; needs ANTHROPIC_API_KEY; detects model drift)
uv run pytest tests/live -q
# Empirical study (opt-in; uses the shipped tool, replay or live)
uv run mcptrustmap study run --dir corpus/real --llm-mode replay --out build/evaluation/study.json
```

## 3. Validation layers

### Layer 1 — Static & schema checks
Format, lint, type-check; JSON Schema validation of every server/tool/finding/candidate_finding/verdict/report/sarif/policy/corpus/study example; fixture-manifest validation. **Failure:** any invalid schema, unknown finding ID, missing evidence ref, duplicate fixture id, unknown OWASP id, or an `llm-verified` finding with an unresolved anchor.

### Layer 2 — Unit tests
One target per analyzer and boundary:
- manifest & multi-client config parsing (valid + invalid per schema; Claude Desktop / Cursor / Windsurf / VS Code-Cline / generic),
- evidence-graph construction (each fact kind anchored: file:line / schema-path / config-key),
- authority classification (each authority class),
- argument-role classification (each role: command/path/credential/url/recipient/payment_destination/content/…),
- deterministic mismatch via `ast` (line-accurate evidence),
- each authz rule (positive + `not_applicable` when context absent),
- over-sharing rules,
- deterministic poisoning markers (hidden-instruction / unicode / name-spoof) and inventory/supply-chain rules,
- **gate logic** (synthetic candidates + stubbed verdicts): anchor-resolves → survive; bogus anchor → drop pre-judge; refuting weighted panel → drop; plus a **gate red-team** (`tests/gate_redteam/`) of known-false candidates the gate must kill in full,
- findings registry invariants (every id has owasp + severity + recommendation; ids referenced by analyzers exist),
- report build/validate/render for **all three formats** (JSON/MD/SARIF), incl. fail-closed cases.

Minimum coverage: every finding family ≥1 unit test; every argument role ≥1 test; every schema has a valid and an invalid example; the gate has a survive / anchor-drop / panel-drop test.

### Layer 3 — Agent-layer tests (cassette replay)
The reasoning layer and gate run under `--llm-mode replay` against recorded cassettes:
- the reasoner emits anchored `CandidateFinding[]` for a non-Python fixture server (cross-language authority) and a semantically-poisoned tool,
- client-side repo tools are sandboxed to the repo root (path-escape attempts rejected),
- structured output is enforced (schema-invalid candidates rejected, not coerced),
- prompt-cache reuse is asserted (`usage.cache_read_input_tokens > 0` on the second per-tool call in the transcript),
- `LlmReplayMiss` is raised on an unrecorded request (prompt-drift guard),
- end-to-end hybrid: at least one candidate survives the gate, one is dropped for a non-resolving anchor, one is dropped by panel majority.

Cassettes are recorded via vcrpy/pytest-recording at the httpx layer with `x-api-key` scrubbed; `scripts/record_cassettes.py` re-records when prompts change. **No cassette may contain an auth header** (checked in Layer 1).

### Layer 4 — Acceptance fixtures (full flows)
Each fixture is a directory: `manifest.json` (+ `server/` source, + `policy.yml`, + `config.json`, + `allowlist.yml`) with an `expected.json` (expected finding IDs, expected `not_applicable`, expected provenance, expected decision). Fixtures cover:
- **vulnerable Python server:** `readOnlyHint:true` + `os.remove` → `MTM-AUTHORITY-MISMATCH` (deterministic); unconstrained `command` → `MTM-UNCONSTRAINED-COMMAND-ARG`; path traversal arg → `MTM-UNCONSTRAINED-PATH-ARG`; credential arg → `MTM-CREDENTIAL-ARG-EXPOSED`.
- **vulnerable non-Python server:** a JS/TS server whose source mutates state under a read-only declaration → `MTM-AUTHORITY-MISMATCH` (**`llm-verified`**, anchor re-resolved).
- **OAuth proxy server:** token passthrough, wildcard redirect, static client id → `MTM-TOKEN-PASSTHROUGH`, `MTM-LAX-REDIRECT-URI`, `MTM-CONFUSED-DEPUTY`, `MTM-SCOPE-CREEP`.
- **poisoned server:** hidden-instruction / unicode-obfuscated / name-spoofing / tool-shadowing → `MTM-TOOL-POISONING` (deterministic markers + an `llm-verified` semantic case).
- **inventory/supply-chain:** a server absent from the allow-list → `MTM-SHADOW-SERVER`; unpinned `npx` spec → `MTM-UNPINNED-SERVER-PACKAGE`; colliding tool names → `MTM-CROSS-ORIGIN-COLLISION`.
- **over-sharing server:** unscoped broad resource → `MTM-CONTEXT-OVERSHARING`.
- **benign controls** (one per family): faithfully-declared read-only tool; constrained command arg (enum); content-only tool; plain stdio server with no OAuth (all authz `not_applicable`); scoped resource; allow-listed + pinned server; a benign description with imperative phrasing about its own function (no poisoning); an LLM candidate whose anchor doesn't resolve (dropped, not reported).

CLI acceptance: `--help` exits 0 for all subcommands; malformed input exits non-zero; `--fail-on high` returns non-zero on the vulnerable fixture and zero on a clean one; `--llm-mode replay` on an unrecorded request exits non-zero with `LlmReplayMiss`. MCP-server entrypoint: `serve` starts over stdio, a test client lists + calls the `audit` tool and gets the same report the CLI produces for that input.

### Layer 5 — Benchmark / matrix metrics
`corpus run` over `examples/corpus` yields per-family TP/FP/FN, per-OWASP counts, **per-provenance counts**, latency median/p95, and per-server pass/fail. `check_acceptance_matrix.py` asserts: every required family (ACCEPTANCE §14) has a passing positive fixture; **zero** findings on benign controls; both confidence tiers and **both provenances** represented; at least one required `llm-verified` family present; OWASP coverage map present. A separate **held-out set** (`tests/heldout/`, labels not used to tune detectors) is scored once and its **recall** recorded — reported, not build-gating — because recall (false negatives) is the documented weak spot of LLM detection.

### Layer 6 — Report evidence audit
Every finding has a resolvable evidence ref (schema path, source file:line, or config key); every `llm-verified` finding's anchor re-resolves against the evidence graph; every severity has a reason; every recommendation maps to a concrete change; every `security_claims` entry maps to a passing fixture family or the study corpus; `not_applicable` entries are never counted as findings. The report validator fails closed on any violation, across JSON and SARIF.

### Layer 7 — Empirical-study validation
`study run` over `corpus/real` produces a `StudySummary` that validates as a study summary; the run uses only the shipped tool; `evaluation/study.md` states corpus size/selection and bounds its claims. A hand-adjudicated sample yields a measured precision on real data and a **judge-vs-human agreement** figure (% / κ) between the gate panel and the human label — the credibility keystone, since no public MCP-security benchmark exists to score against. The study is opt-in and not part of the release gate, but its summary schema and the writeup's claim-bounding are checked.

## 4. Negative controls (false-positive discipline)

False positives are the main risk for an authority auditor, so every detector ships a benign control:
- faithfully-declared authority (declared ⊇ inferred) → no mismatch,
- constrained command/path arguments → no arg finding,
- content/query-only tools → no role finding,
- no-OAuth server → all authz rules `not_applicable`,
- scoped resources → no over-sharing,
- allow-listed + pinned server → no inventory/supply-chain finding,
- benign-but-imperative description → no poisoning finding,
- **LLM candidate with a non-resolving anchor → dropped by the gate, never reported.**

Acceptance requires **zero** findings (any severity) on benign controls; any warning must explain why it is a warning, not a finding.

## 5. Feasibility-driven test emphasis

Because tool annotations are untrusted and a tool's real authority is not in its schema, the **mismatch** detector and the **verification gate** are the highest-value and highest-risk components. They get the deepest tests:
- **AST positives (deterministic):** `os.remove`, `subprocess.run`, `open(...,'w')`, network clients, SQL execute, secret/env reads, each mapped to an authority class with line evidence.
- **AST negatives:** read-only/parse-only tools, helper calls that look dangerous but are guarded.
- **Cross-language (LLM + gate):** a non-Python mutation under a read-only declaration is proposed by the reasoner, its cited line is re-resolved by `anchor.py`, and the panel does not refute → reported as `llm-verified`; a hallucinated line is dropped pre-judge; a plausible-but-wrong claim is killed by panel majority.
- **Confidence/provenance calibration:** `ast` evidence → high / deterministic; gate-survived LLM → confidence from panel margin / llm-verified; schema-only with no source → `not_applicable`.
- **Gate bias resistance:** the panel is anchor-primary, weighted, and spans model tiers (Opus/Sonnet/Haiku) to resist self-enhancement bias; the gate red-team proves it kills plausible-but-wrong candidates, and the judge-vs-human agreement metric quantifies how far the panel can be trusted.
- The report must never assert a tool *is* read-only from its annotation; only "declared read-only, source contradicts," and never report an LLM claim whose anchor didn't resolve.

## 6. Determinism & reproducibility

- All deterministic-tier inputs are checked-in files; outputs go to `build/` (gitignored). Re-running yields byte-identical reports except latency.
- The LLM tier is reproduced via cassettes: same inputs + same cassette set → identical gated findings. The report's `reproducibility` block records the deterministic-core version and the cassette-set hash. Opus 4.8 exposes no temperature knob (adaptive thinking), so determinism is not pinned at sampling — it comes from cassette replay plus the anchor-primary gate, whose decisive stage is non-LLM.
- No wall-clock timestamps embedded in reports; latency lives only in corpus/study metrics.
- `connect.py` (live MCP) and `tests/live/` (live API) are excluded from the gate and have separate, opt-in tests.

## 7. Regression gates

Preserve across versions: finding IDs, OWASP mappings, schema versions (bump + migration note on change), CLI command names, authority classes, argument roles, fixture IDs, the candidate/verdict schemas, and the cassette-keying scheme. Breaking changes require a schema-version bump, migration notes, re-recorded cassettes, and updated acceptance + this command block.

## 8. Manual review checklist (before tagging v0.1)

- README differentiation still accurate vs the live competitor set (AgentAuditKit/MCP-Scan-now-Snyk/apisec); landscape churns — re-verify.
- OWASP MCP Top 10 cited as **beta** everywhere.
- No over-claims (no "secures MCP"; no schema-only authority truth claims; no "LLM judgment is ground truth"; no study over-generalization).
- The mismatch detector's deterministic evidence is line-accurate and reproducible; every `llm-verified` finding's anchor re-resolves by hand.
- Model IDs match the current Claude API (`claude-opus-4-8` for reasoning/gate; `claude-fable-5` avoided by default); cassettes re-recorded if prompts/models changed.
- Reports (JSON/MD/SARIF) readable by a hiring manager, rigorous for a security reviewer.
- The published benchmark (acceptance corpus + held-out recall + judge-vs-human agreement) is present and its numbers reproduce; no comparable MCP tool publishes these, so they are stated as a differentiator, not a guarantee.
- The MCP-server entrypoint (`serve`) returns byte-identical reports to the CLI for the same input.
- The empirical study's claims are bounded to its corpus and clearly separated from tool-capability claims.
