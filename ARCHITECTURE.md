# MCPTrustMap — Architecture

A map of how the code is organized, how control flows through it, how data is
transformed, and where every responsibility lives. Read this beside the source;
function names are stable anchors (line numbers drift).

> **One-sentence model.** MCPTrustMap turns an MCP server into a list of evidence-
> backed `Finding`s two ways — **statically** (read configs / manifests / source →
> deterministic rules + an LLM proposer gated by an adversarial verifier) and at
> **runtime** (drive the server in a sandbox with honeytokens → observe behavior →
> deterministic oracles). Both halves share one contract: a `Finding` validated by a
> fail-closed report engine. **In both halves an LLM may *propose/attack*, but only
> deterministic code decides the verdict.**

---

## 1. The big picture

```
                    ┌───────────────────────────────────────────────┐
                    │              SHARED CONTRACTS                  │
                    │  models.py · findings.py · policy.py           │
                    │  report.py · jsonio.py + schemas/ · errors.py  │
                    └───────────────────────────────────────────────┘
                              ▲                         ▲
                produces      │                         │   produces
              list[Finding]   │                         │  list[Finding]
                              │                         │
   ┌──────────────────────────┴───────┐   ┌─────────────┴──────────────────────────┐
   │   STATIC HALF  (v0.1)            │   │   RUNTIME HALF  (v0.2)                   │
   │   "what the server CLAIMS"       │   │   "what the server actually DOES"        │
   │                                  │   │                                          │
   │   ingest → evidence → detect     │   │   honey → sandbox → drive → observe      │
   │         → reason → verify        │   │        → oracles                         │
   │   (audit.py orchestrates)        │   │   (harness.py / commands.py orchestrate) │
   └──────────────────────────────────┘   └──────────────────────────────────────────┘
                              │                         │
                              └────────────┬────────────┘
                                           ▼
                              report.py → JSON / Markdown / SARIF
```

Both halves are exposed through one CLI (`cli.py` → `commands.py`). The static half
analyzes documents; the runtime half executes the server. They are independent and
can be used separately.

---

## 2. Code map

### Shared contracts — the vocabulary every module speaks
| File | Responsibility |
|---|---|
| `models.py` | Core dataclasses: `ServerRecord`, `ToolRecord`, `ArgRecord`, `Finding` |
| `findings.py` | The finding **registry** (`MTM-*`, `MTM-RT-*` ids → title/severity/OWASP) + `make_finding()` |
| `policy.py` | Closed sets: `SEVERITIES`, `OWASP_MCP_IDS`, `PROVENANCES`, `CONFIDENCES`, `at_or_above` |
| `report.py` | `build_report` / `validate_report` (fail-closed) / `render_json·markdown·sarif` |
| `jsonio.py` + `schemas/*.json` | Schema load + validate (records, report, candidate, verdict, attack_plan) |
| `errors.py` | Typed error hierarchy + exit codes (`InputError`=2, `SchemaValidationError`=3, …) |

### CLI surface
| File | Responsibility |
|---|---|
| `cli.py` | `argparse` definition of every subcommand; `main()` catches `MtmError` → exit code |
| `commands.py` | `dispatch()` + one `cmd_*` handler per subcommand (`cmd_audit`, `cmd_pentest`, …) |

### Static pipeline (v0.1)
| Stage | Files | Does |
|---|---|---|
| **ingest** | `ingest/discovery.py`, `ingest/manifest.py` | Client configs / tool manifests → `ServerRecord` |
| **evidence** | `evidence/prepare.py`, `roles.py`, `authority.py`, `source/python_ast.py`, `source/generic_regex.py`, `graph.py`, `oauth.py`, `poisoning.py`, `inventory.py` | Deterministic *facts*, each pinned to an anchor (`file:line`, schema-path) in an `EvidenceGraph` |
| **detect** | `detect/mismatch.py`, `authz.py`, `oversharing.py`, `poisoning.py`, `arguments.py`, `inventory.py` | Deterministic rules → `Finding`s (`provenance=deterministic`) |
| **reason** | `reasoning.py`, `agent/reasoner.py`, `agent/schemas.py`, `agent/prompts.py`, `agent/tools.py` | LLM reads source/descriptions → `CandidateFinding`s (must cite an anchor) |
| **verify** | `verify/gate.py`, `verify/anchor.py`, `verify/judge.py` | Adversarial gate: anchor must re-resolve **and** a weighted judge panel must not refute → survivors become `Finding`s (`provenance=llm-verified`) |
| **orchestrate** | `audit.py` | `audit_server` (deterministic) + `audit_to_report` (adds reasoning, builds report) |

### Runtime pipeline (v0.2)  — under `runtime/`
| Stage | Files | Does |
|---|---|---|
| **honey** | `honey.py` | Mint markers/secrets, the **computed canary** (`exec_payload`/`exec_proof`), `watch` secrets |
| **recon/probes** | `recon.py`, `probes.py` | Sensitive-file wordlist + role-based deterministic probes (the non-LLM floor) |
| **attacker** | `attacker.py` | LLM-driven planner: `build_attack_request`, `parse_attack_plan`, `LLMAttacker.plan(prior=…)` |
| **sandbox** | `sandbox.py`, `docker.py`, `sink.py` | Run the server (`DockerSandbox`/`LocalStdioSandbox`/`FakeSandbox`); hardened `docker run` argv; egress sink |
| **drive** | `driver.py` | `drive_session` (the multi-round loop) + `build_effect` (fuse response + fs-diff + egress) |
| **observe** | `observe.py`, `fsdiff.py` | `EgressEvent`/`ToolEffect`/`Observation` model; filesystem snapshot/diff |
| **oracles** | `oracles.py` | Observation → `MTM-RT-*` findings (`provenance=runtime-confirmed`) — **deterministic** |
| **orchestrate / eval** | `harness.py`, `metrics.py`, `dvmcp.py` | `pentest_server`, `declared_from_tools`; precision/recall `Scoreboard`; DVMCP benchmark adapter |

### Shared LLM layer (used by both `reason` and `attacker`)
| File | Responsibility |
|---|---|
| `agent/llm_client.py` | `LLMClient` with `replay` / `record` / `live` modes + `provider` routing; `request_hash` keys cassettes |
| `agent/live.py` | Anthropic backend (`live_complete`) for purposes `reason` / `judge` / `runtime-attack` |
| `agent/openai_live.py` | OpenAI backend (`openai_complete`) for `runtime-attack` (provider-agnostic attacker) |

### Misc surfaces
| File | Responsibility |
|---|---|
| `serve.py` | Expose `audit` as an MCP tool a host agent can call |
| `connect.py` | Live MCP ingestion (list a running server's tools) |
| `corpus.py`, `study.py` | Batch audit + empirical-study harnesses |

---

## 3. Control-flow charts

### 3a. `mcptrustmap pentest` (runtime)

```
cli.main ─▶ commands.dispatch ─▶ cmd_pentest
   │
   ├─ mint_honey(seed, declared_root, [watch])                 # taint vocabulary
   ├─ parse_manifest ─▶ declared_from_tools                    # "what each tool CLAIMS"
   │
   ├─ _pentest_observation ───────────────── FORK on source ──┐
   │        │                                                 │
   │        ├─ --replay  ▶ FakeSandbox.from_dict(json).run() ─┼─▶ Observation  (frozen, no subprocess)
   │        │                                                 │
   │        ├─ _build_attacker ── FORK: None | LLMAttacker(replay|live, anthropic|openai)
   │        │                                                 │
   │        ├─ --image   ▶ DockerSandbox(...).run() ──────────┤
   │        └─ local     ▶ seed honey dir                     │
   │                       LocalStdioSandbox(...).run() ──────┘
   │                              │
   │                              ▼  (live backends descend into _drive_stdio)
   │                       ┌──────────────────────────────────────────────┐
   │                       │ _drive_stdio (sandbox.py)                     │
   │                       │   with EgressSink() as sink:   # random port  │
   │                       │   define plan_round(listed, prior):           │
   │                       │       tools→ToolRecords→assign_roles          │
   │                       │       attacker.plan(...) OR probe_plan(...)    │
   │                       │       _resolve_port(args, port)               │
   │                       │   asyncio.run(_go) ▶ drive_session ───────────┼─┐
   │                       └──────────────────────────────────────────────┘ │
   │                              ┌─────────────────────────────────────────┘
   │                              ▼
   │                       ┌──────────────────────────────────────────────┐
   │                       │ drive_session (driver.py)   ◀── THE ENGINE    │
   │                       │   initialize(); listed = list_tools()         │
   │                       │   for _round in range(rounds):    ◀ MULTI-ROUND
   │                       │       plan = plan_round(listed, effects)      │
   │                       │       fresh = dedup(plan)                     │
   │                       │       if not fresh: break       ◀ converged   │
   │                       │       for (name,args) in fresh:               │
   │                       │           snapshot pre; egress pre            │
   │                       │           result = call_tool(name,args) ◀ RUN │
   │                       │           snapshot post; egress slice         │
   │                       │           effects += build_effect(...)  ◀ FUSE│
   │                       │   return Observation(effects, before, after)  │
   │                       └──────────────────────────────────────────────┘
   │                              │
   ├─ run_oracles(server_id, Observation, honey, declared) ◀── THE VERDICT (deterministic)
   ├─ dedupe
   ├─ build_report ─▶ validate_report          # fail-closed
   └─ _emit + --fail-on  ─▶ exit code
```

**The decisive split:** everything *above* `run_oracles` is about *getting* an
`Observation` (and may involve an LLM and a live subprocess); `run_oracles` and
everything below are pure, deterministic, and run in CI. `--replay` exercises only
the deterministic tail.

### 3b. `mcptrustmap audit` (static) — same shape, different evidence

```
cli.main ─▶ dispatch ─▶ cmd_audit
   ├─ _build_audit_target ─▶ ServerRecord     (manifest | --connect | --server-record)
   └─ audit_to_report
        ├─ audit_server                                   ◀ DETERMINISTIC
        │     prepare_server   ▶ assign_roles + classify_declared_authority + EvidenceGraph
        │     infer_source_authority  ▶ python_ast / generic_regex facts
        │     detect_argument / mismatch / authz / oversharing / poisoning / supply_chain / shadow
        │        ─▶ list[Finding]  (provenance=deterministic)
        │
        ├─ if --reason: run_reasoning_layer                ◀ LLM PROPOSES, GATE DECIDES
        │     _make_client(llm_mode)                       # replay | live
        │     run_reasoner  ▶ LLMClient.complete(purpose="reason") ▶ CandidateFinding[]
        │     run_gate:  for each candidate
        │         anchor_resolves(candidate, graph)        # does the cited file:line really say that?
        │         run_judge ▶ LLMClient.complete("judge")  # panel of lenses tries to REFUTE
        │         evaluate(anchor_ok, verdicts)            # source lens counts double; majority refute → drop
        │            survivors ─▶ Finding (provenance=llm-verified)
        │
        └─ build_report ─▶ validate_report ─▶ JSON
```

### 3c. The shared fork — `LLMClient.complete` (llm_client.py)

Both `attacker.plan` and `run_reasoner`/`run_judge` funnel here:

```
LLMClient.complete(request)            # request = hashable dict {purpose, model, salient inputs}
   h = request_hash(request)
   ├─ mode "replay" ▶ cassettes[h]["response"]      # CI: no network; KeyError-equivalent = loud LlmReplayMiss
   ├─ mode "record" ▶ responder(request)            # bake a cassette  (responder may itself call live = live-and-record)
   └─ mode "live"   ▶ _live_call ── provider fork:
                         ├─ "anthropic" ▶ live.py  live_complete
                         └─ "openai"    ▶ openai_live.py  openai_complete
```

---

## 4. Dataflow charts

### 4a. Runtime taint flow — honey in, proof out

```
  mint_honey(seed)                          declared_from_tools(tools)
  ├─ tokens   {marker: "sk-…"}              └─ {tool: {authority:set, read_only:bool}}
  ├─ files    {/honey/secret.txt: marker}                    │ "what it CLAIMS"
  ├─ canary_marker                                           │
  ├─ exec_payload "MTMX..$((a*b))"  ─┐ inject                │
  ├─ exec_proof  "MTMX..<product>"  ─┼─ appears ONLY if a    │
  └─ watch  (3rd-party real secrets) │  shell evaluated it   │
        │                            │                       │
        ▼ seeded into sandbox        ▼ put into probe args   │
  ┌─────────────────────────┐                                │
  │  server runs a probe    │  attacker.plan() / probe_plan()│
  │  (call_tool)            │◀───────────────────────────────┘
  └─────────┬───────────────┘
            │ observed three ways, fused per tool by build_effect:
            ├─ response text   ───────────┐
            ├─ egress events (sink)  ──────┼──▶  ToolEffect ──▶ Observation
            └─ fs-diff (snapshot pre/post)┘
                                                   │
                                                   ▼  run_oracles  (marker matching)
   marker/secret in egress payload ........▶ MTM-RT-CREDENTIAL-EXFIL
   marker in response AND NOT in args .....▶ MTM-RT-CONTEXT-LEAK     (reflection excluded)
   exec_proof in response/execs ...........▶ MTM-RT-COMMAND-EXEC     (computed canary = real exec)
   fs touch outside declared_root .........▶ MTM-RT-PATH-ESCAPE
   egress host ∉ declared_hosts ...........▶ MTM-RT-UNEXPECTED-EGRESS
   actual authority ⊄ declared ............▶ MTM-RT-AUTHORITY-VIOLATION
   tool list before ≠ after ...............▶ MTM-RT-RUG-PULL
```

The `Observation` is the cut point: it is JSON-serializable (`to_dict`/`from_dict`),
so a real run is **frozen** to a fixture and **replayed** through `FakeSandbox` in CI
— the runtime analogue of an LLM cassette.

### 4b. How a `Finding` is assembled (both halves)

```
detector/oracle ─▶ make_finding(id, server_id, evidence[], confidence, provenance, [tool])
        │  looks up findings.REGISTRY[id]  → title, severity, OWASP id
        ▼
   Finding{ finding_id, server_id, tool?, severity, owasp, confidence,
            provenance, status, evidence[{kind, ref, detail}], recommendation }
        │
        ▼  build_report(target, findings, servers, tools)
   report{ summary{by_severity,by_owasp,by_provenance}, findings[], security_claims[], … }
        │
        ▼  validate_report   (fail-closed semantic checks:)
   - every finding_id ∈ REGISTRY        - severity/owasp/confidence/provenance ∈ closed sets
   - every active finding has evidence  - summary counts match  - claims backed by active findings
```

### 4c. Multi-round recon (why ch3 needs round 2)

```
round 1:  plan_round(tools, prior=[])
            search_files("password") ─▶ response: "Private/system_credentials.txt"
            read_file("/etc/passwd")  ─▶ no marker
          effects accumulate ─────────────────┐
round 2:  plan_round(tools, prior=effects)     │  prior carries the response snippet
            └─ model SEES "Private/system_credentials.txt" in prior_effects
            read_file("../Private/system_credentials.txt")
              ─▶ response contains the `watch` secret ─▶ MTM-RT-CONTEXT-LEAK ✓
          dedup ends the loop once no fresh probes appear
```

---

## 5. Invariants & design decisions (the "why")

1. **LLM proposes/attacks; deterministic code decides.** `attacker.plan` and the
   reasoner can use any model; `run_oracles` and the verify gate are pure. A finding
   is never an LLM opinion — it's a marker observed at a sink, a computed canary in
   output, a fs-diff, or an anchor that re-resolves.
2. **Replay-first.** `LLMClient` and `Observation` both serialize, so CI runs with no
   network and no API key. A replay miss fails **loudly** (`LlmReplayMiss`) so prompt/
   model drift can't silently hit the network.
3. **Reflection ≠ proof.** Two oracle subtleties: command-exec uses a *computed*
   canary (`$((a*b))` → product appears only if a shell evaluated it); context-leak
   excludes any marker the attacker put in the probe's own arguments. Both reject
   "the tool echoed my input."
4. **Provider-agnostic attacker.** Because the verdict is the oracle, the attacker is
   a swappable LLM (Anthropic or OpenAI). Claude stays default for the static reason/
   judge layers.
5. **Fail-closed reports.** `validate_report` rejects unknown ids, unbacked claims,
   miscounted summaries — a report is a contract, not a log.
6. **Honest scope.** The runtime harness drives *tools*; DVMCP's agent-level
   (description-poisoning) challenges are explicitly out of scope, and `ch4`/`ch10`
   are recorded as *tested negatives* rather than forced.

---

## 6. The two "mode" matrices

**LLM execution mode** (`--llm-mode`, both halves):

| mode | source of the response | used for |
|---|---|---|
| `replay` | recorded cassette, keyed by `request_hash` | CI, default — deterministic, no key |
| `record` | a responder (which may call live) → saved | baking cassettes |
| `live` | Anthropic / OpenAI API | periodic real evaluation |

**Runtime backend** (`pentest` source flag):

| flag | backend | needs |
|---|---|---|
| `--replay obs.json` | `FakeSandbox` | nothing (pure) |
| `--local-command` | `LocalStdioSandbox` | `mcp` extra + a subprocess |
| `--image` | `DockerSandbox` | Docker + `mcp` extra |

Orthogonal knobs: `--attacker {deterministic,llm}`, `rounds` (multi-round), `--provider {anthropic,openai}`.

---

## 7. How to extend

- **Add a runtime oracle:** add a `FindingSpec` in `findings.py`, emit it from
  `_oracles_for_effect` (or session-level) in `oracles.py`, add a unit test under
  `tests/unit/` that feeds a crafted `ToolEffect`.
- **Add a DVMCP challenge:** add a `DvmcpChallenge` to `CHALLENGES` in `dvmcp.py`
  (subpath, `expect`, an `attack(arsenal)` recipe, `watch`/`llm_blackbox` as needed),
  then `record_attack_cassettes.py` freezes it; the data-driven `test_dvmcp.py` picks
  it up automatically.
- **Add an LLM provider:** add a `*_complete` backend module, route it in
  `LLMClient._live_call`, declare the extra in `pyproject.toml`.
- **Add a static rule:** add `detect_*_findings` in `detect/`, call it from
  `audit_server` in `audit.py`, back each finding with an `EvidenceGraph` anchor.

---

## 8. Where to start reading (control-flow order)
1. `commands.py:cmd_pentest` + `driver.py:drive_session` — the runtime control flow, side by side.
2. Trace a `--replay` run first (5 synchronous frames): `cmd_pentest → _pentest_observation → FakeSandbox.run → run_oracles → build_report`.
3. Re-read with `--local-command --attacker llm` to add the `_drive_stdio → drive_session → attacker.plan → LLMClient.complete` middle.
4. For the static half: `audit.py:audit_to_report` → `run_reasoning_layer` → `verify/gate.py:evaluate`.
5. Tiny tests that crystallize the subtle bits: `tests/unit/test_runtime_exec_oracle.py` (computed canary) and `test_runtime_leak_oracle.py` (reflection exclusion).

---

## 9. Glossary

| Term | Meaning |
|---|---|
| **Honey** | Deterministically-minted markers/secrets/files seeded as taint sources |
| **Computed canary** | `MTMX..$((a*b))`; its *product* in output proves a shell evaluated it (exec, not reflection) |
| **watch** | A third-party target's own known secret, tainted on (substring taint) |
| **Observation** | The full record of a driven run (`ToolEffect[]` + tool lists); serializable, replayable |
| **Oracle** | Deterministic function: `Observation` → `MTM-RT-*` findings |
| **Cassette** | Recorded LLM request→response, keyed by `request_hash`, replayed in CI |
| **Anchor** | A concrete evidence pointer (`file:line`, schema-path) a static finding must cite |
| **Gate** | The adversarial verifier: anchor must re-resolve + judge panel must not refute |
| **declared vs actual** | What a tool *claims* (schema/annotations) vs what it *does* (observed) — the core mismatch |
| **black-box / white-box** | Whether the LLM attacker finds the exploit from the schema alone vs needs known paths |
| **tested negative** | A challenge we drove and *correctly* did not flag / cannot reach — recorded, not hidden |
