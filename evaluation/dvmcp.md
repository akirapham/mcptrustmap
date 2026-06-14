# DVMCP runtime evaluation

We evaluate the runtime harness against [Damn Vulnerable MCP Server (DVMCP)](https://github.com/harishsg993010/damn-vulnerable-MCP-server),
a labeled third-party benchmark of 10 challenges. This is a **production-grade external
benchmark**, not a fixture we authored — the only thing we add is the per-challenge
attack recipe and the ground-truth label.

## Scope: which challenges this tool is *for*

The harness drives **tools** and proves violations from **observed behavior**. It therefore
scores the DVMCP challenges whose **tools misbehave on a directly-crafted call**
(authority/authz/provenance boundary). It does **not** score the *agent-level* challenges,
where the vulnerability only fires when an LLM agent reads a poisoned tool description or a
hidden resource and acts on it — those need the agent-in-the-loop track (future work), and
claiming them here would be dishonest.

| DVMCP challenge | Vulnerability | In scope? | Why |
| --- | --- | --- | --- |
| 1 Basic Prompt Injection | hidden resource + injection | ✗ | agent-mediated; no tool misbehaves on a direct call |
| 2 Tool Poisoning | poisoned tool description | ✗ | agent-mediated (hidden instruction) |
| 3 Excessive Permission Scope | path-unconfined `read_file` | ✓ | tool over-serves a private file on a direct call |
| 4 Rug Pull | tool docstring mutates after N calls | ✗† | **tested negative** — mutation not protocol-observable (see below) |
| 5 Tool Shadowing | cross-server shadowing | ✗ | multi-server agent context |
| 6 Indirect Prompt Injection | data-borne injection | ✗ | agent-mediated |
| 7 Token Theft | error-path token leak in `check_email` | ✓ | tool dumps a real token on a direct call |
| 8 Malicious Code Execution | `execute_python_code` | ✓ | arbitrary code exec on a direct call |
| 9 Remote Access Control | command injection in `ping_host` | ✓ | shell injection on a direct call |
| 10 Multi-Vector | mixed | ✗† | **tested negative** — its `run_system_diagnostic` injection is allowlist-gated (`component not in commands` → error), and its secret is a `@mcp.resource` (agent-level), not a tool |

## Results (wired challenges)

Each run drives the real challenge server over stdio, with the **LLM attacker** planning the
probe; the **deterministic oracle** decides the verdict from observed behavior. The captured
Observation is frozen and replayed in CI (`tests/unit/test_dvmcp.py`), so every row below is
an enforced assertion, not a claim.

| Challenge | Attacker probe | Observed | Finding (ground truth) | Detected |
| --- | --- | --- | --- | --- |
| 3 | `read_file("/…/private/system_credentials.txt")` | planted API key in output | `MTM-RT-CONTEXT-LEAK` | ✓ |
| 7 | `check_email("audit")` (unknown folder → error path) | leaked api key in output | `MTM-RT-CONTEXT-LEAK` | ✓ |
| 8 | `execute_python_code` computes the canary in Python | computed product in output | `MTM-RT-COMMAND-EXEC` | ✓ |
| 9 | `ping_host("127.0.0.1; echo <canary>")` | computed product in output | `MTM-RT-COMMAND-EXEC` | ✓ |

**In-scope detection: 4/4** with the (per-challenge) scripted attack recipe. But "scripted"
hides a crucial distinction the live run below exposes.

### Live validation: does a real model find these, or did the recipe?

The recipes above are deterministic responders we wrote — they prove the *harness + oracle*,
not that an LLM *plans* the exploit. So we ran the attacker live (`gpt-4o`, provider-agnostic
backend) against each challenge **black-box: from the tool schema + arsenal alone**, recorded
the model's own plans (`tests/cassettes/dvmcp_attack.json`), and re-froze the resulting
observations. `test_dvmcp_cassette` then proves in CI — no key — that every executed probe was
one the model planned.

| Challenge | gpt-4o's own winning probe (unaided) | Single-round |
| --- | --- | --- |
| 7 | `check_email("../../../../etc/passwd")` → error-path token leak | ✓ CONTEXT-LEAK |
| 8 | `execute_python_code("__import__('os').system('echo <canary>')")` | ✓ COMMAND-EXEC |
| 9 | `ping_host("127.0.0.1; echo <canary>")` | ✓ COMMAND-EXEC |
| 3 | reads `/etc/passwd` — **can't find the private path in one shot** | ✗ |

**Single-round: 3/4.** Challenge 3's secret is at `/tmp/dvmcp_challenge3/private/
system_credentials.txt` — not in the tool schema — so a one-shot attacker reads `/etc/passwd`
and misses it.

### Multi-round recon closes challenge 3 → 4/4

The attacker now runs up to N rounds, each seeing the prior rounds' effects (including response
snippets). gpt-4o cracks ch3 unaided:

1. `search_files("password")` → output names `Private/system_credentials.txt` (recon).
2. `read_file("../Private/system_credentials.txt")` → traverses from the `public/` dir to the
   private file and leaks the credential — using the filename **the search revealed**, not a
   wordlist entry (the challenge-specific paths were removed from `runtime/recon.py`, so this is
   a genuine search → learn → read loop).

**Autonomous black-box detection: 4/4** — the multi-round attacker matches the white-box recipe
with no out-of-band knowledge. ch3 is the hardest (it needs the `../private` inference), so we
run the planner at `temperature=0` and the recorder retries it a few times; it is less reliable
than the one-shot 7/8/9, which is the honest texture of an inferential exploit.

**A false positive the live run caught.** While enumerating keywords, gpt-4o searched for a
*honey marker* as a `search_files` keyword; the tool echoed it back ("no files containing
`<marker>`") and the context-leak oracle fired on our own reflected input. That's reflection,
not a leaked secret. We hardened the oracle: a context leak now counts only when the marker did
**not** appear in the probe's own arguments — the same reflection-vs-real distinction the
computed canary draws for command-exec. The model doing something our scripted probes never did
is exactly how live testing earns its keep.

Three takeaways: (1) a real frontier model — not our recipe — generates every exploit from the
schema alone, so "the LLM drives the attack" is empirically real; (2) multi-round recon turns a
3/4 into 4/4 by chaining search → read; (3) running it live is what separated a genuine
capability from a scripted one, and surfaced a real oracle bug.

## Precision / recall (with negatives)

Recall alone is meaningless without a false-positive denominator, so we added a **controlled
benign server** (`tests/fixtures/benign_mcp_server.py`: pure add, canned forecast, string
reverse — no shell, fs, network, or seeded state) and drove it both deterministically and with
gpt-4o live. Both yield **zero findings** — including when gpt-4o echoes a honey marker through
`reverse_text` (the reflection fix holds end-to-end). The scoreboards (`test_precision_recall.py`,
all CI-replayed):

| Attacker | TP | FN | FP | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Autonomous gpt-4o (multi-round) | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |

Over the four in-scope challenges + two benign targets: every vulnerable target detected, **zero
false positives** on the benign negatives (including gpt-4o echoing a honey marker through
`reverse_text`). The single-round attacker scores 3/4 recall; multi-round closes the gap. (This
is a deliberately small, curated set — a sanity benchmark, not a population estimate; a larger
wired corpus is future work.)

## Baseline: why static scanners structurally miss these

We attempted a baseline with `mcp-scan` (now `snyk-agent-scan`): it requires Snyk's *hosted*
analysis service (`--analysis-url` / `--control-server`) and did not complete offline in our
sandbox, so we report the comparison structurally rather than with a number we couldn't fairly
produce. The substantive point doesn't depend on the run: `mcp-scan` and its peers analyze tool
**descriptions and schemas** for poisoning / hidden-instruction injection. DVMCP 7/8/9's
vulnerabilities live in the **implementation** — `subprocess(..., shell=True)`, an error path that
dumps a token, `execute_python_code` — behind entirely benign descriptions ("Ping a host", "Check
emails"). A description/schema scanner has no signal to flag them; only running the tool and
observing the behavior does. This is the exact static-vs-runtime gap the v0.2 pivot targets, and
it cuts both ways: static scanners catch the *description-poisoning* challenges (1/2/4/6,
agent-level) that we hold out of scope. The approaches are complementary — static reads the
manifest, runtime watches the behavior — which is why MCPTrustMap ships both layers.

Full precision/recall over a larger wired corpus remains future work.

### † Challenge 4 (Rug Pull): a tested negative

Challenge 4 mutates `get_weather_forecast.__doc__` after three calls, injecting an
`<IMPORTANT>` instruction that tells an agent to exfiltrate system config. We drove the real
server (list tools → call it 4× → list again) and compared the full descriptions: **they are
identical** — FastMCP snapshots a tool's description at decoration time, so the runtime
`__doc__` mutation is invisible over the MCP protocol. No external runtime harness (ours or
otherwise) can observe this rug pull via `list_tools`; the *behavioral* change (richer data
after the threshold) is observable but is not, on its own, a deterministic violation (benign
tools vary their output too). Our membership/definition rug-pull oracle (`MTM-RT-RUG-PULL`) is
validated by unit tests against an actual tool-set change; challenge 4 simply does not surface
one. We record this rather than claim a detection — testing the assumption is the point.

## Why the LLM attacker is load-bearing here

The deterministic role-based probe **cannot** reach any of these: it classifies `ping_host`'s
`host` as a URL (→ the sink, no injection), and it has no notion that `read_file` should be
pointed at a specific private path. DVMCP is precisely where the LLM attacker earns its place
over deterministic probing — while the **verdict stays deterministic** (a marker/secret/
computed-canary observed at a sink or in output), never an LLM opinion.

## Two techniques worth calling out

- **Computed canary (command-exec without eBPF).** A literal echoed marker can't distinguish
  reflection from execution. We inject an *un-evaluated* product (shell `$((a*b))`, Python
  `a*b`); only if code *evaluates* it does the product `tag+str(a*b)` appear. The attacker is
  given the factors, never the proof — so reflection can't masquerade as execution. This is
  what lets a shell-injection (ch9) and a Python-exec (ch8) both be labeled `COMMAND-EXEC`
  deterministically.
- **Substring-taint of a target's own secrets.** For excessive-disclosure (ch3), we register
  the challenge's *real* planted secret as a watch marker; a tool returning it is a proven
  context leak. (Cf. MCP-SandboxScan's real-value substring taint.)

## Reproduce

```bash
# deterministic CI replay of the frozen runs (no checkout, no mcp extra):
uv run pytest tests/unit/test_dvmcp.py

# live, against a real DVMCP checkout (regenerates the frozen observations):
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server /tmp/dvmcp
uv pip install 'mcp>=1.0'
MTM_DVMCP_ROOT=/tmp/dvmcp uv run pytest tests/unit/test_dvmcp_live.py -v
```
