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
| 10 Multi-Vector | mixed | ◐ | candidate; not yet wired |

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

**In-scope detection: 4/4.** Two finding families (context-leak, command-exec). Full
precision/recall over a larger wired set, plus a baseline comparison vs `mcp-sec-audit` /
`mcp-scan`, is the next step.

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
