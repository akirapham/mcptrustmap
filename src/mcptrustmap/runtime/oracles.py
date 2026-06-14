"""Deterministic oracles: observed behavior -> MTM-RT-* findings (proof).

No LLM here — a finding fires iff a marker reached a sink, a canary ran, or a
tool's actual authority exceeded what it declared. The LLM may have generated the
probe that provoked it, but the verdict is observed, not opined.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from ..findings import make_finding
from ..models import Finding
from .honey import HoneySet
from .observe import Observation, ToolEffect

RT = "runtime-confirmed"


def _ev(tool: str, detail: str) -> list[dict[str, str]]:
    return [{"kind": "runtime", "ref": f"runtime:{tool}", "detail": detail}]


def _within(path: str, root: str) -> bool:
    p, r = PurePosixPath(path), PurePosixPath(root)
    return p == r or r in p.parents


def _exfil_hit(payload: str, honey: HoneySet) -> str | None:
    for marker in honey.markers():
        if marker and marker in payload:
            return marker
    for marker, secret in honey.tokens.items():
        if secret in payload:
            return marker
    return None


def _oracles_for_effect(
    server_id: str, eff: ToolEffect, honey: HoneySet, declared: dict
) -> list[Finding]:
    out: list[Finding] = []

    for event in eff.egress:
        hit = _exfil_hit(event.payload, honey)
        if hit:
            out.append(
                make_finding(
                    "MTM-RT-CREDENTIAL-EXFIL",
                    server_id,
                    _ev(eff.tool, f"honeytoken {hit} exfiltrated to {event.host}"),
                    confidence="high",
                    provenance=RT,
                    tool=eff.tool,
                )
            )

    leak = next((m for m in honey.markers() if m and m in eff.response), None)
    if leak:
        out.append(
            make_finding(
                "MTM-RT-CONTEXT-LEAK",
                server_id,
                _ev(eff.tool, f"honey marker {leak} returned in tool output"),
                confidence="high",
                provenance=RT,
                tool=eff.tool,
            )
        )

    if honey.canary_marker and any(honey.canary_marker in x for x in eff.execs):
        out.append(
            make_finding(
                "MTM-RT-COMMAND-EXEC",
                server_id,
                _ev(eff.tool, f"canary command executed ({honey.canary_marker})"),
                confidence="high",
                provenance=RT,
                tool=eff.tool,
            )
        )

    escaped = next((p for p in eff.fs_touches() if not _within(p, honey.declared_root)), None)
    if escaped:
        out.append(
            make_finding(
                "MTM-RT-PATH-ESCAPE",
                server_id,
                _ev(eff.tool, f"accessed {escaped} outside declared root {honey.declared_root}"),
                confidence="high",
                provenance=RT,
                tool=eff.tool,
            )
        )

    if honey.declared_hosts:
        rogue = next((e.host for e in eff.egress if e.host not in honey.declared_hosts), None)
        if rogue:
            out.append(
                make_finding(
                    "MTM-RT-UNEXPECTED-EGRESS",
                    server_id,
                    _ev(eff.tool, f"connected to undeclared host {rogue}"),
                    confidence="high",
                    provenance=RT,
                    tool=eff.tool,
                )
            )

    decl = declared.get(eff.tool, {})
    declared_auth = set(decl.get("authority", set()))
    actual = eff.mutating_authorities()
    if decl.get("read_only") and actual:
        out.append(
            make_finding(
                "MTM-RT-AUTHORITY-VIOLATION",
                server_id,
                _ev(eff.tool, f"declared read-only but performed {', '.join(sorted(actual))}"),
                confidence="high",
                provenance=RT,
                tool=eff.tool,
                title_suffix=f"declared read-only, did {', '.join(sorted(actual))}",
            )
        )
    elif actual - declared_auth:
        undeclared = sorted(actual - declared_auth)
        out.append(
            make_finding(
                "MTM-RT-AUTHORITY-VIOLATION",
                server_id,
                _ev(eff.tool, f"exercised undeclared authority {', '.join(undeclared)}"),
                confidence="high",
                provenance=RT,
                tool=eff.tool,
                title_suffix=", ".join(undeclared),
            )
        )

    return out


def run_oracles(
    server_id: str, observation: Observation, honey: HoneySet, *, declared: dict
) -> list[Finding]:
    """Turn an Observation into runtime-confirmed findings.

    `declared` maps tool name -> {"authority": set[str], "read_only": bool} from
    the static surface-mapper (what the tool *claims* it can do).
    """
    findings: list[Finding] = []
    for eff in observation.effects:
        findings.extend(_oracles_for_effect(server_id, eff, honey, declared))

    before, after = set(observation.tool_list_before), set(observation.tool_list_after)
    if before and after != before:
        delta = f"{sorted(before)} -> {sorted(after)}"
        findings.append(
            make_finding(
                "MTM-RT-RUG-PULL",
                server_id,
                [{"kind": "runtime", "ref": "runtime:tools", "detail": f"tools changed: {delta}"}],
                confidence="high",
                provenance=RT,
            )
        )
    return findings
