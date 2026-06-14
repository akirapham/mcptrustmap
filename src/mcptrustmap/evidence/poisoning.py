"""Deterministic tool/schema poisoning markers (Phase 5).

Language-agnostic, high-precision lexical/structural markers. The LLM layer adds
semantic poisoning judgment on top (gate-verified). Returns (sub_type, anchor_ref,
detail) tuples; the detector turns them into MTM-TOOL-POISONING findings.
"""

from __future__ import annotations

import re
import unicodedata

from ..models import ToolRecord

# hidden-instruction markers (injection aimed at the agent reading the description)
_HIDDEN_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+|the\s+)?(previous|prior|above)",
        r"disregard\s+(the|all|any|previous|prior)",
        r"do\s+not\s+(tell|mention|inform|reveal|disclose)",
        r"you\s+must\s+(always|never|immediately|first)",
        r"instead\s+of\s+(the|your|calling)",
        r"new\s+instructions?\b",
        r"system\s*:",
        r"<\s*/?\s*system\s*>",
        r"<\s*/?\s*important\s*>",
        r"<!--",
        r"\boverride\s+(the|your|all)\b",
        r"assistant\s*:",
    )
]

# name tokens that impersonate authority/trust
_SPOOF_TOKENS = frozenset({"official", "verified", "trusted", "system", "builtin", "internal"})
_SPLIT = re.compile(r"[^a-z0-9]+")

# zero-width / bidi / format control code points
_ZW_BIDI = (
    set(range(0x200B, 0x2010))
    | {0xFEFF}
    | set(range(0x2060, 0x2065))
    | set(range(0x2066, 0x206A))
    | set(range(0x202A, 0x202F))
)

Marker = tuple[str, str, str]  # (sub_type, anchor_ref, detail)


def _hidden_instruction(desc: str) -> str | None:
    for pat in _HIDDEN_PATTERNS:
        m = pat.search(desc)
        if m:
            return f"hidden-instruction marker: {m.group(0)!r}"
    return None


def _unicode_obfuscation(text: str) -> str | None:
    for ch in text:
        code = ord(ch)
        if code in _ZW_BIDI or unicodedata.category(ch) == "Cf":
            return f"zero-width/format control U+{code:04X}"
        if 0x0400 <= code <= 0x04FF or 0x0370 <= code <= 0x03FF:
            return f"non-Latin homoglyph U+{code:04X}"
    return None


def _name_spoof(name: str) -> str | None:
    tokens = {t for t in _SPLIT.split(name.lower()) if t}
    hit = tokens & _SPOOF_TOKENS
    if hit:
        return f"name claims authority/trust: {', '.join(sorted(hit))}"
    return None


def poisoning_markers(tool: ToolRecord) -> list[Marker]:
    markers: list[Marker] = []
    name = tool.name or ""
    desc = tool.description or ""

    hidden = _hidden_instruction(desc)
    if hidden:
        markers.append(("hidden-instruction", f"{tool.name}:description", hidden))

    for field, text in (("name", name), ("description", desc)):
        obf = _unicode_obfuscation(text)
        if obf:
            markers.append(("unicode-obfuscation", f"{tool.name}:{field}", obf))
            break

    spoof = _name_spoof(name)
    if spoof:
        markers.append(("name-spoofing", f"{tool.name}:name", spoof))

    return markers
