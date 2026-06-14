"""Non-Python source authority via curated regex (low-confidence anchors).

`ast` only covers Python. For other languages we emit line-accurate `call` facts
into the evidence graph as *anchors* — they are NOT turned into deterministic
findings (regex is imprecise). Instead they give the LLM layer something to cite
and the gate something to re-resolve: a cross-language mismatch the reasoner
proposes must land on one of these lines, or the gate drops it.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...models import ServerRecord
from ..graph import Anchor, EvidenceFact, EvidenceGraph

_PY = ".py"

# (compiled pattern, authority class). Applied line-by-line to non-Python source.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bfs\.(unlink|rm|rmdir|unlinkSync|rmSync)\b"), "filesystem"),
    (
        re.compile(r"\bfs\.(write|writeFile|writeFileSync|appendFile|appendFileSync)\b"),
        "filesystem",
    ),
    (re.compile(r"\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bspawn\("), "command_exec"),
    (re.compile(r"\bexec\.Command\b|\bos/exec\b"), "command_exec"),
    (re.compile(r"\bfetch\(|\baxios\.(get|post|put|delete)\b|\bhttp\.(get|request)\b"), "network"),
    (re.compile(r"\b(DELETE|INSERT|UPDATE)\s+(FROM|INTO|\w)"), "database"),
]

_NON_PY_EXTS = frozenset(
    {".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".rs", ".php", ".cs"}
)


def add_generic_facts(server: ServerRecord, graph: EvidenceGraph) -> None:
    """Scan non-Python source for dangerous calls; add anchor-only `call` facts."""
    if not server.source_path:
        return
    root = Path(server.source_path)
    if not root.exists():
        return
    files = [root] if root.is_file() else sorted(root.rglob("*"))
    base = root.parent if root.is_file() else root
    for file in files:
        if not file.is_file() or file.suffix == _PY or file.suffix not in _NON_PY_EXTS:
            continue
        relref = file.name if root.is_file() else str(file.relative_to(base))
        text = file.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern, authority in _PATTERNS:
                m = pattern.search(line)
                if m:
                    graph.add(
                        EvidenceFact(
                            kind="call",
                            anchor=Anchor("file_line", f"{relref}:{lineno}"),
                            detail=m.group(0),
                            authority=authority,
                            language=file.suffix.lstrip("."),
                            extra={"sub_source": "regex"},
                        )
                    )
                    break
