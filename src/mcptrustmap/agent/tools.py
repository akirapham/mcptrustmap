"""Client-side, repo-scoped tools the reasoning agent uses to read server source.

Every path is resolved and confined to the repo root — a path-escape attempt is
rejected, never followed. In `live` mode these back a tool-use loop; in all modes
they gather the source the reasoner reasons over (kept on our side, recordable).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..errors import InputError

_TEXT_EXTS = frozenset(
    {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".rs", ".php", ".cs", ".json"}
)
_MAX_BYTES = 200_000


class RepoTools:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise InputError(f"source root does not exist: {self.root}")

    def _safe(self, rel: str) -> Path:
        target = (self.root / rel).resolve()
        if target != self.root and not target.is_relative_to(self.root):
            raise InputError(f"path escapes repo root: {rel!r}")
        return target

    def list_dir(self, rel: str = ".") -> list[str]:
        base = self._safe(rel)
        if not base.is_dir():
            return []
        return sorted(p.name + ("/" if p.is_dir() else "") for p in base.iterdir())

    def read_file(self, rel: str) -> str:
        target = self._safe(rel)
        if not target.is_file():
            raise InputError(f"not a file: {rel!r}")
        return target.read_text(encoding="utf-8", errors="replace")[:_MAX_BYTES]

    def grep(self, pattern: str, *, glob: str = "**/*") -> list[tuple[str, int, str]]:
        rx = re.compile(pattern)
        hits: list[tuple[str, int, str]] = []
        for path in sorted(self.root.glob(glob)):
            if not path.is_file() or path.suffix not in _TEXT_EXTS:
                continue
            rel = str(path.relative_to(self.root))
            for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if rx.search(line):
                    hits.append((rel, i, line.strip()))
        return hits

    def read_repo(self) -> dict[str, str]:
        """All readable source files, keyed by repo-relative path (sorted, stable)."""
        out: dict[str, str] = {}
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.suffix in _TEXT_EXTS:
                rel = str(path.relative_to(self.root))
                out[rel] = path.read_text(encoding="utf-8", errors="replace")[:_MAX_BYTES]
        return out
