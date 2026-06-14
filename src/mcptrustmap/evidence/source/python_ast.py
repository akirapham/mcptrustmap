"""Python source authority inference via stdlib `ast` (line-accurate evidence).

For each top-level function (a tool implementation), we scan its body for calls
that imply a real authority class, and emit an InferredAuthority anchored at
`relpath:line`. Deterministic; no execution of the analyzed code.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ...models import InferredAuthority, ServerRecord, ToolRecord
from ..graph import Anchor, EvidenceFact, EvidenceGraph

# dotted callee -> authority class
_CALL_AUTHORITY: dict[str, str] = {
    "os.remove": "filesystem",
    "os.unlink": "filesystem",
    "os.rmdir": "filesystem",
    "os.removedirs": "filesystem",
    "os.rename": "filesystem",
    "os.replace": "filesystem",
    "os.mkdir": "filesystem",
    "os.makedirs": "filesystem",
    "os.chmod": "filesystem",
    "os.chown": "filesystem",
    "os.truncate": "filesystem",
    "shutil.rmtree": "filesystem",
    "shutil.move": "filesystem",
    "shutil.copy": "filesystem",
    "shutil.copyfile": "filesystem",
    "os.system": "command_exec",
    "os.popen": "command_exec",
    "subprocess.run": "command_exec",
    "subprocess.call": "command_exec",
    "subprocess.Popen": "command_exec",
    "subprocess.check_output": "command_exec",
    "subprocess.check_call": "command_exec",
    "requests.get": "network",
    "requests.post": "network",
    "requests.put": "network",
    "requests.delete": "network",
    "requests.request": "network",
    "httpx.get": "network",
    "httpx.post": "network",
    "urllib.request.urlopen": "network",
    "socket.socket": "network",
}

# bare builtins
_BUILTIN_AUTHORITY: dict[str, str] = {"eval": "command_exec", "exec": "command_exec"}

# callee suffix -> authority (handles variable receivers, e.g. cursor.execute)
_SUFFIX_AUTHORITY: dict[str, str] = {"execute": "database", "executemany": "database"}

_WRITE_MODE_CHARS = frozenset("wax+")


def _dotted(node: ast.AST) -> str | None:
    """Resolve an attribute/name chain to a dotted string, or None."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _open_is_write(call: ast.Call) -> bool:
    mode: str | None = None
    if len(call.args) >= 2:
        mode = _const_str(call.args[1])
    for kw in call.keywords:
        if kw.arg == "mode":
            mode = _const_str(kw.value) or mode
    return mode is not None and any(c in _WRITE_MODE_CHARS for c in mode)


def _call_authority(call: ast.Call) -> tuple[str, str] | None:
    """Return (authority, callee-label) for a dangerous call, else None."""
    dotted = _dotted(call.func)
    if dotted is not None:
        if dotted in _CALL_AUTHORITY:
            return _CALL_AUTHORITY[dotted], dotted
        suffix = dotted.rsplit(".", 1)[-1]
        if suffix in _SUFFIX_AUTHORITY:
            return _SUFFIX_AUTHORITY[suffix], dotted
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name == "open" and _open_is_write(call):
            return "filesystem", "open(mode=w)"
        if name in _BUILTIN_AUTHORITY:
            return _BUILTIN_AUTHORITY[name], name
    return None


def _function_authority(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, relref: str
) -> list[InferredAuthority]:
    out: list[InferredAuthority] = []
    seen: set[tuple[str, int]] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            hit = _call_authority(node)
            if hit is None:
                continue
            authority, label = hit
            key = (authority, node.lineno)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                InferredAuthority(
                    authority=authority,
                    sub_source="ast",
                    anchor=f"{relref}:{node.lineno}",
                    detail=label,
                )
            )
    return out


def analyze_python_source(root: str | Path) -> dict[str, list[InferredAuthority]]:
    """Analyze a .py file or a directory of them; map function name -> inferred[]."""
    root_path = Path(root)
    files: list[Path]
    base: Path
    if root_path.is_file():
        files = [root_path]
        base = root_path.parent
    else:
        files = sorted(root_path.rglob("*.py"))
        base = root_path

    result: dict[str, list[InferredAuthority]] = {}
    for file in files:
        try:
            tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        except (OSError, SyntaxError):
            continue
        relref = file.name if root_path.is_file() else str(file.relative_to(base))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                inferred = _function_authority(node, relref)
                if inferred:
                    result.setdefault(node.name, []).extend(inferred)
    return result


def infer_python_authority(server: ServerRecord, graph: EvidenceGraph) -> None:
    """Attach AST-inferred authority to matching tools and seed `call` facts."""
    if not server.source_path:
        return
    source = Path(server.source_path)
    if not source.exists():
        return
    by_func = analyze_python_source(source)
    for tool in server.tools:
        inferred = by_func.get(tool.name)
        if not inferred:
            continue
        _attach(tool, inferred, graph)


def _attach(tool: ToolRecord, inferred: list[InferredAuthority], graph: EvidenceGraph) -> None:
    for ia in inferred:
        tool.inferred_authority.append(ia)
        graph.add(
            EvidenceFact(
                kind="call",
                anchor=Anchor("file_line", ia.anchor),
                detail=ia.detail,
                authority=ia.authority,
                language="python",
                extra={"tool": tool.name, "sub_source": "ast"},
            )
        )
