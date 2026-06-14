"""Phase 6: repo-scoped tools are sandboxed and read source."""

from __future__ import annotations

import pytest

from mcptrustmap.agent.tools import RepoTools
from mcptrustmap.errors import InputError


def test_sandbox_rejects_path_escape(examples):
    tools = RepoTools(examples / "servers" / "vulnerable-mcp")
    with pytest.raises(InputError):
        tools.read_file("../../../../etc/passwd")


def test_read_repo(examples):
    tools = RepoTools(examples / "servers" / "vulnerable-mcp")
    files = tools.read_repo()
    assert "server.py" in files
    assert "subprocess" in files["server.py"]


def test_grep(examples):
    tools = RepoTools(examples / "servers" / "vulnerable-mcp")
    hits = tools.grep(r"os\.remove")
    assert any(rel == "server.py" for rel, _line, _text in hits)


def test_missing_root_raises(tmp_path):
    with pytest.raises(InputError):
        RepoTools(tmp_path / "nope")
