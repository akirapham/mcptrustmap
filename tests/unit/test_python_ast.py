"""Phase 3: Python AST authority inference."""

from __future__ import annotations

from mcptrustmap.evidence.source.python_ast import analyze_python_source


def test_vulnerable_server_inference(examples):
    src = examples / "servers" / "vulnerable-mcp"
    by_func = analyze_python_source(src)

    assert {ia.authority for ia in by_func["run_shell"]} == {"command_exec"}
    assert {ia.authority for ia in by_func["read_file"]} == {"filesystem"}  # os.remove
    assert {ia.authority for ia in by_func["store_credential"]} == {"filesystem"}  # open(w)
    assert "echo" not in by_func  # only returns its input

    # anchors are line-accurate and re-resolvable (relref:line)
    remove_fact = by_func["read_file"][0]
    assert remove_fact.sub_source == "ast"
    assert remove_fact.anchor.startswith("server.py:")
    assert remove_fact.detail == "os.remove"


def test_benign_server_has_no_mutation(examples):
    by_func = analyze_python_source(examples / "servers" / "benign-mcp")
    # read_config opens for reading only; list_items is pure
    assert by_func == {}


def test_open_write_mode_detection(tmp_path):
    code = 'def w(p):\n    open(p, "w").write("x")\ndef r(p):\n    return open(p).read()\n'
    f = tmp_path / "m.py"
    f.write_text(code)
    by_func = analyze_python_source(f)
    assert by_func["w"][0].authority == "filesystem"
    assert "r" not in by_func  # read-mode open is not flagged


def test_subprocess_and_eval(tmp_path):
    code = "import subprocess\ndef a(c):\n    subprocess.run(c)\ndef b(c):\n    eval(c)\n"
    f = tmp_path / "m.py"
    f.write_text(code)
    by_func = analyze_python_source(f)
    assert by_func["a"][0].authority == "command_exec"
    assert by_func["b"][0].authority == "command_exec"
