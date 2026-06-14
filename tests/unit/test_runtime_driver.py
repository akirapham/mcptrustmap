"""Runtime: the MCP driver's pure fusion — response + fs-diff + egress -> ToolEffect."""

from __future__ import annotations

from dataclasses import dataclass

from mcptrustmap.runtime.driver import build_effect, names_of, result_text
from mcptrustmap.runtime.fsdiff import FsDelta
from mcptrustmap.runtime.observe import EgressEvent


@dataclass
class _Block:
    text: str


def test_result_text_flattens_object_blocks():
    assert result_text([_Block("a"), _Block("b")]) == "a\nb"


def test_result_text_flattens_dict_blocks_and_handles_none():
    assert result_text([{"type": "text", "text": "hi"}, {"type": "image"}]) == "hi"
    assert result_text(None) == ""
    assert result_text("raw") == "raw"


def test_names_of_handles_object_and_dict_shapes():
    @dataclass
    class _Tool:
        name: str

    @dataclass
    class _Result:
        tools: list

    assert names_of(_Result([_Tool("a"), _Tool("b")])) == ["a", "b"]
    assert names_of([{"name": "x"}, {"name": "y"}]) == ["x", "y"]


def test_build_effect_reanchors_fs_and_carries_channels():
    eff = build_effect(
        "exfil",
        {"url": "http://sink/"},
        response="MTMHONEY-FILE-abc returned",
        fs_delta=FsDelta(writes=["out.txt"], deletes=["secret.txt"]),
        egress=[EgressEvent(host="sink", payload="secret=MTMHONEY-TOKEN-1")],
        declared_root="/workspace",
    )
    assert eff.tool == "exfil"
    assert eff.arguments == {"url": "http://sink/"}
    assert eff.fs_writes == ["/workspace/out.txt"]
    assert eff.fs_deletes == ["/workspace/secret.txt"]
    assert eff.egress[0].host == "sink"
    # base backend leaves syscall-only channels empty rather than guessing
    assert eff.execs == []
    assert eff.fs_reads == []


def test_build_effect_mutating_authorities_follow_from_fusion():
    eff = build_effect(
        "writer", {}, "", FsDelta(writes=["a"], deletes=[]), [], declared_root="/workspace"
    )
    assert eff.mutating_authorities() == {"filesystem"}
