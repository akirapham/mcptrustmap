"""Runtime: the filesystem-diff observer (write/delete proof, per-tool attributed)."""

from __future__ import annotations

from mcptrustmap.runtime.fsdiff import (
    diff_snapshots,
    snapshot_tree,
    under_root,
)


def test_snapshot_hashes_files(tmp_path):
    (tmp_path / "a.txt").write_text("one")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("two")
    snap = snapshot_tree(tmp_path)
    assert set(snap.files) == {"a.txt", "sub/b.txt"}
    assert snap.files["a.txt"] != snap.files["sub/b.txt"]


def test_snapshot_missing_root_is_empty(tmp_path):
    assert snapshot_tree(tmp_path / "nope").files == {}


def test_diff_detects_write_modify_delete(tmp_path):
    (tmp_path / "keep.txt").write_text("keep")
    (tmp_path / "gone.txt").write_text("bye")
    before = snapshot_tree(tmp_path)

    (tmp_path / "gone.txt").unlink()  # delete
    (tmp_path / "keep.txt").write_text("changed")  # modify
    (tmp_path / "new.txt").write_text("hi")  # create
    after = snapshot_tree(tmp_path)

    delta = diff_snapshots(before, after)
    assert delta.writes == ["keep.txt", "new.txt"]
    assert delta.deletes == ["gone.txt"]


def test_unchanged_tree_is_clean(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    snap = snapshot_tree(tmp_path)
    delta = diff_snapshots(snap, snapshot_tree(tmp_path))
    assert delta.writes == []
    assert delta.deletes == []


def test_under_root_reanchors_to_declared_root():
    assert under_root(["secret.txt", "sub/b"], "/workspace") == [
        "/workspace/secret.txt",
        "/workspace/sub/b",
    ]
