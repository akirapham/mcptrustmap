"""Filesystem-diff observer — proves write/delete authority by content, not opinion.

We snapshot the honey directory (a host-side bind dir mounted into the sandbox at
the declared root) as {relative-path -> sha256}, and diff two snapshots into
writes / modifies / deletes. Because the driver runs one probe per tool and
snapshots around each call, the diff is attributable to that single tool — which
is exactly the per-tool effect the observation model expects.

Pure given a directory: `snapshot_tree` reads the disk, `diff_snapshots` is a
total function over two snapshots. Reads are *not* observable this way (no content
change); capturing them needs syscall tracing, a later increment.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


@dataclass
class FsSnapshot:
    """A content hash of every file under a root, keyed by POSIX relative path."""

    files: dict[str, str] = field(default_factory=dict)


@dataclass
class FsDelta:
    writes: list[str] = field(default_factory=list)  # created or modified
    deletes: list[str] = field(default_factory=list)


def snapshot_tree(root: str | Path) -> FsSnapshot:
    """Hash every regular file under `root`; keys are POSIX paths relative to it."""
    base = Path(root)
    files: dict[str, str] = {}
    if not base.exists():
        return FsSnapshot(files)
    for path in sorted(base.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(base).as_posix()
            files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return FsSnapshot(files)


def diff_snapshots(before: FsSnapshot, after: FsSnapshot) -> FsDelta:
    """Created or content-changed paths -> writes; vanished paths -> deletes."""
    writes = sorted(
        rel for rel, h in after.files.items() if before.files.get(rel) != h
    )
    deletes = sorted(rel for rel in before.files if rel not in after.files)
    return FsDelta(writes=writes, deletes=deletes)


def under_root(relpaths: list[str], declared_root: str) -> list[str]:
    """Re-anchor diff-relative paths to the in-container declared root."""
    root = PurePosixPath(declared_root)
    return [str(root / rel) for rel in relpaths]
