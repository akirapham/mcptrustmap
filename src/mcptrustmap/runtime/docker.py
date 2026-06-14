"""Docker primitives for the sandbox: the hardened run argv + honey bind seeding.

`container_argv` is the sandbox's security policy expressed as code, so the policy
is unit-tested rather than trusted: non-root, read-only rootfs, every capability
dropped, no-new-privileges, pid/memory/cpu ceilings, and exactly one writable
mount — the isolated honey directory at the declared root. The MCP server speaks
over stdio, so the container runs with `-i` and is driven through its stdin/stdout.

The only bind mount is a throwaway host honey dir holding decoys; the user's
filesystem and the Docker socket are never exposed. Functions that actually invoke
the daemon are thin and no-cover (they need a live Docker).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Limits:
    memory: str = "256m"
    cpus: str = "1.0"
    pids: int = 128
    tmpfs_size: str = "16m"


def container_argv(
    image: str,
    *,
    honey_dir: str,
    mount: str,
    network: str = "none",
    env: dict[str, str] | None = None,
    extra_hosts: tuple[str, ...] = (),
    user: str = "65534:65534",
    limits: Limits | None = None,
    entrypoint: tuple[str, ...] = (),
) -> list[str]:
    """Build the hardened `docker run -i` argv for an untrusted MCP server."""
    lim = limits or Limits()
    argv = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        network,
        "--user",
        user,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(lim.pids),
        "--memory",
        lim.memory,
        "--cpus",
        lim.cpus,
        "--mount",
        f"type=bind,src={honey_dir},dst={mount}",
        "--tmpfs",
        f"/tmp:rw,size={lim.tmpfs_size},noexec,nosuid",
    ]
    for host in extra_hosts:
        argv += ["--add-host", host]
    for key, value in (env or {}).items():
        argv += ["--env", f"{key}={value}"]
    argv.append(image)
    argv += list(entrypoint)
    return argv


def seed_honey_dir(honey_dir: str | Path, *, declared_root: str, files: dict[str, str]) -> None:
    """Materialize honeyfiles onto the host bind dir, mapping container paths in.

    `files` maps an in-container absolute path (under `declared_root`) to its
    marker content; we strip the root and write each under `honey_dir`.
    """
    base = Path(honey_dir)
    base.mkdir(parents=True, exist_ok=True)
    root = declared_root.rstrip("/") + "/"
    for container_path, content in files.items():
        rel = container_path[len(root) :] if container_path.startswith(root) else container_path
        rel = rel.lstrip("/")
        target = base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def docker_available() -> bool:  # pragma: no cover - environment-dependent
    """True iff a Docker CLI and a responsive daemon are present (for skipif)."""
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0
