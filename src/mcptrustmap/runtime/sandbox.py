"""Sandbox backends — where the untrusted server runs and behavior is observed.

`Sandbox.run()` returns an Observation. `FakeSandbox` replays a scripted one (the
deterministic test/oracle path, and the way a frozen real run is replayed in CI).
`DockerSandbox` runs a real untrusted server in an isolated container; the
Docker-free `LocalStdioSandbox` drives a plain stdio MCP subprocess in a honey
working dir — the same driver/observe/oracle pipeline, used to prove the harness
end-to-end against a controlled target without a container build.
"""

from __future__ import annotations

import tempfile
from abc import ABC, abstractmethod
from typing import Any

from .docker import Limits, container_argv, seed_honey_dir
from .honey import HoneySet
from .observe import Observation


class Sandbox(ABC):
    @abstractmethod
    def run(self) -> Observation:
        """Exercise the server and return what was observed."""


class FakeSandbox(Sandbox):
    """A scripted sandbox: returns a preset Observation (for tests + oracle dev).

    The same path replays a *real* run frozen to JSON: capture a sandbox
    Observation once, persist `observation.to_dict()`, and `from_dict` it here for
    a fast, deterministic CI proof — the runtime analogue of an LLM cassette.
    """

    def __init__(self, observation: Observation) -> None:
        self._observation = observation

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FakeSandbox:
        return cls(Observation.from_dict(payload))

    def run(self) -> Observation:
        return self._observation


def _drive_stdio(
    command: str,
    args: list[str],
    *,
    honey: HoneySet,
    honey_dir: str,
    sink_url: str,
    cwd: str | None = None,
    attacker: Any = None,
) -> Observation:  # pragma: no cover - needs the `mcp` extra + a live stdio server
    """Drive a stdio MCP server end-to-end: list tools, probe each, observe, relist.

    Honey is already seeded under `honey_dir`; the egress sink is raised here and
    its per-call slice + the honey-dir fs-diff are fused by the driver. `command`/
    `args` select the transport (a hardened `docker run` argv, or a local
    interpreter invocation); everything downstream is identical. `attacker`, if
    given, plans the probes (LLM-driven); otherwise role-based probes are used.
    """
    import asyncio
    import importlib

    from ..errors import InputError
    from ..evidence.roles import assign_roles
    from ..ingest.manifest import tool_from_entry
    from .driver import drive_session
    from .fsdiff import snapshot_tree
    from .probes import probe_plan
    from .sink import EgressSink

    try:
        mcp_mod = importlib.import_module("mcp")
        stdio_client = importlib.import_module("mcp.client.stdio").stdio_client
    except ModuleNotFoundError as exc:
        raise InputError(
            "runtime pentest needs the optional extra: pip install 'mcptrustmap[mcp]'"
        ) from exc
    client_session = mcp_mod.ClientSession
    stdio_params = mcp_mod.StdioServerParameters

    with EgressSink(host="0.0.0.0") as sink:  # noqa: S104 - sandbox-local sink only
        resolved_url = sink_url.replace("{port}", str(sink.port))
        params = stdio_params(command=command, args=args, cwd=cwd)

        def make_probes(listed: Any) -> list[tuple[str, dict[str, Any]]]:
            records = []
            for tool in listed.tools:
                annotations = getattr(tool, "annotations", None)
                record = tool_from_entry(
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.inputSchema or {},
                        "annotations": dict(annotations) if annotations else {},
                    }
                )
                assign_roles(record)
                records.append(record)
            if attacker is not None:
                return attacker.plan(records, honey, sink_url=resolved_url)
            return probe_plan(records, honey, sink_url=resolved_url)

        def snapshot():
            return snapshot_tree(honey_dir)

        def egress_since(n: int):
            return sink.events()[n:]

        async def _go() -> Observation:
            async with (
                stdio_client(params) as (read, write),
                client_session(read, write) as session,
            ):
                return await drive_session(
                    session,
                    make_probes,
                    snapshot=snapshot,
                    egress_since=egress_since,
                    declared_root=honey.declared_root,
                )

        return asyncio.run(_go())


class DockerSandbox(Sandbox):
    """Run an untrusted MCP server in Docker: honey-seeded fs, egress sink, driver.

    Non-root, dropped caps, read-only rootfs except the honey bind, no-new-privs,
    pid/memory/cpu ceilings, network reaching only the sink. The MCP server is
    driven over the container's stdio; effects are fused per tool by the driver.
    """

    def __init__(
        self,
        image: str,
        honey: HoneySet,
        *,
        mount: str | None = None,
        network: str = "bridge",
        limits: Limits | None = None,
        sink_host: str = "host.docker.internal",
        attacker: Any = None,
    ) -> None:
        self.image = image
        self.honey = honey
        self.mount = mount or honey.declared_root
        self.network = network
        self.limits = limits
        self.sink_host = sink_host
        self.attacker = attacker

    def run(self) -> Observation:  # pragma: no cover - needs Docker + the `mcp` extra
        honey = self.honey
        with tempfile.TemporaryDirectory(prefix="mtm-honey-") as honey_dir:
            seed_honey_dir(honey_dir, declared_root=honey.declared_root, files=honey.files)
            argv = container_argv(
                self.image,
                honey_dir=honey_dir,
                mount=self.mount,
                network=self.network,
                extra_hosts=(f"{self.sink_host}:host-gateway",),
                limits=self.limits,
            )
            # The container reaches the host-side sink via host-gateway; {port} is
            # filled once the sink binds.
            sink_url = f"http://{self.sink_host}:{{port}}/exfil"
            return _drive_stdio(
                argv[0],
                argv[1:],
                honey=honey,
                honey_dir=honey_dir,
                sink_url=sink_url,
                attacker=self.attacker,
            )


class LocalStdioSandbox(Sandbox):
    """Drive a plain stdio MCP subprocess in a pre-seeded honey working dir.

    Docker-free path used to prove the harness end-to-end against a controlled
    target: the server runs with cwd = `honey_dir` (so its relative file ops hit
    our decoys) and reaches the sink at 127.0.0.1. The caller seeds `honey_dir`
    and mints `honey` with `declared_root == honey_dir`, so observed paths and the
    oracle's boundary check line up exactly.
    """

    def __init__(
        self,
        command: str,
        args: list[str],
        honey: HoneySet,
        *,
        honey_dir: str,
        attacker: Any = None,
    ) -> None:
        self.command = command
        self.args = args
        self.honey = honey
        self.honey_dir = honey_dir
        self.attacker = attacker

    def run(self) -> Observation:  # pragma: no cover - needs the `mcp` extra + a live server
        sink_url = "http://127.0.0.1:{port}/exfil"
        return _drive_stdio(
            self.command,
            self.args,
            honey=self.honey,
            honey_dir=self.honey_dir,
            sink_url=sink_url,
            cwd=self.honey_dir,
            attacker=self.attacker,
        )
