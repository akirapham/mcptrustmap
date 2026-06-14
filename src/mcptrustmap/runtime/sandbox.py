"""Sandbox backends — where the untrusted server runs and behavior is observed.

`Sandbox.run()` returns an Observation. `FakeSandbox` replays a scripted one (the
deterministic test/oracle path, and the way a frozen real run is replayed in CI).
`DockerSandbox` runs a real untrusted server in an isolated container with honey
seeding + an egress sink + the MCP driver — the production backend.
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

    The same path replays a *real* run frozen to JSON: capture a DockerSandbox
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
    ) -> None:
        self.image = image
        self.honey = honey
        self.mount = mount or honey.declared_root
        self.network = network
        self.limits = limits
        self.sink_host = sink_host

    def run(self) -> Observation:  # pragma: no cover - needs Docker + the `mcp` extra
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

        honey = self.honey
        with tempfile.TemporaryDirectory(prefix="mtm-honey-") as honey_dir:
            seed_honey_dir(honey_dir, declared_root=honey.declared_root, files=honey.files)

            # Sink binds all interfaces so the container reaches it via host-gateway.
            with EgressSink(host="0.0.0.0") as sink:  # noqa: S104 - sandbox-local sink
                in_container_url = f"http://{self.sink_host}:{sink.port}/exfil"
                argv = container_argv(
                    self.image,
                    honey_dir=honey_dir,
                    mount=self.mount,
                    network=self.network,
                    extra_hosts=(f"{self.sink_host}:host-gateway",),
                    limits=self.limits,
                )
                params = stdio_params(command=argv[1], args=argv[2:])

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
                    return probe_plan(records, honey, sink_url=in_container_url)

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
