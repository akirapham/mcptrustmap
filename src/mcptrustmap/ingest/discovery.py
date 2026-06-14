"""Multi-client config inventory: client configs -> validated ServerRecord[].

All supported clients store servers under an `mcpServers` map; we tag each
record with its client of origin. A config-root is searched for the known
filenames per client, so discovery is fully offline and testable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..errors import InputError
from ..jsonio import load_json
from ..models import OAuthConfig, ServerRecord

# client -> candidate config filenames (relative to --config-root)
CLIENT_CONFIG_NAMES: dict[str, tuple[str, ...]] = {
    "claude_desktop": ("claude_desktop_config.json",),
    "cursor": ("cursor_mcp.json", ".cursor/mcp.json"),
    "windsurf": ("windsurf_mcp_config.json", "mcp_config.json"),
    "vscode_cline": ("cline_mcp_settings.json",),
    "generic": ("generic_mcp.json", "mcp.json"),
}

# launchers whose first positional arg is a package spec (supply chain)
_PACKAGE_RUNNERS = frozenset({"npx", "uvx", "pipx", "uv", "pip", "pnpm", "bunx"})


def detect_package(command: str | None, args: list[str]) -> str | None:
    """Return the package spec a launcher resolves, else None."""
    if not command:
        return None
    runner = Path(command).name
    if runner not in _PACKAGE_RUNNERS:
        return None
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("run", "tool", "x", "--from"):
            skip_next = arg == "--from"
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _oauth_from_spec(spec: dict[str, Any]) -> OAuthConfig | None:
    oauth = spec.get("oauth")
    if not isinstance(oauth, dict):
        return None
    return OAuthConfig.from_dict(oauth)


def server_from_spec(name: str, spec: Any, client: str) -> ServerRecord:
    spec = spec if isinstance(spec, dict) else {}
    command = spec.get("command")
    url = spec.get("url")
    if command:
        transport = "stdio"
    elif url:
        transport = "sse" if "sse" in str(url).lower() else "http"
    else:
        raise InputError(f"server {name!r} in {client} config has neither command nor url")
    args = [str(a) for a in spec.get("args", [])]
    return ServerRecord(
        server_id=f"{client}:{name}",
        client=client,
        transport=transport,
        command=command,
        args=args,
        env={str(k): str(v) for k, v in (spec.get("env") or {}).items()},
        url=url,
        package=detect_package(command, args),
        source_path=spec.get("source_path"),
        oauth=_oauth_from_spec(spec),
    )


def parse_client_config(path: str | Path, client: str) -> list[ServerRecord]:
    """Parse one client config file into ServerRecord[]."""
    data = load_json(path)
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        raise InputError(f"{path}: missing or invalid 'mcpServers' map")
    return [server_from_spec(name, spec, client) for name, spec in servers.items()]


def discover(client: str, config_root: str | Path) -> list[ServerRecord]:
    """Find and parse configs for one client (or 'all') under config_root."""
    if client == "all":
        clients = list(CLIENT_CONFIG_NAMES)
    elif client in CLIENT_CONFIG_NAMES:
        clients = [client]
    else:
        known = ", ".join(sorted(CLIENT_CONFIG_NAMES))
        raise InputError(f"unknown client {client!r}; known: {known}, all")

    root = Path(config_root)
    if not root.exists():
        raise InputError(f"config root does not exist: {root}")

    records: list[ServerRecord] = []
    for c in clients:
        for filename in CLIENT_CONFIG_NAMES[c]:
            path = root / filename
            if path.is_file():
                records.extend(parse_client_config(path, c))
    return records
