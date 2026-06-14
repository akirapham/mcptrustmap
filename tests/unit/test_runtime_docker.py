"""Runtime: the hardened docker argv is the sandbox policy — assert it as code."""

from __future__ import annotations

from mcptrustmap.runtime.docker import Limits, container_argv, seed_honey_dir


def _argv(**kw):
    return container_argv("vuln/server:latest", honey_dir="/h", mount="/workspace", **kw)


def test_argv_is_hardened_by_default():
    argv = _argv()
    joined = " ".join(argv)
    # non-root, read-only rootfs, no caps, no privilege escalation
    assert "--user" in argv and "65534:65534" in argv
    assert "--read-only" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in argv
    # interactive stdio for the MCP transport, auto-removed
    assert "-i" in argv and "--rm" in argv
    # exactly the honey bind, writable, at the declared root
    assert "type=bind,src=/h,dst=/workspace" in joined
    # image is the final positional (no entrypoint override by default)
    assert argv[-1] == "vuln/server:latest"


def test_default_network_is_isolated():
    assert container_argv("i", honey_dir="/h", mount="/w")[
        container_argv("i", honey_dir="/h", mount="/w").index("--network") + 1
    ] == "none"


def test_limits_and_env_and_hosts_render():
    argv = _argv(
        network="mtm-sink",
        env={"MCP_ROOT": "/workspace"},
        extra_hosts=("sink.local:172.17.0.1",),
        limits=Limits(memory="128m", cpus="0.5", pids=64),
    )
    assert argv[argv.index("--network") + 1] == "mtm-sink"
    assert argv[argv.index("--memory") + 1] == "128m"
    assert argv[argv.index("--cpus") + 1] == "0.5"
    assert argv[argv.index("--pids-limit") + 1] == "64"
    assert "--env" in argv and "MCP_ROOT=/workspace" in argv
    assert "--add-host" in argv and "sink.local:172.17.0.1" in argv


def test_entrypoint_appended_after_image():
    argv = _argv(entrypoint=("python", "server.py"))
    assert argv[-3:] == ["vuln/server:latest", "python", "server.py"]


def test_seed_honey_dir_strips_declared_root(tmp_path):
    seed_honey_dir(
        tmp_path,
        declared_root="/workspace",
        files={"/workspace/secret.txt": "MARKER", "/workspace/sub/key": "K"},
    )
    assert (tmp_path / "secret.txt").read_text() == "MARKER"
    assert (tmp_path / "sub" / "key").read_text() == "K"
