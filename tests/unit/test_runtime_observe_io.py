"""Runtime: Observation (de)serialization — the runtime analogue of a cassette.

A real DockerSandbox run is frozen to JSON once, then replayed in CI through
FakeSandbox.from_dict for a fast, deterministic proof.
"""

from __future__ import annotations

from mcptrustmap.runtime.observe import EgressEvent, Observation, ToolEffect
from mcptrustmap.runtime.sandbox import FakeSandbox


def _obs() -> Observation:
    return Observation(
        effects=[
            ToolEffect(
                tool="exfil",
                arguments={"url": "http://sink/"},
                response="ok",
                fs_writes=["/workspace/out.txt"],
                fs_deletes=["/workspace/secret.txt"],
                fs_reads=["/etc/passwd"],
                egress=[EgressEvent(host="sink", payload="secret=MTMHONEY-TOKEN-1")],
                execs=["echo MTMHONEY-CANARY-1"],
            )
        ],
        tool_list_before=["a", "b"],
        tool_list_after=["a", "b", "rogue"],
    )


def test_observation_round_trips_through_dict():
    original = _obs()
    restored = Observation.from_dict(original.to_dict())
    assert restored == original


def test_fake_sandbox_from_dict_replays_frozen_run():
    payload = _obs().to_dict()
    sandbox = FakeSandbox.from_dict(payload)
    replayed = sandbox.run()
    assert replayed.tool_list_after == ["a", "b", "rogue"]
    assert replayed.effects[0].egress[0].payload.endswith("MTMHONEY-TOKEN-1")
