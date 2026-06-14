"""Phase 0: the CLI surface exists and parses; unbuilt commands fail cleanly."""

from __future__ import annotations

import pytest

from mcptrustmap.cli import build_parser, main
from mcptrustmap.errors import NotImplementedYet


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--help"])
    assert exc.value.code == 0
    assert "mcptrustmap" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["discover", "--help"],
        ["audit", "--help"],
        ["corpus", "run", "--help"],
        ["study", "run", "--help"],
        ["report", "validate", "--help"],
        ["report", "render", "--help"],
        ["findings", "list", "--help"],
        ["serve", "--help"],
    ],
)
def test_every_subcommand_help_exits_zero(argv):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code == 0


def test_no_subcommand_errors():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([])
    assert exc.value.code != 0


def test_unbuilt_command_returns_nonzero():
    # main() catches MtmError and returns its exit code. `serve` is the last
    # handler to land (Phase 12); until then it is a clean not-yet stub.
    assert main(["serve"]) == NotImplementedYet.exit_code
