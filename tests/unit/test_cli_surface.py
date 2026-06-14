"""Phase 0: the CLI surface exists and parses; unbuilt commands fail cleanly."""

from __future__ import annotations

import pytest

from mcptrustmap.cli import build_parser, main
from mcptrustmap.errors import InputError


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


def test_mterror_maps_to_exit_code():
    # main() catches MtmError and returns its exit code: audit with no target
    # is always an InputError.
    assert main(["audit"]) == InputError.exit_code


def test_serve_self_test_ok():
    assert main(["serve", "--self-test"]) == 0
