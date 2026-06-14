"""Shared test fixtures: paths to the example corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


@pytest.fixture
def examples() -> Path:
    return EXAMPLES


@pytest.fixture
def configs_dir() -> Path:
    return EXAMPLES / "configs"


@pytest.fixture
def manifests_dir() -> Path:
    return EXAMPLES / "manifests"
