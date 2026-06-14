"""Phase 9: corpus batch mode + the acceptance matrix."""

from __future__ import annotations

import sys
from pathlib import Path

from mcptrustmap.corpus import run_corpus
from mcptrustmap.report import validate_report

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from check_acceptance_matrix import REQUIRED_FAMILIES, check  # noqa: E402


def test_corpus_runs_and_validates(examples):
    summary = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    validate_report(summary)  # the corpus summary is itself a valid report
    assert summary["corpus"]["metrics"]["servers"] == 8


def test_acceptance_matrix_passes(examples):
    summary = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    errors = check(summary)
    assert errors == [], errors


def test_all_required_families_present(examples):
    summary = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    families = summary["corpus"]["families"]
    for fam in REQUIRED_FAMILIES:
        assert fam in families, fam


def test_benign_controls_have_zero_findings(examples):
    summary = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    benign = [s for s in summary["corpus"]["per_server"] if s["entry"].startswith("benign")]
    assert benign
    for entry in benign:
        assert entry["findings"] == 0, entry


def test_hybrid_family_is_llm_verified(examples):
    summary = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    mismatch = summary["corpus"]["families"]["MTM-AUTHORITY-MISMATCH"]
    assert "llm-verified" in mismatch["provenances"]
    assert "deterministic" in mismatch["provenances"]


def test_determinism_byte_identical(examples):
    a = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    b = run_corpus(examples / "corpus", llm_mode="replay", repo_root=ROOT)
    assert a == b  # same inputs + same cassettes -> identical summary
