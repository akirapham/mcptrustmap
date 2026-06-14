"""Phase 11: empirical-study harness."""

from __future__ import annotations

from pathlib import Path

from mcptrustmap.jsonio import validate
from mcptrustmap.study import run_study

ROOT = Path(__file__).resolve().parents[2]


def test_study_runs_and_validates():
    study = run_study(ROOT / "corpus" / "real", llm_mode="replay", repo_root=ROOT)
    validate(study, "study_summary")
    assert study["prevalence"]["servers"] == 3
    assert study["corpus_manifest_hash"]


def test_study_reports_adjudicated_precision():
    study = run_study(ROOT / "corpus" / "real", llm_mode="replay", repo_root=ROOT)
    adj = study["adjudication"]
    assert adj is not None
    assert adj["sample_size"] == 5
    assert adj["measured_precision"] == 0.8  # 4 real / 5 sampled
    assert "judge_human_agreement" in adj


def test_study_is_bounded():
    study = run_study(ROOT / "corpus" / "real", llm_mode="replay", repo_root=ROOT)
    assert "not a census" in study["bounds"]
    assert "lower bound" in study["bounds"]


def test_study_deterministic():
    a = run_study(ROOT / "corpus" / "real", llm_mode="replay", repo_root=ROOT)
    b = run_study(ROOT / "corpus" / "real", llm_mode="replay", repo_root=ROOT)
    assert a == b
