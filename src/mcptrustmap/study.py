"""Empirical-study harness: run the corpus tooling and report prevalence.

Ships in v0.1 so the layered study is an addition, not a rewrite. Reports
per-finding prevalence (a lower bound), and — when an `adjudication.json` is
present — a manually-measured precision and judge-vs-human agreement on a sample.
Uses only the shipped tool; claims are bounded to the documented corpus.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION, __version__
from .corpus import run_corpus
from .findings import spec_for
from .jsonio import load_json, validate


def _corpus_manifest_hash(study_dir: Path) -> str:
    h = hashlib.sha256()
    for entry in sorted(study_dir.glob("*/entry.json")):
        h.update(entry.read_bytes())
    return h.hexdigest()[:16]


def _prevalence(summary: dict[str, Any]) -> dict[str, Any]:
    servers = summary["inventory"]["servers"] or 1
    families = summary["corpus"]["families"]
    per_finding = {fid: round(meta["count"] / servers, 3) for fid, meta in families.items()}
    owasp_counts: dict[str, int] = {}
    for fid, meta in families.items():
        owasp = spec_for(fid).owasp
        owasp_counts[owasp] = owasp_counts.get(owasp, 0) + meta["count"]
    by_owasp = {ow: round(c / servers, 3) for ow, c in sorted(owasp_counts.items())}
    return {
        "servers": summary["inventory"]["servers"],
        "per_finding": per_finding,
        "by_owasp": by_owasp,
    }


def _adjudicate(study_dir: Path) -> dict[str, Any] | None:
    adj_path = study_dir / "adjudication.json"
    if not adj_path.exists():
        return None
    adj = load_json(adj_path)
    sample = adj.get("sample", [])
    if not sample:
        return None
    real = sum(1 for s in sample if s["human_verdict"] == "real")
    total = len(sample)
    precision = round(real / total, 3)
    return {
        "sample_size": total,
        "measured_precision": precision,
        # the tool reports every sampled item as a finding (a positive); agreement
        # is the rate at which the human reviewer confirms it. A full Cohen's kappa
        # needs an adjudicated negative set, which a real-ecosystem run would add.
        "judge_human_agreement": precision,
        "method": "manual adjudication of a sampled subset of reported findings (positives)",
    }


def run_study(
    study_dir: str | Path, *, llm_mode: str = "replay", repo_root: str | Path | None = None
) -> dict[str, Any]:
    study_path = Path(study_dir)
    summary = run_corpus(study_path, llm_mode=llm_mode, repo_root=repo_root)
    study = {
        "study_id": f"study:{study_path.name}",
        "tool_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "corpus_manifest_hash": _corpus_manifest_hash(study_path),
        "prevalence": _prevalence(summary),
        "adjudication": _adjudicate(study_path),
        "bounds": (
            "Convenience sample, not a census; prevalence is a lower bound. "
            "Findings reflect the documented corpus only and do not generalize "
            "to the MCP ecosystem."
        ),
    }
    validate(study, "study_summary")
    return study
