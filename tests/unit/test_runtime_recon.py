"""Runtime: secret-recon vocabulary reaches the attacker's arsenal."""

from __future__ import annotations

from mcptrustmap.runtime.attacker import build_attack_request
from mcptrustmap.runtime.honey import mint_honey
from mcptrustmap.runtime.recon import SECRET_KEYWORDS, SECRET_PATHS


def test_wordlists_cover_the_usual_suspects():
    assert "/etc/passwd" in SECRET_PATHS
    assert ".env" in SECRET_PATHS
    assert "password" in SECRET_KEYWORDS
    assert "private_key" in SECRET_KEYWORDS


def test_arsenal_carries_recon_vocabulary():
    honey = mint_honey("s", declared_root="/honey")
    arsenal = build_attack_request([], honey, sink_url="http://x/{port}", model="m")["arsenal"]
    assert "/etc/passwd" in arsenal["secret_paths"]
    assert "api_key" in arsenal["secret_keywords"]
