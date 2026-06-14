"""Source-derived authority inference (the *actual* side of the mismatch check).

Python is analyzed with stdlib `ast` (line-accurate, high confidence). Other
languages are handled by the LLM layer, gated by anchor re-resolution.
"""

from __future__ import annotations

from .python_ast import analyze_python_source, infer_source_authority

__all__ = ["analyze_python_source", "infer_source_authority"]
