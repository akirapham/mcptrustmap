"""Detection metrics — a target-level confusion matrix over positives + negatives.

A *positive* is a known-vulnerable target that should yield its expected finding; a
*negative* is a benign target that should yield none. Precision needs negatives (a
detector that flags everything has perfect recall and useless precision), which is
why the benign fixtures exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Scoreboard:
    tp: int  # vulnerable target, expected finding detected
    fn: int  # vulnerable target, missed
    fp: int  # benign target, spuriously flagged
    tn: int  # benign target, correctly clean

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "tn": self.tn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
        }


def score(positives: list[bool], negatives: list[bool]) -> Scoreboard:
    """positives[i] = was target i detected; negatives[j] = was benign j flagged."""
    return Scoreboard(
        tp=sum(1 for d in positives if d),
        fn=sum(1 for d in positives if not d),
        fp=sum(1 for f in negatives if f),
        tn=sum(1 for f in negatives if not f),
    )
