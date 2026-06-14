"""Runtime: the precision/recall/F1 math."""

from __future__ import annotations

from mcptrustmap.runtime.metrics import score


def test_perfect_detector():
    sb = score([True, True, True], [False, False])
    assert (sb.tp, sb.fn, sb.fp, sb.tn) == (3, 0, 0, 2)
    assert sb.precision == 1.0 and sb.recall == 1.0 and sb.f1 == 1.0


def test_a_miss_lowers_recall_only():
    sb = score([True, True, True, False], [False])
    assert sb.precision == 1.0
    assert sb.recall == 0.75


def test_a_false_positive_lowers_precision_only():
    sb = score([True, True], [True, False])  # one benign target flagged
    assert sb.recall == 1.0
    assert sb.precision == 2 / 3


def test_empty_is_vacuously_one():
    sb = score([], [])
    assert sb.precision == 1.0 and sb.recall == 1.0
