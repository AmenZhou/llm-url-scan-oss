import importlib.util
import math
import os

import pytest

from evals import stats as S

ORIGINAL = os.environ.get("LLMURL_EVAL_ORIGINAL_STATS", "")      # the original analysis script, outside git; test skips without it


def test_mcnemar_exact_hand_values():
    assert S.mcnemar_exact(2, 8) == 2 * (1 + 10 + 45) / 1024
    assert S.mcnemar_exact(0, 0) == 1.0 and S.mcnemar_exact(5, 5) == 1.0
    assert 1e-6 < S.mcnemar_exact(121, 59) < 1e-4      # Wikipedia's 59/121 example


def test_wilson_and_newcombe_published_examples():
    lo, hi = S.wilson(81, 263)      # Newcombe (1998): 0.2553 to 0.3662
    assert (round(lo, 4), round(hi, 4)) == (0.2553, 0.3662)
    lo, hi = S.newcombe(56 / 70, *S.wilson(56, 70), 48 / 80, *S.wilson(48, 80), 0.0)      # 0.0524 to 0.3339
    assert (round(lo, 4), round(hi, 4)) == (0.0524, 0.3339)


def test_paired_interval_phi_correction():
    d, lo, hi = S.paired_interval(40, 10, 10, 40)      # ad - bc = 1500 > n/2: phi = (1500 - 50) / 2500
    l1, u1 = S.wilson(50, 100)
    assert (lo, hi) == S.newcombe(0.5, l1, u1, 0.5, l1, u1, 0.58) and d == 0 and math.isclose(lo, -hi, abs_tol=1e-12)
    assert S.paired_interval(25, 25, 25, 25)[1:] == S.newcombe(0.5, l1, u1, 0.5, l1, u1, 0.0)


def test_holm():
    assert S.holm([0.01, 0.04, 0.03]) == [0.03, 0.06, 0.06]
    assert S.holm([0.5, 0.001, 0.2]) == [0.5, 0.003, 0.4]


@pytest.mark.skipif(not os.path.exists(ORIGINAL), reason="original analyze_rag.py not present")
def test_values_equal_the_original_script():
    spec = importlib.util.spec_from_file_location("analyze_rag_original", ORIGINAL)
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    for k, n in ((0, 10), (3, 150), (103, 150), (6, 300), (300, 300)):
        assert S.wilson(k, n) == A.wilson(k, n)
    for b, c in ((0, 0), (1, 7), (6, 4), (20, 3), (50, 50)):
        assert S.mcnemar_exact(b, c) == A.mcnemar_exact(b, c)
    assert S.holm([0.2, 0.01, 0.04, 0.5]) == A.holm([0.2, 0.01, 0.04, 0.5])
    for t in ((98, 4, 5, 43), (6, 1, 0, 293), (97, 4, 6, 43), (0, 0, 0, 100), (10, 12, 1, 77), (5, 0, 9, 86)):
        assert S.paired_interval(*t) == A.paired_interval(*t)
