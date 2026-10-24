import numpy as np
import pandas as pd
import pytest

from src.detection.alerts import Alert
from src.evaluation import confusion_counts, evaluate, summarise_counts


def test_confusion_and_metrics():
    t = np.array([1, 1, 1, 0, 0, 0, 0, 0], bool)
    p = np.array([1, 1, 0, 1, 0, 0, 0, 0], bool)
    c = confusion_counts(t, p)
    assert c == {"tp": 2, "fp": 1, "tn": 4, "fn": 1}
    s = summarise_counts(c)
    assert s["precision"] == pytest.approx(2 / 3) and s["recall"] == pytest.approx(2 / 3)
    assert s["f1"] == pytest.approx(2 / 3) and s["accuracy"] == pytest.approx(6 / 8)


def test_undefined_metrics_are_none():
    s = summarise_counts({"tp": 0, "fp": 0, "tn": 5, "fn": 0})
    assert s["precision"] is None and s["recall"] is None and s["f1"] is None and s["accuracy"] == 1.0


def test_length_mismatch():
    with pytest.raises(ValueError):
        confusion_counts([1, 0], [1])


def _alert(cat, det, ids):
    return Alert(cat, "X", det, 0, 1, "s", "d", "low", {}, "", "", [], ids)


def test_evaluate_modes_and_per_category():
    labels = pd.DataFrame({"is_malicious": [True, True, False, False, True], "attack_type": ["port_scan", "port_scan", "benign", "benign", "dos"]})
    alerts = [_alert("port_scan", "rule", [0, 2]), _alert("anomaly", "anomaly", [4])]
    r = evaluate(labels, None, alerts, "rules")["flows"]
    assert r["overall"]["tp"] == 1 and r["overall"]["fp"] == 1 and r["overall"]["fn"] == 2
    h = evaluate(labels, None, alerts, "hybrid")["flows"]
    assert h["overall"]["tp"] == 2 and h["per_category"]["port_scan"]["tp"] == 1 and h["per_category"]["dos"]["tp"] == 0
    assert h["false_positive_ids"] == [2] and h["false_negative_ids"] == [1]
    with pytest.raises(ValueError):
        evaluate(labels, None, alerts, "bogus")
