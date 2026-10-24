"""Evaluation against ground truth. Labels enter only here, after detection has finished."""
from __future__ import annotations

import numpy as np
import pandas as pd

from ..detection.alerts import Alert

FLOW_CATEGORIES = ["port_scan", "dos"]
AUTH_CATEGORIES = ["auth_failures"]


def confusion_counts(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    t, p = np.asarray(y_true, dtype=bool), np.asarray(y_pred, dtype=bool)
    if t.shape != p.shape:
        raise ValueError("y_true and y_pred must have the same length.")
    return {"tp": int((t & p).sum()), "fp": int((~t & p).sum()), "tn": int((~t & ~p).sum()), "fn": int((t & ~p).sum())}


def _div(a: float, b: float):
    return None if b == 0 else a / b


def summarise_counts(c: dict) -> dict:
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    precision, recall = _div(tp, tp + fp), _div(tp, tp + fn)
    f1 = None if precision is None or recall is None or (precision + recall) == 0 else 2 * precision * recall / (precision + recall)
    n = tp + fp + tn + fn
    return {**c, "n": n, "positives": tp + fn, "prevalence": _div(tp + fn, n), "precision": precision,
            "recall": recall, "f1": f1, "accuracy": _div(tp + tn, n),
            "false_positive_rate": _div(fp, fp + tn)}


def _covered(alerts: list[Alert], kind: str, n: int, category: str | None = None) -> np.ndarray:
    mask = np.zeros(n, dtype=bool)
    for a in alerts:
        if a.evidence_kind == kind and (category is None or a.category == category):
            mask[[i for i in a.evidence_ids if 0 <= i < n]] = True
    return mask


def _eval_table(labels: pd.DataFrame, alerts: list[Alert], kind: str, categories: list[str]) -> dict:
    n = len(labels)
    truth = labels["is_malicious"].to_numpy()
    pred = _covered(alerts, kind, n)
    out = {"overall": summarise_counts(confusion_counts(truth, pred)), "per_category": {}}
    for cat in categories:
        t = (labels["attack_type"] == cat).to_numpy()
        if t.sum() == 0 and not (labels["attack_type"] == "benign").any():
            continue
        # Per category: positives = that attack type; negatives = benign records only,
        # so other attack types do not count as false positives for this category.
        sel = t | (labels["attack_type"] == "benign").to_numpy()
        p = _covered(alerts, kind, n, cat)
        out["per_category"][cat] = summarise_counts(confusion_counts(t[sel], p[sel]))
    fp_ids = np.flatnonzero(~truth & pred)
    fn_ids = np.flatnonzero(truth & ~pred)
    out["false_positive_ids"], out["false_negative_ids"] = fp_ids.tolist(), fn_ids.tolist()
    return out


def evaluate(flow_labels: pd.DataFrame | None, auth_labels: pd.DataFrame | None, alerts: list[Alert], mode: str = "hybrid") -> dict:
    """mode: 'rules' | 'anomaly' | 'hybrid' selects which detector's alerts are scored."""
    if mode not in {"rules", "anomaly", "hybrid"}:
        raise ValueError("mode must be rules, anomaly or hybrid")
    keep = [a for a in alerts if mode == "hybrid" or (mode == "rules") == (a.detector == "rule")]
    res: dict = {"mode": mode}
    if flow_labels is not None:
        res["flows"] = _eval_table(flow_labels, keep, "flow", FLOW_CATEGORIES)
    if auth_labels is not None:
        res["auth"] = _eval_table(auth_labels, keep, "auth", AUTH_CATEGORIES)
    return res
