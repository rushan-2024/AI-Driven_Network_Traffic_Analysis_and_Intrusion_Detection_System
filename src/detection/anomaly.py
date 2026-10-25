"""Isolation Forest anomaly layer over per-source, per-window behaviour features.

Design (disclosed): an Isolation Forest fitted only on benign-baseline windows scores
out-of-range windows poorly (isolation scores saturate beyond the training range; this was
measured, see report). So each analysis fits the forest on the baseline windows POOLED with
the windows of the capture under analysis (unsupervised, no labels). The alert threshold is
the chosen quantile of the *baseline* windows' scores under that same fitted model.
Consequences: baseline records are disjoint from every scenario; the capture's own windows
are included in fitting (transductive); if a capture is mostly anomalous the forest can
treat that as normal (masking). The model has learned patterns in synthetic data only.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from ..config import SAMPLES_DIR, DetectionConfig
from ..features.extract import ANOMALY_FEATURES, add_window, window_features
from .alerts import Alert


def _log1p(x):
    return np.log1p(np.clip(np.asarray(x, dtype=float), 0, None))


class TooLittleData(ValueError):
    """Raised when a capture has too few source windows for meaningful anomaly scores."""


MIN_SCORED_WINDOWS = 5


class AnomalyModel:
    def __init__(self, cfg: DetectionConfig):
        self.cfg = cfg
        self.pipeline: Pipeline | None = None
        self.baseline: pd.DataFrame | None = None
        self.threshold: float | None = None
        self.info: dict = {}

    def _build(self) -> Pipeline:
        return Pipeline([
            ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("log", FunctionTransformer(_log1p)),
            ("scale", StandardScaler()),
            ("forest", IsolationForest(n_estimators=200, random_state=self.cfg.random_seed, contamination="auto")),
        ])

    @staticmethod
    def _matrix(feats: pd.DataFrame) -> pd.DataFrame:
            x = feats[ANOMALY_FEATURES].astype(float)
            return x.where(np.isfinite(x), np.nan)

    def fit(self, baseline_flows: pd.DataFrame) -> dict:
        feats = window_features(baseline_flows, self.cfg.window_seconds)
        if len(feats) < self.cfg.anomaly_min_training_windows:
            raise ValueError(f"Need at least {self.cfg.anomaly_min_training_windows} baseline windows to train; got {len(feats)}.")
        self.baseline = feats
        self.info = {"baseline_windows": int(len(feats)), "quantile": self.cfg.anomaly_quantile,
                     "features": ANOMALY_FEATURES, "seed": self.cfg.random_seed, "n_estimators": 200}
        return self.info

    def _scores(self, feats: pd.DataFrame) -> np.ndarray:
        # Higher = more anomalous (negated sklearn decision_function).
        return -self.pipeline.decision_function(self._matrix(feats))

    def score_windows(self, flows: pd.DataFrame) -> pd.DataFrame:
        if self.baseline is None:
            raise RuntimeError("Model has no baseline; call fit() first.")
        feats = window_features(flows, self.cfg.window_seconds)
        if feats.empty:
            return feats.assign(anomaly_score=[], flagged=[])
        if len(feats) < MIN_SCORED_WINDOWS:
            raise TooLittleData(f"Only {len(feats)} source-and-time windows in the file; at least {MIN_SCORED_WINDOWS} are needed for the anomaly model.")
        pool = pd.concat([self.baseline, feats], ignore_index=True)
        self.pipeline = self._build().fit(self._matrix(pool))
        self.threshold = float(np.quantile(self._scores(self.baseline), self.cfg.anomaly_quantile))
        self.info["threshold"] = round(self.threshold, 4)
        feats = feats.copy()
        feats["anomaly_score"] = self._scores(feats)
        feats["flagged"] = feats["anomaly_score"] > self.threshold
        return feats

    def validate(self, benign_flows: pd.DataFrame) -> dict:
        """Held-out benign validation (disjoint seed): fraction of benign windows flagged, i.e. the
        model's false-flag rate when the capture is benign."""
        s = self.score_windows(benign_flows)
        return {"validation_windows": int(len(s)), "validation_flagged": int(s["flagged"].sum()),
                "validation_flag_rate": round(float(s["flagged"].mean()), 4) if len(s) else None}

    def _top_deviations(self, row: pd.Series, k: int = 3) -> list[str]:
        x = self._matrix(row.to_frame().T)
        z = self.pipeline[:-1].transform(x)[0]
        order = np.argsort(-np.abs(z))[:k]
        return [f"{ANOMALY_FEATURES[i]}={row[ANOMALY_FEATURES[i]]:.4g} ({z[i]:+.1f} sd vs baseline)" for i in order]

    def alerts(self, flows: pd.DataFrame, scored: pd.DataFrame | None = None) -> list[Alert]:
        scored = self.score_windows(flows) if scored is None else scored
        out: list[Alert] = []
        if scored.empty:
            return out
        groups = add_window(flows, self.cfg.window_seconds).groupby(["src_ip", "win"]).groups
        w = self.cfg.window_seconds
        for _, r in scored[scored["flagged"]].iterrows():
            margin = r["anomaly_score"] - self.threshold
            sev = "low" if margin < 0.05 else ("medium" if margin < 0.15 else "high")
            dev = self._top_deviations(r)
            out.append(Alert(
                "anomaly", "ML-IF1", "anomaly", float(r["win"]), float(r["win"]) + w, r["src_ip"], None, sev,
                {"anomaly_score": round(float(r["anomaly_score"]), 4), "threshold": round(self.threshold, 4),
                 "top_deviations": "; ".join(dev)},
                f"anomaly_score > {self.threshold:.4f} (benign-baseline {self.cfg.anomaly_quantile:.1%} quantile)",
                f"Behaviour of {r['src_ip']} in this {w}s window is unusual compared with the benign baseline. "
                f"Largest deviations: {'; '.join(dev)}. This is a statistical outlier score, not a rule match or "
                f"an attack classification; unusual benign activity can also score high.",
                ["Compare the source's flows with its normal behaviour and role.",
                 "Check whether a known job (backup, scan, deployment) explains the pattern.",
                 "If unexplained, escalate to the matching rule-based category for confirmation."],
                [int(i) for i in groups[(r["src_ip"], r["win"])]]))
        return out


def load_default_model(cfg: DetectionConfig) -> tuple[AnomalyModel | None, dict]:
    """Train on the bundled baseline capture; return (model, info). Never raises."""
    from ..ingestion import load_flows
    train, val = SAMPLES_DIR / "baseline_training_flows.csv", SAMPLES_DIR / "baseline_validation_flows.csv"
    if not train.exists():
        return None, {"error": f"Baseline file missing: {train.name}. Run scripts/generate_data.py."}
    try:
        model = AnomalyModel(cfg)
        info = model.fit(load_flows(train).data)
        if val.exists():
            info.update(model.validate(load_flows(val).data))
        info["baseline_source"] = train.name
        return model, info
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI as a note
        return None, {"error": str(exc)}
