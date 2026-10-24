"""Hybrid detection engine: rules + optional anomaly model."""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from ..config import DetectionConfig
from .alerts import Alert, alerts_to_frame
from .anomaly import AnomalyModel, TooLittleData, load_default_model
from .rules import detect_auth_failures, detect_dos, detect_port_scans


@dataclass
class DetectionResult:
    alert_objects: list[Alert]
    alerts: pd.DataFrame
    window_scores: pd.DataFrame | None = None
    model_info: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def run_detection(flows: pd.DataFrame, auth: pd.DataFrame | None = None, cfg: DetectionConfig | None = None,
                  model: AnomalyModel | None = None) -> DetectionResult:
    cfg = cfg or DetectionConfig()
    notes: list[str] = []
    objs: list[Alert] = []
    objs += detect_port_scans(flows, cfg)
    objs += detect_dos(flows, cfg)
    if auth is not None and not auth.empty:
        objs += detect_auth_failures(auth, cfg)
    else:
        notes.append("No authentication events supplied: the authentication-failure rule did not run.")
    scores, info = None, {}
    if cfg.anomaly_enabled:
        if model is None:
            model, info = load_default_model(cfg)
        else:
            info = dict(model.info)
        if model is None:
            notes.append(f"Anomaly layer skipped: {info.get('error', 'no trained model')}")
        else:
            try:
                scores = model.score_windows(flows)
                objs += model.alerts(flows, scores)
            except TooLittleData as exc:
                scores = None
                notes.append(f"Anomaly layer skipped: {exc}")
    return DetectionResult(objs, alerts_to_frame(objs), scores, info, notes)
