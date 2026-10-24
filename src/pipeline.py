"""End-to-end analysis used by the dashboard, scripts and tests."""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .config import SAMPLES_DIR, DetectionConfig
from .detection import AnomalyModel, DetectionResult, run_detection
from .evaluation import evaluate
from .ingestion import LoadResult, load_auth, load_flows
from .synthetic import SCENARIOS, generate_scenario, write_samples


@dataclass
class Analysis:
    flows: LoadResult
    auth: LoadResult | None
    detection: DetectionResult
    cfg: DetectionConfig


def scenario_paths(key: str):
    n = SCENARIOS[key]["number"]
    return SAMPLES_DIR / f"scenario{n}_{key}_flows.csv", SAMPLES_DIR / f"scenario{n}_{key}_auth.csv"


def ensure_samples() -> None:
    f, a = scenario_paths("benign")
    if not (f.exists() and a.exists() and (SAMPLES_DIR / "baseline_training_flows.csv").exists()):
        write_samples(SAMPLES_DIR)


def analyze(flows_src, auth_src=None, cfg: DetectionConfig | None = None, model: AnomalyModel | None = None) -> Analysis:
    cfg = cfg or DetectionConfig()
    flows = load_flows(flows_src)
    auth = load_auth(auth_src) if auth_src is not None else None
    det = run_detection(flows.data, auth.data if auth else None, cfg, model)
    return Analysis(flows, auth, det, cfg)


def analyze_scenario(key: str, cfg: DetectionConfig | None = None, model: AnomalyModel | None = None) -> Analysis:
    ensure_samples()
    f, a = scenario_paths(key)
    return analyze(f, a, cfg, model)


def evaluate_analysis(an: Analysis, mode: str = "hybrid") -> dict:
    return evaluate(an.flows.labels, an.auth.labels if an.auth else None, an.detection.alert_objects, mode)
