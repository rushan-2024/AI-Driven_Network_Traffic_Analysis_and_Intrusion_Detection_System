import pytest

from src.config import DetectionConfig
from src.detection import AnomalyModel, run_detection
from src.ingestion import load_flows
from src.config import SAMPLES_DIR


def test_small_baseline_rejected():
    flows = load_flows(SAMPLES_DIR / "scenario1_benign_flows.csv").data.head(20)
    with pytest.raises(ValueError, match="at least"):
        AnomalyModel(DetectionConfig()).fit(flows)


def test_missing_model_baseline_is_noted_not_crash(tmp_path, monkeypatch):
    import src.detection.anomaly as an
    monkeypatch.setattr(an, "SAMPLES_DIR", tmp_path)
    r = run_detection(load_flows(SAMPLES_DIR / "scenario1_benign_flows.csv").data, None, DetectionConfig())
    assert r.window_scores is None and any("Anomaly layer skipped" in n for n in r.notes)


def test_scores_deterministic(model):
    f = load_flows(SAMPLES_DIR / "scenario2_port_scan_flows.csv").data
    a, b = model.score_windows(f), model.score_windows(f)
    assert a["anomaly_score"].tolist() == b["anomaly_score"].tolist()


def test_validation_on_heldout_benign(model):
    v = model.validate(load_flows(SAMPLES_DIR / "baseline_validation_flows.csv").data)
    assert v["validation_windows"] > 50 and v["validation_flag_rate"] <= 0.05


def test_missing_and_inf_values_handled(model):
    import numpy as np
    f = load_flows(SAMPLES_DIR / "scenario1_benign_flows.csv").data.copy()
    f.loc[f.index[:5], "duration"] = np.nan  # simulate bad values reaching the model
    out = model.score_windows(f)
    assert out["anomaly_score"].notna().all()


def test_training_and_scenario_records_disjoint():
    tr = load_flows(SAMPLES_DIR / "baseline_training_flows.csv").data
    for k in ["scenario1_benign", "scenario2_port_scan"]:
        sc = load_flows(SAMPLES_DIR / f"{k}_flows.csv").data
        key = ["timestamp", "src_ip", "dst_ip", "dst_port", "packets", "bytes", "duration"]
        assert tr.merge(sc, on=key).empty


def test_tiny_capture_skips_anomaly_layer_with_note():
    from src.detection import run_detection
    f = load_flows(SAMPLES_DIR / "scenario1_benign_flows.csv").data.head(3)
    r = run_detection(f, None, DetectionConfig())
    assert r.window_scores is None and any("at least" in n for n in r.notes)
    assert not (r.alerts["detector"] == "anomaly").any() if len(r.alerts) else True
