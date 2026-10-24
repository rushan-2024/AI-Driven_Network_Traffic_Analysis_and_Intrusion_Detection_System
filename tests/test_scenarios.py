import pandas as pd
import pytest

from src.config import DetectionConfig
from src.detection import run_detection
from src.ingestion import load_flows
from src.pipeline import evaluate_analysis
from src.synthetic import SCENARIO_ORDER, generate_scenario


def rules(an):
    return set(an.detection.alerts.query("detector == 'rule'")["rule_id"])


def test_five_scenarios_exist():
    assert len(SCENARIO_ORDER) == 5


def test_generator_is_deterministic():
    for k in SCENARIO_ORDER:
        a, b = generate_scenario(k), generate_scenario(k)
        pd.testing.assert_frame_equal(a.flows, b.flows)
        pd.testing.assert_frame_equal(a.auth, b.auth)


def test_sample_files_match_generator():
    from src.config import SAMPLES_DIR
    s = generate_scenario("port_scan")
    disk = pd.read_csv(SAMPLES_DIR / "scenario2_port_scan_flows.csv")
    assert len(disk) == len(s.flows) and disk["timestamp"].tolist() == s.flows["timestamp"].tolist()


def test_s1_benign_no_rule_alerts(analyses):
    assert rules(analyses["benign"]) == set()
    assert evaluate_analysis(analyses["benign"], "rules")["flows"]["overall"]["fp"] == 0


def test_s2_port_scan(analyses):
    assert {"SCAN-V1", "SCAN-H1"} <= rules(analyses["port_scan"])
    o = evaluate_analysis(analyses["port_scan"], "rules")["flows"]["per_category"]["port_scan"]
    assert o["recall"] == 1.0 and o["fp"] == 0


def test_s3_dos(analyses):
    assert {"DOS-S1", "DOS-D1"} <= rules(analyses["dos"])
    assert evaluate_analysis(analyses["dos"], "rules")["flows"]["per_category"]["dos"]["recall"] == 1.0


def test_s3_victim_performance_degrades(analyses):
    f = analyses["dos"].flows.data
    v = f[(f["dst_ip"] == "10.0.1.10") & (f["packets"] > 5)]  # benign-looking sessions
    rel = v["ts"] - 1767225600.0
    during = v[((rel >= 200) & (rel <= 235)) | ((rel >= 380) & (rel <= 400))]["duration"].median()
    assert during > 3 * v["duration"].median()


def test_s4_auth_failures(analyses):
    a = analyses["auth_failures"].detection.alerts.query("rule_id == 'AUTH-F1'")
    assert len(a) == 2 and "critical" in set(a["severity"])
    assert evaluate_analysis(analyses["auth_failures"], "rules")["auth"]["overall"]["recall"] == 1.0


def test_s5_expected_false_positive_and_false_negatives(analyses):
    e = evaluate_analysis(analyses["ambiguous"], "rules")
    assert e["flows"]["overall"]["fp"] > 0 and e["flows"]["overall"]["fn"] > 0   # authorised scanner; connect + slow scan
    assert e["auth"]["overall"]["fp"] > 0 and e["auth"]["overall"]["fn"] > 0     # stale credential; slow brute force
    assert not any(a for a in analyses["ambiguous"].detection.alert_objects if a.rule_id.startswith("DOS"))  # flash crowd


def test_reproducible_results(cfg, model):
    f = load_flows(generate_scenario("dos").flows).data
    a, b = run_detection(f, None, cfg, model).alerts, run_detection(f, None, cfg, model).alerts
    pd.testing.assert_frame_equal(a.drop(columns="evidence_ids"), b.drop(columns="evidence_ids"))


def test_labels_do_not_influence_detection(cfg, model):
    s = generate_scenario("port_scan")
    shuffled = s.flows.assign(attack_type=s.flows["attack_type"].sample(frac=1, random_state=0).values,
                              label=s.flows["label"].sample(frac=1, random_state=0).values)
    a = run_detection(load_flows(s.flows).data, None, cfg, model).alerts
    b = run_detection(load_flows(shuffled).data, None, cfg, model).alerts
    pd.testing.assert_frame_equal(a.drop(columns="evidence_ids"), b.drop(columns="evidence_ids"))


def test_detectors_receive_no_label_columns(analyses):
    for an in analyses.values():
        assert not ({"label", "attack_type", "is_malicious"} & set(an.flows.data.columns))
        if an.auth:
            assert not ({"label", "attack_type", "is_malicious"} & set(an.auth.data.columns))


def test_small_dataset_does_not_crash(cfg, model):
    f = load_flows(generate_scenario("benign").flows.head(5)).data
    r = run_detection(f, None, cfg, model)
    assert r.alerts is not None


def test_alert_fields_complete(analyses):
    a = analyses["port_scan"].detection.alerts
    for col in ["category", "window_start", "src_ip", "severity", "observed", "threshold", "explanation", "recommendations"]:
        assert a[col].astype(str).str.len().gt(0).all() or col == "src_ip"
