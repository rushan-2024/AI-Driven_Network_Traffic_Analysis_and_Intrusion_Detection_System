"""Reproducible evaluation of all five scenarios. Writes results/evaluation_results.json and .md.

Usage:  python scripts/run_evaluation.py [--profile]
"""
import _path  # noqa: F401
import argparse
import json

import numpy as np
import pandas as pd

from src.config import RESULTS_DIR, SAMPLES_DIR, DetectionConfig
from src.detection import load_default_model
from src.evaluation import confusion_counts, summarise_counts
from src.features.extract import add_window
from src.ingestion import load_auth, load_flows
from src.pipeline import analyze_scenario, ensure_samples, evaluate_analysis
from src.synthetic import SCENARIO_ORDER, SCENARIOS

MODES = ["rules", "anomaly", "hybrid"]


def baseline_profile(cfg: DetectionConfig) -> dict:
    """Benign-only distribution used to choose thresholds (training baseline + validation baseline)."""
    out = {}
    for name in ("baseline_training_flows", "baseline_validation_flows"):
        df = add_window(load_flows(SAMPLES_DIR / f"{name}.csv").data, cfg.window_seconds)
        ports = df.groupby(["src_ip", "dst_ip", "win"])["dst_port"].nunique()
        hosts = df.groupby(["src_ip", "protocol", "dst_port", "win"])["dst_ip"].nunique()
        peak = df.assign(b=df["ts"] // cfg.rate_bin_seconds).groupby(["src_ip", "dst_ip", "win", "b"]).size() / cfg.rate_bin_seconds
        out[name] = {"max_distinct_ports_per_host_window": int(ports.max()), "max_distinct_hosts_per_port_window": int(hosts.max()),
                     "max_peak_flow_rate_single_source": float(peak.max()), "flows": int(len(df))}
    a = load_auth(SAMPLES_DIR / "scenario1_benign_auth.csv").data
    f = add_window(a[a["outcome"] == "failure"], cfg.auth_window_seconds)
    out["benign_auth"] = {"max_failures_per_source_window": int(f.groupby(["src_ip", "dst_ip", "service", "win"]).size().max()) if len(f) else 0}
    return out


def fmt(x):
    return "n/a" if x is None else f"{x:.3f}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", action="store_true", help="print the benign baseline profile only")
    args = ap.parse_args()
    cfg = DetectionConfig()
    ensure_samples()
    if args.profile:
        print(json.dumps(baseline_profile(cfg), indent=2))
        return
    model, info = load_default_model(cfg)
    results = {"config": cfg.to_dict(), "model": info, "baseline_profile": baseline_profile(cfg), "scenarios": {}}
    pooled = {m: {"flows": dict(tp=0, fp=0, tn=0, fn=0), "auth": dict(tp=0, fp=0, tn=0, fn=0)} for m in MODES}
    lines = ["# Evaluation summary (synthetic data)", "",
             "All numbers below are produced by `scripts/run_evaluation.py` on deterministic SYNTHETIC scenarios.",
             "They show how the detectors behave on this synthetic data and do not estimate real-network performance.", ""]
    for key in SCENARIO_ORDER:
        an = analyze_scenario(key, cfg, model)
        res = {"title": SCENARIOS[key]["title"], "alerts": int(len(an.detection.alerts)),
               "alerts_by_rule": an.detection.alerts.groupby("rule_id").size().to_dict() if len(an.detection.alerts) else {}}
        for mode in MODES:
            e = evaluate_analysis(an, mode)
            res[mode] = {t: {"overall": e[t]["overall"], "per_category": e[t]["per_category"],
                             "false_positive_ids": e[t]["false_positive_ids"][:5], "false_negative_ids": e[t]["false_negative_ids"][:5]}
                         for t in ("flows", "auth")}
            for t in ("flows", "auth"):
                for k in ("tp", "fp", "tn", "fn"):
                    pooled[mode][t][k] += e[t]["overall"][k]
        results["scenarios"][key] = res
    results["pooled"] = {m: {t: summarise_counts(pooled[m][t]) for t in ("flows", "auth")} for m in MODES}

    lines += ["## Per scenario (flow records, then authentication events)", "",
              "| Scenario | Detector | Records | TP | FP | TN | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|---|---|---|"]
    for key in SCENARIO_ORDER:
        for mode in MODES:
            for t in ("flows", "auth"):
                o = results["scenarios"][key][mode][t]["overall"]
                lines.append(f"| {SCENARIOS[key]['number']} {key} | {mode} | {t} ({o['n']}) | {o['tp']} | {o['fp']} | {o['tn']} | {o['fn']} | {fmt(o['precision'])} | {fmt(o['recall'])} | {fmt(o['f1'])} |")
    lines += ["", "## Pooled over all five scenarios", "",
              "Pooled counts mix scenarios with very different attack prevalence; read them with the per-scenario table.", "",
              "| Detector | Records | Positives | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for mode in MODES:
        for t in ("flows", "auth"):
            o = results["pooled"][mode][t]
            lines.append(f"| {mode} | {t} ({o['n']}) | {o['positives']} | {o['tp']} | {o['fp']} | {o['tn']} | {o['fn']} | {fmt(o['precision'])} | {fmt(o['recall'])} | {fmt(o['f1'])} | {fmt(o['accuracy'])} |")
    lines += ["", "## Anomaly model", "", f"```\n{json.dumps(info, indent=1)}\n```", "",
              "## Benign baseline profile (threshold calibration)", "", f"```\n{json.dumps(results['baseline_profile'], indent=1)}\n```", ""]
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "evaluation_results.json").write_text(json.dumps(results, indent=2, default=float))
    (RESULTS_DIR / "evaluation_summary.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
