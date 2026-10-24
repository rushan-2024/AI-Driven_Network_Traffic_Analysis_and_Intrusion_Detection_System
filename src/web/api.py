"""JSON API logic for the web dashboard (no HTTP code here, so it is easy to test)."""
from __future__ import annotations

import io
import math
import threading
from collections import OrderedDict
from dataclasses import fields

import numpy as np
import pandas as pd

from ..config import PROJECT_TITLE, THRESHOLD_DOCS, DetectionConfig
from ..detection.alerts import SEVERITY_CRITERIA, fmt_ts, order_alerts
from ..evaluation import summarise_counts
from ..features import protocol_distribution
from ..ingestion import DataValidationError
from ..pipeline import Analysis, analyze, analyze_scenario, ensure_samples, evaluate_analysis
from ..synthetic import SCENARIO_ORDER, SCENARIOS

MAX_UPLOAD_CHARS = 25_000_000
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
MODES = ["hybrid", "rules", "anomaly"]
GROUPS = [
    ("General", ["window_seconds", "random_seed"]),
    ("Port scan", ["scan_min_ports", "scan_min_hosts", "scan_max_mean_packets"]),
    ("Denial of service", ["dos_min_flows", "dos_min_flow_rate", "rate_bin_seconds", "dos_max_mean_packets",
                           "ddos_min_flows", "ddos_min_sources", "ddos_max_top_source_share"]),
    ("Authentication failures", ["auth_window_seconds", "auth_min_failures", "auth_spray_min_users", "auth_success_grace_seconds"]),
    ("Anomaly model", ["anomaly_quantile", "anomaly_min_training_windows"]),
]
CATEGORIES = {
    "port_scan": {"label": "Port scan", "help": "Someone is checking which network services are open. This is often the first step before an attack."},
    "dos": {"label": "Flood (denial of service)", "help": "A machine is being hit with so many connections that real users may not be able to reach it."},
    "auth_failures": {"label": "Repeated login failures", "help": "Many failed logins from one place, which suggests password guessing."},
    "anomaly": {"label": "Unusual behaviour", "help": "Activity that looks different from the normal baseline. Unusual does not always mean malicious."},
}
_ANALYSIS_LOCK = threading.Lock()


def headline(o) -> str:
    """One plain-English sentence describing what happened."""
    ob, src, dst = o.observed, o.src_ip or "A source", o.dst_ip or "a target"
    if o.rule_id == "SCAN-V1":
        return f"{src} probed {ob['distinct_dst_ports']} different ports on {dst}"
    if o.rule_id == "SCAN-H1":
        return f"{src} probed {ob['distinct_dst_hosts']} different machines ({ob['target']})"
    if o.rule_id == "DOS-S1":
        return f"{src} sent {ob['flows']:,} connections to {dst} in a very short time"
    if o.rule_id == "DOS-D1":
        return f"{dst} received a flood of {ob['flows']:,} connections from {ob['distinct_sources']} different sources"
    if o.rule_id == "AUTH-F1":
        tail = ", then a login succeeded" if ob.get("success_after_failures") else ""
        return f"{src} failed to log in {ob['failures']} times to {ob['service']} on {dst}{tail}"
    return f"{src} behaved unusually compared with the normal baseline"


def jsonable(o):
    """Recursively convert numpy / pandas / NaN values to strict-JSON-safe Python values."""
    if isinstance(o, dict):
        return {str(k): jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [jsonable(v) for v in o]
    if isinstance(o, (np.bool_, bool)):
        return bool(o)
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating, float)):
        f = float(o)
        return None if math.isnan(f) or math.isinf(f) else f
    if isinstance(o, (pd.Timestamp,)):
        return str(o)
    return o


class RunStore:
    def __init__(self, keep: int = 8):
        self.keep, self._runs, self._lock, self._n = keep, OrderedDict(), threading.Lock(), 0

    def add(self, an: Analysis) -> str:
        with self._lock:
            self._n += 1
            rid = f"r{self._n}"
            self._runs[rid] = {"an": an, "alerts": {f"A{i:04d}": o for i, o in enumerate(order_alerts(an.detection.alert_objects), 1)}}
            while len(self._runs) > self.keep:
                self._runs.popitem(last=False)
            return rid

    def get(self, rid: str) -> dict:
        with self._lock:
            if rid not in self._runs:
                raise KeyError("That analysis is no longer available. Run it again.")
            return self._runs[rid]


STORE = RunStore()


# ------------------------------------------------------------------ configuration
def config_info() -> dict:
    d = DetectionConfig().to_dict()
    groups = []
    for title, names in GROUPS:
        groups.append({"title": title, "fields": [{"name": n, "label": THRESHOLD_DOCS[n][0], "help": THRESHOLD_DOCS[n][1],
                                                    "default": d[n], "kind": "float" if isinstance(d[n], float) else "int"} for n in names]})
    return {"title": PROJECT_TITLE, "defaults": d, "groups": groups, "categories": CATEGORIES, "severity_criteria": SEVERITY_CRITERIA,
            "scenarios": [{"key": k, **{x: SCENARIOS[k][x] for x in ("number", "title", "description", "expectation")}} for k in SCENARIO_ORDER]}


def config_from_dict(raw: dict | None) -> DetectionConfig:
    base = DetectionConfig()
    raw = raw or {}
    if not isinstance(raw, dict):
        raise DataValidationError("Settings must be an object.")
    vals = base.to_dict()
    for f in fields(DetectionConfig):
        if f.name not in raw:
            continue
        default, v = vals[f.name], raw[f.name]
        try:
            if isinstance(default, bool):
                vals[f.name] = bool(v)
            elif isinstance(default, int):
                if float(v) != int(float(v)):
                    raise ValueError
                vals[f.name] = int(float(v))
            else:
                vals[f.name] = float(v)
        except (TypeError, ValueError):
            label = THRESHOLD_DOCS.get(f.name, (f.name,))[0]
            raise DataValidationError(f"Setting '{label}' must be a valid number.") from None
        if not isinstance(default, bool) and (vals[f.name] < 0 or (vals[f.name] == 0 and f.name != "random_seed")):
            raise DataValidationError(f"Setting '{THRESHOLD_DOCS.get(f.name, (f.name,))[0]}' must be greater than zero.")
    if not 0.5 <= vals["anomaly_quantile"] < 1:
        raise DataValidationError("Anomaly threshold quantile must be between 0.5 and 0.9999.")
    if vals["ddos_max_top_source_share"] > 1:
        raise DataValidationError("Maximum share from the top source must be between 0 and 1.")
    return DetectionConfig(**vals)


# ------------------------------------------------------------------ analysis payload
def _graph(an: Analysis, objs, max_nodes: int = 110, max_edges: int = 260) -> dict:
    flows = an.flows.data
    flagged_edges: set[tuple[str, str]] = set()
    for o in objs:
        src = an.auth.data if o.evidence_kind == "auth" and an.auth else flows
        if o.evidence_kind == "auth" and not an.auth:
            continue
        ev = src.loc[[i for i in o.evidence_ids if i < len(src)], ["src_ip", "dst_ip"]].drop_duplicates()
        flagged_edges.update(map(tuple, ev.to_numpy()))
    pair = flows.groupby(["src_ip", "dst_ip"]).size().reset_index(name="flows")
    pair["flagged"] = [(s, d) in flagged_edges for s, d in zip(pair["src_ip"], pair["dst_ip"])]
    suspects = {s for s, _ in flagged_edges}
    targets = {d for _, d in flagged_edges}
    node_flows = pd.concat([pair.groupby("src_ip")["flows"].sum(), pair.groupby("dst_ip")["flows"].sum()]).groupby(level=0).sum()
    keep = set(suspects | targets)
    for ip in node_flows.sort_values(ascending=False).index:
        if len(keep) >= max_nodes:
            break
        keep.add(ip)
    pair = pair[pair["src_ip"].isin(keep) & pair["dst_ip"].isin(keep)]
    pair = pd.concat([pair[pair["flagged"]], pair[~pair["flagged"]].nlargest(max_edges, "flows")]).head(max_edges * 2)
    nodes = []
    for ip in sorted(keep):
        role = "suspect" if ip in suspects and ip not in targets else ("target" if ip in targets and ip not in suspects else ("both" if ip in suspects else "normal"))
        nodes.append({"id": ip, "flows": int(node_flows.get(ip, 0)), "role": role})
    return {"nodes": nodes, "edges": [{"s": r.src_ip, "t": r.dst_ip, "flows": int(r.flows), "flagged": bool(r.flagged)} for r in pair.itertuples()],
            "shown": len(keep), "total": int(len(node_flows))}


def _perf(an: Analysis, objs, cfg: DetectionConfig) -> list[dict]:
    flows = an.flows.data
    alerted = [o.dst_ip for o in objs if o.dst_ip]
    order = list(dict.fromkeys(alerted + flows["dst_ip"].value_counts().index.tolist()))[:4]
    out = []
    for dst in order:
        d = flows[flows["dst_ip"] == dst].assign(b=lambda x: (x["ts"] // 10) * 10)
        sess = d[d["packets"] > cfg.dos_max_mean_packets].groupby("b")["duration"].median()
        cnt = d.groupby("b").size()
        out.append({"dst": dst, "alerted": dst in alerted,
                    "bins": [[float(b), int(n), (float(sess[b]) if b in sess.index else None)] for b, n in cnt.items()]})
    return out


def _examples(an: Analysis, kind: str, ids: list[int], labels: pd.DataFrame) -> list[dict]:
    data = an.flows.data if kind == "flows" else an.auth.data
    rows = data.loc[ids[:15]].drop(columns=["ts"]).assign(attack_type=labels.loc[ids[:15], "attack_type"].to_numpy())
    return rows.to_dict("records")


def _evaluation(an: Analysis) -> dict | None:
    if not an.flows.report.labels_present:
        return None
    out = {}
    for mode in MODES:
        e = evaluate_analysis(an, mode)
        entry = {}
        for kind in ("flows", "auth"):
            if kind not in e:
                continue
            labels = an.flows.labels if kind == "flows" else an.auth.labels
            entry[kind] = {"overall": e[kind]["overall"], "per_category": e[kind]["per_category"],
                           "fp_total": len(e[kind]["false_positive_ids"]), "fn_total": len(e[kind]["false_negative_ids"]),
                           "fp_examples": _examples(an, kind, e[kind]["false_positive_ids"], labels),
                           "fn_examples": _examples(an, kind, e[kind]["false_negative_ids"], labels)}
        out[mode] = entry
    return out


def build_payload(run_id: str, an: Analysis, label: str, kind: str) -> dict:
    flows = an.flows.data
    det = an.detection
    objs = order_alerts(det.alert_objects)
    alerts = [{"alert_id": f"A{i:04d}", "headline": headline(o), "category_label": CATEGORIES[o.category]["label"], "severity": o.severity, "category": o.category, "rule_id": o.rule_id, "detector": o.detector,
               "window_start": fmt_ts(o.window_start), "window_end": fmt_ts(o.window_end), "src_ip": o.src_ip or "", "dst_ip": o.dst_ip or "",
               "observed": o.observed, "threshold": o.threshold, "explanation": o.explanation, "recommendations": o.recommendations,
               "evidence_kind": o.evidence_kind, "evidence_count": len(o.evidence_ids)} for i, o in enumerate(objs, 1)]
    rep = an.flows.report
    issues = []
    for r in [rep] + ([an.auth.report] if an.auth else []):
        issues += [f"{r.kind}: dropped {n} row(s): {why}" for why, n in r.dropped.items()]
        if r.duplicates_removed:
            issues.append(f"{r.kind}: removed {r.duplicates_removed} duplicate row(s)")
        issues += [f"{r.kind}: {w}" for w in r.warnings]
    issues += det.notes
    top = next((s for s in reversed(SEVERITY_ORDER) if any(a["severity"] == s for a in alerts)), None)
    ts = flows.assign(b=(flows["ts"] // 10) * 10).groupby("b").size()
    anomaly = {"enabled": an.cfg.anomaly_enabled, "ran": det.window_scores is not None, "info": det.model_info, "windows": []}
    if det.window_scores is not None:
        ws = det.window_scores
        anomaly["windows"] = [[r.src_ip, float(r.win), round(float(r.anomaly_score), 4), bool(r.flagged), int(r.flows), int(r.unique_dst_ports)] for r in ws.itertuples()]
    return jsonable({
        "run_id": run_id, "label": label, "kind": kind,
        "dataset": {"flows_read": rep.rows_read, "flows_kept": rep.rows_kept, "auth_events": len(an.auth.data) if an.auth else 0,
                    "status": rep.status if not issues else "valid with warnings", "start": fmt_ts(rep.time_start), "end": fmt_ts(rep.time_end),
                    "labels_present": rep.labels_present, "issues": issues, "sources": int(flows["src_ip"].nunique()),
                    "destinations": int(flows["dst_ip"].nunique())},
        "stats": {"alerts": len(alerts), "rule_alerts": sum(a["detector"] == "rule" for a in alerts),
                  "anomaly_alerts": sum(a["detector"] == "anomaly" for a in alerts), "highest": top},
        "timeline": [[float(b), int(n)] for b, n in ts.items()],
        "protocols": protocol_distribution(flows).to_dict("records"),
        "top_sources": flows.groupby("src_ip").agg(flows=("ts", "size"), ports=("dst_port", "nunique")).reset_index().nlargest(8, "flows").to_dict("records"),
        "alerts": alerts, "graph": _graph(an, objs), "perf": _perf(an, objs, an.cfg), "anomaly": anomaly,
        "evaluation": _evaluation(an), "severity_criteria": SEVERITY_CRITERIA, "session_threshold": an.cfg.dos_max_mean_packets,
    })


def run_analysis(body: dict) -> dict:
    if not isinstance(body, dict):
        raise DataValidationError("Request body must be a JSON object.")
    cfg = config_from_dict(body.get("config"))
    ensure_samples()
    source = body.get("source")
    with _ANALYSIS_LOCK:
        if source == "scenario":
            key = body.get("scenario")
            if key not in SCENARIOS:
                raise DataValidationError(f"Unknown scenario. Choose one of: {', '.join(SCENARIO_ORDER)}.")
            an = analyze_scenario(key, cfg)
            label = f"Scenario {SCENARIOS[key]['number']}: {SCENARIOS[key]['title']} (synthetic)"
            kind = "scenario"
        elif source == "upload":
            flows_csv, auth_csv = body.get("flows_csv"), body.get("auth_csv")
            if not isinstance(flows_csv, str) or not flows_csv.strip():
                raise DataValidationError("Choose a flow CSV file first.")
            if len(flows_csv) + len(auth_csv or "") > MAX_UPLOAD_CHARS:
                raise DataValidationError("The files are too large (limit about 25 MB in total).")
            an = analyze(io.StringIO(flows_csv), io.StringIO(auth_csv) if isinstance(auth_csv, str) and auth_csv.strip() else None, cfg)
            label = f"Uploaded file: {str(body.get('name') or 'flows.csv')[:80]}"
            kind = "upload"
        else:
            raise DataValidationError("Choose an included scenario or upload a file.")
    return build_payload(STORE.add(an), an, label, kind)


def evaluate_all(body: dict) -> dict:
    cfg = config_from_dict((body or {}).get("config"))
    ensure_samples()
    rows, pooled = [], {m: {t: dict(tp=0, fp=0, tn=0, fn=0) for t in ("flows", "auth")} for m in MODES}
    with _ANALYSIS_LOCK:
        for key in SCENARIO_ORDER:
            an = analyze_scenario(key, cfg)
            for mode in MODES:
                e = evaluate_analysis(an, mode)
                for t in ("flows", "auth"):
                    o = e[t]["overall"]
                    rows.append({"scenario": f"{SCENARIOS[key]['number']}. {SCENARIOS[key]['title']}", "detector": mode, "records": t, **{k: o[k] for k in ("n", "tp", "fp", "tn", "fn", "precision", "recall", "f1")}})
                    for k in ("tp", "fp", "tn", "fn"):
                        pooled[mode][t][k] += o[k]
    for mode in MODES:
        for t in ("flows", "auth"):
            o = summarise_counts(pooled[mode][t])
            rows.append({"scenario": "All five (pooled)", "detector": mode, "records": t, **{k: o[k] for k in ("n", "tp", "fp", "tn", "fn", "precision", "recall", "f1")}})
    return jsonable({"rows": rows})


# ------------------------------------------------------------------ evidence / exports
def template_csv(kind: str) -> str:
    """A small example file (no labels) that users can copy the format from."""
    from ..config import SAMPLES_DIR
    if kind not in {"flows", "auth"}:
        raise KeyError("Unknown template.")
    ensure_samples()
    df = pd.read_csv(SAMPLES_DIR / f"scenario1_benign_{kind}.csv").drop(columns=["label", "attack_type"], errors="ignore")
    return df.head(12 if kind == "flows" else 10).to_csv(index=False)


def _evidence_frame(run: dict, alert_id: str) -> pd.DataFrame:
    if alert_id not in run["alerts"]:
        raise KeyError("Unknown alert.")
    o, an = run["alerts"][alert_id], run["an"]
    src = an.auth.data if o.evidence_kind == "auth" else an.flows.data
    return src.loc[[i for i in o.evidence_ids if i < len(src)]].drop(columns=["ts"])


def evidence_json(run_id: str, alert_id: str, limit: int = 200) -> dict:
    df = _evidence_frame(STORE.get(run_id), alert_id)
    return jsonable({"columns": list(df.columns), "rows": df.head(limit).astype(object).where(df.head(limit).notna(), None).values.tolist(), "total": len(df)})


def evidence_csv(run_id: str, alert_id: str) -> str:
    return _evidence_frame(STORE.get(run_id), alert_id).to_csv(index=False)


def findings_csv(run_id: str) -> str:
    a = STORE.get(run_id)["an"].detection.alerts
    return a.assign(evidence_ids=a["evidence_ids"].map(lambda ids: ";".join(map(str, ids)))).to_csv(index=False)
