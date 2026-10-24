"""Alert structure shared by the rule and anomaly detectors."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

SEVERITIES = ["low", "medium", "high", "critical"]

SEVERITY_CRITERIA = (
    "Heuristic rating, not a calibrated probability. Rules: observed/threshold ratio "
    "< 2 = low, 2 to < 4 = medium, >= 4 = high; a corroborating indicator (authentication success "
    "shortly after repeated failures) raises the rating one level, up to critical. Anomaly alerts: margin above the "
    "benign-score threshold < 0.05 = low, < 0.15 = medium, otherwise high."
)


def fmt_ts(seconds: float) -> str:
    return datetime.fromtimestamp(float(seconds), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def severity_from_ratio(ratio: float, corroborated: bool = False) -> str:
    level = 0 if ratio < 2 else (1 if ratio < 4 else 2)
    return SEVERITIES[min(level + int(corroborated), 3)]


@dataclass
class Alert:
    category: str            # port_scan | dos | auth_failures | anomaly
    rule_id: str
    detector: str            # rule | anomaly
    window_start: float
    window_end: float
    src_ip: str | None
    dst_ip: str | None
    severity: str
    observed: dict
    threshold: str
    explanation: str
    recommendations: list[str]
    evidence_ids: list[int] = field(default_factory=list)
    evidence_kind: str = "flow"  # flow | auth


def order_alerts(alerts: list[Alert]) -> list[Alert]:
    """Canonical order; alert_id A0001.. follows this order."""
    return sorted(alerts, key=lambda x: (x.window_start, x.category, x.src_ip or "", x.dst_ip or ""))


def alerts_to_frame(alerts: list[Alert]) -> pd.DataFrame:
    cols = ["alert_id", "category", "rule_id", "detector", "window_start", "window_end", "src_ip", "dst_ip",
            "severity", "observed", "threshold", "explanation", "recommendations", "evidence_kind", "evidence_count",
            "evidence_ids"]
    if not alerts:
        return pd.DataFrame(columns=cols)
    rows = []
    for i, a in enumerate(order_alerts(alerts), 1):
        rows.append({
            "alert_id": f"A{i:04d}", "category": a.category, "rule_id": a.rule_id, "detector": a.detector,
            "window_start": fmt_ts(a.window_start), "window_end": fmt_ts(a.window_end),
            "src_ip": a.src_ip or "", "dst_ip": a.dst_ip or "", "severity": a.severity,
            "observed": "; ".join(f"{k}={v}" for k, v in a.observed.items()),
            "threshold": a.threshold, "explanation": a.explanation,
            "recommendations": " | ".join(a.recommendations),
            "evidence_kind": a.evidence_kind, "evidence_count": len(a.evidence_ids),
            "evidence_ids": list(a.evidence_ids),
        })
    return pd.DataFrame(rows, columns=cols)
