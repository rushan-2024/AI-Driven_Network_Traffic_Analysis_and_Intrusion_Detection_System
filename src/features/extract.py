"""Feature extraction. Operates only on observable traffic fields, never on labels."""
from __future__ import annotations

import numpy as np
import pandas as pd

FORBIDDEN_COLUMNS = {"label", "attack_type", "is_malicious", "ground_truth"}

# Per-source, per-window features given to the Isolation Forest.
ANOMALY_FEATURES = [
    "flows", "unique_dst_ports", "unique_dst_hosts", "packets", "bytes",
    "mean_packets", "mean_bytes", "mean_duration",
    "flow_rate", "packet_rate", "byte_rate", "udp_frac", "icmp_frac",
]


def assert_no_labels(df: pd.DataFrame) -> None:
    """Guard against ground-truth leakage into features or detectors."""
    leaked = FORBIDDEN_COLUMNS & set(df.columns)
    if leaked:
        raise ValueError(f"Ground-truth column(s) {sorted(leaked)} must not be used for detection or features.")


def add_window(df: pd.DataFrame, seconds: int, col: str = "win") -> pd.DataFrame:
    if seconds <= 0:
        raise ValueError("Window length must be positive.")
    return df.assign(**{col: np.floor(df["ts"] / seconds) * seconds})


def protocol_distribution(flows: pd.DataFrame) -> pd.DataFrame:
    g = flows.groupby("protocol").agg(flows=("ts", "size"), packets=("packets", "sum"), bytes=("bytes", "sum"))
    return g.reset_index()


def window_features(flows: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    """One row per (src_ip, window): behaviour summary used by the anomaly model.

    Rates use the active span (last minus first flow, floored at 10 s so that single-flow windows do not produce artificial rate spikes) so that a burst
    inside a window is not diluted by the idle remainder of the window.
    """
    assert_no_labels(flows)
    if flows.empty:
        return pd.DataFrame(columns=["src_ip", "win", *ANOMALY_FEATURES])
    df = add_window(flows, window_seconds).assign(
        is_udp=lambda d: (d["protocol"] == "UDP").astype(float),
        is_icmp=lambda d: (d["protocol"] == "ICMP").astype(float),
    )
    g = df.groupby(["src_ip", "win"]).agg(
        flows=("ts", "size"), ts_min=("ts", "min"), ts_max=("ts", "max"),
        packets=("packets", "sum"), bytes=("bytes", "sum"),
        mean_packets=("packets", "mean"), mean_bytes=("bytes", "mean"),
        mean_duration=("duration", "mean"),
        unique_dst_ports=("dst_port", "nunique"), unique_dst_hosts=("dst_ip", "nunique"),
        udp_frac=("is_udp", "mean"), icmp_frac=("is_icmp", "mean"),
    )
    span = (g["ts_max"] - g["ts_min"]).clip(lower=10.0)
    g["flow_rate"] = g["flows"] / span
    g["packet_rate"] = g["packets"] / span
    g["byte_rate"] = g["bytes"] / span
    return g.drop(columns=["ts_min", "ts_max"]).reset_index()[["src_ip", "win", *ANOMALY_FEATURES]]
