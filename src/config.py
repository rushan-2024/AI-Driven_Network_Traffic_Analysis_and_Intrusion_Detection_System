"""Detection configuration and the documented rationale for every threshold."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "data" / "samples"
RESULTS_DIR = ROOT / "results"
PROJECT_TITLE = "AI-Driven Network Traffic Analysis and Intrusion Detection System"


@dataclass
class DetectionConfig:
    """All tunable thresholds. Defaults were set from the benign baseline profile
    (see scripts/run_evaluation.py --profile) with a wide margin, then checked
    against the synthetic scenarios. They are NOT tuned on real networks."""

    window_seconds: int = 60
    # Port scan / reconnaissance
    scan_min_ports: int = 20
    scan_min_hosts: int = 20
    scan_max_mean_packets: float = 3.0
    # DoS / flood
    dos_min_flows: int = 200
    dos_min_flow_rate: float = 30.0
    rate_bin_seconds: int = 5
    dos_max_mean_packets: float = 5.0
    ddos_min_flows: int = 500
    ddos_min_sources: int = 10
    ddos_max_top_source_share: float = 0.5
    # Authentication failures
    auth_window_seconds: int = 300
    auth_min_failures: int = 8
    auth_spray_min_users: int = 5
    auth_success_grace_seconds: int = 60
    # Anomaly model
    anomaly_enabled: bool = True
    anomaly_quantile: float = 0.995
    anomaly_min_training_windows: int = 30
    random_seed: int = 42

    def to_dict(self) -> dict:
        return asdict(self)


# (label, rationale) shown in the dashboard and README.
THRESHOLD_DOCS: dict[str, tuple[str, str]] = {
    "window_seconds": ("Flow window (s)", "Tumbling window used to aggregate per-source behaviour. 60 s is long enough to see a scan or flood build up and short enough to localise it in time. Attacks straddling a window edge can be split."),
    "scan_min_ports": ("Scan: distinct ports on one host", "Benign clients in the baseline touch at most a handful of ports per host per window. 20 leaves a wide margin yet catches fast scans."),
    "scan_min_hosts": ("Scan: distinct hosts on one port", "Horizontal sweeps contact many hosts on the same port. The baseline network has only six servers, so 20 is far above normal. Larger networks need a higher value."),
    "scan_max_mean_packets": ("Scan: max mean packets per flow", "Probes are short (SYN, SYN/RST, ICMP echo). Requiring small flows avoids flagging busy hosts with bulk sessions, but a scanner that completes handshakes can evade this check."),
    "dos_min_flows": ("DoS: min flows (one source to one target)", "Volume floor so that a short burst of connections is not enough by itself."),
    "dos_min_flow_rate": ("DoS: min peak flow rate (flows/s)", "Peak rate over short bins inside the window (see bin length), so a burst is not diluted by background traffic in the same window. Baseline clients stay far below this."),
    "rate_bin_seconds": ("Rate bin (s)", "Bin length for the peak-rate measurement."),
    "dos_max_mean_packets": ("DoS: max mean packets per flow", "Flood flows are typically short and unfinished. Large, completed flows suggest a legitimate surge (flash crowd) rather than a flood."),
    "ddos_min_flows": ("Distributed: min flows to one target", "Volume floor at the destination."),
    "ddos_min_sources": ("Distributed: min distinct sources", "A flood from one source is handled by the single-source rule."),
    "ddos_max_top_source_share": ("Distributed: max share from top source", "If one source sends most of the flows, it is a single-source flood, not a distributed one."),
    "auth_window_seconds": ("Auth window (s)", "Failures are counted per source, target and service in a tumbling window. Slow attacks spread over longer periods fall below the threshold."),
    "auth_min_failures": ("Auth: min failures per window", "Humans mistype a password a few times; automated guessing produces many more. 8 sits above benign typo bursts in the baseline."),
    "auth_spray_min_users": ("Auth: distinct users for spray label", "Failures against many usernames from one source indicate password spraying rather than one user's typos."),
    "auth_success_grace_seconds": ("Auth: success-after-failure grace (s)", "A success from the same source shortly after the failures raises severity to critical (possible compromise)."),
    "anomaly_quantile": ("Anomaly: threshold quantile", "Windows scoring above this quantile of the benign training scores are flagged. A higher value means fewer alerts."),
    "anomaly_min_training_windows": ("Anomaly: min training windows", "With fewer windows the model is not trained and the anomaly layer is skipped."),
    "random_seed": ("Random seed", "Fixes Isolation Forest randomness for reproducible results."),
}
