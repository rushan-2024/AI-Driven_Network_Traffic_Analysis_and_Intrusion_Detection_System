# Evaluation summary (synthetic data)

All numbers below are produced by `scripts/run_evaluation.py` on deterministic SYNTHETIC scenarios.
They show how the detectors behave on this synthetic data and do not estimate real-network performance.

## Per scenario (flow records, then authentication events)

| Scenario | Detector | Records | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| 1 benign | rules | flows (1396) | 0 | 0 | 1396 | 0 | n/a | n/a | n/a |
| 1 benign | rules | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 1 benign | anomaly | flows (1396) | 0 | 6 | 1390 | 0 | 0.000 | n/a | n/a |
| 1 benign | anomaly | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 1 benign | hybrid | flows (1396) | 0 | 6 | 1390 | 0 | 0.000 | n/a | n/a |
| 1 benign | hybrid | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 2 port_scan | rules | flows (1781) | 360 | 0 | 1421 | 0 | 1.000 | 1.000 | 1.000 |
| 2 port_scan | rules | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 2 port_scan | anomaly | flows (1781) | 360 | 2 | 1419 | 0 | 0.994 | 1.000 | 0.997 |
| 2 port_scan | anomaly | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 2 port_scan | hybrid | flows (1781) | 360 | 2 | 1419 | 0 | 0.994 | 1.000 | 0.997 |
| 2 port_scan | hybrid | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 3 dos | rules | flows (3676) | 2200 | 0 | 1476 | 0 | 1.000 | 1.000 | 1.000 |
| 3 dos | rules | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 3 dos | anomaly | flows (3676) | 1300 | 7 | 1469 | 900 | 0.995 | 0.591 | 0.741 |
| 3 dos | anomaly | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 3 dos | hybrid | flows (3676) | 2200 | 7 | 1469 | 0 | 0.997 | 1.000 | 0.998 |
| 3 dos | hybrid | auth (60) | 0 | 0 | 60 | 0 | n/a | n/a | n/a |
| 4 auth_failures | rules | flows (1407) | 0 | 0 | 1407 | 0 | n/a | n/a | n/a |
| 4 auth_failures | rules | auth (179) | 119 | 0 | 60 | 0 | 1.000 | 1.000 | 1.000 |
| 4 auth_failures | anomaly | flows (1407) | 0 | 4 | 1403 | 0 | 0.000 | n/a | n/a |
| 4 auth_failures | anomaly | auth (179) | 0 | 0 | 60 | 119 | n/a | 0.000 | n/a |
| 4 auth_failures | hybrid | flows (1407) | 0 | 4 | 1403 | 0 | 0.000 | n/a | n/a |
| 4 auth_failures | hybrid | auth (179) | 119 | 0 | 60 | 0 | 1.000 | 1.000 | 1.000 |
| 5 ambiguous | rules | flows (3739) | 0 | 150 | 3489 | 100 | 0.000 | 0.000 | n/a |
| 5 ambiguous | rules | auth (152) | 0 | 14 | 126 | 12 | 0.000 | 0.000 | n/a |
| 5 ambiguous | anomaly | flows (3739) | 100 | 172 | 3467 | 0 | 0.368 | 1.000 | 0.538 |
| 5 ambiguous | anomaly | auth (152) | 0 | 0 | 140 | 12 | n/a | 0.000 | n/a |
| 5 ambiguous | hybrid | flows (3739) | 100 | 172 | 3467 | 0 | 0.368 | 1.000 | 0.538 |
| 5 ambiguous | hybrid | auth (152) | 0 | 14 | 126 | 12 | 0.000 | 0.000 | n/a |

## Pooled over all five scenarios

Pooled counts mix scenarios with very different attack prevalence; read them with the per-scenario table.

| Detector | Records | Positives | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | flows (11999) | 2660 | 2560 | 150 | 9189 | 100 | 0.945 | 0.962 | 0.953 | 0.979 |
| rules | auth (511) | 131 | 119 | 14 | 366 | 12 | 0.895 | 0.908 | 0.902 | 0.949 |
| anomaly | flows (11999) | 2660 | 1760 | 191 | 9148 | 900 | 0.902 | 0.662 | 0.763 | 0.909 |
| anomaly | auth (511) | 131 | 0 | 0 | 380 | 131 | n/a | 0.000 | n/a | 0.744 |
| hybrid | flows (11999) | 2660 | 2660 | 191 | 9148 | 0 | 0.933 | 1.000 | 0.965 | 0.984 |
| hybrid | auth (511) | 131 | 119 | 14 | 366 | 12 | 0.895 | 0.908 | 0.902 | 0.949 |

## Anomaly model

```
{
 "baseline_windows": 400,
 "quantile": 0.995,
 "features": [
  "flows",
  "unique_dst_ports",
  "unique_dst_hosts",
  "packets",
  "bytes",
  "mean_packets",
  "mean_bytes",
  "mean_duration",
  "flow_rate",
  "packet_rate",
  "byte_rate",
  "udp_frac",
  "icmp_frac"
 ],
 "seed": 42,
 "n_estimators": 200,
 "threshold": 0.0918,
 "validation_windows": 200,
 "validation_flagged": 0,
 "validation_flag_rate": 0.0,
 "baseline_source": "baseline_training_flows.csv"
}
```

## Benign baseline profile (threshold calibration)

```
{
 "baseline_training_flows": {
  "max_distinct_ports_per_host_window": 2,
  "max_distinct_hosts_per_port_window": 1,
  "max_peak_flow_rate_single_source": 0.8,
  "flows": 2825
 },
 "baseline_validation_flows": {
  "max_distinct_ports_per_host_window": 2,
  "max_distinct_hosts_per_port_window": 1,
  "max_peak_flow_rate_single_source": 0.8,
  "flows": 1373
 },
 "benign_auth": {
  "max_failures_per_source_window": 1
 }
}
```
