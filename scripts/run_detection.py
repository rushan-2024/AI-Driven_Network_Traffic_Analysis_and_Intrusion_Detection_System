"""Command-line detection on any CSV.

Example:
  python scripts/run_detection.py --flows data/samples/scenario2_port_scan_flows.csv --out alerts.csv
"""
import _path  # noqa: F401
import argparse
import sys

from src.config import DetectionConfig
from src.ingestion import DataValidationError
from src.pipeline import analyze


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows", required=True)
    ap.add_argument("--auth")
    ap.add_argument("--out", help="write alerts CSV here")
    ap.add_argument("--no-anomaly", action="store_true")
    args = ap.parse_args()
    cfg = DetectionConfig(anomaly_enabled=not args.no_anomaly)
    try:
        an = analyze(args.flows, args.auth, cfg)
    except DataValidationError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    a = an.detection.alerts
    print(f"Flows: {an.flows.report.rows_kept} valid of {an.flows.report.rows_read} ({an.flows.report.status})")
    for n in an.detection.notes:
        print("Note:", n)
    print(f"Alerts: {len(a)}")
    for _, r in a.iterrows():
        print(f"[{r.severity.upper():8}] {r.alert_id} {r.category:13} {r.rule_id:8} {r.window_start}  {r.src_ip or '-'} -> {r.dst_ip or '-'}\n    {r.explanation}")
    if args.out:
        a.drop(columns=["evidence_ids"]).to_csv(args.out, index=False)
        print("Wrote", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
