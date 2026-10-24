import pandas as pd

from src.config import DetectionConfig
from src.detection.rules import detect_auth_failures, detect_dos, detect_port_scans
from src.ingestion import load_auth, load_flows

CFG = DetectionConfig()


def mk(rows):
    df = pd.DataFrame(rows, columns=["t", "src", "dst", "port", "proto", "pk"])
    return load_flows(pd.DataFrame({"timestamp": pd.to_datetime(df["t"] + 1767225600, unit="s", utc=True).astype(str), "src_ip": df["src"],
                                    "dst_ip": df["dst"], "dst_port": df["port"], "protocol": df["proto"], "packets": df["pk"],
                                    "bytes": df["pk"] * 60, "duration": 0.01})).data


def test_vertical_scan_detected_with_evidence():
    f = mk([(i * 0.1, "9.9.9.9", "10.0.1.1", 1000 + i, "TCP", 1) for i in range(30)])
    a = detect_port_scans(f, CFG)
    assert len(a) == 1 and a[0].rule_id == "SCAN-V1" and a[0].observed["distinct_dst_ports"] == 30 and len(a[0].evidence_ids) == 30


def test_scan_just_below_threshold_not_flagged():
    f = mk([(i * 0.1, "9.9.9.9", "10.0.1.1", 1000 + i, "TCP", 1) for i in range(CFG.scan_min_ports - 1)])
    assert detect_port_scans(f, CFG) == []


def test_many_ports_with_bulk_flows_not_flagged():
    f = mk([(i, "10.0.0.5", "10.0.1.1", 1000 + i, "TCP", 50) for i in range(40)])
    assert detect_port_scans(f, CFG) == []


def test_horizontal_sweep_and_icmp():
    f = mk([(i * 0.2, "9.9.9.9", f"10.0.2.{i + 1}", 22, "TCP", 1) for i in range(30)])
    assert [a.rule_id for a in detect_port_scans(f, CFG)] == ["SCAN-H1"]
    f = mk([(i * 0.2, "9.9.9.9", f"10.0.2.{i + 1}", 0, "ICMP", 1) for i in range(30)])
    assert detect_port_scans(f, CFG)[0].observed["target"] == "ICMP echo"


def test_single_source_flood():
    f = mk([(i / 50, "9.9.9.9", "10.0.1.1", 80, "TCP", 2) for i in range(500)])
    a = detect_dos(f, CFG)
    assert [x.rule_id for x in a] == ["DOS-S1"] and a[0].observed["peak_flow_rate_per_s"] >= CFG.dos_min_flow_rate


def test_high_packet_count_alone_is_not_dos():
    # Few flows with enormous packet counts (bulk transfer) must not be called a flood.
    f = mk([(i, "10.0.0.5", "10.0.1.1", 443, "TCP", 100000) for i in range(30)])
    assert detect_dos(f, CFG) == []


def test_many_connections_but_slow_rate_not_flood():
    f = mk([(i * 0.5, "10.0.0.5", "10.0.1.1", 443, "TCP", 2) for i in range(250)])
    assert detect_dos(f, CFG) == []


def test_distributed_flood():
    rows = [(i / 60, f"203.0.113.{i % 20 + 1}", "10.0.1.1", 443, "TCP", 2) for i in range(600)]
    assert [x.rule_id for x in detect_dos(mk(rows), CFG)] == ["DOS-D1"]


def test_flash_crowd_with_large_flows_not_flagged():
    rows = [(i / 40, f"192.0.2.{i % 50 + 1}", "10.0.1.1", 443, "TCP", 20) for i in range(600)]
    assert detect_dos(mk(rows), CFG) == []


def _auth(rows):
    return load_auth(pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "service", "username", "outcome"])).data


def _a(n, user="root", out="failure", start=0, src="1.2.3.4"):
    return [(f"2026-01-01T00:00:{start + i:02d}Z", src, "10.0.1.12", "ssh", user if isinstance(user, str) else user[i], out) for i in range(n)]


def test_auth_bruteforce_and_threshold_edge():
    assert detect_auth_failures(_auth(_a(CFG.auth_min_failures - 1)), CFG) == []
    a = detect_auth_failures(_auth(_a(CFG.auth_min_failures)), CFG)
    assert len(a) == 1 and a[0].observed["failures"] == CFG.auth_min_failures and a[0].evidence_kind == "auth"


def test_auth_spray_and_success_escalates_severity():
    users = [f"u{i}" for i in range(10)]
    a = detect_auth_failures(_auth(_a(10, users) + _a(1, "u3", "success", start=15)), CFG)
    assert len(a) == 1 and a[0].severity == "medium" and a[0].observed["success_after_failures"] and "spraying" in a[0].explanation


def test_benign_typos_not_flagged():
    assert detect_auth_failures(_auth(_a(4) + _a(1, out="success", start=10)), CFG) == []


def test_flow_data_alone_cannot_trigger_auth_rule():
    from src.detection import run_detection
    f = mk([(i, "9.9.9.9", "10.0.1.12", 22, "TCP", 8) for i in range(50)])
    r = run_detection(f, None, DetectionConfig(anomaly_enabled=False))
    assert "auth_failures" not in set(r.alerts["category"]) and any("authentication" in n for n in r.notes)
