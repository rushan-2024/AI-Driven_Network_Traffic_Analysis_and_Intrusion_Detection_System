import pytest

from src.features import ANOMALY_FEATURES, add_window, assert_no_labels, protocol_distribution, window_features
from src.ingestion import load_flows
from tests.conftest import csv


def _flows():
    rows = ["timestamp,src_ip,dst_ip,dst_port,protocol,packets,bytes,duration"]
    for i in range(6):
        rows.append(f"2026-01-01T00:00:{i:02d}Z,10.0.0.1,10.0.1.{i % 2 + 1},{80 + i},{'UDP' if i == 0 else 'TCP'},{i + 1},{100 * (i + 1)},0.5")
    return load_flows(csv("\n".join(rows))).data


def test_window_features_values():
    f = window_features(_flows(), 60)
    assert len(f) == 1 and list(f.columns)[2:] == ANOMALY_FEATURES
    r = f.iloc[0]
    assert r["flows"] == 6 and r["unique_dst_ports"] == 6 and r["unique_dst_hosts"] == 2
    assert r["packets"] == 21 and r["bytes"] == 2100 and abs(r["udp_frac"] - 1 / 6) < 1e-9
    assert r["flow_rate"] == pytest.approx(6 / 10.0)  # span floor is 10 s


def test_protocol_distribution():
    d = protocol_distribution(_flows()).set_index("protocol")
    assert d.loc["TCP", "flows"] == 5 and d.loc["UDP", "flows"] == 1


def test_window_length_validation():
    with pytest.raises(ValueError):
        add_window(_flows(), 0)


def test_features_reject_label_columns():
    df = _flows().assign(attack_type="dos")
    with pytest.raises(ValueError, match="Ground-truth"):
        window_features(df)
    with pytest.raises(ValueError):
        assert_no_labels(df)


def test_empty_flows():
    assert window_features(_flows().iloc[0:0]).empty
