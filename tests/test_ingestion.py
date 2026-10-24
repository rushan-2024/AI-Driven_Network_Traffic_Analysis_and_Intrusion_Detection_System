import pandas as pd
import pytest

from src.ingestion import DataValidationError, load_auth, load_flows
from tests.conftest import csv

HEADER = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,duration"


def test_valid_flows_load_and_split_labels():
    r = load_flows(csv(HEADER + ",label,attack_type\n2026-01-01T00:00:00Z,10.0.0.1,10.0.1.1,40000,443,tcp,10,5000,0.5,benign,benign\n"
                       "2026-01-01T00:00:01Z,10.0.0.2,10.0.1.1,40001,80,TCP,2,100,0.1,malicious,dos"))
    assert len(r.data) == 2 and set(r.data["protocol"]) == {"TCP"}
    assert "label" not in r.data.columns and "attack_type" not in r.data.columns
    assert r.labels is not None and r.labels["is_malicious"].tolist() == [False, True]


def test_missing_column_message():
    with pytest.raises(DataValidationError, match="Missing required flow column.*duration"):
        load_flows(csv("timestamp,src_ip,dst_ip,dst_port,protocol,packets,bytes\n2026-01-01T00:00:00Z,10.0.0.1,10.0.1.1,80,TCP,1,1"))


def test_empty_and_header_only():
    with pytest.raises(DataValidationError):
        load_flows(csv(""))
    with pytest.raises(DataValidationError, match="no rows"):
        load_flows(csv(HEADER))


def test_malformed_file_and_missing_path():
    with pytest.raises(DataValidationError):
        load_flows(csv('a,b\n"unterminated,1\n1,2,3,4'))
    with pytest.raises(DataValidationError, match="not found"):
        load_flows("/definitely/not/here.csv")


def test_invalid_rows_dropped_and_reported():
    r = load_flows(csv(HEADER + "\nnot-a-time,10.0.0.1,10.0.1.1,1,80,TCP,1,1,0.1\n"
                       "2026-01-01T00:00:00Z,999.1.1.1,10.0.1.1,1,80,TCP,1,1,0.1\n"
                       "2026-01-01T00:00:01Z,10.0.0.1,10.0.1.1,1,80,SCTP,1,1,0.1\n"
                       "2026-01-01T00:00:02Z,10.0.0.1,10.0.1.1,1,80,TCP,abc,1,0.1\n"
                       "2026-01-01T00:00:03Z,10.0.0.1,10.0.1.1,1,80,TCP,-5,1,0.1\n"
                       "2026-01-01T00:00:04Z,10.0.0.1,10.0.1.1,1,80,TCP,3,1,0.1"))
    assert len(r.data) == 1 and sum(r.report.dropped.values()) == 5 and r.report.status == "valid with warnings"


def test_all_rows_invalid_is_error():
    with pytest.raises(DataValidationError):
        load_flows(csv(HEADER + "\nbad,10.0.0.1,10.0.1.1,1,80,TCP,1,1,0.1"))


def test_duplicates_removed_and_reported():
    row = "2026-01-01T00:00:00Z,10.0.0.1,10.0.1.1,1,80,TCP,1,1,0.1"
    r = load_flows(csv(HEADER + "\n" + row + "\n" + row))
    assert len(r.data) == 1 and r.report.duplicates_removed == 1


def test_missing_values_icmp_port_filled():
    r = load_flows(csv(HEADER + "\n2026-01-01T00:00:00Z,10.0.0.1,10.0.1.1,,,icmp,1,64,0.01"))
    assert r.data.loc[0, "dst_port"] == 0


def test_auth_loader():
    r = load_auth(csv("timestamp,src_ip,dst_ip,service,username,outcome\n2026-01-01T00:00:00Z,1.2.3.4,10.0.1.1,ssh,root,FAILED\n"
                      "2026-01-01T00:00:01Z,1.2.3.4,10.0.1.1,ssh,root,weird"))
    assert r.data["outcome"].tolist() == ["failure"] and r.report.dropped
    with pytest.raises(DataValidationError, match="Missing required"):
        load_auth(csv("timestamp,src_ip\n2026-01-01T00:00:00Z,1.1.1.1"))


def test_dataframe_input_not_mutated():
    df = pd.DataFrame({"timestamp": ["2026-01-01T00:00:00Z"], "src_ip": ["10.0.0.1"], "dst_ip": ["10.0.1.1"], "dst_port": [80],
                       "protocol": ["tcp"], "packets": [1], "bytes": [1], "duration": [0.1]})
    load_flows(df)
    assert df["protocol"].iloc[0] == "tcp"
