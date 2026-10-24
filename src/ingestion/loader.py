"""CSV ingestion and validation for flow and authentication-event data.

Ground-truth columns (``label``, ``attack_type``) are split off here into a separate
frame so that downstream feature extraction and detectors never see them.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Union

import pandas as pd

Source = Union[str, Path, IO, pd.DataFrame]

FLOW_REQUIRED = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "packets", "bytes", "duration"]
AUTH_REQUIRED = ["timestamp", "src_ip", "dst_ip", "service", "username", "outcome"]
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}
LABEL_COLUMNS = ["label", "attack_type"]
SUCCESS = {"success", "succeeded", "ok", "accepted"}
FAILURE = {"failure", "failed", "fail", "denied", "invalid"}


class DataValidationError(ValueError):
    """Raised for input that cannot be analysed; the message is safe to show to users."""


@dataclass
class ValidationReport:
    kind: str
    rows_read: int = 0
    rows_kept: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    duplicates_removed: int = 0
    warnings: list[str] = field(default_factory=list)
    labels_present: bool = False
    time_start: float | None = None
    time_end: float | None = None

    @property
    def status(self) -> str:
        if self.warnings or self.duplicates_removed or any(self.dropped.values()):
            return "valid with warnings"
        return "valid"


@dataclass
class LoadResult:
    data: pd.DataFrame
    labels: pd.DataFrame | None  # columns: is_malicious (bool), attack_type (str); same index as data
    report: ValidationReport


def _read(source: Source, kind: str) -> pd.DataFrame:
    if isinstance(source, pd.DataFrame):
        df = source.copy()
    else:
        try:
            if hasattr(source, "seek"):
                source.seek(0)
            df = pd.read_csv(source)
        except pd.errors.EmptyDataError:
            raise DataValidationError(f"The {kind} file is empty.") from None
        except pd.errors.ParserError as exc:
            raise DataValidationError(f"The {kind} file is not valid CSV: {exc}") from None
        except UnicodeDecodeError:
            raise DataValidationError(f"The {kind} file is not UTF-8 text. Export it as a UTF-8 CSV.") from None
        except FileNotFoundError:
            raise DataValidationError(f"{kind.capitalize()} file not found: {source}") from None
    if df.empty:
        raise DataValidationError(f"The {kind} file has a header but no rows.")
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df


def _check_columns(df: pd.DataFrame, required: list[str], kind: str) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise DataValidationError(
            f"Missing required {kind} column(s): {', '.join(missing)}. "
            f"Required: {', '.join(required)}. Found: {', '.join(df.columns)}."
        )


def _valid_ips(series: pd.Series) -> pd.Series:
    cache: dict[str, bool] = {}

    def ok(v: object) -> bool:
        s = str(v).strip()
        if s not in cache:
            try:
                ipaddress.ip_address(s)
                cache[s] = True
            except ValueError:
                cache[s] = False
        return cache[s]

    return series.map(ok).astype(bool)


def _drop(df: pd.DataFrame, mask_bad: pd.Series, reason: str, report: ValidationReport) -> pd.DataFrame:
    n = int(mask_bad.sum())
    if n:
        report.dropped[reason] = report.dropped.get(reason, 0) + n
    return df.loc[~mask_bad]


def _extract_labels(df: pd.DataFrame, report: ValidationReport) -> pd.DataFrame | None:
    if not any(c in df.columns for c in LABEL_COLUMNS):
        return None
    report.labels_present = True
    if "attack_type" in df.columns:
        at = df["attack_type"].fillna("benign").astype(str).str.strip().str.lower()
    else:
        raw = df["label"].astype(str).str.strip().str.lower()
        at = raw.map(lambda v: "benign" if v in {"benign", "normal", "0", "false"} else "unspecified")
    return pd.DataFrame({"is_malicious": at != "benign", "attack_type": at}, index=df.index)


def _finish(df: pd.DataFrame, labels: pd.DataFrame | None, report: ValidationReport, cols: list[str]) -> LoadResult:
    if df.empty:
        raise DataValidationError("No valid rows remain after validation. Dropped rows: " + str(report.dropped))
    df = df.sort_values("ts", kind="stable")
    before = len(df)
    dup_mask = df.duplicated(subset=cols, keep="first")
    report.duplicates_removed = int(dup_mask.sum())
    df = df.loc[~dup_mask]
    assert len(df) == before - report.duplicates_removed
    if labels is not None:
        labels = labels.loc[df.index]
    # Positional ids: the index is the record id used as alert evidence.
    df = df.reset_index(drop=True)
    if labels is not None:
        labels = labels.reset_index(drop=True)
    report.rows_kept = len(df)
    report.time_start, report.time_end = float(df["ts"].min()), float(df["ts"].max())
    return LoadResult(df, labels, report)


def _parse_time(df: pd.DataFrame, report: ValidationReport) -> pd.DataFrame:
    parsed = pd.to_datetime(df["timestamp"], errors="coerce", utc=True, format="mixed")
    ts = parsed.map(lambda t: t.timestamp() if pd.notna(t) else float("nan")).astype(float)
    return _drop(df.assign(ts=ts), ts.isna(), "invalid timestamp", report)


def load_flows(source: Source) -> LoadResult:
    df = _read(source, "flow")
    _check_columns(df, FLOW_REQUIRED, "flow")
    report = ValidationReport("flows", rows_read=len(df))
    labels = _extract_labels(df, report)
    df = df.drop(columns=[c for c in LABEL_COLUMNS if c in df.columns])
    if labels is not None:
        pass  # labels share df.index until _finish re-indexes both
    df = _parse_time(df, report)
    n_ts_bad = report.dropped.get("invalid timestamp", 0)
    if n_ts_bad == report.rows_read:
        raise DataValidationError("No timestamp could be parsed. Use ISO 8601, e.g. 2026-01-01T00:00:00Z.")
    df["src_ip"] = df["src_ip"].astype(str).str.strip()
    df["dst_ip"] = df["dst_ip"].astype(str).str.strip()
    df = _drop(df, ~_valid_ips(df["src_ip"]) | ~_valid_ips(df["dst_ip"]), "invalid IP address", report)
    df["protocol"] = df["protocol"].astype(str).str.strip().str.upper()
    df = _drop(df, ~df["protocol"].isin(VALID_PROTOCOLS), "unsupported protocol (TCP, UDP, ICMP only)", report)
    for col in ["packets", "bytes", "duration", "dst_port"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    icmp = df["protocol"] == "ICMP"
    df.loc[icmp & df["dst_port"].isna(), "dst_port"] = 0
    df = _drop(df, df[["packets", "bytes", "duration", "dst_port"]].isna().any(axis=1), "missing or non-numeric value", report)
    bad_range = (df["packets"] < 1) | (df["bytes"] < 0) | (df["duration"] < 0) | (df["dst_port"] < 0) | (df["dst_port"] > 65535)
    df = _drop(df, bad_range, "out-of-range value", report)
    df["dst_port"] = df["dst_port"].astype(int)
    if "src_port" in df.columns:
        df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    else:
        df["src_port"] = float("nan")
        report.warnings.append("No src_port column; source-port features are unavailable.")
    keep = ["ts", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "packets", "bytes", "duration"]
    df = df[keep]
    if labels is not None:
        labels = labels.loc[df.index]
    if len(df) < 10:
        report.warnings.append(f"Only {len(df)} valid flows; statistics and anomaly scores are unreliable.")
    return _finish(df, labels, report, [c for c in keep if c != "timestamp"])


def load_auth(source: Source) -> LoadResult:
    df = _read(source, "authentication-event")
    _check_columns(df, AUTH_REQUIRED, "authentication-event")
    report = ValidationReport("auth", rows_read=len(df))
    labels = _extract_labels(df, report)
    df = df.drop(columns=[c for c in LABEL_COLUMNS if c in df.columns])
    df = _parse_time(df, report)
    if report.dropped.get("invalid timestamp", 0) == report.rows_read:
        raise DataValidationError("No timestamp could be parsed in the authentication events.")
    for c in ["src_ip", "dst_ip", "service", "username"]:
        df[c] = df[c].astype(str).str.strip()
    df = _drop(df, ~_valid_ips(df["src_ip"]) | ~_valid_ips(df["dst_ip"]), "invalid IP address", report)
    out = df["outcome"].astype(str).str.strip().str.lower()
    df["outcome"] = out.map(lambda v: "success" if v in SUCCESS else ("failure" if v in FAILURE else None))
    df = _drop(df, df["outcome"].isna(), "unknown outcome (use success/failure)", report)
    keep = ["ts", "timestamp", "src_ip", "dst_ip", "service", "username", "outcome"]
    df = df[keep]
    if labels is not None:
        labels = labels.loc[df.index]
    return _finish(df, labels, report, [c for c in keep if c != "timestamp"])
