"""Deterministic synthetic scenario generator.

All data is SYNTHETIC. Ground-truth columns (label, attack_type) are written to the
sample CSVs for evaluation only; the loader strips them before detection.
Reserved documentation addresses (RFC 5737) are used for external actors.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

T0 = 1767225600.0  # 2026-01-01T00:00:00Z
CLIENTS = [f"10.0.0.{i}" for i in range(11, 31)]
VICTIM = "10.0.1.10"
SERVICES = [  # (dst_ip, port, proto, weight)
    ("10.0.1.10", 443, "TCP", 0.40), ("10.0.1.10", 80, "TCP", 0.10), ("10.0.1.11", 53, "UDP", 0.25),
    ("10.0.1.12", 22, "TCP", 0.04), ("10.0.1.13", 5432, "TCP", 0.08), ("10.0.1.14", 993, "TCP", 0.07),
    ("10.0.1.14", 25, "TCP", 0.03), ("10.0.1.15", 123, "UDP", 0.03),
]
BASELINE_SEEDS = {"training": 101, "validation": 102}


@dataclass
class Scenario:
    key: str
    number: int
    title: str
    description: str
    expectation: str
    seed: int
    duration: int
    flows: pd.DataFrame
    auth: pd.DataFrame


SCENARIOS = {
    "benign": dict(number=1, seed=11, duration=600, title="Normal traffic baseline",
                   description="Twenty internal clients using web, DNS, mail, database and SSH services, plus routine logins.",
                   expectation="No alerts from rules. The anomaly layer may flag a small number of benign windows; any that appear are false positives."),
    "port_scan": dict(number=2, seed=12, duration=600, title="Reconnaissance and port scanning",
                      description="Benign background plus a vertical scan (300 ports on one host) and a horizontal sweep (60 hosts on port 22).",
                      expectation="Both scans are detected by rules (SCAN-V1, SCAN-H1) with high severity."),
    "dos": dict(number=3, seed=13, duration=600, title="Denial of service",
                description="Benign background plus a single-source connection flood and a distributed flood against the web server. Benign flows to the victim slow down while the floods run.",
                expectation="Both floods detected (DOS-S1, DOS-D1). Victim flow duration rises during the attack."),
    "auth_failures": dict(number=4, seed=14, duration=600, title="Repeated authentication failures",
                          description="Benign flows and logins plus an SSH brute-force that ends in a successful login, and a password-spraying run. Flows contain no attack records by design: login failures are only visible in authentication events.",
                          expectation="AUTH-F1 fires for both sources; the brute-force alert is critical (success after failures)."),
    "ambiguous": dict(number=5, seed=15, duration=1200, title="Ambiguous and borderline cases",
                      description="An authorised internal vulnerability scanner (benign), a benign flash crowd, a full-handshake connect scan, a slow low-rate scan, a misconfigured service account (benign) and a slow brute-force.",
                      expectation="Designed to expose limits. Rules: the authorised scanner and misconfigured service account are false positives; the connect scan, slow scan and slow brute-force are missed; the flash crowd is correctly not flagged as DoS. The anomaly layer behaves differently and adds its own false positives."),
}
SCENARIO_ORDER = list(SCENARIOS)


def _iso(t: np.ndarray | float) -> pd.Series:
    return pd.to_datetime(np.round(np.asarray(t, dtype=float), 3), unit="s", utc=True).strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z"


def _flows(rng, times, src, dst, dport, proto, pkts, byts, dur, label="benign", sport=None) -> pd.DataFrame:
    n = len(times)
    return pd.DataFrame({
        "timestamp": _iso(np.asarray(times)), "src_ip": src, "src_port": sport if sport is not None else rng.integers(32768, 61000, n),
        "dst_ip": dst, "dst_port": dport, "protocol": proto, "packets": np.asarray(pkts, dtype=int),
        "bytes": np.asarray(byts, dtype=int), "duration": np.round(np.asarray(dur, dtype=float), 4), "attack_type": label,
    })


def _benign_flows(rng, duration: int, rate: float = 0.12) -> pd.DataFrame:
    probs = np.array([s[3] for s in SERVICES]) / sum(s[3] for s in SERVICES)
    parts = []
    for c in CLIENTS:
        n = rng.poisson(rate * duration)
        t = T0 + np.sort(rng.uniform(0, duration, n))
        k = rng.choice(len(SERVICES), n, p=probs)
        dst = [SERVICES[i][0] for i in k]
        port = [SERVICES[i][1] for i in k]
        proto = [SERVICES[i][2] for i in k]
        udp = np.array([p == "UDP" for p in proto])
        pk = np.where(udp, rng.integers(1, 4, n), 6 + rng.lognormal(2.2, 0.8, n).astype(int))
        by = (pk * rng.lognormal(6.0, 0.5, n)).astype(int) + 40
        du = np.where(udp, rng.lognormal(-3, 0.5, n), rng.lognormal(-0.3, 1.0, n))
        parts.append(_flows(rng, t, c, dst, port, proto, pk, by, du))
    return pd.concat(parts, ignore_index=True)


def _auth(rng, times, src, dst, svc, users, outcome, label="benign") -> pd.DataFrame:
    return pd.DataFrame({"timestamp": _iso(np.asarray(times)), "src_ip": src, "dst_ip": dst, "service": svc,
                         "username": users, "outcome": outcome, "attack_type": label})


def _benign_auth(rng, duration: int) -> pd.DataFrame:
    n = 60 * duration // 600
    t = T0 + np.sort(rng.uniform(0, duration, n))
    src = rng.choice(CLIENTS, n)
    svc = rng.choice(["ssh", "web"], n, p=[0.4, 0.6])
    dst = np.where(svc == "ssh", "10.0.1.12", "10.0.1.10")
    users = [f"user{(CLIENTS.index(s) % 12) + 1:02d}" for s in src]
    out = np.where(rng.random(n) < 0.04, "failure", "success")
    return _auth(rng, t, src, dst, svc, users, out)


def _scan_flows(rng, t, src, dst, ports, proto="TCP", label="port_scan", pkts=(1, 2), full=False) -> pd.DataFrame:
    n = len(t)
    pk = rng.integers(6, 9, n) if full else rng.integers(pkts[0], pkts[1] + 1, n)
    dur = rng.uniform(0.2, 0.6, n) if full else rng.uniform(0.0005, 0.3, n)
    return _flows(rng, t, src, dst, ports, proto, pk, pk * 60, dur, label)


def _build(key: str, seed: int, duration: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    rng = np.random.default_rng(seed)
    flows, auth = [_benign_flows(rng, duration)], [_benign_auth(rng, duration)]
    if key == "port_scan":
        ports = rng.permutation(np.arange(1, 1025))[:300]
        t = T0 + 100 + np.arange(300) / 15.0
        flows.append(_scan_flows(rng, t, "198.51.100.23", "10.0.1.12", ports))
        hosts = [f"10.0.2.{i}" for i in range(1, 61)]
        flows.append(_scan_flows(rng, T0 + 300 + np.arange(60) / 5.0, "198.51.100.24", hosts, 22))
    elif key == "dos":
        n = 1200
        t = T0 + 200 + np.sort(rng.uniform(0, 20, n))
        flows.append(_flows(rng, t, "198.51.100.7", VICTIM, 80, "TCP", rng.integers(1, 3, n), rng.integers(40, 120, n),
                            rng.uniform(0.0, 0.05, n), "dos"))
        srcs = [f"203.0.113.{i}" for i in range(1, 26)]
        t = T0 + 380 + np.sort(rng.uniform(0, 12, 1000))
        s = rng.choice(srcs, 1000)
        flows.append(_flows(rng, t, s, VICTIM, 443, "TCP", rng.integers(1, 4, 1000), rng.integers(40, 200, 1000),
                            rng.uniform(0.0, 0.1, 1000), "dos"))
        b = flows[0]
        ts = pd.to_datetime(b["timestamp"], utc=True).map(lambda t: t.timestamp())
        hit = (b["dst_ip"] == VICTIM) & (((ts >= T0 + 200) & (ts <= T0 + 235)) | ((ts >= T0 + 380) & (ts <= T0 + 400)))
        b.loc[hit, "duration"] = (b.loc[hit, "duration"] * 6).round(4)  # degraded victim service
        b.loc[hit, "bytes"] = (b.loc[hit, "bytes"] * 0.5).astype(int)
    elif key == "auth_failures":
        n = 90
        t = T0 + 150 + np.arange(n) * 1.0
        users = np.where(np.arange(n) % 2 == 0, "root", "admin")
        auth.append(_auth(rng, t, "203.0.113.99", "10.0.1.12", "ssh", users, "failure", "auth_failures"))
        auth.append(_auth(rng, [T0 + 241], "203.0.113.99", "10.0.1.12", "ssh", ["admin"], "success", "auth_failures"))
        names = [f"user{i:02d}" for i in range(1, 29)]
        auth.append(_auth(rng, T0 + 350 + np.arange(28) * 1.7, "203.0.113.77", "10.0.1.10", "web", names, "failure", "auth_failures"))
    elif key == "ambiguous":
        ports = np.arange(1, 151)
        flows.append(_scan_flows(rng, T0 + 300 + np.arange(150) / 10.0, "10.0.0.5", "10.0.1.14", ports, label="benign"))  # authorised scanner
        n = 600
        t = T0 + 700 + np.sort(rng.uniform(0, 30, n))
        srcs = rng.choice([f"192.0.2.{i}" for i in range(1, 61)], n)
        pk = rng.integers(8, 41, n)
        flows.append(_flows(rng, t, srcs, VICTIM, 443, "TCP", pk, pk * 700, rng.uniform(0.5, 3, n), "benign"))  # flash crowd
        ports = rng.permutation(np.arange(1, 1025))[:40]
        flows.append(_scan_flows(rng, T0 + 500 + np.arange(40) / 8.0, "198.51.100.201", "10.0.1.13", ports, full=True))  # connect scan
        ports = rng.permutation(np.arange(1, 1025))[:60]
        flows.append(_scan_flows(rng, T0 + 20 + np.arange(60) * 19.0 + rng.uniform(0, 3, 60), "198.51.100.200", "10.0.1.13", ports))  # slow scan
        t = T0 + 600 + np.arange(14) * 17.0
        auth.append(_auth(rng, t, "10.0.0.30", "10.0.1.13", "postgres", "svc_report", "failure"))  # stale service credential
        t = T0 + 900 + np.arange(5) * 9.0
        auth.append(_auth(rng, np.r_[t, T0 + 950], "10.0.0.21", "10.0.1.12", "ssh", "user10", ["failure"] * 5 + ["success"]))  # typos
        t = T0 + 30 + np.arange(12) * 100.0
        auth.append(_auth(rng, t, "203.0.113.150", "10.0.1.12", "ssh", ["root"] * 12, "failure", "auth_failures"))  # slow brute force
    f = pd.concat(flows, ignore_index=True)
    a = pd.concat(auth, ignore_index=True)
    for df in (f, a):
        df["label"] = np.where(df["attack_type"] == "benign", "benign", "malicious")
    f = f.sort_values("timestamp", kind="stable").reset_index(drop=True)
    a = a.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return f, a


def generate_scenario(key: str, seed: int | None = None) -> Scenario:
    if key not in SCENARIOS:
        raise KeyError(f"Unknown scenario '{key}'. Choose from {SCENARIO_ORDER}.")
    m = SCENARIOS[key]
    seed = m["seed"] if seed is None else seed
    f, a = _build(key, seed, m["duration"])
    return Scenario(key, m["number"], m["title"], m["description"], m["expectation"], seed, m["duration"], f, a)


def generate_baseline(kind: str = "training") -> pd.DataFrame:
    """Benign-only flows for model training/validation (disjoint seeds from every scenario)."""
    rng = np.random.default_rng(BASELINE_SEEDS[kind])
    f = _benign_flows(rng, 1200 if kind == "training" else 600)
    f["label"] = "benign"
    return f.sort_values("timestamp", kind="stable").reset_index(drop=True)


def write_samples(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for key in SCENARIO_ORDER:
        s = generate_scenario(key)
        for kind, df in (("flows", s.flows), ("auth", s.auth)):
            p = out_dir / f"scenario{s.number}_{key}_{kind}.csv"
            df.to_csv(p, index=False)
            paths.append(p)
    for kind in BASELINE_SEEDS:
        p = out_dir / f"baseline_{kind}_flows.csv"
        generate_baseline(kind).to_csv(p, index=False)
        paths.append(p)
    return paths
