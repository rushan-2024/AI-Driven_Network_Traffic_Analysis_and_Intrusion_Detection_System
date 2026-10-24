"""Rule-based detectors. Each returns Alerts with observed values, threshold and evidence ids.

Rules combine volume, rate, flow shape and (for floods) source concentration. No rule
fires on packet count alone.
"""
from __future__ import annotations

import pandas as pd

from ..config import DetectionConfig
from ..features.extract import add_window, assert_no_labels
from .alerts import Alert, severity_from_ratio


def _r(x: float, n: int = 1) -> float:
    return round(float(x), n)


def _peak_rate(df: pd.DataFrame, keys: list[str], bin_s: int) -> pd.Series:
    """Highest flows/s seen in any short bin, per group; robust to background traffic in the window."""
    b = df.assign(_bin=(df["ts"] // bin_s))
    return b.groupby([*keys, "_bin"]).size().groupby(level=list(range(len(keys)))).max() / bin_s


def detect_port_scans(flows: pd.DataFrame, cfg: DetectionConfig) -> list[Alert]:
    assert_no_labels(flows)
    alerts: list[Alert] = []
    if flows.empty:
        return alerts
    w = cfg.window_seconds
    df = add_window(flows, w)

    # Vertical scan: many distinct ports on one host from one source.
    tu = df[df["protocol"].isin(["TCP", "UDP"])]
    if not tu.empty:
        g = tu.groupby(["src_ip", "dst_ip", "win"])
        agg = g.agg(ports=("dst_port", "nunique"), flows=("ts", "size"), mean_pk=("packets", "mean"),
                    t0=("ts", "min"), t1=("ts", "max"))
        hits = agg[(agg["ports"] >= cfg.scan_min_ports) & (agg["mean_pk"] <= cfg.scan_max_mean_packets)]
        for (src, dst, win), r in hits.iterrows():
            alerts.append(Alert(
                "port_scan", "SCAN-V1", "rule", win, win + w, src, dst,
                severity_from_ratio(r["ports"] / cfg.scan_min_ports),
                {"distinct_dst_ports": int(r["ports"]), "flows": int(r["flows"]),
                 "mean_packets_per_flow": _r(r["mean_pk"]), "active_span_s": _r(r["t1"] - r["t0"])},
                f"distinct_dst_ports >= {cfg.scan_min_ports} AND mean_packets_per_flow <= {cfg.scan_max_mean_packets}",
                f"{src} contacted {int(r['ports'])} distinct ports on {dst} within one {w}s window "
                f"(threshold {cfg.scan_min_ports}). Flows averaged {r['mean_pk']:.1f} packets, which fits short "
                f"probes rather than application sessions. This is consistent with a vertical port scan.",
                ["Confirm whether {0} is an authorised scanner or asset-inventory host.".format(src),
                 f"List which ports on {dst} answered (open) versus reset or timed out.",
                 "Check firewall and host logs on the target for follow-on connections to open ports.",
                 "If unauthorised, rate-limit or block the source and review exposed services."],
                [int(i) for i in g.groups[(src, dst, win)]]))

    # Horizontal sweep: one port (or ICMP) across many hosts.
    g = df.groupby(["src_ip", "protocol", "dst_port", "win"])
    agg = g.agg(hosts=("dst_ip", "nunique"), flows=("ts", "size"), mean_pk=("packets", "mean"),
                t0=("ts", "min"), t1=("ts", "max"))
    hits = agg[(agg["hosts"] >= cfg.scan_min_hosts) & (agg["mean_pk"] <= cfg.scan_max_mean_packets)]
    for (src, proto, port, win), r in hits.iterrows():
        what = "ICMP echo" if proto == "ICMP" else f"{proto}/{port}"
        alerts.append(Alert(
            "port_scan", "SCAN-H1", "rule", win, win + w, src, None,
            severity_from_ratio(r["hosts"] / cfg.scan_min_hosts),
            {"distinct_dst_hosts": int(r["hosts"]), "target": what, "flows": int(r["flows"]),
             "mean_packets_per_flow": _r(r["mean_pk"]), "active_span_s": _r(r["t1"] - r["t0"])},
            f"distinct_dst_hosts >= {cfg.scan_min_hosts} AND mean_packets_per_flow <= {cfg.scan_max_mean_packets}",
            f"{src} sent {what} probes to {int(r['hosts'])} distinct hosts in one {w}s window "
            f"(threshold {cfg.scan_min_hosts}) with short flows (mean {r['mean_pk']:.1f} packets). "
            f"This is consistent with a horizontal sweep looking for hosts running that service.",
            [f"Confirm whether {src} is an authorised network scanner.",
             "Identify which hosts replied; those are now known to the sender.",
             "Review logs on responding hosts for subsequent access attempts."],
            [int(i) for i in g.groups[(src, proto, port, win)]]))
    return alerts


def detect_dos(flows: pd.DataFrame, cfg: DetectionConfig) -> list[Alert]:
    assert_no_labels(flows)
    alerts: list[Alert] = []
    if flows.empty:
        return alerts
    w = cfg.window_seconds
    df = add_window(flows, w)

    # Single-source flood: high connection count AND rate AND short flows, one source -> one target.
    g = df.groupby(["src_ip", "dst_ip", "win"])
    agg = g.agg(flows=("ts", "size"), packets=("packets", "sum"), mean_pk=("packets", "mean"),
                t0=("ts", "min"), t1=("ts", "max"))
    span = (agg["t1"] - agg["t0"]).clip(lower=1.0)
    agg["rate"] = _peak_rate(df, ["src_ip", "dst_ip", "win"], cfg.rate_bin_seconds)
    agg["pps"] = agg["packets"] / span
    hits = agg[(agg["flows"] >= cfg.dos_min_flows) & (agg["rate"] >= cfg.dos_min_flow_rate)
               & (agg["mean_pk"] <= cfg.dos_max_mean_packets)]
    for (src, dst, win), r in hits.iterrows():
        alerts.append(Alert(
            "dos", "DOS-S1", "rule", float(r["t0"]), float(r["t1"]) + 1, src, dst,
            severity_from_ratio(r["rate"] / cfg.dos_min_flow_rate),
            {"flows": int(r["flows"]), "peak_flow_rate_per_s": _r(r["rate"]), "packet_rate_per_s": _r(r["pps"]),
             "mean_packets_per_flow": _r(r["mean_pk"]), "active_span_s": _r(r["t1"] - r["t0"])},
            f"flows >= {cfg.dos_min_flows} AND peak_flow_rate >= {cfg.dos_min_flow_rate}/s AND mean_packets_per_flow <= {cfg.dos_max_mean_packets}",
            f"{src} opened {int(r['flows'])} flows to {dst} at a peak of {r['rate']:.0f} flows/s (threshold {cfg.dos_min_flow_rate}/s). "
            f"Flows were short (mean {r['mean_pk']:.1f} packets), unlike normal sessions. "
            f"This is consistent with a single-source connection flood; it does not prove intent, "
            f"and a misbehaving client or load test could look similar.",
            [f"Check the load and error rate on {dst} during {w}s window.",
             "Confirm no load test or batch job was scheduled from the source.",
             "Apply rate limiting or temporary blocking at the edge if the target is degraded.",
             "Preserve flow records and server logs for the incident timeline."],
            [int(i) for i in g.groups[(src, dst, win)]]))

    # Distributed flood: many sources, none dominant, short flows at one target.
    g = df.groupby(["dst_ip", "win"])
    agg = g.agg(flows=("ts", "size"), srcs=("src_ip", "nunique"), mean_pk=("packets", "mean"),
                t0=("ts", "min"), t1=("ts", "max"))
    agg["top_share"] = g["src_ip"].agg(lambda s: s.value_counts().iloc[0] / len(s))
    agg["rate"] = _peak_rate(df, ["dst_ip", "win"], cfg.rate_bin_seconds)
    hits = agg[(agg["flows"] >= cfg.ddos_min_flows) & (agg["srcs"] >= cfg.ddos_min_sources)
               & (agg["top_share"] <= cfg.ddos_max_top_source_share)
               & (agg["rate"] >= cfg.dos_min_flow_rate) & (agg["mean_pk"] <= cfg.dos_max_mean_packets)]
    for (dst, win), r in hits.iterrows():
        idx = g.groups[(dst, win)]
        short = [int(i) for i in idx if flows.at[i, "packets"] <= cfg.dos_max_mean_packets]
        alerts.append(Alert(
            "dos", "DOS-D1", "rule", float(r["t0"]), float(r["t1"]) + 1, None, dst,
            severity_from_ratio(r["rate"] / cfg.dos_min_flow_rate),
            {"flows": int(r["flows"]), "distinct_sources": int(r["srcs"]), "peak_flow_rate_per_s": _r(r["rate"]),
             "top_source_share": _r(r["top_share"], 2), "mean_packets_per_flow": _r(r["mean_pk"])},
            f"flows >= {cfg.ddos_min_flows} AND sources >= {cfg.ddos_min_sources} AND top_source_share <= {cfg.ddos_max_top_source_share} "
            f"AND peak_flow_rate >= {cfg.dos_min_flow_rate}/s AND mean_packets_per_flow <= {cfg.dos_max_mean_packets}",
            f"{dst} received {int(r['flows'])} flows from {int(r['srcs'])} sources at a peak of {r['rate']:.0f} flows/s; no source "
            f"exceeded {r['top_share']:.0%} of the flows and flows were short (mean {r['mean_pk']:.1f} packets). "
            f"This is consistent with a distributed flood. A flash crowd of real users would normally "
            f"produce longer, completed flows and is excluded by the flow-size condition.",
            [f"Check service health and connection-table usage on {dst}.",
             "Look for common traits across sources (ASN, geography, user agent) to separate a botnet from a flash crowd.",
             "Engage upstream provider or DDoS mitigation if capacity is affected."],
            short or [int(i) for i in idx]))
    return alerts


def detect_auth_failures(auth: pd.DataFrame, cfg: DetectionConfig) -> list[Alert]:
    """Repeated authentication failures from authentication-event data only."""
    assert_no_labels(auth)
    alerts: list[Alert] = []
    if auth is None or auth.empty:
        return alerts
    w = cfg.auth_window_seconds
    df = add_window(auth, w)
    fails = df[df["outcome"] == "failure"]
    if fails.empty:
        return alerts
    g = fails.groupby(["src_ip", "dst_ip", "service", "win"])
    agg = g.agg(failures=("ts", "size"), users=("username", "nunique"), t0=("ts", "min"), t1=("ts", "max"))
    hits = agg[agg["failures"] >= cfg.auth_min_failures]
    successes = df[df["outcome"] == "success"]
    for (src, dst, svc, win), r in hits.iterrows():
        ids = [int(i) for i in g.groups[(src, dst, svc, win)]]
        s = successes[(successes["src_ip"] == src) & (successes["dst_ip"] == dst) & (successes["service"] == svc)
                      & (successes["ts"] >= r["t0"]) & (successes["ts"] <= r["t1"] + cfg.auth_success_grace_seconds)]
        compromised = not s.empty
        ids += [int(i) for i in s.index]
        spray = r["users"] >= cfg.auth_spray_min_users
        pattern = (f"failures spread across {int(r['users'])} usernames (password-spraying pattern)" if spray
                   else f"failures concentrated on {int(r['users'])} username(s) (brute-force pattern)")
        extra = (f" A successful {svc} login from the same source followed within {cfg.auth_success_grace_seconds}s, "
                 f"so a credential may have been guessed.") if compromised else ""
        alerts.append(Alert(
            "auth_failures", "AUTH-F1", "rule", float(r["t0"]), float(r["t1"]) + 1, src, dst,
            severity_from_ratio(r["failures"] / cfg.auth_min_failures, corroborated=compromised),
            {"failures": int(r["failures"]), "distinct_usernames": int(r["users"]), "service": svc,
             "success_after_failures": compromised, "active_span_s": _r(r["t1"] - r["t0"])},
            f"failures >= {cfg.auth_min_failures} per source/target/service in {w}s",
            f"{src} produced {int(r['failures'])} failed {svc} logins against {dst} within {w}s "
            f"(threshold {cfg.auth_min_failures}); {pattern}.{extra}",
            (["Treat the account as potentially compromised: reset credentials and revoke active sessions.",
              "Review activity of the successful session after the login."] if compromised else [])
            + ["Check whether the account owner or a service with stale credentials explains the failures.",
               "Block or rate-limit the source and enable account lockout or MFA on the service.",
               "Search for the same source against other services and hosts."],
            ids, "auth"))
    return alerts
