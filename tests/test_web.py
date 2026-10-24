"""Tests for the local web server and JSON API (real HTTP on an ephemeral port)."""
import http.client
import json
import threading

import pytest

from src.web.server import make_server


@pytest.fixture(scope="module")
def srv():
    s = make_server("127.0.0.1", 0)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield s
    s.shutdown()
    s.server_close()


def req(srv, method, path, body=None, headers=None):
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    h = {"Host": f"127.0.0.1:{port}"}
    h.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body)
        h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    c.close()
    return r.status, dict(r.getheaders()), raw


def jpost(srv, path, body):
    st, _, raw = req(srv, "POST", path, body)
    return st, json.loads(raw)


def test_index_and_assets_served(srv):
    st, hdr, raw = req(srv, "GET", "/")
    assert st == 200 and b"AI-Driven Network Traffic Analysis and Intrusion Detection System" in raw
    assert "script-src 'self'" in hdr["Content-Security-Policy"]
    for p in ["/app.js", "/charts.js", "/graph3d.js", "/style.css", "/vendor/three.min.js"]:
        assert req(srv, "GET", p)[0] == 200


def test_path_traversal_blocked(srv):
    for p in ["/../src/config.py", "/..%2fsrc/config.py", "/%2e%2e/app.py", "/web/../app.py"]:
        assert req(srv, "GET", p)[0] in (404, 403)


def test_foreign_host_and_origin_rejected(srv):
    assert req(srv, "GET", "/api/config", headers={"Host": "evil.example"})[0] == 403
    assert req(srv, "POST", "/api/analyze", {"source": "scenario", "scenario": "benign"}, {"Origin": "http://evil.example"})[0] == 403


def test_post_requires_json_content_type(srv):
    assert req(srv, "POST", "/api/analyze", None, {"Content-Type": "text/plain", "Content-Length": "2"})[0] in (415, 400)


def test_config_endpoint(srv):
    st, _, raw = req(srv, "GET", "/api/config")
    cfg = json.loads(raw)
    assert st == 200 and len(cfg["scenarios"]) == 5 and cfg["groups"]


@pytest.mark.parametrize("key,rule", [("port_scan", "SCAN-V1"), ("dos", "DOS-S1"), ("auth_failures", "AUTH-F1")])
def test_scenarios_via_api(srv, key, rule):
    st, p = jpost(srv, "/api/analyze", {"source": "scenario", "scenario": key})
    assert st == 200 and rule in {a["rule_id"] for a in p["alerts"]}
    assert p["graph"]["nodes"] and p["timeline"] and p["evaluation"]["hybrid"]["flows"]["overall"]["n"] > 0
    a = p["alerts"][0]
    for f in ["severity", "explanation", "recommendations", "observed", "threshold", "window_start"]:
        assert a[f]


def test_payload_is_strict_json(srv):
    _, _, raw = req(srv, "POST", "/api/analyze", {"source": "scenario", "scenario": "ambiguous"})
    json.loads(raw, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))


def test_evidence_and_exports(srv):
    _, p = jpost(srv, "/api/analyze", {"source": "scenario", "scenario": "port_scan"})
    aid, rid = p["alerts"][0]["alert_id"], p["run_id"]
    st, _, raw = req(srv, "GET", f"/api/evidence?run={rid}&alert={aid}")
    ev = json.loads(raw)
    assert st == 200 and ev["total"] == p["alerts"][0]["evidence_count"] and "src_ip" in ev["columns"]
    st, hdr, raw = req(srv, "GET", f"/api/findings.csv?run={rid}")
    assert st == 200 and b"alert_id" in raw and "csv" in hdr["Content-Type"]
    assert req(srv, "GET", f"/api/evidence.csv?run={rid}&alert={aid}")[0] == 200
    assert req(srv, "GET", "/api/evidence?run=nope&alert=A0001")[0] == 404


def test_upload_flow_and_error_messages(srv):
    st, p = jpost(srv, "/api/analyze", {"source": "upload", "name": "x.csv", "flows_csv": open("data/samples/scenario2_port_scan_flows.csv").read()})
    assert st == 200 and p["kind"] == "upload" and p["stats"]["alerts"] > 0
    st, e = jpost(srv, "/api/analyze", {"source": "upload", "flows_csv": "a,b\n1,2\n"})
    assert st == 400 and "Missing required flow column" in e["error"]
    st, e = jpost(srv, "/api/analyze", {"source": "upload", "flows_csv": ""})
    assert st == 400
    st, e = jpost(srv, "/api/analyze", {"source": "scenario", "scenario": "nope"})
    assert st == 400


def test_invalid_json_and_settings(srv):
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.request("POST", "/api/analyze", body="{bad", headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"})
    assert c.getresponse().status == 400
    st, e = jpost(srv, "/api/analyze", {"source": "scenario", "scenario": "benign", "config": {"scan_min_ports": "abc"}})
    assert st == 400 and "valid number" in e["error"]
    st, e = jpost(srv, "/api/analyze", {"source": "scenario", "scenario": "benign", "config": {"anomaly_quantile": 2}})
    assert st == 400


def test_settings_change_results(srv):
    base = {"source": "scenario", "scenario": "port_scan", "config": {"anomaly_enabled": False}}
    _, a = jpost(srv, "/api/analyze", base)
    _, b = jpost(srv, "/api/analyze", {**base, "config": {"anomaly_enabled": False, "scan_min_ports": 500}})
    assert any(x["rule_id"] == "SCAN-V1" for x in a["alerts"]) and not any(x["rule_id"] == "SCAN-V1" for x in b["alerts"])
    assert a["anomaly"]["ran"] is False


def test_unlabelled_upload_has_no_evaluation(srv):
    import pandas as pd
    df = pd.read_csv("data/samples/scenario1_benign_flows.csv").drop(columns=["label", "attack_type"])
    _, p = jpost(srv, "/api/analyze", {"source": "upload", "flows_csv": df.to_csv(index=False)})
    assert p["evaluation"] is None and not p["dataset"]["labels_present"]


def test_evaluate_all(srv):
    st, r = jpost(srv, "/api/evaluate-all", {})
    assert st == 200 and len(r["rows"]) == (5 + 1) * 3 * 2


def test_hidden_attribute_not_overridden_by_css(srv):
    """Regression: .drawer/.loading set display, which used to defeat the hidden attribute."""
    _, _, css = req(srv, "GET", "/style.css")
    assert b"[hidden]{display:none!important}" in css


def test_alert_headlines_are_plain_english(srv):
    _, p = jpost(srv, "/api/analyze", {"source": "scenario", "scenario": "auth_failures"})
    heads = [a["headline"] for a in p["alerts"] if a["rule_id"] == "AUTH-F1"]
    assert any("failed to log in" in h and "then a login succeeded" in h for h in heads)
    assert all(a["category_label"] and a["headline"] for a in p["alerts"])
    _, c = req(srv, "GET", "/api/config")[0], json.loads(req(srv, "GET", "/api/config")[2])
    assert set(c["categories"]) == {"port_scan", "dos", "auth_failures", "anomaly"}


def test_example_templates_are_loadable(srv):
    from src.ingestion import load_auth, load_flows
    import io
    for kind, loader in [("flows", load_flows), ("auth", load_auth)]:
        st, hdr, raw = req(srv, "GET", f"/api/template.csv?kind={kind}")
        assert st == 200 and "attack_type" not in raw.decode()
        assert len(loader(io.StringIO(raw.decode())).data) >= 10
    assert req(srv, "GET", "/api/template.csv?kind=evil")[0] == 404
