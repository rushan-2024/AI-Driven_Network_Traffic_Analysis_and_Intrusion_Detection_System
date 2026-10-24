# AI-Driven Network Traffic Analysis and Intrusion Detection System

Individual assessment project for the Cybersecurity and Network Security Research Intern role at Megaminds IT Services.

A hybrid intrusion-detection prototype. It ingests flow records and authentication events from CSV files, extracts per-source behavioural features, applies documented rule-based detectors and an Isolation Forest anomaly layer, explains every alert with its evidence, and evaluates the results against ground-truth labels.

> **All bundled data is synthetic.** Results show how the detectors behave on deterministic synthetic scenarios. They do not estimate performance on a real network. The dashboard analyses files; it does not capture or monitor live traffic.

## Quick start (no experience needed)

1. **Install Python** (free) from https://www.python.org/downloads/ . On Windows, tick **Add python.exe to PATH** in the installer. Any version from 3.10 up is fine.
2. **Unzip the project** to a folder, for example your Desktop.
3. **Start it.**
   - **Windows:** double-click **`run_windows.bat`**.
   - **macOS:** double-click **`run_mac.command`** (if macOS blocks it, open Terminal in the folder and type `bash run.sh`).
   - **Linux:** open a terminal in the folder and type `bash run.sh`.

The first start installs what it needs (a few minutes, internet required, once only). After that it starts in seconds. Your browser opens the dashboard by itself. If it does not, go to **http://127.0.0.1:8000**. Keep the black window open while you use it, and close it to stop.

Then click a scenario card. Everything else is explained on the page.

If something goes wrong: see *Troubleshooting* at the end of this file.

## Problem statement

Signature-based detection finds known patterns but misses novel behaviour, and a bare "malicious" label gives an analyst nothing to act on. This project asks: can simple, inspectable rules plus a statistical anomaly model detect reconnaissance, flooding and credential-guessing in flow and login data, and can each alert carry enough evidence to be investigated and challenged?

## Features

- CSV ingestion with schema, type, IP, timestamp, range and duplicate validation, and readable error messages.
- Feature extraction: packet and byte counts, flow duration, protocol mix, destination-port and host diversity, connection rate, packet and byte rates, per-source behaviour over configurable time windows.
- Rule detectors: port scan (vertical and horizontal), DoS (single-source and distributed), repeated authentication failures (brute force and password spraying).
- Isolation Forest anomaly layer with preprocessing, fixed seeds, small-data guards and a held-out benign validation.
- Every alert reports category, time window, source and destination, severity, rule or score, observed values, threshold, explanation and recommended investigation steps.
- Evaluation: TP/FP/TN/FN, precision, recall, F1, accuracy, confusion matrix, per-category results, false-positive and false-negative examples, for rules only, anomaly only, or hybrid.
- Browser dashboard served by a small Python standard-library web server (no web framework). One click runs a scenario; a 3D host map shows who talked to whom and which hosts are involved in alerts; alert details open in a side panel with the supporting records; CSV upload, threshold settings and CSV exports are included.

## Detection methodology

| Detector | Rule (defaults) | Why |
|---|---|---|
| SCAN-V1 vertical scan | One source touches at least 20 distinct ports on one host in a 60 s window, and flows average at most 3 packets | Benign clients in the baseline touch at most 2 ports per host per window. Short flows distinguish probes from busy sessions. |
| SCAN-H1 horizontal sweep | One source probes at least 20 hosts on the same port or ICMP, with the same short-flow condition | Baseline maximum is 1 host per port per window. |
| DOS-S1 single-source flood | One source to one target: at least 200 flows, peak rate at least 30 flows/s (5 s bins), mean at most 5 packets per flow | Baseline peak rate is 0.8 flows/s. Count, rate and flow shape are all required, so packet count alone never triggers it. |
| DOS-D1 distributed flood | At least 500 flows to one target from at least 10 sources, no source above 50 percent, peak rate at least 30 flows/s, short flows | Excludes single-source floods and flash crowds with long completed flows. |
| AUTH-F1 authentication failures | At least 8 failures per source, target and service in 300 s, from authentication events only | Baseline maximum is 1 failure per window. 5 or more usernames marks password spraying. A success within 60 s raises severity one level. |
| ML-IF1 anomaly | Isolation Forest score above the 99.5th percentile of baseline windows | Catches behaviour no rule describes. It is an outlier score, not a classification. |

Thresholds were chosen from `python scripts/run_evaluation.py --profile`, which prints the benign baseline maxima, then set well above them. They were checked on the same synthetic scenarios the project reports, so they are not independently validated. Each threshold and its rationale is shown in the dashboard Configuration tab.

**Severity is a heuristic rating, not a probability.** Rules: observed value divided by threshold below 2 is low, 2 to 4 is medium, 4 or more is high; corroboration (login success after failures) raises it one level, up to critical. Anomaly alerts: score margin above threshold below 0.05 is low, below 0.15 medium, otherwise high. No confidence percentages are shown.

**Anomaly model design.** A forest trained on benign baseline windows alone gave out-of-range attack windows scores close to benign extremes (isolation scores saturate beyond the training range). Each analysis therefore fits the forest on the baseline windows pooled with the windows of the capture being analysed, using no labels, and sets the threshold from the baseline windows' scores. The capture's own windows influence the fit, and a capture dominated by anomalies could be treated as normal. Ground-truth labels are never features; the loader strips them and the feature code refuses to run if they are present (tested).

## Architecture and data flow

```
CSV -> ingestion (validate, strip labels) -> features (windows) -> rules + Isolation Forest -> alerts + evidence
                                   labels (kept apart) ---------------------------------> evaluation (after detection)
```

```
app.py                     launcher: python app.py
web/                       dashboard front end (index.html, style.css, app.js, charts.js, graph3d.js)
web/vendor/                three.js r149 (MIT), bundled so the 3D view works offline
src/ingestion/             CSV loading and validation
src/features/              window and protocol features, label-leak guard
src/detection/             rules.py, anomaly.py, engine.py, alerts.py
src/evaluation/            confusion matrix and metrics
src/synthetic/             deterministic scenario generator
src/web/                   api.py (JSON logic) and server.py (stdlib HTTP server)
src/pipeline.py            shared end-to-end functions
scripts/                   generate_data.py, run_evaluation.py, run_detection.py
data/samples/              synthetic CSVs (1.5 MB)
results/                   output of run_evaluation.py
tests/                     pytest suite
report/                    technical report and video outline
```

## Requirements

Python 3.10 or newer, and the packages in `requirements.txt` (pandas, numpy, scikit-learn), plus any modern browser. The web server is the Python standard library and three.js is bundled, so nothing is downloaded at run time. No API key, account, database, Docker, administrator rights or network access is needed after installation. The 3D map needs WebGL; without it the rest of the dashboard still works. PCAP ingestion is **not implemented**; the CSV workflow is the supported path.

## Manual setup and launch (alternative to the launchers)

### Windows (PowerShell)

```powershell
git clone <your-repository-url> ai-network-traffic-ids
cd ai-network-traffic-ids
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

A browser window opens at http://127.0.0.1:8000. If it does not, open that address yourself. If activation is blocked, run `Set-ExecutionPolicy -Scope Process Bypass` first. If the port is busy, use `python app.py --port 8100`. Use `--no-browser` to skip opening a window. The server listens on your own computer only. Run commands from the repository root.

### macOS / Linux

```bash
git clone <your-repository-url> ai-network-traffic-ids && cd ai-network-traffic-ids
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Using the dashboard

1. **Choose data.** Click one of the five scenario cards, or select *Analyse your own CSV file*, choose your files and press *Analyse files*. Results appear straight away.
2. **Look at the host map.** Drag to rotate, scroll to zoom, hover a host for details, click a host to list its alerts. Red hosts are sources in alerts, amber hosts are targets. The map shows the hosts in the file, not a live network.
3. **Read the results.** The box under the title says in plain words what was found; select any finding to open it. The tabs go deeper:
   - *Summary*: activity over time, kinds of traffic, busiest machines, and whether a server slowed down during an attack.
   - *Alerts*: a searchable, filterable table. Select a row to see what happened, why it was flagged, what to check next, the numbers behind it and the exact records.
   - *Unusual behaviour*: the anomaly model's scores.
   - *Accuracy check*: how many attacks were caught, missed or falsely flagged, in plain words and as a table. **Run all five examples** compares every scenario.
   - *Settings*: choose **More alerts**, **Balanced** or **Fewer alerts**, then **Apply and re-run**. Individual limits are under *Advanced*.
4. **Need help?** **Take the tour** gives a 7-step walkthrough (it also starts the first time you open the page). **Help and glossary** explains every term. Small **?** icons next to numbers explain what they mean.

## Sample data and provenance

All files in `data/samples/` are generated by `src/synthetic/generator.py` with fixed seeds and can be regenerated with `python scripts/generate_data.py`. They use private (RFC 1918) and documentation (RFC 5737) addresses. No real traffic, personal data or third-party dataset is included.

| File | Content | Seed |
|---|---|---|
| `scenario1_benign_*` | 20 clients, 600 s, flows and logins | 11 |
| `scenario2_port_scan_*` | Benign plus vertical scan and horizontal sweep | 12 |
| `scenario3_dos_*` | Benign plus single-source and distributed floods | 13 |
| `scenario4_auth_failures_*` | Benign plus SSH brute force with a later success, and password spraying | 14 |
| `scenario5_ambiguous_*` | Authorised scanner, flash crowd, connect scan, slow scan, stale service credential, slow brute force | 15 |
| `baseline_training_flows.csv`, `baseline_validation_flows.csv` | Benign only, for the anomaly model | 101, 102 |

`*_flows.csv` columns: `timestamp, src_ip, src_port, dst_ip, dst_port, protocol, packets, bytes, duration` plus ground truth `attack_type, label`. `*_auth.csv` columns: `timestamp, src_ip, dst_ip, service, username, outcome` plus ground truth. Your own files only need the required columns; add `attack_type` or `label` (`benign` or anything else) to enable evaluation. Scenario 4 flow data contains no attack flows by design: login failures are visible only in authentication events.

## Run the five scenarios

**Dashboard:** click each scenario card in turn and open the tabs. *Run all five examples* in the Accuracy check tab shows every scenario in one table.

**Command line:**

```bash
python scripts/run_detection.py --flows data/samples/scenario2_port_scan_flows.csv --out alerts.csv
python scripts/run_detection.py --flows data/samples/scenario4_auth_failures_flows.csv --auth data/samples/scenario4_auth_failures_auth.csv
python scripts/run_evaluation.py          # all scenarios; writes results/evaluation_results.json and evaluation_summary.md
python scripts/run_evaluation.py --profile  # benign baseline maxima used to set thresholds
```

## Run the tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite covers CSV validation, features, each rule including threshold edges, benign and borderline cases, small datasets and missing values, reproducibility, metric and confusion-matrix correctness, label-leakage prevention, scenario expectations, and the web server and its JSON API over real HTTP (including path-traversal, host-header and bad-input cases).

Result on the author's machine (Linux, Python 3.12): **71 passed**. Not run on Windows or macOS. The browser front end was exercised in a simulated browser (jsdom) covering every scenario, tabs, the guided tour, help, alert details, filters, settings presets, upload, a hostile-CSV script-injection check and error messages. The 3D scene code was run against a stubbed renderer. **It was not checked visually in a real browser during development, so please check the layout and the 3D map yourself before submitting.**

## Interpreting the metrics

Metrics are computed per record: a flow or authentication event counts as flagged if it is in the evidence of an alert. Precision is the share of flagged records that are truly malicious; recall is the share of malicious records that were flagged. Accuracy is misleading when attacks are rare, so rely on precision and recall. `n/a` means the denominator is zero, for example precision when nothing was flagged. Per-category scores treat that attack type as positive and benign records as negative; other categories' alerts are ignored. Pooled numbers mix scenarios with different attack prevalence. Record-level counts weight a long scan more heavily than a single login failure.

## Results on the synthetic scenarios (default configuration)

Produced by `scripts/run_evaluation.py`; see `results/evaluation_summary.md` for every row.

| Scenario | Rules (flows) TP / FP / FN | Hybrid (flows) TP / FP / FN | Rules (auth) TP / FP / FN |
|---|---|---|---|
| 1 Benign | 0 / 0 / 0 | 0 / 6 / 0 | 0 / 0 / 0 |
| 2 Port scan | 360 / 0 / 0 | 360 / 2 / 0 | 0 / 0 / 0 |
| 3 DoS | 2200 / 0 / 0 | 2200 / 7 / 0 | 0 / 0 / 0 |
| 4 Auth failures | 0 / 0 / 0 | 0 / 4 / 0 | 119 / 0 / 0 |
| 5 Ambiguous | 0 / 150 / 100 | 100 / 172 / 0 | 0 / 14 / 12 |

Perfect rule results in scenarios 2 to 4 mostly show that the thresholds separate attacks from the benign baseline that the same author generated; they are not evidence of general accuracy. Scenario 5 shows the limits. The anomaly layer alone catches 59 percent of DoS flow records in scenario 3; the distributed-flood sources are recognised mainly by the rules.

## Limitations and ethical considerations

- The 3D map lays hosts out with a force-directed algorithm; distances have no physical meaning. Large files show only the busiest hosts and every host involved in an alert.
- Synthetic traffic only; no real-network validation. The generator, thresholds and evaluation share an author, which favours the detectors.
- The anomaly model's strong result on the slow scan in scenario 5 partly reflects that synthetic probe flows (1 to 2 packets, millisecond durations) are always unlike benign flows. Real slow scans may look different.
- Tumbling windows can split an attack across a boundary. Slow attacks below the per-window thresholds are missed.
- Rules can be evaded: a scan with completed handshakes exceeds the short-flow condition; distributed or slow attacks stay under per-source limits.
- Thresholds assume a small network (six servers); larger networks need recalibration.
- Flow records omit payloads, so encrypted or application-layer attacks are not visible. ARP/MITM detection is not covered.
- No live capture, no inline operation, no latency or throughput measurements. The batch design is not a claim of real-time suitability.
- Use only on data you are authorised to analyse. Alerts are leads for human investigation, not proof of intent, and blocking decisions based on them can harm legitimate users.

## Future improvements

PCAP/Zeek log ingestion; evaluation on a public dataset such as CICIDS2017; sliding windows; per-asset baselines; adversarial and evasion tests; alert deduplication and correlation across detectors; streaming mode with latency measurement.

## Licence

MIT, see `LICENSE`.

## Troubleshooting

| Problem | Fix |
|---|---|
| "Python was not found" | Install Python from python.org and tick **Add python.exe to PATH**, then start again. |
| Windows opens the Microsoft Store when Python is run | Install Python from python.org instead, then start again. |
| Package installation fails | Check your internet connection and start again; it resumes. Behind a proxy, install the packages in `requirements.txt` manually with `pip`. |
| "Could not start on port 8000" | Another program uses the port. Run `python app.py --port 8100` (with the environment active) and open that address. |
| Browser does not open | Open http://127.0.0.1:8000 yourself. |
| The 3D map shows "3D view unavailable" | Your browser has WebGL turned off. Turn on hardware acceleration or use another browser. The rest still works. |
| Want to start over | Delete the `.venv` folder and start again. |
