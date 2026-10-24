# Video demonstration outline (target 9 minutes, limit 8 to 10)

Record the screen and speak over it. Before recording: activate the virtual environment, run `python app.py` from the repository root, and keep a second terminal open at the same folder. Do not show source code as the main content.

| Time | Segment | What to show and say |
|---|---|---|
| 0:00-0:45 | Problem and goal | Title slide or README top. Port scans, floods and password guessing; signatures miss novel behaviour; an analyst needs reasons, not labels. State the hybrid approach in one sentence. |
| 0:45-1:45 | Architecture | README data-flow diagram. CSV in, validation strips labels, features, rules plus Isolation Forest, alerts with evidence, evaluation afterwards. Mention offline, no API keys. |
| 1:45-2:45 | Data and features | Terminal: `python scripts/generate_data.py`, then `dir data\samples` (or `ls`). Say all data is synthetic, seeded and reproducible. Optionally start with the Take the tour button (30 seconds). Dashboard: the 3D host map (drag to rotate), the summary tiles with validation status, protocol chart. Name the window features. |
| 2:45-3:30 | Scenario 1: baseline | Click the scenario 1 card. Zero rule alerts. Open the Unusual behaviour tab: two low-severity benign windows flagged. Say these are false positives and show the Accuracy check tab confirming 0 rule FPs and 6 hybrid FP flows. |
| 3:30-4:30 | Scenario 2: port scan | Click the scenario 2 card. Alerts tab, filter category port_scan. Investigate SCAN-V1: observed 300 ports, threshold 20, short flows, recommended steps, evidence table. Then SCAN-H1. |
| 4:30-5:30 | Scenario 3: DoS | Click the scenario 3 card. Investigate DOS-S1 and DOS-D1. Overview, Target performance: choose 10.0.1.10 and show session duration rising during the floods. Say this effect is built into the generator. |
| 5:30-6:30 | Scenario 4: authentication | Click the scenario 4 card. Investigate the critical AUTH-F1 alert: failures, success afterward, severity reason. Show the spraying alert. Point out flow data alone cannot prove login failures. |
| 6:30-7:45 | Scenario 5: ambiguous | Click the scenario 5 card. Accuracy check tab, Rules only: 150 flow FPs (authorised scanner), 100 FNs, 14 auth FPs, 12 auth FNs. Open the false-negative expander. Switch to Hybrid: model catches the scans but adds false positives. Explain slow-attack, evasion and context limits. |
| 7:45-8:30 | Evaluation | Accuracy check tab: Run all five examples. Read pooled precision and recall from `results/evaluation_summary.md`. Explain per-record scoring, class imbalance, why accuracy misleads, and that numbers are synthetic. |
| 8:30-9:15 | Tests and reproducibility | Terminal: `python -m pytest` (71 tests). Mention reproducibility, label-leak tests, one command to launch. |
| 9:15-9:45 | Limitations and close | Synthetic data only, tumbling windows, evadable thresholds, transductive model, no PCAP, no latency measurements. Future work: real datasets, sliding windows, streaming. |

Commands in order: `python app.py`, `python scripts/generate_data.py`, `python scripts/run_evaluation.py`, `python -m pytest`.

Check before submitting: the video must show the running system, not only code; run the commands yourself so the numbers on screen match `results/evaluation_summary.md`.
