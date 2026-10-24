# AI-Driven Network Traffic Analysis and Intrusion Detection System

Technical report, Megaminds IT Services Cybersecurity and Network Security Research Intern assessment. Author: Rushan. All numbers come from `python scripts/run_evaluation.py` and `python -m pytest` as run on the author's Linux machine (Python 3.12); the results are on synthetic data.

## 1. Problem overview and objectives

Port scanning, flooding and credential guessing are common first steps or disruptions in network attacks. Signature rules recognise known patterns, while behavioural methods can flag unusual activity that has no signature. Either way, an analyst needs to know why an event was flagged and what supports it.

The objectives were to build a prototype that (1) ingests network data, (2) extracts traffic features, (3) detects intrusions with a justified method, (4) explains each alert, and (5) evaluates the detector honestly. I chose a hybrid design: transparent threshold rules for three attack classes, plus an Isolation Forest to flag behaviour the rules do not describe. Rules give explainable, testable detections; the model adds coverage of unusual behaviour, at the cost of weaker explanations and false positives.

## 2. Dataset and traffic generation

I generated deterministic synthetic data rather than running Mininet or a live capture, so a reviewer can reproduce every result offline with one command. The cost is realism: the data reflects my assumptions about traffic, not a real network. I did not use CICIDS2017 or NSL-KDD because they lack the authentication events and the controlled borderline cases I needed.

The generator (`src/synthetic/generator.py`) models 20 internal clients using web, DNS, mail, database and SSH services on six servers. Benign flows have packet counts, byte counts and durations drawn from log-normal distributions; DNS and NTP are short UDP flows. Five scenarios add attacks, each with its own seed:

1. Normal traffic: 1,396 flows and 60 login events over 600 s.
2. Reconnaissance: a vertical scan of 300 ports on one host and a horizontal sweep of 60 hosts on port 22.
3. DoS: a single-source flood (1,200 flows in 20 s) and a distributed flood (1,000 flows from 25 sources in 12 s) against the web server. Benign flows to the victim are given longer durations during the attacks to model degraded service.
4. Authentication failures: an SSH brute force (90 failures, then a success) and a password-spraying run (28 usernames), present only in authentication-event data.
5. Ambiguous cases over 1,200 s: an authorised internal vulnerability scanner (benign), a flash crowd (benign), a connect scan with completed handshakes, a slow scan, a stale service credential (benign) and a slow brute force.

Separate benign-only captures (seeds 101 and 102) train and validate the anomaly model; their records are disjoint from all scenarios (tested). Ground-truth columns are written to the sample files for evaluation only. The loader removes them before detection, and the feature code raises an error if label columns reach it.

## 3. System architecture

The pipeline has separate modules: ingestion and validation, feature extraction, rule detection, anomaly detection, alert construction, evaluation and presentation. CSV files are validated for required columns, timestamps, IP addresses, protocols, numeric ranges and duplicates; invalid rows are dropped and reported, and unusable files produce an explanatory error. Detectors output alerts with evidence record identifiers. Evaluation runs only after detection and is the only place labels are read. A local browser dashboard, served by the Python standard library, presents the results with a 3D map of the hosts in the analysed file; command-line scripts run the same pipeline.

## 4. Feature extraction

Flow records carry timestamp, source and destination address, ports, protocol, packets, bytes and duration. From these I compute, per source and 60-second window: flow count, distinct destination ports and hosts, total and mean packets and bytes, mean duration, flow, packet and byte rates, and the UDP and ICMP share. Rates divide by the active span, floored at 10 s, so that a lone flow does not create an artificial rate spike. This floor was added after the first evaluation flagged single-flow windows of benign traffic.

Port and host diversity separate scanning from normal use; connection rate and flow size separate floods from busy sessions; per-source windows localise behaviour in time. The rules also use peak rate over 5-second bins, because my first version divided by the whole window and let background traffic hide a flood at a busy target; that version missed the distributed flood, which I found by running the scenario.

## 5. Detection methodology

**Rules.** Each rule needs several conditions. Port scans require at least 20 distinct ports on a host (or 20 hosts on one port) in a window and flows averaging at most 3 packets. A single-source flood requires 200 flows, a peak of 30 flows/s and short flows. A distributed flood requires 500 flows from at least 10 sources, none above 50 percent, with the same rate and size conditions. A high packet count alone never triggers a rule (tested with a bulk transfer). Authentication failures require 8 failures per source, target and service in 300 s, and use authentication events only; flow data alone cannot trigger this rule (tested).

I set thresholds from the benign baseline profile: the largest values seen were 2 ports per host, 1 host per port, 0.8 flows/s and 1 login failure per window. Thresholds sit far above these. This margin is a judgement, not a measured optimum, and I checked the thresholds on the same synthetic scenarios I report, so they are not independently validated.

**Severity** is a heuristic: the ratio of observed value to threshold (below 2 low, 2 to 4 medium, 4 or more high), raised one level when a login succeeds after the failures. It is not a calibrated probability, and the system shows no confidence percentages.

**Anomaly model.** The Isolation Forest (200 trees, seed 42) runs on log-transformed, standardised, median-imputed window features. I first trained it on benign baseline windows only. Attack windows then scored close to the largest benign scores and were mostly missed, because isolation scores saturate for points outside the training range. The final design fits the forest on baseline windows pooled with the capture under analysis, without labels, and sets the alert threshold at the 99.5th percentile of the baseline windows' scores. This is transductive: the capture influences the fit, and a capture dominated by anomalies could be treated as normal. Validation on the held-out benign capture flagged 0 of 200 windows. The model has learned patterns in synthetic data only and does not recognise real-world attack signatures.

## 6. Experimental design

Every flow and authentication event is a record. A record is predicted malicious if it appears in the evidence of an alert. I score three detector configurations: rules only, anomaly model only, and hybrid. Per-category results treat one attack type as positive and benign records as negative. I report TP, FP, TN, FN, precision, recall, F1 and accuracy; where a denominator is zero the value is shown as not available. Because attack prevalence differs sharply between scenarios (22 percent of flow records pooled), I report per-scenario tables and treat pooled figures cautiously. Runs are deterministic: the tests confirm that repeated runs give identical alerts and that shuffling labels does not change them.

## 7. Results

| Scenario | Rules flows TP/FP/FN | Hybrid flows TP/FP/FN | Rules auth TP/FP/FN |
|---|---|---|---|
| 1 Benign | 0/0/0 | 0/6/0 | 0/0/0 |
| 2 Port scan | 360/0/0 | 360/2/0 | 0/0/0 |
| 3 DoS | 2200/0/0 | 2200/7/0 | 0/0/0 |
| 4 Auth failures | 0/0/0 | 0/4/0 | 119/0/0 |
| 5 Ambiguous | 0/150/100 | 100/172/0 | 0/14/12 |

Pooled over all scenarios, rules on flow records achieved precision 94.5 percent, recall 96.2 percent and F1 95.3 percent (accuracy 97.9 percent). The hybrid reached precision 93.3 percent and recall 100 percent (F1 96.5 percent). On authentication events, rules achieved precision 89.5 percent, recall 90.8 percent and F1 90.2 percent. The anomaly model alone reached precision 90.2 percent and recall 66.2 percent on flows and detected no authentication failures, as it sees only flow features.

Rules separated scans, floods and credential attacks cleanly in scenarios 2 to 4, with no false positives. That is expected: the same author wrote the generator and the thresholds, and the attacks are far from the benign baseline. In scenario 3, the single-source flood was rated medium and the distributed flood medium; the brute force with a later success was rated critical and the spray medium. The anomaly layer alone found 59 percent of the scenario 3 flood records. In scenario 3, benign session-flow duration to the victim rises during the floods, which the dashboard plots as the performance impact; this is built into the generator, so it illustrates the measurement rather than demonstrating a real effect.

## 8. False-positive and false-negative analysis

**False positives.** In scenario 1 the model flagged two benign windows (six flows) at low severity; no rule fired, so the baseline raised no rule alert. In scenario 5 the authorised internal scanner swept 150 ports and the rule fired with high severity: it is indistinguishable from an attacker by traffic alone, and only an asset inventory or allow-list would separate them. The stale service credential produced 14 failures in four minutes and triggered the authentication rule, as it would on a real system. The anomaly model also flagged one window of the benign flash crowd (12 flows) and some other internal windows (10 flows). The DoS rules correctly did not fire on the flash crowd, because its flows were large and completed.

**False negatives.** Rules missed the connect scan (40 flows) because its completed handshakes made flows longer than the short-flow condition, a trade-off that avoids flagging busy hosts but gives an evasion route. They missed the slow scan (60 flows, about three ports per window) and the slow brute force (12 failures, under three per window), which stay below per-window thresholds. The anomaly model flagged both scans, but this partly reflects my generator: probe flows of one or two packets with millisecond durations are always unlike benign flows here. No detector found the slow brute force, because the model does not see authentication data. Scenario 5 therefore shows that fixed windows and per-source thresholds are a weakness, and that borderline benign activity needs context.

## 9. Security and network considerations

*Performance.* This is a batch tool; I did not measure latency or throughput. Inline detection would need streaming aggregation, bounded memory per source, and fail-open behaviour so detection cannot block traffic. The forest refit per analysis would not suit real-time use.

*Data completeness.* Flow records omit payloads and may be sampled or truncated; missed records can hide scans or inflate rates. Encrypted or application-layer attacks and ARP spoofing are outside this design.

*Evasion.* Attackers can slow scans, spread them across sources, complete handshakes, or stay under thresholds. Published thresholds are easy to tune around, so rules should not be the only layer.

*Operational impact.* False positives cost analyst time, and automatic blocking on the authorised-scanner or flash-crowd cases would disrupt legitimate work. The alert text states what is observed and avoids claiming intent.

*Scalability.* Windows, groupings and the pooled model scale with sources and windows. Thresholds tuned for six servers need recalibration elsewhere; a larger deployment would need per-asset baselines.

## 10. Limitations and future work

The main limitation is that all evidence is synthetic. The results show the detectors behave as designed on constructed cases, not that they work on real networks. Further limits include tumbling windows, no PCAP ingestion, no ARP/MITM detection, and a transductive model. I did not test the application on Windows or macOS.

Future work: evaluate on CICIDS2017 or captured lab traffic; use sliding windows; build per-asset baselines and an allow-list for authorised scanners; test adversarial evasion; correlate alerts across detectors; add a streaming mode with latency measurements.
