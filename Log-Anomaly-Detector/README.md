# Log Anomaly Detector

**An offline, explainable SSH log analyzer for a personal SOC lab.**

Python standard library only · Python 3.10+ · IPv4 / IPv6 · JSON / CSV / HTML

Analyze OpenSSH authentication events, correlate suspicious activity within a sliding time window, and investigate alerts in a portable dashboard. This is a rule-based portfolio project, not a machine-learning model, production SIEM, or replacement for Wazuh.

## Quick start

```bash
git clone https://github.com/thedyname/Log-Anomaly-Detector.git
cd Log-Anomaly-Detector
python3 -m logdetector samples/ssh_demo.log --output reports
```

Open `reports/dashboard.html` in a browser. On Kali:

```bash
xdg-open reports/dashboard.html
```

No pip packages, API keys, internet connection, or running Wazuh server are needed for analysis. On Windows, replace `python3` with `py -3` if needed.

**Expected demo result:** 13 input lines, 12 parsed SSH events, 1 ignored line, 4 alerts. All example data are synthetic and use documentation IP addresses.

[Open the sample dashboard source](docs/demo/dashboard.html) · [Investigation walkthrough](docs/INVESTIGATION.md) · [Architecture and limitations](docs/ARCHITECTURE.md) · [Guide en français](docs/GUIDE_FR.md)

GitHub shows HTML as source; download and open it locally to view the dashboard.

## Detection rules

| Rule | Default condition | Severity | What to investigate |
|---|---|---|---|
| SSH_FAILURE_BURST | 5 failures from one IP against one host within 300 seconds | Medium | Repeated guessing, a broken client, or a user forgetting a password |
| SSH_MULTI_ACCOUNT | Failures against 4 distinct accounts from one IP on one host within 300 seconds | Medium | Possible account enumeration or spraying; logs cannot reveal whether passwords were reused |
| SSH_SUCCESS_AFTER_FAILURES | Success after 5 failures for the same account, IP and host within 300 seconds | High | Potential compromised credentials or a legitimate recovery |
| SSH_ROOT_LOGIN | Successful direct root SSH authentication | Medium | Authorized maintenance versus unexpected privileged access |

Alert evidence contains **original input line numbers**. Threshold alerts fire once while their condition remains true, then re-arm when the window falls below the threshold. A correlated success consumes failures for that account. Root login alerts are emitted for each matching success.

## Input formats

1. ISO timestamp + hostname + `sshd` message:

   `2026-11-17T10:00:00Z lab sshd[42]: Failed password for alice from 192.0.2.10 port 50000 ssh2`

2. Traditional syslog, with an explicit year:

   `Nov 17 10:00:00 lab sshd[42]: Failed password for alice from 192.0.2.10 port 50000 ssh2`

   ```bash
   python3 -m logdetector private_logs/auth.log --year 2026 --output reports
   ```

3. Wazuh JSONL records containing `timestamp` and a complete supported syslog message in `full_log`:

   ```bash
   python3 -m logdetector samples/wazuh_demo.jsonl --output reports/wazuh
   ```

Only `Failed` / `Accepted` `password` / `publickey` OpenSSH events are supported. Malformed or unsupported lines are counted as ignored. Input is sorted by timestamp, then original line number. Offset-aware timestamps are converted to UTC; naive timestamps are interpreted as UTC. Traditional syslog spanning New Year must first be normalized to full dates.

Wazuh's alert files may contain only selected events, so they do **not** necessarily provide a complete authentication history. This tool does not connect to the Wazuh API. Do not combine duplicate copies of the same events from multiple exports: duplicates are counted as separate events.

## Configuration and automation

```bash
python3 -m logdetector samples/ssh_demo.log --window 120 --threshold 6 --users 4 --output reports/custom
python3 -m logdetector samples/ssh_demo.log --fail-on-alert
python3 -m logdetector --help
```

| Option | Meaning | Default |
|---|---|---|
| `--window` | Inclusive time window in seconds | 300 |
| `--threshold` | Failed authentication count, minimum 2 | 5 |
| `--users` | Distinct failed accounts, minimum 2 | 4 |
| `--year` | Year for traditional syslog | None; such lines are ignored without it |
| `--output` | Destination; existing report files are overwritten | reports |
| `--fail-on-alert` | Return exit code 1 if alerts exist | Disabled |

Exit codes: **0** successful analysis, **1** alerts found with `--fail-on-alert`, **2** invalid arguments, input or output errors, or no supported events.

## Reports

- `alerts.json`: versioned report envelope, effective configuration, parsing counts and complete alerts.
- `alerts.csv`: alert table for spreadsheet review; formula-like cell values are neutralized.
- `dashboard.html`: self-contained report with search, severity filter and rule distribution. No external scripts, fonts, tracking or uploads.

HTML data are escaped. JSON preserves original parsed field values. Reports can contain account names and IP addresses: keep real logs and reports private. The repository ignores `private_logs/` and `reports/`; only synthetic examples belong in public commits.

## Test

```bash
python3 -m unittest discover -s tests -v
```

The suite covers window boundaries, separation by host/IP/account, burst suppression and re-arming, out-of-order input, IPv6, timestamp offsets, Wazuh records, malformed input, CLI exit codes, HTML escaping and CSV formula protection. A GitHub Actions workflow runs the suite on Python 3.10, 3.12 and 3.13 after publication. Local validation does not imply those remote jobs have run.

## Project layout

| Path | Responsibility |
|---|---|
| `logdetector/parser.py` | Parse and normalize supported events |
| `logdetector/detector.py` | Stateful sliding-window detection |
| `logdetector/report.py` | JSON, CSV and interactive HTML output |
| `logdetector/__main__.py` | Command-line configuration and error handling |
| `samples/` | Synthetic suspicious, normal, syslog and Wazuh inputs |
| `tests/` | Automated regression tests |
| `docs/` | Architecture, investigation, learning guide and demo reports |

## Portfolio scope

Current capabilities: offline parsing, rule correlation, configurable thresholds, evidence lines, report generation and automated tests. Live collection, persistence, machine learning, production performance benchmarks and full Wazuh integration are **not implemented**.

Use this project as a starting point for hands-on investigation. Run it, inspect the evidence, change a threshold and document your own observations before claiming proficiency on a CV. Development of this initial version was AI-assisted; understanding, validation in the lab and subsequent improvements are part of the learning work.
