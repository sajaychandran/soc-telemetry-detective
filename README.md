# SOC Telemetry Detective

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A small Python investigation pipeline for practising SOC triage. It loads
authentication, process and network evidence, runs detection rules, groups the
resulting alerts into incidents by host and time, and writes an incident report
with a timeline, MITRE ATT&CK mapping and recommended actions.

All sample data in `data/` is synthetic and made for training. IP addresses
come from the reserved documentation ranges (RFC 5737).

See [docs/sample_report.md](docs/sample_report.md) for a full example report.

## How it works

```
data/*.json ──► loader ──► detector ──► correlator ──► reporter ──► output/
                (load +     (rules →     (alerts →      (Markdown +
                 validate)   alerts)      incidents)      JSON)
```

| Module | Role |
|--------|------|
| [src/loader.py](src/loader.py) | Loads and validates the three JSON evidence files |
| [src/detector.py](src/detector.py) | Runs detection rules and returns alerts |
| [src/correlator.py](src/correlator.py) | Groups alerts on the same host within a 30-minute window into incidents, scores severity and builds a timeline |
| [src/reporter.py](src/reporter.py) | Writes `output/incident_report.md` and `output/incidents.json` |
| [src/main.py](src/main.py) | Runs the full pipeline |

### Detection rules

| Rule | What it flags | Severity | ATT&CK |
|------|---------------|----------|--------|
| `AUTH-001` | 5+ failed logons (4625) followed by a success (4624) for the same account and source IP within 5 minutes | HIGH | T1110 Brute Force |
| `PROC-001` | Discovery commands: `whoami`, `ipconfig`, `net user`, `Get-Service` | MEDIUM | T1033 / T1016 / T1087 / T1007 |
| `NET-001` | IDS alerts with severity 1–2 (Suricata scale, 1 = worst) | MEDIUM | T1071 Application Layer Protocol |

### Incident scoring

An incident's severity rises with the number of evidence sources that agree:

- Alerts from all three sources (authentication, process, network) → **CRITICAL**
- Two sources → at least **HIGH**
- Otherwise → the highest alert severity in the group

Findings are triage leads, not proof of compromise.

## Project structure

```
soc-telemetry-detective/
├── .github/workflows/ci.yml  # Lint, test and end-to-end run on every push
├── data/
│   ├── auth_events.json      # Windows logon events (4624/4625)
│   ├── process_event.json    # Sysmon process creation events
│   └── network_alert.json    # Suricata / Zeek network events
├── docs/
│   └── sample_report.md      # Example of the generated report
├── output/                   # Generated reports (git-ignored)
├── src/
│   ├── loader.py
│   ├── detector.py
│   ├── correlator.py
│   ├── reporter.py
│   └── main.py
├── tests/
│   ├── test_detector.py      # Detection rules and correlation
│   └── test_reporter.py      # Report building and saving
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml            # Project metadata, pytest and ruff config
├── requirements.txt
└── README.md
```

## Getting started

Requires Python 3.9 or newer. There are no runtime dependencies.

```bash
git clone https://github.com/sajaychandran/soc-telemetry-detective.git
cd soc-telemetry-detective

# Optional: create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS / Linux

# Install development tools (pytest, ruff)
pip install -r requirements.txt
```

## Usage

Run the full pipeline from the project root:

```bash
python src/main.py
```

This prints the report and saves:

- `output/incident_report.md` — human-readable incident report
- `output/incidents.json` — structured incident data

Each stage can also be run on its own for debugging:

```bash
python src/loader.py       # evidence counts per source
python src/detector.py     # raised alerts
python src/correlator.py   # incidents and their timelines
```

### Example output

With the bundled sample data, the pipeline raises 6 alerts and correlates them
into one incident:

```
INC-001 — CRITICAL on WS-FIN-023
- Accounts: svc_backup
- Evidence sources: authentication, network, process
- Attack stages: Credential Access → Discovery → Command and Control
```

## Running tests

```bash
python -m pytest          # tests
ruff check src tests      # lint
# or, with no extra tools installed
python -m unittest discover tests
```

The tests cover each detection rule, timestamp parsing, correlation of the
sample evidence into a single critical incident, exclusion of benign or
unrelated activity from the timeline, and writing the report files.

GitHub Actions runs lint, tests and a full pipeline run on Linux and Windows
for Python 3.9–3.13 on every push and pull request.

## Using your own data

Replace the files in `data/` with your own events. Each file must be a JSON
list of objects. The fields the rules rely on are:

- **auth_events.json**: `event_id`, `timestamp`, `computer`, `username`,
  `windows_event_id`, `source_ip`, `description`
- **process_event.json**: `event_id`, `timestamp`, `computer`, `username`,
  `command_line`
- **network_alert.json**: `event_id`, `timestamp`, `computer`, `source`,
  `src_ip`, `dest_ip`, `dest_port`, `alert_signature`, `severity`

Timestamps should be ISO 8601, for example `2026-10-29T09:58:10Z`.

## Limitations

- Rules are simple heuristics for learning, not production detections.
- Evidence is read from local JSON files; there is no SIEM or live log
  integration.
- Thresholds (5 failures in 5 minutes, 30-minute correlation window) are
  fixed in code.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the [MIT License](LICENSE).
