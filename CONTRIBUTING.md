# Contributing

Thanks for your interest in improving SOC Telemetry Detective.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Before opening a pull request

```bash
ruff check src tests      # lint
python -m pytest          # tests
python src/main.py        # end-to-end run on the sample data
```

All three must pass; CI runs the same checks on Linux and Windows.

## Adding a detection rule

1. Add a `detect_*` function in `src/detector.py` that returns alert
   dictionaries with `rule_id`, `title`, `computer`, `severity` and `reason`.
2. Call it from `run_detections()`.
3. Map the new `rule_id` to an attack stage and MITRE technique in
   `RULE_CONTEXT` in `src/correlator.py`, and add a recommendation for the
   stage in `src/reporter.py` if it is new.
4. Add tests covering both a positive and a benign case.

## Sample data

Only use synthetic data. IP addresses must come from the documentation
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and never from
real systems or logs.
