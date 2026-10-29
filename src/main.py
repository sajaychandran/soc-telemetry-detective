import sys

try:
    from .loader import load_all_evidence
    from .detector import run_detections
    from .correlator import correlate_alerts
    from .reporter import build_report, save_report
except ImportError:
    from loader import load_all_evidence
    from detector import run_detections
    from correlator import correlate_alerts
    from reporter import build_report, save_report


def main():
    """Load evidence, detect, correlate, and write the incident report."""
    # The Windows console defaults to a legacy code page; force UTF-8.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("SOC TELEMETRY DETECTIVE — Investigation pipeline")
    print("=" * 45)

    evidence = load_all_evidence()
    alerts = run_detections(evidence)
    print(f"Detections raised: {len(alerts)} alerts")

    incidents = correlate_alerts(evidence, alerts)
    print(f"Correlated incidents: {len(incidents)}")

    report = build_report(incidents, alerts)
    markdown_path, json_path = save_report(report, incidents)

    print("\n" + report)
    print(f"Report saved to: {markdown_path}")
    print(f"Incident data saved to: {json_path}")


if __name__ == "__main__":
    main()
