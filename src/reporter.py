import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "output"


RECOMMENDATIONS = {
    "Credential Access": (
        "Reset the affected account's password and review where the "
        "failed logons originated."
    ),
    "Discovery": (
        "Confirm with the account owner whether the commands were "
        "authorised administrative activity."
    ),
    "Command and Control": (
        "Check the destination IP against threat intelligence and "
        "consider blocking it at the perimeter."
    ),
}


def build_report(incidents, alerts):
    """Build a Markdown incident report from correlated incidents."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# SOC Telemetry Detective — Incident Report",
        "",
        f"Generated: {generated}",
        "",
        "## Summary",
        "",
        f"- Alerts raised: {len(alerts)}",
        f"- Incidents after correlation: {len(incidents)}",
        "",
    ]

    if not incidents:
        lines.append("No incidents identified. No further action required.")
        return "\n".join(lines) + "\n"

    for incident in incidents:
        lines.extend([
            f"## {incident['incident_id']} — {incident['severity']} "
            f"on {incident['computer']}",
            "",
            f"- Accounts: {', '.join(incident['accounts']) or 'n/a'}",
            f"- Time range: {incident['start']} to {incident['end']}",
            f"- Evidence sources: {', '.join(incident['evidence_sources'])}",
            f"- Alerts: {incident['alert_count']}",
            "",
            "### Attack stages",
            "",
        ])

        for stage in incident["stages"]:
            lines.append(f"- **{stage['stage']}** ({stage['mitre']})")

        lines.extend(["", "### Alerts", ""])

        for alert in incident["alerts"]:
            lines.append(
                f"- [{alert['severity']}] {alert['rule_id']} "
                f"{alert['title']}: {alert['reason']}"
            )

        lines.extend([
            "",
            "### Timeline",
            "",
            "| Time | Source | Event | Summary |",
            "|------|--------|-------|---------|",
        ])

        for entry in incident["timeline"]:
            summary = entry["summary"].replace("|", "\\|")
            lines.append(
                f"| {entry['timestamp']} | {entry['source']} | "
                f"{entry['event_id']} | {summary} |"
            )

        lines.extend(["", "### Recommended actions", ""])

        for stage in incident["stages"]:
            action = RECOMMENDATIONS.get(stage["stage"])

            if action:
                lines.append(f"- {action}")

        lines.append(
            "- Treat these findings as triage leads, not proof of "
            "compromise, until validated."
        )
        lines.append("")

    return "\n".join(lines) + "\n"


def save_report(report_text, incidents, report_dir=REPORT_DIR):
    """Write the Markdown report and a JSON copy of the incidents."""
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = report_dir / "incident_report.md"
    json_path = report_dir / "incidents.json"

    markdown_path.write_text(report_text, encoding="utf-8")
    json_path.write_text(
        json.dumps(incidents, indent=2), encoding="utf-8"
    )

    return markdown_path, json_path
