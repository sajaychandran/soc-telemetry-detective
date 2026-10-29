from datetime import timedelta

try:
    from .detector import parse_timestamp
except ImportError:
    from detector import parse_timestamp


# Map each detection rule to the attack stage it most likely represents.
RULE_CONTEXT = {
    "AUTH-001": {
        "source": "authentication",
        "stage": "Credential Access",
        "mitre": "T1110 Brute Force",
    },
    "PROC-001": {
        "source": "process",
        "stage": "Discovery",
        "mitre": "T1033/T1016/T1087/T1007 System & Account Discovery",
    },
    "NET-001": {
        "source": "network",
        "stage": "Command and Control",
        "mitre": "T1071 Application Layer Protocol",
    },
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def alert_start_time(alert):
    """Return the earliest time an alert covers."""
    return parse_timestamp(
        alert.get("first_failure") or alert.get("timestamp")
    )


def alert_end_time(alert):
    """Return the latest time an alert covers."""
    return parse_timestamp(
        alert.get("successful_logon") or alert.get("timestamp")
    )


def describe_event(source, event):
    """Build a one-line, human-readable summary of a raw event."""
    if source == "authentication":
        return (
            f"{event.get('description')} (EventID "
            f"{event.get('windows_event_id')}) for "
            f"{event.get('username')} from {event.get('source_ip')}"
        )

    if source == "process":
        return (
            f"{event.get('username')} ran: {event.get('command_line')}"
        )

    signature = event.get("alert_signature")
    detail = f" — {signature}" if signature else ""

    return (
        f"{event.get('source')}: {event.get('src_ip')} -> "
        f"{event.get('dest_ip')}:{event.get('dest_port')}{detail}"
    )


def build_host_timeline(evidence, computer, accounts, start, end):
    """
    Collect raw events on one host inside the incident time range.

    Events with a username are kept only when the user is one of the
    accounts named in the alerts, so unrelated users stay out.
    """
    timeline = []

    for source, events in evidence.items():
        for event in events:
            if event.get("computer") != computer:
                continue

            username = event.get("username")

            if username and username not in accounts:
                continue

            event_time = parse_timestamp(event.get("timestamp"))

            if event_time is None or not (start <= event_time <= end):
                continue

            timeline.append({
                "timestamp": event.get("timestamp"),
                "source": source,
                "event_id": event.get("event_id"),
                "summary": describe_event(source, event),
            })

    timeline.sort(key=lambda item: parse_timestamp(item["timestamp"]))
    return timeline


def score_incident(host_alerts):
    """
    Rate an incident by how many evidence sources agree.

    Activity seen across authentication, process and network data is
    far more convincing than a single noisy alert.
    """
    sources = {
        RULE_CONTEXT.get(alert["rule_id"], {}).get("source")
        for alert in host_alerts
    }
    sources.discard(None)

    if len(sources) >= 3:
        return "CRITICAL", sources

    highest = max(
        (alert["severity"] for alert in host_alerts),
        key=lambda level: SEVERITY_RANK.get(level, 0)
    )

    if len(sources) == 2 and SEVERITY_RANK[highest] < SEVERITY_RANK["HIGH"]:
        return "HIGH", sources

    return highest, sources


def correlate_alerts(evidence, alerts, window_minutes=30):
    """
    Group alerts by host into incidents with a shared timeline.

    Alerts on the same host are merged when each one starts within
    window_minutes of the previous alert ending.
    """
    by_host = {}

    for alert in alerts:
        if alert.get("computer") and alert_start_time(alert) is not None:
            by_host.setdefault(alert["computer"], []).append(alert)

    incidents = []
    window = timedelta(minutes=window_minutes)

    for computer, host_alerts in by_host.items():
        host_alerts.sort(key=alert_start_time)
        groups = [[host_alerts[0]]]

        for alert in host_alerts[1:]:
            group_end = max(alert_end_time(item) for item in groups[-1])

            if alert_start_time(alert) - group_end <= window:
                groups[-1].append(alert)
            else:
                groups.append([alert])

        for group in groups:
            incidents.append(build_incident(evidence, computer, group))

    incidents.sort(
        key=lambda item: SEVERITY_RANK.get(item["severity"], 0),
        reverse=True
    )

    for number, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{number:03d}"

    return incidents


def build_incident(evidence, computer, group):
    """Turn one group of related alerts into an incident record."""
    start = min(alert_start_time(alert) for alert in group)
    end = max(alert_end_time(alert) for alert in group)
    accounts = sorted({
        alert["username"] for alert in group if alert.get("username")
    })
    severity, sources = score_incident(group)

    stages = []

    for alert in group:
        context = RULE_CONTEXT.get(alert["rule_id"])

        if context and context["stage"] not in [s["stage"] for s in stages]:
            stages.append({
                "stage": context["stage"],
                "mitre": context["mitre"],
            })

    return {
        "incident_id": None,
        "computer": computer,
        "accounts": accounts,
        "severity": severity,
        "evidence_sources": sorted(sources),
        "start": start.isoformat().replace("+00:00", "Z"),
        "end": end.isoformat().replace("+00:00", "Z"),
        "alert_count": len(group),
        "stages": stages,
        "alerts": group,
        "timeline": build_host_timeline(
            evidence, computer, set(accounts), start, end
        ),
    }


if __name__ == "__main__":
    from loader import load_all_evidence
    from detector import run_detections

    evidence = load_all_evidence()
    incidents = correlate_alerts(evidence, run_detections(evidence))

    for incident in incidents:
        print(
            f"\n{incident['incident_id']} | {incident['severity']} | "
            f"{incident['computer']} | accounts: "
            f"{', '.join(incident['accounts']) or 'n/a'}"
        )

        for entry in incident["timeline"]:
            print(f"  {entry['timestamp']}  [{entry['source']}] "
                  f"{entry['summary']}")
