import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from correlator import correlate_alerts  # noqa: E402
from detector import (  # noqa: E402
    detect_failed_logon_bursts,
    detect_interesting_processes,
    detect_suspicious_network,
    parse_timestamp,
    run_detections,
)
from loader import load_all_evidence  # noqa: E402
from reporter import build_report  # noqa: E402


def auth_event(event_id, timestamp, windows_event_id, user="bob",
               source_ip="10.0.0.5"):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": "HOST-1",
        "username": user,
        "windows_event_id": windows_event_id,
        "source_ip": source_ip,
    }


def failures_then_success(count, success_time="2026-01-01T10:05:00Z"):
    events = [
        auth_event(f"F{i}", f"2026-01-01T10:0{i}:00Z", 4625)
        for i in range(count)
    ]
    events.append(auth_event("S1", success_time, 4624))
    return events


class TestParseTimestamp(unittest.TestCase):
    def test_parses_zulu_time_as_utc(self):
        parsed = parse_timestamp("2026-10-29T10:00:00Z")
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)

    def test_invalid_or_missing_values_return_none(self):
        self.assertIsNone(parse_timestamp("not a date"))
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp(""))


class TestFailedLogonBursts(unittest.TestCase):
    def test_five_failures_then_success_alerts(self):
        alerts = detect_failed_logon_bursts(failures_then_success(5))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_below_threshold_does_not_alert(self):
        self.assertEqual(
            detect_failed_logon_bursts(failures_then_success(4)), []
        )

    def test_failures_outside_window_are_ignored(self):
        events = failures_then_success(
            5, success_time="2026-01-01T11:00:00Z"
        )
        self.assertEqual(detect_failed_logon_bursts(events), [])

    def test_failures_from_other_source_are_ignored(self):
        events = failures_then_success(5)
        events[0]["source_ip"] = "10.9.9.9"
        self.assertEqual(detect_failed_logon_bursts(events), [])


class TestProcessDetection(unittest.TestCase):
    def test_discovery_commands_are_flagged(self):
        events = [
            {"event_id": "P1", "command_line": "whoami.exe /all"},
            {"event_id": "P2", "command_line": "net.exe user"},
            {"event_id": "P3", "command_line": "notepad.exe"},
        ]
        flagged = [a["event_id"] for a in detect_interesting_processes(events)]
        self.assertEqual(flagged, ["P1", "P2"])

    def test_missing_command_line_does_not_crash(self):
        events = [{"event_id": "P1", "command_line": None}, {}]
        self.assertEqual(detect_interesting_processes(events), [])


class TestNetworkDetection(unittest.TestCase):
    def test_only_severe_ids_alerts_are_flagged(self):
        events = [
            {"event_id": "N1", "alert_signature": "Bad", "severity": 2},
            {"event_id": "N2", "alert_signature": "Info", "severity": 4},
            {"event_id": "N3", "bytes_sent": 100},
        ]
        flagged = [a["event_id"] for a in detect_suspicious_network(events)]
        self.assertEqual(flagged, ["N1"])


class TestSampleEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = load_all_evidence()
        cls.alerts = run_detections(cls.evidence)
        cls.incidents = correlate_alerts(cls.evidence, cls.alerts)

    def test_expected_alerts_are_raised(self):
        rules = [alert["rule_id"] for alert in self.alerts]
        self.assertEqual(rules.count("AUTH-001"), 1)
        self.assertEqual(rules.count("PROC-001"), 4)
        self.assertEqual(rules.count("NET-001"), 1)

    def test_benign_activity_is_not_flagged(self):
        flagged_events = {alert.get("event_id") for alert in self.alerts}
        self.assertNotIn("PROC-005", flagged_events)
        self.assertNotIn("NET-003", flagged_events)

    def test_alerts_correlate_into_one_critical_incident(self):
        self.assertEqual(len(self.incidents), 1)

        incident = self.incidents[0]
        self.assertEqual(incident["computer"], "WS-FIN-023")
        self.assertEqual(incident["severity"], "CRITICAL")
        self.assertEqual(incident["accounts"], ["svc_backup"])

    def test_timeline_excludes_unrelated_user(self):
        timeline_ids = {
            entry["event_id"] for entry in self.incidents[0]["timeline"]
        }
        self.assertIn("AUTH-007", timeline_ids)
        self.assertNotIn("AUTH-008", timeline_ids)
        self.assertNotIn("PROC-005", timeline_ids)

    def test_report_mentions_incident(self):
        report = build_report(self.incidents, self.alerts)
        self.assertIn("INC-001", report)
        self.assertIn("WS-FIN-023", report)


if __name__ == "__main__":
    unittest.main()
