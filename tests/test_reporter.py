import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from reporter import REPORT_DIR, build_report, save_report  # noqa: E402


class TestBuildReport(unittest.TestCase):
    def test_no_incidents_says_no_action_needed(self):
        report = build_report([], [])
        self.assertIn("Incidents after correlation: 0", report)
        self.assertIn("No incidents identified", report)

    def test_pipe_characters_are_escaped_in_timeline(self):
        incident = {
            "incident_id": "INC-001",
            "severity": "HIGH",
            "computer": "HOST-1",
            "accounts": ["bob"],
            "start": "2026-01-01T10:00:00Z",
            "end": "2026-01-01T10:05:00Z",
            "evidence_sources": ["process"],
            "alert_count": 0,
            "stages": [],
            "alerts": [],
            "timeline": [{
                "timestamp": "2026-01-01T10:00:00Z",
                "source": "process",
                "event_id": "P1",
                "summary": "bob ran: dir | findstr secret",
            }],
        }
        report = build_report([incident], [])
        self.assertIn("dir \\| findstr", report)


class TestSaveReport(unittest.TestCase):
    def test_default_location_is_output_folder(self):
        self.assertEqual(REPORT_DIR.name, "output")

    def test_writes_markdown_and_json(self):
        incidents = [{"incident_id": "INC-001", "severity": "HIGH"}]

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "new_folder"
            markdown_path, json_path = save_report(
                "# Report\n", incidents, report_dir=report_dir
            )

            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"), "# Report\n"
            )
            self.assertEqual(
                json.loads(json_path.read_text(encoding="utf-8")),
                incidents,
            )


if __name__ == "__main__":
    unittest.main()
