import json
import tempfile
import unittest
from pathlib import Path

from src.detections import (
    detect_audit_logging_impairment,
    detect_privileged_api_fanout,
    detect_privileged_login_without_mfa,
    detect_public_storage_change,
    run_detections,
)
from src.io import load_events
from src.models import CloudEvent
from src.reporting import posture_score, render_markdown


def event(**overrides):
    base = {
        "event_id": "e1",
        "timestamp": "2026-09-09T10:00:00Z",
        "provider": "aws",
        "actor": "admin@example.test",
        "action": "ConsoleLogin",
        "source_ip": "203.0.113.5",
        "region": "eu-west-1",
        "resource": "account",
        "outcome": "success",
        "mfa": False,
        "privileged": True,
    }
    base.update(overrides)
    return CloudEvent.from_dict(base)


class DetectionTests(unittest.TestCase):
    def test_privileged_login_without_mfa(self):
        self.assertEqual(len(detect_privileged_login_without_mfa([event()])), 1)

    def test_mfa_login_is_not_flagged(self):
        self.assertEqual(detect_privileged_login_without_mfa([event(mfa=True)]), [])

    def test_logging_impairment(self):
        self.assertEqual(len(detect_audit_logging_impairment([event(action="StopLogging")])), 1)

    def test_public_storage_change(self):
        self.assertEqual(len(detect_public_storage_change([event(action="PutBucketPolicy:Public")])), 1)

    def test_region_fanout(self):
        events = [event(event_id=f"e{i}", region=region, timestamp=f"2026-09-09T10:0{i}:00Z", action="AdminAPI") for i, region in enumerate(["eu-west-1", "us-east-1", "ap-southeast-1"], 1)]
        self.assertEqual(len(detect_privileged_api_fanout(events)), 1)

    def test_duplicate_ids_fail_closed(self):
        records = [
            {"event_id":"dup","timestamp":"2026-09-09T10:00:00Z","provider":"aws","actor":"a","action":"x","source_ip":"203.0.113.1","region":"r1","resource":"r","outcome":"success"},
            {"event_id":"dup","timestamp":"2026-09-09T10:01:00Z","provider":"aws","actor":"a","action":"y","source_ip":"203.0.113.1","region":"r1","resource":"r","outcome":"success"}
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(json.dumps(records), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_events(path)

    def test_unsupported_provider_rejected(self):
        with self.assertRaises(ValueError):
            event(provider="other")

    def test_reporting_contains_evidence(self):
        findings = run_detections([event()])
        report = render_markdown(findings)
        self.assertIn("CLD-001", report)
        self.assertIn("e1", report)
        self.assertLess(posture_score(findings), 100)


if __name__ == "__main__":
    unittest.main()
