import json
import sys
import tempfile
import unittest
from pathlib import Path

APP_DIR = Path(__file__).parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

from audit_log import AuditIntegrityError, AuditLedger  # noqa: E402


class AuditLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ledger = AuditLedger(self.root / "audit")

    def tearDown(self):
        self.temporary.cleanup()

    def append(self, index=1, **overrides):
        values = {
            "actor_id": "local-session:test",
            "source": "test",
            "action": "operation.completed",
            "target_host": "10.40.20.15",
            "result": "succeeded",
            "details": {"job_id": f"job-{index}"},
        }
        values.update(overrides)
        return self.ledger.append(**values)

    def test_ledger_is_append_only_without_a_500_record_cap(self):
        for index in range(525):
            self.append(index)
        entries = self.ledger.query(host="10.40.20.15", limit=1000)
        self.assertEqual(len(entries), 525)
        self.assertEqual(entries[0]["sequence"], 525)
        self.assertTrue(self.ledger.verify()["ok"])

    def test_secrets_are_redacted_recursively(self):
        self.append(
            details={
                "username": "nutanix",
                "password": "do-not-store",
                "nested": {
                    "api_key": "do-not-store-either",
                    "typed_confirmation": "APPLY 10.40.20.15",
                },
            }
        )
        serialized = json.dumps(self.ledger.query(limit=10))
        self.assertNotIn("do-not-store", serialized)
        self.assertNotIn("APPLY 10.40.20.15", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_modified_entry_breaks_hash_chain_and_locks_append(self):
        self.append(1)
        self.append(2)
        ledger_file = next((self.root / "audit").glob("audit-*.jsonl"))
        lines = ledger_file.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["details"]["job_id"] = "tampered"
        lines[0] = json.dumps(first, sort_keys=True)
        ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verification = self.ledger.verify()
        self.assertFalse(verification["ok"])
        self.assertIn("hash mismatch", verification["problems"][0].lower())
        with self.assertRaises(AuditIntegrityError):
            self.append(3)

    def test_tail_deletion_is_detected_against_chain_state(self):
        self.append(1)
        self.append(2)
        ledger_file = next((self.root / "audit").glob("audit-*.jsonl"))
        first_line = ledger_file.read_text(encoding="utf-8").splitlines()[0]
        ledger_file.write_text(first_line + "\n", encoding="utf-8")
        verification = self.ledger.verify()
        self.assertFalse(verification["ok"])
        self.assertIn("tail", verification["problems"][0].lower())

    def test_daily_rotation_preserves_one_global_chain(self):
        self.ledger.update_settings(3650, "daily")
        self.append(1, timestamp="2026-07-23T12:00:00+00:00")
        self.append(2, timestamp="2026-07-24T12:00:00+00:00")
        files = list((self.root / "audit").glob("audit-*.jsonl"))
        self.assertEqual(len(files), 2)
        self.assertTrue(self.ledger.verify()["ok"])

    def test_rotation_setting_change_does_not_reorder_the_chain(self):
        self.ledger.update_settings(3650, "daily")
        self.append(1, timestamp="2026-07-23T12:00:00+00:00")
        self.ledger.update_settings(3650, "monthly")
        self.append(2, timestamp="2026-07-24T12:00:00+00:00")
        self.assertTrue(self.ledger.verify()["ok"])
        self.assertEqual(
            [entry["sequence"] for entry in self.ledger.query(limit=10)],
            [2, 1],
        )

    def test_missing_chain_state_is_detected_before_append(self):
        self.append(1)
        self.ledger.state_file.unlink()
        self.assertFalse(self.ledger.verify()["ok"])
        with self.assertRaises(AuditIntegrityError):
            self.append(2)

    def test_query_filters_by_host_action_result_and_date(self):
        self.append(
            1,
            action="connection.ssh_tested",
            timestamp="2026-07-23T12:00:00+00:00",
        )
        self.append(
            2,
            action="operation.completed",
            result="failed",
            timestamp="2026-07-24T12:00:00+00:00",
        )
        entries = self.ledger.query(
            host="10.40.20.15",
            action="operation",
            result="failed",
            date_from="2026-07-24T00:00:00+00:00",
            date_to="2026-07-24T23:59:59+00:00",
        )
        self.assertEqual([entry["sequence"] for entry in entries], [2])

    def test_legacy_array_is_migrated_without_rewriting_the_new_ledger(self):
        legacy_file = self.root / "audit.json"
        legacy_file.write_text(
            json.dumps(
                [
                    {
                        "id": "old-job",
                        "cluster_host": "10.40.20.15",
                        "status": "succeeded",
                        "mode": "DRY_RUN",
                        "completed_at": "2026-07-20T12:00:00+00:00",
                    }
                ]
            ),
            encoding="utf-8",
        )
        ledger = AuditLedger(self.root / "migrated-audit", legacy_file)
        self.assertEqual(ledger.migrate_legacy(), 1)
        entries = ledger.query(limit=10)
        self.assertEqual(entries[0]["actor_id"], "legacy-import")
        self.assertEqual(entries[0]["details"]["job_id"], "old-job")
        self.assertTrue(ledger.verify()["ok"])
        self.assertTrue((self.root / "audit.legacy-migrated.json").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
