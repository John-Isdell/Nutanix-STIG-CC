import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

APP_DIR = Path(__file__).parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

import server  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class ControlCenterSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        data = Path(self.temp.name)
        server.DATA_DIR = data
        server.RUNS_DIR = data / "runs"
        server.RUNS_DIR.mkdir()
        server.KNOWN_HOSTS = data / "known_hosts"
        server.KNOWN_HOSTS.touch()
        server.STATE_FILE = data / "state.json"
        server.sessions.clear()
        server.jobs.clear()
        server.pending_host_keys.clear()
        server.current_job_id = None
        self.client = TestClient(server.app, base_url="http://127.0.0.1")
        bootstrap = self.client.get("/api/bootstrap")
        self.assertEqual(bootstrap.status_code, 200)
        self.csrf = bootstrap.json()["csrf"]

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def payload(self):
        return {
            "cluster_host": "10.40.20.15",
            "ssh_port": 22,
            "username": "nutanix",
            "auth_method": "password",
            "password": "never-persist-this",
            "private_key": "",
            "key_passphrase": "",
            "pc_host": "",
            "pc_port": 22,
            "pc_username": "nutanix",
            "profile": "STIG_STANDARD",
            "scopes": ["cvm", "ahv"],
            "full_health_check": True,
            "command_timeout": 300,
            "verification_timeout": 120,
            "verification_interval": 10,
            "min_name_servers": 2,
            "min_ntp_servers": 2,
            "syslog_enabled": False,
            "syslog_server_name": "SIEM01",
            "syslog_server_ip": "",
            "syslog_port": 514,
            "syslog_protocol": "tcp",
            "syslog_relp": True,
            "syslog_modules": "AUDIT,API_AUDIT,PRISM",
            "api_enabled": False,
            "api_host": "",
            "api_port": 9440,
            "api_auth_method": "basic",
            "api_username": "",
            "api_password": "also-never-persist",
            "api_key": "api-key-never-persist",
            "api_ca_pem": "",
            "api_cluster_ext_id": "",
        }

    def post(self, path, payload):
        return self.client.post(
            path,
            headers={"X-CSRF-Token": self.csrf},
            json=payload,
        )

    def test_local_health_and_remote_host_header_is_blocked(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        blocked = self.client.get(
            "/api/health", headers={"host": "workstation.example.test"}
        )
        self.assertEqual(blocked.status_code, 403)

    def test_configuration_never_persists_credentials(self):
        response = self.post("/api/configuration/activate", self.payload())
        self.assertEqual(response.status_code, 200, response.text)
        saved = server.STATE_FILE.read_text(encoding="utf-8")
        self.assertNotIn("never-persist-this", saved)
        self.assertNotIn("also-never-persist", saved)
        self.assertNotIn("api-key-never-persist", saved)
        state = json.loads(saved)
        self.assertFalse(state["active_cluster"]["credentials_saved"])
        audit_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (server.DATA_DIR / "audit").glob("audit-*.jsonl")
        )
        self.assertNotIn("never-persist-this", audit_text)
        self.assertNotIn("also-never-persist", audit_text)
        self.assertNotIn("api-key-never-persist", audit_text)

    def test_audit_api_filters_exports_and_reports_integrity(self):
        response = self.post("/api/configuration/activate", self.payload())
        self.assertEqual(response.status_code, 200, response.text)
        filtered = self.client.get(
            "/api/audit",
            params={
                "host": self.payload()["cluster_host"],
                "action": "configuration",
                "result": "succeeded",
            },
        )
        self.assertEqual(filtered.status_code, 200, filtered.text)
        body = filtered.json()
        self.assertTrue(body["integrity"]["ok"])
        self.assertEqual(len(body["entries"]), 1)
        self.assertEqual(body["entries"][0]["action"], "configuration.activated")

        json_export = self.client.get(
            "/api/audit/export",
            params={"format": "json", "host": self.payload()["cluster_host"]},
        )
        self.assertEqual(json_export.status_code, 200)
        self.assertIn("attachment;", json_export.headers["content-disposition"])
        self.assertTrue(json_export.json()["integrity"]["ok"])

        csv_export = self.client.get(
            "/api/audit/export",
            params={"format": "csv", "host": self.payload()["cluster_host"]},
        )
        self.assertEqual(csv_export.status_code, 200)
        self.assertIn("configuration.activated", csv_export.text)

    def test_audit_settings_are_operator_configurable_and_audited(self):
        response = self.post(
            "/api/audit/settings",
            {"retention_days": 730, "rotation": "daily"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json()["settings"],
            {"retention_days": 730, "rotation": "daily"},
        )
        audit = self.client.get("/api/audit", params={"action": "audit.settings"})
        self.assertEqual(audit.status_code, 200)
        self.assertEqual(audit.json()["entries"][0]["action"], "audit.settings_updated")

    def test_tampered_audit_ledger_locks_security_actions(self):
        ledger_file = next((server.DATA_DIR / "audit").glob("audit-*.jsonl"))
        entry = json.loads(ledger_file.read_text(encoding="utf-8").splitlines()[0])
        entry["details"]["local_only"] = False
        ledger_file.write_text(json.dumps(entry) + "\n", encoding="utf-8")

        audit = self.client.get("/api/audit", params={"host": "*"})
        self.assertEqual(audit.status_code, 200)
        self.assertFalse(audit.json()["integrity"]["ok"])

        response = self.post("/api/configuration/activate", self.payload())
        self.assertEqual(response.status_code, 503)
        self.assertFalse(server.STATE_FILE.exists())
        server.sessions.clear()
        restarted = self.client.get("/api/bootstrap")
        self.assertEqual(restarted.status_code, 200)
        self.assertIn("integrity", restarted.json()["audit_warning"].lower())

    def test_v4_basic_auth_uses_http_basic_without_api_key_header(self):
        captured = {}

        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {"data": [{"name": "Cluster A", "extId": "cluster-a"}]}

        class Client:
            def __init__(self, **kwargs):
                captured["options"] = kwargs

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def get(self, url, params):
                captured["url"] = url
                captured["params"] = params
                return Response()

        payload = {
            "api_host": "pc.example.test",
            "api_port": 9440,
            "api_auth_method": "basic",
            "api_username": "viewer",
            "api_password": "basic-secret",
            "api_key": "",
            "api_ca_pem": "",
        }
        with patch.object(server.httpx, "Client", Client):
            response = self.post("/api/v4/cluster-identity", payload)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(captured["options"]["auth"], ("viewer", "basic-secret"))
        self.assertNotIn("headers", captured["options"])
        self.assertEqual(response.json()["auth_method"], "basic")

    def test_v4_api_key_uses_only_nutanix_api_key_header(self):
        captured = {}

        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {"data": [{"name": "Cluster A", "extId": "cluster-a"}]}

        class Client:
            def __init__(self, **kwargs):
                captured["options"] = kwargs

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def get(self, url, params):
                captured["url"] = url
                captured["params"] = params
                return Response()

        payload = {
            "api_host": "pc.example.test",
            "api_port": 9440,
            "api_auth_method": "api_key",
            "api_username": "must-not-be-used",
            "api_password": "must-not-be-used",
            "api_key": "one-time-secret",
            "api_ca_pem": "",
        }
        with patch.object(server.httpx, "Client", Client):
            response = self.post("/api/v4/cluster-identity", payload)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            captured["options"]["headers"],
            {"X-Ntnx-Api-Key": "one-time-secret"},
        )
        self.assertNotIn("auth", captured["options"])
        self.assertEqual(response.json()["auth_method"], "api_key")

    def test_v4_auth_method_requires_only_its_selected_credential(self):
        missing_key = self.post(
            "/api/v4/cluster-identity",
            {
                "api_host": "pc.example.test",
                "api_auth_method": "api_key",
                "api_username": "unused",
                "api_password": "unused",
                "api_key": "",
            },
        )
        self.assertEqual(missing_key.status_code, 422)
        self.assertNotIn("unused", missing_key.text)

        missing_basic = self.post(
            "/api/v4/cluster-identity",
            {
                "api_host": "pc.example.test",
                "api_auth_method": "basic",
                "api_username": "",
                "api_password": "",
                "api_key": "unused-key",
            },
        )
        self.assertEqual(missing_basic.status_code, 422)
        self.assertNotIn("unused-key", missing_basic.text)

    def test_second_cluster_is_rejected_until_context_is_closed(self):
        self.assertEqual(
            self.post("/api/configuration/activate", self.payload()).status_code, 200
        )
        different = self.payload()
        different["cluster_host"] = "10.40.20.16"
        response = self.post("/api/configuration/activate", different)
        self.assertEqual(response.status_code, 409)
        denied = self.client.get(
            "/api/audit",
            params={"host": "*", "action": "configuration", "result": "denied"},
        ).json()["entries"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["target_host"], "10.40.20.16")

    def test_apply_requires_matching_successful_gate_and_confirmation(self):
        payload = self.payload()
        fingerprint = server.config_fingerprint(payload)
        state = server.active_state()
        state["active_cluster"] = server.sanitize_config(payload)
        state["latest_dry_run"] = {
            "apply_ready": True,
            "configuration_fingerprint": fingerprint,
            "cluster_host": payload["cluster_host"],
        }
        server.write_state(state)
        approved = {
            **payload,
            "approval_id": "CHG012345",
            "typed_confirmation": f"APPLY {payload['cluster_host']}",
            "ack_backup": True,
            "ack_window": True,
            "ack_authorized": True,
        }
        server.validate_apply(approved)
        approved["scopes"] = ["cvm"]
        with self.assertRaises(server.HTTPException) as context:
            server.validate_apply(approved)
        self.assertEqual(context.exception.status_code, 409)

    def test_rollback_preview_and_apply_share_a_bound_fingerprint(self):
        preview = {
            **self.payload(),
            "source_job_id": "0123456789abcdef",
            "manifest_name": "rollback.json",
            "apply_rollback": False,
            "approval_id": "",
            "typed_confirmation": "",
            "ack_backup": False,
            "ack_window": False,
            "ack_authorized": False,
        }
        apply = {
            **preview,
            "apply_rollback": True,
            "approval_id": "CHG-ROLLBACK-01",
            "typed_confirmation": "ROLLBACK 10.40.20.15",
            "ack_backup": True,
            "ack_window": True,
            "ack_authorized": True,
        }
        self.assertEqual(
            server.config_fingerprint(preview), server.config_fingerprint(apply)
        )
        server.validate_authorization(apply, "ROLLBACK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
