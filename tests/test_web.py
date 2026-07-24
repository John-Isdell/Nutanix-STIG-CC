import json
import sys
import tempfile
import unittest
from pathlib import Path

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
        server.AUDIT_FILE = data / "audit.json"
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
            "api_username": "",
            "api_password": "also-never-persist",
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
        state = json.loads(saved)
        self.assertFalse(state["active_cluster"]["credentials_saved"])

    def test_second_cluster_is_rejected_until_context_is_closed(self):
        self.assertEqual(
            self.post("/api/configuration/activate", self.payload()).status_code, 200
        )
        different = self.payload()
        different["cluster_host"] = "10.40.20.16"
        response = self.post("/api/configuration/activate", different)
        self.assertEqual(response.status_code, 409)

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
