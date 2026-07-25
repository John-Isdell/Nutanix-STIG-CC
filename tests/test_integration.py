import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path

WORK_DIR = Path(__file__).parent
APP_DIR = WORK_DIR.parent / "app"
sys.path.insert(0, str(WORK_DIR))
sys.path.insert(0, str(APP_DIR))

import server  # noqa: E402
from test_engine import MockSSHListener, MockState  # noqa: E402


def operation_payload(
    ssh_port,
    *,
    pc_host="",
    pc_port=22,
    scopes=None,
):
    return {
        "cluster_host": "127.0.0.1",
        "ssh_port": ssh_port,
        "username": "nutanix",
        "auth_method": "password",
        "password": "mock-password",
        "private_key": "",
        "key_passphrase": "",
        "pc_host": pc_host,
        "pc_port": pc_port,
        "pc_username": "nutanix",
        "profile": "STIG_STANDARD",
        "scopes": scopes or ["cvm", "ahv"],
        "full_health_check": False,
        "command_timeout": 30,
        "verification_timeout": 0,
        "verification_interval": 1,
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
        "api_auth_method": "api_key",
        "api_username": "",
        "api_password": "",
        "api_key": "operation-api-key-must-be-cleared",
        "api_ca_pem": "",
        "api_cluster_ext_id": "",
    }


class ControlCenterEngineIntegrationTest(unittest.TestCase):
    def test_web_job_reaches_mock_cvm_and_dry_run_makes_no_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            server.DATA_DIR = data_dir
            server.RUNS_DIR = data_dir / "runs"
            server.RUNS_DIR.mkdir()
            server.KNOWN_HOSTS = data_dir / "known_hosts"
            server.STATE_FILE = data_dir / "state.json"
            server.AUDIT_FILE = data_dir / "audit.json"
            server.jobs.clear()
            server.current_job_id = None

            mock_state = MockState()
            mock = MockSSHListener(mock_state).start()
            mock.write_known_hosts(str(server.KNOWN_HOSTS))
            payload = operation_payload(mock.port)
            try:
                job = server.begin_job(payload, "DRY_RUN")
                deadline = time.time() + 30
                while server.jobs[job["id"]]["status"] == "running" and time.time() < deadline:
                    time.sleep(0.1)
                completed = server.jobs[job["id"]]
            finally:
                mock.close()

            self.assertEqual(completed["status"], "succeeded", completed)
            self.assertTrue(any(command == "ncli cluster info" for command in mock_state.commands))
            self.assertFalse(
                any(" edit-" in command and "=" in command for command in mock_state.commands)
            )
            evidence = server.RUNS_DIR / job["id"] / completed["evidence_file"]
            self.assertTrue(evidence.is_file())
            operation = server.RUNS_DIR / job["id"] / "operation.json"
            self.assertNotIn(
                "operation-api-key-must-be-cleared",
                operation.read_text(encoding="utf-8"),
            )
            self.assertEqual(payload["api_key"], "")

    def test_web_job_reports_reachable_cluster_and_unreachable_pcvm(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            server.DATA_DIR = data_dir
            server.RUNS_DIR = data_dir / "runs"
            server.RUNS_DIR.mkdir()
            server.KNOWN_HOSTS = data_dir / "known_hosts"
            server.STATE_FILE = data_dir / "state.json"
            server.AUDIT_FILE = data_dir / "audit.json"
            server.jobs.clear()
            server.current_job_id = None

            mock_state = MockState()
            mock = MockSSHListener(mock_state).start()
            mock.write_known_hosts(str(server.KNOWN_HOSTS))
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
            probe.close()
            payload = operation_payload(
                mock.port,
                pc_host="127.0.0.1",
                pc_port=closed_port,
                scopes=["cvm", "ahv", "pcvm"],
            )
            try:
                job = server.begin_job(payload, "DRY_RUN")
                deadline = time.time() + 30
                while (
                    server.jobs[job["id"]]["status"] == "running"
                    and time.time() < deadline
                ):
                    time.sleep(0.1)
                completed = server.jobs[job["id"]]
            finally:
                mock.close()

            self.assertEqual(completed["status"], "failed", completed)
            self.assertEqual(completed["return_code"], 2)
            self.assertEqual(completed["failure"], "")
            self.assertIsNone(completed["report"].get("fatal_error"))
            targets = completed["report"]["targets"]
            self.assertEqual(
                [(target["type"], target["status"]) for target in targets],
                [
                    ("cluster", "complete"),
                    ("prism_central", "connection_failed"),
                ],
            )
            self.assertIn("SSH connection", targets[1]["error"])
            self.assertTrue(targets[1]["report_path"])
            self.assertTrue(targets[1]["csv_log"])
            saved_state = server.load_json(server.STATE_FILE, {})
            self.assertFalse(saved_state["latest_dry_run"]["apply_ready"])
            evidence = server.RUNS_DIR / job["id"] / completed["evidence_file"]
            self.assertTrue(evidence.is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
