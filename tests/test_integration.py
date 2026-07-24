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
            payload = {
                "cluster_host": "127.0.0.1",
                "ssh_port": mock.port,
                "username": "nutanix",
                "auth_method": "password",
                "password": "mock-password",
                "private_key": "",
                "key_passphrase": "",
                "pc_host": "",
                "pc_port": 22,
                "pc_username": "nutanix",
                "profile": "STIG_STANDARD",
                "scopes": ["cvm", "ahv"],
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
                "api_username": "",
                "api_password": "",
                "api_ca_pem": "",
                "api_cluster_ext_id": "",
            }
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
