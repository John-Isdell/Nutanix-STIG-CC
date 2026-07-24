import json
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import supervisor  # noqa: E402


class SupervisorHTTPTests(unittest.TestCase):
    def setUp(self):
        supervisor.JOBS.clear()
        supervisor.CURRENT_JOB_ID = None
        supervisor.LAST_ERROR = ""
        supervisor.DEPENDENCY_CACHE = {"checked_at": 0.0, "ready": False}
        self.patches = [
            mock.patch.object(
                supervisor.control_center,
                "dependencies_work",
                return_value=True,
            ),
            mock.patch.object(
                supervisor.control_center,
                "running_state",
                return_value=(None, None),
            ),
            mock.patch.object(
                supervisor.supervisor_setup,
                "registration_status",
                return_value={
                    "kind": "test user service",
                    "registered_at": "2026-07-24T00:00:00+00:00",
                },
            ),
        ]
        for patch in self.patches:
            patch.start()
        self.server = supervisor.SupervisorHTTPServer(
            ("127.0.0.1", 0),
            supervisor.SupervisorHandler,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        for patch in reversed(self.patches):
            patch.stop()

    def get_json(self, path):
        request = Request(
            self.url + path,
            headers={"Accept": "application/json"},
        )
        with urlopen(request, timeout=3) as response:
            return response.status, json.load(response)

    def post_json(self, path, csrf=None):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = Request(
            self.url + path,
            method="POST",
            data=b"{}",
            headers=headers,
        )
        with urlopen(request, timeout=3) as response:
            return response.status, json.load(response)

    def test_health_and_bootstrap_are_local_and_report_stopped(self):
        status, health = self.get_json("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(health["supervisor"])
        self.assertTrue(health["local_only"])
        status, bootstrap = self.get_json("/api/bootstrap")
        self.assertEqual(status, 200)
        self.assertEqual(bootstrap["status"]["state"], "Stopped")
        self.assertTrue(bootstrap["status"]["dependencies_ready"])
        self.assertTrue(bootstrap["status"]["registration"]["registered"])

    def test_state_changing_action_requires_csrf(self):
        with self.assertRaises(HTTPError) as context:
            self.post_json("/api/actions/start")
        self.assertEqual(context.exception.code, 403)

    def test_remote_host_header_is_rejected(self):
        request = Request(
            self.url + "/api/health",
            headers={"Host": "example.invalid"},
        )
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=3)
        self.assertEqual(context.exception.code, 403)

    def test_untrusted_origin_is_rejected(self):
        _, bootstrap = self.get_json("/api/bootstrap")
        request = Request(
            self.url + "/api/actions/start",
            method="POST",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": bootstrap["csrf"],
                "Origin": "https://example.invalid",
            },
        )
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=3)
        self.assertEqual(context.exception.code, 403)

    def test_action_job_is_polled_to_completion_with_progress(self):
        _, bootstrap = self.get_json("/api/bootstrap")

        def fake_action(action, job_id):
            supervisor.add_progress(job_id, "Starting verified test service.")
            return {"message": f"{action} complete", "url": "http://127.0.0.1:5555"}

        with mock.patch.object(supervisor, "execute_action", side_effect=fake_action):
            status, job = self.post_json(
                "/api/actions/start",
                csrf=bootstrap["csrf"],
            )
            self.assertEqual(status, 202)
            deadline = time.time() + 3
            while time.time() < deadline:
                _, current = self.get_json(f"/api/jobs/{job['id']}")
                if current["status"] in {"succeeded", "failed"}:
                    break
                time.sleep(0.02)
        self.assertEqual(current["status"], "succeeded")
        self.assertEqual(current["result"]["url"], "http://127.0.0.1:5555")
        self.assertTrue(
            any("verified test service" in item["message"] for item in current["progress"])
        )

    def test_package_repository_credentials_are_redacted(self):
        value = supervisor.redact(
            "Downloading https://operator:secret-token@packages.example.test/simple"
        )
        self.assertNotIn("operator", value)
        self.assertNotIn("secret-token", value)
        self.assertIn("[redacted]:[redacted]", value)

    def test_uninstall_verifies_registration_removal_before_success(self):
        with mock.patch.object(
            supervisor.control_center,
            "stop_service",
        ) as stop:
            with mock.patch.object(
                supervisor.supervisor_setup,
                "unregister_supervisor",
            ) as unregister:
                result = supervisor.execute_action("uninstall", "test-job")
        stop.assert_called_once()
        unregister.assert_called_once_with(
            supervisor.ROOT,
            progress=mock.ANY,
            stop_running=False,
        )
        self.assertTrue(result["uninstall_ready"])
        self.assertIn("registration was removed", result["message"])

    def test_completed_job_history_is_bounded(self):
        for number in range(supervisor.MAX_JOBS):
            supervisor.JOBS[f"old-{number}"] = {
                "id": f"old-{number}",
                "status": "succeeded",
            }
        with mock.patch.object(supervisor.threading, "Thread") as thread:
            job = supervisor.begin_job("start", self.server)
        self.assertEqual(len(supervisor.JOBS), supervisor.MAX_JOBS)
        self.assertNotIn("old-0", supervisor.JOBS)
        self.assertIn(job["id"], supervisor.JOBS)
        thread.return_value.start.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
