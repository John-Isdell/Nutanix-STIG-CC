import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import supervisor_setup  # noqa: E402


class SupervisorRegistrationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "Nutanix STIG Control Center"
        self.root.mkdir()
        (self.root / "supervisor.py").write_text("# test\n", encoding="utf-8")
        self.python = self.base / "Python 3" / "python"
        self.python.parent.mkdir()
        self.python.write_text("", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_windows_task_is_per_user_on_logon_and_least_privilege(self):
        command = supervisor_setup.windows_task_command(
            self.root,
            self.python,
            username="DOMAIN\\operator",
        )
        self.assertEqual(command[0], "schtasks.exe")
        self.assertIn(supervisor_setup.WINDOWS_TASK_NAME, command)
        self.assertEqual(command[command.index("/SC") + 1], "ONLOGON")
        self.assertEqual(command[command.index("/RU") + 1], "DOMAIN\\operator")
        self.assertEqual(command[command.index("/RL") + 1], "LIMITED")
        self.assertIn("/IT", command)
        action = command[command.index("/TR") + 1]
        self.assertIn(str(self.root / "supervisor.py"), action)

    def test_windows_task_acl_keeps_runtime_limited_but_user_manageable(self):
        command = supervisor_setup.windows_task_security_command(
            username="DOMAIN\\operator",
        )
        script = command[command.index("-Command") + 1]
        self.assertIn("SetSecurityDescriptor", script)
        self.assertIn("(A;;GA;;;SY)", script)
        self.assertIn("(A;;GA;;;BA)", script)
        self.assertEqual(command[-1], "DOMAIN\\operator")

    def test_windows_installer_requests_one_time_elevation(self):
        installer = (ROOT / "Install-Control-Center.cmd").read_text(
            encoding="utf-8"
        )
        self.assertIn("-Verb RunAs", installer)
        self.assertIn("--elevated", installer)
        self.assertIn("fltmc.exe", installer)

    def test_failed_windows_removal_preserves_registration_marker(self):
        marker_path = supervisor_setup.registration_file(self.root)
        marker_path.parent.mkdir(parents=True)
        marker_path.write_text(
            '{"platform":"Windows","kind":"Scheduled Task"}',
            encoding="utf-8",
        )
        with mock.patch.object(
            supervisor_setup,
            "_run",
            side_effect=supervisor_setup.SupervisorSetupError("denied"),
        ):
            with self.assertRaises(supervisor_setup.SupervisorSetupError):
                supervisor_setup.unregister_supervisor(
                    self.root,
                    platform_name="Windows",
                )
        self.assertTrue(marker_path.exists())

    def test_partial_windows_registration_is_rolled_back(self):
        commands = []

        def fake_run(command, label, progress=None, check=True):
            commands.append(command)
            if label == "Windows Scheduled Task permission assignment":
                raise supervisor_setup.SupervisorSetupError("ACL failed")
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(supervisor_setup, "_run", side_effect=fake_run):
            with self.assertRaises(supervisor_setup.SupervisorSetupError):
                supervisor_setup.register_supervisor(
                    self.root,
                    self.python,
                    platform_name="Windows",
                )
        self.assertTrue(
            any("/Delete" in command for command in commands),
        )
        self.assertFalse(
            supervisor_setup.registration_file(self.root).exists(),
        )

    def test_macos_launch_agent_is_user_scoped_and_keepalive(self):
        definition = supervisor_setup.macos_launch_agent(self.root, self.python)
        encoded = plistlib.dumps(definition)
        decoded = plistlib.loads(encoded)
        self.assertEqual(decoded["Label"], supervisor_setup.MACOS_LABEL)
        self.assertTrue(decoded["RunAtLoad"])
        self.assertEqual(decoded["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(decoded["WorkingDirectory"], str(self.root))
        self.assertIn(str(self.root / "supervisor.py"), decoded["ProgramArguments"])

    def test_linux_systemd_unit_is_user_service_with_restart_policy(self):
        unit = supervisor_setup.linux_systemd_unit(self.root, self.python)
        self.assertIn("WantedBy=default.target", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("supervisor.py", unit)
        self.assertIn("WorkingDirectory=", unit)

    def test_distribution_has_exactly_one_installer_per_os(self):
        expected = {
            "Install-Control-Center.cmd",
            "Install-Control-Center.command",
            "install.sh",
        }
        present = {
            path.name
            for path in ROOT.iterdir()
            if path.name.startswith(
                ("Install-Control-Center", "Start-Control-Center", "Stop-Control-Center",
                 "Status-Control-Center", "Repair-Control-Center")
            )
            or path.name in {"install.sh", "start.sh", "stop.sh", "status.sh"}
        }
        self.assertEqual(present, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
