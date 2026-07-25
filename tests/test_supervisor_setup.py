import json
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

    def test_windows_startup_shortcut_is_per_user(self):
        shortcut_path = supervisor_setup.windows_startup_shortcut_path(
            self.base
        )
        command = supervisor_setup.windows_startup_shortcut_command(
            self.root,
            self.python,
            shortcut_path,
        )
        self.assertEqual(command[0], "powershell.exe")
        self.assertIn(
            str(
                self.base
                / "AppData"
                / "Roaming"
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "Startup"
            ),
            str(shortcut_path),
        )
        script = command[command.index("-Command") + 1]
        self.assertIn("WScript.Shell", script)
        self.assertIn("CreateShortcut", script)
        self.assertIn(str(shortcut_path), script)
        self.assertIn(str(self.root / "supervisor.py"), script)

    def test_windows_installer_does_not_request_elevation(self):
        installer = (ROOT / "Install-Control-Center.cmd").read_text(
            encoding="utf-8"
        )
        registration = (ROOT / "supervisor_setup.py").read_text(
            encoding="utf-8"
        )
        windows_install_code = installer + registration
        for forbidden in (
            "-Verb RunAs",
            "--elevated",
            "fltmc.exe",
            "schtasks.exe",
            "Scheduled Task",
        ):
            self.assertNotIn(forbidden, windows_install_code)
        self.assertIn("Startup folder", installer)

    def test_failed_windows_shortcut_removal_preserves_registration_marker(self):
        marker_path = supervisor_setup.registration_file(self.root)
        marker_path.parent.mkdir(parents=True)
        shortcut_path = supervisor_setup.windows_startup_shortcut_path(
            self.base
        )
        marker_path.write_text(
            json.dumps(
                {
                    "platform": "Windows",
                    "kind": "Startup-folder shortcut",
                    "path": str(shortcut_path),
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.object(
            supervisor_setup,
            "_unlink",
            side_effect=PermissionError("denied"),
        ):
            with self.assertRaises(supervisor_setup.SupervisorSetupError):
                supervisor_setup.unregister_supervisor(
                    self.root,
                    platform_name="Windows",
                )
        self.assertTrue(marker_path.exists())

    def test_partial_windows_shortcut_registration_is_rolled_back(self):
        shortcut_path = supervisor_setup.windows_startup_shortcut_path(
            self.base
        )
        with (
            mock.patch.object(
                supervisor_setup,
                "_run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            mock.patch.object(supervisor_setup, "_start_windows_supervisor"),
            mock.patch.object(
                supervisor_setup,
                "wait_for_supervisor",
                side_effect=supervisor_setup.SupervisorSetupError(
                    "start failed"
                ),
            ),
        ):
            with self.assertRaises(supervisor_setup.SupervisorSetupError):
                supervisor_setup.register_supervisor(
                    self.root,
                    self.python,
                    platform_name="Windows",
                    home=self.base,
                )
        self.assertFalse(shortcut_path.exists())
        self.assertFalse(
            supervisor_setup.registration_file(self.root).exists(),
        )

    def test_windows_unregister_removes_shortcut_and_marker(self):
        shortcut_path = supervisor_setup.windows_startup_shortcut_path(
            self.base
        )
        shortcut_path.parent.mkdir(parents=True)
        shortcut_path.write_text("shortcut", encoding="utf-8")
        marker_path = supervisor_setup.registration_file(self.root)
        marker_path.parent.mkdir(parents=True)
        marker_path.write_text(
            json.dumps(
                {
                    "platform": "Windows",
                    "kind": "Startup-folder shortcut",
                    "path": str(shortcut_path),
                }
            ),
            encoding="utf-8",
        )

        supervisor_setup.unregister_supervisor(
            self.root,
            platform_name="Windows",
            home=self.base,
        )

        self.assertFalse(shortcut_path.exists())
        self.assertFalse(marker_path.exists())

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
        systemd_root = supervisor_setup._systemd_path(self.root)
        self.assertIn(f"WorkingDirectory={systemd_root}", unit)
        self.assertNotIn(f'WorkingDirectory="{systemd_root}"', unit)

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
