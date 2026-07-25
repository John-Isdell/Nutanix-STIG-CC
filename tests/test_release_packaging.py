import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
MODULE_PATH = ROOT / "scripts" / "build_release.py"
SPEC = importlib.util.spec_from_file_location("release_builder", MODULE_PATH)
release_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_builder)


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name)
        self.artifacts = release_builder.build_release("1.2.0", self.output)

    def tearDown(self):
        self.temp.cleanup()

    def member_data_and_mode(self, archive_path, member_name):
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path) as archive:
                info = archive.getinfo(member_name)
                return archive.read(member_name), info.external_attr >> 16
        with tarfile.open(archive_path, mode="r:gz") as archive:
            info = archive.getmember(member_name)
            extracted = archive.extractfile(info)
            self.assertIsNotNone(extracted)
            return extracted.read(), info.mode

    def member_names(self, archive_path):
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path) as archive:
                return set(archive.namelist())
        with tarfile.open(archive_path, mode="r:gz") as archive:
            return {member.name for member in archive.getmembers() if member.isfile()}

    def test_three_platform_archives_and_checksum_manifest_are_created(self):
        self.assertEqual(
            {path.name for path in self.artifacts},
            {
                "Nutanix-STIG-Control-Center-1.2.0-windows.zip",
                "Nutanix-STIG-Control-Center-1.2.0-macos.zip",
                "Nutanix-STIG-Control-Center-1.2.0-linux.tar.gz",
                "SHA256SUMS.txt",
            },
        )
        checksum_lines = (self.output / "SHA256SUMS.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertEqual(len(checksum_lines), 3)
        for line in checksum_lines:
            expected, file_name = line.split("  ", 1)
            actual = hashlib.sha256((self.output / file_name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected)

    def test_each_archive_has_only_its_platform_installer(self):
        prefix = "Nutanix-STIG-Control-Center-1.2.0/"
        installers = {
            "windows": "Install-Control-Center.cmd",
            "macos": "Install-Control-Center.command",
            "linux": "install.sh",
        }
        for platform_name, installer in installers.items():
            archive_path = next(
                path for path in self.artifacts if platform_name in path.name
            )
            names = self.member_names(archive_path)
            self.assertIn(prefix + installer, names)
            for other in set(installers.values()) - {installer}:
                self.assertNotIn(prefix + other, names)
            self.assertIn(prefix + "LICENSE", names)
            self.assertIn(prefix + "app/core/nutanix_stig_harden.py", names)
            self.assertFalse(any("/.runtime/" in name for name in names))
            self.assertFalse(any("/app/data/" in name for name in names))
            self.assertFalse(any("/tests/" in name for name in names))
            self.assertFalse(any("/.github/" in name for name in names))
            self.assertFalse(any("/scripts/" in name for name in names))
            self.assertNotIn(prefix + "requirements-dev.txt", names)

    def test_platform_installer_modes_and_windows_line_endings(self):
        prefix = "Nutanix-STIG-Control-Center-1.2.0/"
        cases = (
            ("windows", "Install-Control-Center.cmd", 0o644),
            ("macos", "Install-Control-Center.command", 0o755),
            ("linux", "install.sh", 0o755),
        )
        for platform_name, installer, expected_mode in cases:
            archive_path = next(
                path for path in self.artifacts if platform_name in path.name
            )
            data, mode = self.member_data_and_mode(
                archive_path,
                prefix + installer,
            )
            self.assertEqual(mode & 0o777, expected_mode)
            if platform_name == "windows":
                self.assertIn(b"\r\n", data)
                self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def test_each_archive_contains_a_runnable_controller_layout(self):
        prefix = "Nutanix-STIG-Control-Center-1.2.0"
        for archive_path in self.artifacts:
            if archive_path.name == "SHA256SUMS.txt":
                continue
            target = self.output / f"extract-{archive_path.name}"
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message="Python 3.14 will, by default, filter extracted tar archives",
                    category=DeprecationWarning,
                )
                shutil.unpack_archive(archive_path, target)
            product_root = target / prefix
            result = subprocess.run(
                [sys.executable, "control_center.py", "doctor"],
                cwd=product_root,
                capture_output=True,
                text=True,
                errors="replace",
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Nutanix STIG Control Center diagnostics", result.stdout)

    def test_version_mismatch_fails_closed(self):
        with self.assertRaises(release_builder.ReleaseBuildError):
            release_builder.build_release("9.9.9", self.output)

    def test_application_and_controller_versions_match(self):
        self.assertEqual(release_builder.source_version(), "1.2.0")
        self.assertEqual(release_builder.application_versions(), {"1.2.0"})

    def test_unexpected_output_file_fails_closed(self):
        (self.output / "unexpected.txt").write_text("not a release artifact")
        with self.assertRaises(release_builder.ReleaseBuildError):
            release_builder.build_release("1.2.0", self.output)

    def test_repeated_builds_are_byte_for_byte_reproducible(self):
        second_output = self.output / "second"
        second_artifacts = release_builder.build_release("1.2.0", second_output)
        first_by_name = {path.name: path for path in self.artifacts}
        second_by_name = {path.name: path for path in second_artifacts}
        self.assertEqual(first_by_name.keys(), second_by_name.keys())
        for file_name, first_path in first_by_name.items():
            self.assertEqual(
                hashlib.sha256(first_path.read_bytes()).hexdigest(),
                hashlib.sha256(second_by_name[file_name].read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
