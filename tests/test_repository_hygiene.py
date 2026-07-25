import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent


class RepositoryHygieneTests(unittest.TestCase):
    def test_direct_dependencies_are_exactly_pinned(self):
        requirement_files = (
            ROOT / "app" / "requirements.txt",
            ROOT / "requirements-dev.txt",
        )
        pattern = re.compile(
            r"^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+$"
        )
        for requirement_file in requirement_files:
            lines = [
                line.strip()
                for line in requirement_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            self.assertTrue(lines, f"{requirement_file} is empty")
            for line in lines:
                self.assertRegex(
                    line,
                    pattern,
                    f"{requirement_file.name} has an unpinned entry: {line}",
                )

    def test_github_actions_are_pinned_to_full_commit_shas(self):
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        uses_pattern = re.compile(r"^\s*uses:\s*([^#\s]+)")
        full_sha_pattern = re.compile(r"^[^@]+@[0-9a-f]{40}$")
        for workflow in workflows:
            for line in workflow.read_text(encoding="utf-8").splitlines():
                match = uses_pattern.match(line)
                if not match:
                    continue
                reference = match.group(1)
                if reference.startswith("./"):
                    continue
                self.assertRegex(
                    reference,
                    full_sha_pattern,
                    f"{workflow.name} has a mutable action reference: {reference}",
                )

    def test_sensitive_runtime_paths_are_ignored(self):
        ignored = set(
            (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        )
        for required in (
            ".runtime/",
            "app/data/",
            "wheelhouse/",
            ".env",
            "*.pem",
            "*.key",
        ):
            self.assertIn(required, ignored)

    def test_services_remain_loopback_only(self):
        service_sources = (
            ROOT / "control_center.py",
            ROOT / "supervisor.py",
            ROOT / "supervisor_setup.py",
            ROOT / "app" / "server.py",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in service_sources
        )
        self.assertNotIn("0.0.0.0", combined)
        self.assertIn('SUPERVISOR_HOST = "127.0.0.1"', combined)
        self.assertIn('default="127.0.0.1"', combined)

    def test_public_release_requires_human_document_review(self):
        checklist = (ROOT / "PUBLIC-RELEASE-CHECKLIST.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "Nutanix_STIG_Hardening_Client_Execution_Guide.docx",
            checklist,
        )
        self.assertIn("human legal/content review", checklist)
        release_workflow = (
            ROOT / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("DOCS_COPYRIGHT_REVIEWED", release_workflow)
        self.assertIn('!= "true"', release_workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
