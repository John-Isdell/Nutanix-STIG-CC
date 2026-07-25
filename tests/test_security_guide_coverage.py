import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "tests" / "testdeps"))

MODULE_PATH = ROOT / "app" / "core" / "nutanix_stig_harden.py"
SPEC = importlib.util.spec_from_file_location("security_guide_engine", MODULE_PATH)
stig = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stig)


class SecurityGuideCoverageTests(unittest.TestCase):
    def test_ahv_75_mitigation_labels_are_parsed(self):
        parsed, unmapped = stig.parse_security_config(
            "Enable iTLB Multihit M... : false\n"
            "Enable Retbleed Mitiga... : true\n"
            "Enable Memory Poison : false\n"
        )

        self.assertEqual(
            parsed,
            {
                "enable_itlb_multihit_mitigation": False,
                "enable_retbleed_mitigation": True,
                "enable_memory_poison": False,
            },
        )
        self.assertEqual(unmapped, {})

    def test_release_help_discovers_guide_parameter_spellings(self):
        class Session:
            @staticmethod
            def run(command):
                return (
                    0,
                    "Options: --enable-itlb-multihit-mitigation "
                    "--enable-retbleed-mitigation --enable-memory-poison "
                    "--enable-dodin-opts\n",
                    "",
                )

        supported = stig.discover_supported_params(Session(), "ahv")

        self.assertEqual(
            supported["enable_itlb_multihit_mitigation"],
            "enable-itlb-multihit-mitigation",
        )
        self.assertEqual(
            supported["enable_retbleed_mitigation"],
            "enable-retbleed-mitigation",
        )
        self.assertEqual(
            supported["enable_memory_poison"],
            "enable-memory-poison",
        )
        self.assertEqual(
            supported["enable_dodin_additional_controls"],
            "enable-dodin-opts",
        )

    def test_high_assurance_profiles_include_safe_ahv_mitigations(self):
        guide_mitigations = {
            "enable_itlb_multihit_mitigation",
            "enable_retbleed_mitigation",
            "enable_memory_poison",
        }

        for profile_name in ("STIG_HIGH", "DODIN_APL"):
            profile = stig.PROFILES[profile_name]
            self.assertTrue(guide_mitigations.issubset(profile))
            for parameter in guide_mitigations:
                self.assertIs(profile[parameter], True)

    def test_aos_75_ahv_scope_emits_product_stig_advisory(self):
        advisories = stig.platform_stig_advisories(
            "7.5.1", ["cvm", "ahv"], "cluster"
        )

        self.assertEqual(len(advisories), 1)
        self.assertIn("RHEL 9 STIG limitation", advisories[0])
        self.assertEqual(
            stig.platform_stig_advisories("7.5.1", ["cvm"], "cluster"),
            [],
        )
        self.assertEqual(
            stig.platform_stig_advisories("7.3.1", ["cvm", "ahv"], "cluster"),
            [],
        )

    def test_lockout_and_policy_sensitive_controls_are_never_profile_writes(self):
        manual_only = {
            "enable_fapolicy",
            "enable_dodin_additional_controls",
        }

        for profile in stig.PROFILES.values():
            self.assertTrue(manual_only.isdisjoint(profile))

        manual_text = " ".join(stig.MANUAL_CONTROLS).lower()
        for phrase in (
            "fapolicy",
            "dodin additional",
            "lock status",
            "ssh security levels",
            "allowlists",
            "banner files",
            "enable user core dump",
        ):
            self.assertIn(phrase, manual_text)

    def test_new_manual_controls_do_not_shift_existing_tracking_indices(self):
        legacy_controls = [
            "Export an external SCC/SCAP scan and complete the STIG Viewer checklist.",
            "Configure and visually verify the Prism Element and Prism Central web banners.",
            "Validate CVM/AHV/PCVM propagation on every node or VM in the deployment.",
            "Remove or rotate factory/default credentials and validate vaulted break-glass access.",
            "Stage and test individual SSH keys, then perform cluster lockdown in a separate window.",
            "Configure PCVM/CVM SSH allowlists and SSH security level using the release-specific guide.",
            "Configure LDAPS, least-privilege RBAC, CAC/PIV, revocation checking, and session timeout.",
            "Replace self-signed certificates and externally validate the complete trust chain.",
            "Decide, configure, and escrow data-at-rest encryption/KMS only with ISSO approval.",
            "Validate management-network segmentation, upstream ACLs, and Flow policies.",
            "Confirm syslog events arrive at the SIEM with correct time, severity, and retention.",
            "Run NCC, functional regression, evidence-package, POA&M, and ISSO sign-off activities.",
        ]

        self.assertEqual(stig.MANUAL_CONTROLS[: len(legacy_controls)], legacy_controls)

    def test_client_guide_cites_all_three_source_sections(self):
        guide = (ROOT / "CLIENT-GUIDE.md").read_text(encoding="utf-8")
        bundled_guide = (
            ROOT
            / "app"
            / "docs"
            / "Nutanix_STIG_Control_Center_Universal_Client_Guide.md"
        ).read_text(encoding="utf-8")

        self.assertEqual(guide, bundled_guide)
        for target_id in (
            "sec-ahv-configuration-c.html",
            "sec-controller-virtual-machine-t.html",
            "sec-pcvm-configuration-c.html",
        ):
            self.assertIn(target_id, guide)
        self.assertIn("AOS 7.5/AHV 11.0 RHEL 9 limitation", guide)


if __name__ == "__main__":
    unittest.main()
