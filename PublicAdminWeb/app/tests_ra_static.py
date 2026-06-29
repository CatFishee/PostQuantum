from pathlib import Path

from django.test import SimpleTestCase


REPO_ROOT = Path(__file__).resolve().parents[2]


class RAStaticIntegrationTests(SimpleTestCase):
    def test_ca_service_exposes_issue_officer_certificate_endpoint(self):
        ca_main = (REPO_ROOT / "CA-KMS Server" / "main.py").read_text(encoding="utf-8")
        self.assertIn('@app.post("/issue-officer-certificate")', ca_main)
        self.assertIn("def issue_officer_certificate", ca_main)

    def test_seed_admin_management_command_exists(self):
        command_path = (
            REPO_ROOT
            / "PublicAdminWeb"
            / "app"
            / "management"
            / "commands"
            / "seed_demo_admin.py"
        )
        self.assertTrue(command_path.exists())

    def test_demo_launcher_opens_three_isolated_chrome_profiles(self):
        launcher = (REPO_ROOT / "deployment" / "start-local-demo.ps1").read_text(encoding="utf-8")
        self.assertIn("OpenDemoProfiles", launcher)
        self.assertIn("--user-data-dir", launcher)
        self.assertIn("citizen", launcher)
        self.assertIn("officer", launcher)
        self.assertIn("admin", launcher)
