from pathlib import Path

from django.test import SimpleTestCase


REPO_ROOT = Path(__file__).resolve().parents[2]


class RAStaticIntegrationTests(SimpleTestCase):
    def test_ca_service_exposes_issue_officer_certificate_endpoint(self):
        old_ca_kms_dir = REPO_ROOT / "CA-KMS Server"
        ca_main_path = REPO_ROOT / "CA-TSA Server" / "main.py"

        self.assertFalse(old_ca_kms_dir.exists())
        self.assertTrue(ca_main_path.exists())

        ca_main = ca_main_path.read_text(encoding="utf-8")
        self.assertIn('@app.post("/issue-officer-certificate")', ca_main)
        self.assertIn("def issue_officer_certificate", ca_main)
        self.assertIn("PQC CA/TSA Security Server", ca_main)

    def test_ra_server_is_separate_top_level_service(self):
        ra_main_path = REPO_ROOT / "RA Server" / "main.py"

        self.assertTrue(ra_main_path.exists())
        ra_main = ra_main_path.read_text(encoding="utf-8")
        self.assertIn("PQC Registration Authority Server", ra_main)
        self.assertIn('@app.post("/certificate-requests")', ra_main)
        self.assertIn('@app.post("/certificate-requests/{request_id}/approve")', ra_main)
        self.assertIn("CA_SERVICE_URL", ra_main)

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
        self.assertIn("CA-TSA Server", launcher)
        self.assertIn("RA Server", launcher)
        self.assertIn("RA_SERVICE_URL", launcher)
        self.assertIn("5002", launcher)
        self.assertNotIn("CA-KMS Server", launcher)
        self.assertIn("--user-data-dir", launcher)
        self.assertIn("citizen", launcher)
        self.assertIn("officer", launcher)
        self.assertIn("admin", launcher)

    def test_docs_describe_ra_as_separate_service(self):
        boundary = (REPO_ROOT / "docs" / "CA_TSA_BOUNDARY.md").read_text(encoding="utf-8")
        self.assertIn("CA/TSA Boundary", boundary)
        self.assertIn("The Registration Authority runs as a separate RA Server", boundary)
        self.assertNotIn("CA/RA/TSA service", boundary)
