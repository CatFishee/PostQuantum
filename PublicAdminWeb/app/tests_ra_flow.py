import importlib
import sys
from unittest.mock import Mock, patch

from django.test import SimpleTestCase


def load_views_without_mongo():
    sys.modules.pop("app.views", None)
    with patch("app.db_connection.get_db", return_value=None):
        return importlib.import_module("app.views")


class RACertificateFlowTests(SimpleTestCase):
    def test_store_pending_certificate_request_posts_csr_to_ra_server(self):
        views = load_views_without_mongo()
        response = Mock()
        response.json.return_value = {"request_id": "csr-123"}
        response.raise_for_status.return_value = None

        with patch.object(views.requests, "post", return_value=response) as post_mock:
            request_id = views._store_pending_certificate_request(
                officer_id="officer-1",
                username="canboDemo",
                full_name="Can Bo Demo",
                ml_dsa_pk_hex="aa11",
                ml_kem_pk_hex="bb22",
            )

        self.assertEqual(request_id, "csr-123")
        post_mock.assert_called_once()
        url = post_mock.call_args.args[0]
        payload = post_mock.call_args.kwargs["json"]
        self.assertTrue(url.endswith("/certificate-requests"))
        self.assertEqual(payload["officer_id"], "officer-1")
        self.assertEqual(payload["username"], "canboDemo")
        self.assertEqual(payload["subject_dn"], "CN=canboDemo, OU=Officers, O=PQC-System")
        self.assertEqual(payload["public_keys"]["ml_dsa_pk_hex"], "aa11")
        self.assertEqual(payload["public_keys"]["ml_kem_pk_hex"], "bb22")

    def test_approve_certificate_request_posts_decision_to_ra_server(self):
        views = load_views_without_mongo()
        response = Mock()
        response.json.return_value = {"status": "approved", "cert_serial": "cert-123"}
        response.raise_for_status.return_value = None

        with patch.object(views.requests, "post", return_value=response) as post_mock:
            result = views._approve_certificate_request("csr-1", "admin-1")

        self.assertEqual(result["cert_serial"], "cert-123")
        post_mock.assert_called_once()
        url = post_mock.call_args.args[0]
        payload = post_mock.call_args.kwargs["json"]
        self.assertTrue(url.endswith("/certificate-requests/csr-1/approve"))
        self.assertEqual(payload["reviewer_id"], "admin-1")
