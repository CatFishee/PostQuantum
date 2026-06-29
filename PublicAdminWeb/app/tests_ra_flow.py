import importlib
import sys
from unittest.mock import patch

from django.test import SimpleTestCase


class FakeInsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = {}
        for doc in docs or []:
            self.docs[str(doc["_id"])] = dict(doc)

    def insert_one(self, doc):
        inserted_id = doc.get("_id") or f"fake-{len(self.docs) + 1}"
        stored = dict(doc)
        stored["_id"] = inserted_id
        self.docs[str(inserted_id)] = stored
        return FakeInsertResult(inserted_id)

    def find_one(self, query):
        for doc in self.docs.values():
            if all(doc.get(key) == value for key, value in query.items()):
                return doc
        return None

    def update_one(self, query, update, upsert=False):
        doc = self.find_one(query)
        if doc is None and upsert:
            doc = dict(query)
            doc["_id"] = query.get("_id") or f"fake-{len(self.docs) + 1}"
            self.docs[str(doc["_id"])] = doc
        if doc is not None:
            doc.update(update.get("$set", {}))

    def find(self, query=None):
        query = query or {}
        return [
            doc
            for doc in self.docs.values()
            if all(doc.get(key) == value for key, value in query.items())
        ]


class FakeDB:
    def __init__(self):
        self.users = FakeCollection()
        self.certificate_requests = FakeCollection()


def load_views_without_mongo():
    sys.modules.pop("app.views", None)
    with patch("app.db_connection.get_db", return_value=None):
        return importlib.import_module("app.views")


class RACertificateFlowTests(SimpleTestCase):
    def test_store_pending_certificate_request_records_csr_without_ca_issue(self):
        views = load_views_without_mongo()
        fake_db = FakeDB()
        views.db = fake_db

        request_id = views._store_pending_certificate_request(
            officer_id="officer-1",
            username="canboDemo",
            full_name="Can Bo Demo",
            ml_dsa_pk_hex="aa11",
            ml_kem_pk_hex="bb22",
        )

        csr = fake_db.certificate_requests.docs[str(request_id)]
        self.assertEqual(csr["request_type"], "officer_certificate")
        self.assertEqual(csr["status"], "pending")
        self.assertEqual(csr["officer_id"], "officer-1")
        self.assertEqual(csr["subject_dn"], "CN=canboDemo, OU=Officers, O=PQC-System")
        self.assertEqual(csr["public_keys"]["ml_dsa_pk_hex"], "aa11")
        self.assertEqual(csr["public_keys"]["ml_kem_pk_hex"], "bb22")
        self.assertNotIn("cert_serial", csr)

    def test_approve_certificate_request_issues_cert_and_activates_officer(self):
        views = load_views_without_mongo()
        fake_db = FakeDB()
        fake_db.users = FakeCollection([
            {
                "_id": "officer-1",
                "username": "canboDemo",
                "role": "officer",
                "pqc_status": "pending_approval",
            }
        ])
        fake_db.certificate_requests = FakeCollection([
            {
                "_id": "csr-1",
                "request_type": "officer_certificate",
                "status": "pending",
                "officer_id": "officer-1",
                "username": "canboDemo",
                "public_keys": {
                    "ml_dsa_pk_hex": "aa11",
                    "ml_kem_pk_hex": "bb22",
                },
            }
        ])
        views.db = fake_db

        with patch.object(
            views,
            "_issue_officer_certificate_via_ca",
            return_value={"cert_serial": "cert-123"},
        ) as issue_mock:
            result = views._approve_certificate_request("csr-1", "admin-1")

        issue_mock.assert_called_once()
        self.assertEqual(result["cert_serial"], "cert-123")
        self.assertEqual(fake_db.users.docs["officer-1"]["pqc_status"], "active")
        csr = fake_db.certificate_requests.docs["csr-1"]
        self.assertEqual(csr["status"], "approved")
        self.assertEqual(csr["reviewed_by"], "admin-1")
        self.assertEqual(csr["cert_serial"], "cert-123")

