import datetime
import json
import os
from contextlib import asynccontextmanager

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel


current_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.dirname(current_dir)
ca_tsa_dir = os.path.join(repo_root, "CA-TSA Server")
if os.name == "nt" and hasattr(os, "add_dll_directory"):
    os.add_dll_directory(ca_tsa_dir)
os.environ["PATH"] = ca_tsa_dir + os.pathsep + os.environ.get("PATH", "")

import oqs
from bson import ObjectId
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db_connection import get_db


CA_SERVICE_URL = os.getenv("CA_SERVICE_URL", "http://127.0.0.1:5001").rstrip("/")


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 60)
    print(" >> [SYSTEM STATE: PQC REGISTRATION AUTHORITY SERVER IS RUNNING]")
    print(" >> Port: 5002 | Endpoint: http://127.0.0.1:5002")
    print("=" * 60 + "\n")
    yield


app = FastAPI(title="PQC Registration Authority Server", lifespan=lifespan)
db = get_db()


class CertificateRequestIn(BaseModel):
    officer_id: str
    username: str
    full_name: str = ""
    subject_dn: str
    public_keys: dict


class ReviewRequest(BaseModel):
    reviewer_id: str
    review_note: str = ""


def _to_object_id_local(value):
    if not value:
        return value
    try:
        return ObjectId(str(value))
    except Exception:
        return value


def _object_id_queries(value):
    queries = []
    mongo_id = _to_object_id_local(value)
    if mongo_id != value:
        queries.append({"_id": mongo_id})
    queries.append({"_id": value})
    return queries


def _serialize(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    return value


def _find_certificate_request(request_id):
    if db is None:
        return None
    for query in _object_id_queries(request_id):
        found = db.certificate_requests.find_one(query)
        if found:
            return found
    return None


def _aes_gcm_encrypt(key, plaintext):
    aesgcm = AESGCM(key[:32])
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def _aes_gcm_decrypt(key, nonce, ciphertext, tag):
    aesgcm = AESGCM(key[:32])
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


def _encrypt_payload_for_ca(payload_dict):
    r_pub = requests.get(f"{CA_SERVICE_URL}/master-public-key", timeout=10)
    r_pub.raise_for_status()
    master_pub = bytes.fromhex(r_pub.json()["public_key"])

    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        kem_cipher, shared_secret = kem.encap_secret(master_pub)

    payload_bytes = json.dumps(payload_dict).encode("utf-8")
    nonce, encrypted_data = _aes_gcm_encrypt(shared_secret, payload_bytes)
    cipher, tag = encrypted_data[:-16], encrypted_data[-16:]
    return {
        "kem_ciphertext": kem_cipher.hex(),
        "aes_iv": nonce.hex(),
        "aes_tag": tag.hex(),
        "encrypted_payload": cipher.hex(),
    }, shared_secret


def _decrypt_ca_response(response_payload, shared_secret):
    if not response_payload.get("encrypted_payload"):
        return response_payload
    payload_bytes = _aes_gcm_decrypt(
        shared_secret,
        bytes.fromhex(response_payload["aes_iv"]),
        bytes.fromhex(response_payload["encrypted_payload"]),
        bytes.fromhex(response_payload["aes_tag"]),
    )
    return json.loads(payload_bytes.decode("utf-8"))


def _issue_officer_certificate_via_ca(csr_doc):
    public_keys = csr_doc.get("public_keys") or {}
    payload = {
        "officer_id": str(csr_doc.get("officer_id")),
        "username": csr_doc.get("username"),
        "subject_dn": csr_doc.get("subject_dn"),
        "ml_dsa_pk_hex": public_keys.get("ml_dsa_pk_hex"),
        "ml_kem_pk_hex": public_keys.get("ml_kem_pk_hex"),
    }
    ca_req_data, shared_secret = _encrypt_payload_for_ca(payload)
    response = requests.post(f"{CA_SERVICE_URL}/issue-officer-certificate", json=ca_req_data, timeout=20)
    response.raise_for_status()
    return _decrypt_ca_response(response.json(), shared_secret)


@app.get("/health")
def health():
    return {"status": "ok", "service": "registration-authority"}


@app.post("/certificate-requests")
def create_certificate_request(req: CertificateRequestIn):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")

    now = datetime.datetime.utcnow()
    csr_doc = {
        "request_type": "officer_certificate",
        "status": "pending",
        "officer_id": str(req.officer_id),
        "username": req.username,
        "full_name": req.full_name,
        "subject_dn": req.subject_dn,
        "public_keys": {
            "ml_dsa_pk_hex": req.public_keys.get("ml_dsa_pk_hex"),
            "ml_kem_pk_hex": req.public_keys.get("ml_kem_pk_hex"),
        },
        "created_at": now,
        "ra_service": "RA Server",
    }
    inserted = db.certificate_requests.insert_one(csr_doc)
    return {"status": "pending", "request_id": str(inserted.inserted_id)}


@app.get("/certificate-requests")
def list_certificate_requests(status: str = Query("pending")):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    query = {}
    if status:
        query["status"] = status
    rows = list(db.certificate_requests.find(query).sort("created_at", -1))
    return {"requests": _serialize(rows)}


@app.post("/certificate-requests/{request_id}/approve")
def approve_certificate_request(request_id: str, req: ReviewRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    csr_doc = _find_certificate_request(request_id)
    if not csr_doc:
        raise HTTPException(status_code=404, detail="Certificate request not found")
    if csr_doc.get("status") != "pending":
        raise HTTPException(status_code=409, detail="Certificate request is not pending")

    ca_result = _issue_officer_certificate_via_ca(csr_doc)
    cert_serial = ca_result.get("cert_serial")
    if not cert_serial:
        raise HTTPException(status_code=502, detail="CA did not return a certificate serial")

    reviewed_at = datetime.datetime.utcnow()
    db.certificate_requests.update_one(
        {"_id": csr_doc["_id"]},
        {"$set": {
            "status": "approved",
            "reviewed_at": reviewed_at,
            "reviewed_by": str(req.reviewer_id),
            "review_note": req.review_note,
            "cert_serial": cert_serial,
            "ca_status": ca_result.get("status", "success"),
        }},
    )
    db.users.update_one(
        {"_id": _to_object_id_local(csr_doc.get("officer_id"))},
        {"$set": {
            "pqc_status": "active",
            "cert_serial": cert_serial,
            "certificate_approved_at": reviewed_at,
            "certificate_approved_by": str(req.reviewer_id),
        }},
    )
    return {"status": "approved", "cert_serial": cert_serial}


@app.post("/certificate-requests/{request_id}/reject")
def reject_certificate_request(request_id: str, req: ReviewRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    csr_doc = _find_certificate_request(request_id)
    if not csr_doc:
        raise HTTPException(status_code=404, detail="Certificate request not found")
    if csr_doc.get("status") != "pending":
        raise HTTPException(status_code=409, detail="Certificate request is not pending")

    reviewed_at = datetime.datetime.utcnow()
    db.certificate_requests.update_one(
        {"_id": csr_doc["_id"]},
        {"$set": {
            "status": "rejected",
            "reviewed_at": reviewed_at,
            "reviewed_by": str(req.reviewer_id),
            "review_note": req.review_note,
        }},
    )
    db.users.update_one(
        {"_id": _to_object_id_local(csr_doc.get("officer_id"))},
        {"$set": {
            "pqc_status": "inactive",
            "certificate_rejected_at": reviewed_at,
            "certificate_rejected_by": str(req.reviewer_id),
            "certificate_rejection_note": req.review_note,
        }},
    )
    return {"status": "rejected"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=5002)
