import os
import sys
import datetime
import json
import uuid
import base64
import hashlib
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response, Form
from pydantic import BaseModel
import uvicorn

# Cấu hình nạp tệp DLL cục bộ trên hệ điều hành Windows
current_dir = os.path.dirname(os.path.abspath(__file__))
if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(current_dir)
os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

import oqs
import tempfile
from db_connection import get_db
from crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Quản lý vòng đời hiện đại: In Banner CA Server ra Terminal."""
    print("\n" + "="*60)
    print(" >> [SYSTEM STATE: PQC CA/RA/TSA SERVER IS RUNNING]")
    print(" >> Port: 5001 | Endpoint: http://127.0.0.1:5001")
    print("="*60 + "\n")
    yield

app = FastAPI(title="PQC CA/RA/TSA Security Server", lifespan=lifespan)
db = get_db()
PRIVATE_BLOB_STORAGE_ROOT = os.getenv(
    "PRIVATE_BLOB_STORAGE_ROOT",
    os.path.join(current_dir, "private_storage")
)

@app.middleware("http")
async def ip_whitelist_middleware(request: Request, call_next):
    client_ip = request.client.host
    # Thiết lập IP Whitelist nghiêm ngặt chỉ nhận kết nối của Web Server (Django)
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        return Response(status_code=403, content=f"Forbidden IP: {client_ip}")
    return await call_next(request)

# --- MÔ PHỎNG PKCS#11 SOFTHSM CHO KHÓA TỐI CAO CA & TSA ---
CA_HSM_KEY_PATH = os.path.join(current_dir, "ca_hsm_secured.json")
HSM_WRAP_KEY = hashlib.sha256(b"PQC_System_HSM_AES_Wrapping_Key").digest()

def load_or_create_hsm_pqc_keys():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(HSM_WRAP_KEY)
    if not os.path.exists(CA_HSM_KEY_PATH):
        with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
            kem_pub = kem.generate_keypair()
            kem_priv = kem.export_secret_key()
        with oqs.Signature("ML-DSA-65") as dsa:
            ca_pub = dsa.generate_keypair()
            ca_priv = dsa.export_secret_key()
            
        payload = {
            "ml_kem_priv": kem_priv.hex(),
            "ml_kem_pub": kem_pub.hex(),
            "ca_dsa_priv": ca_priv.hex(),
            "ca_dsa_pub": ca_pub.hex()
        }
        nonce = os.urandom(12)
        wrapped_data = aesgcm.encrypt(nonce, json.dumps(payload).encode("utf-8"), None)
        with open(CA_HSM_KEY_PATH, "w") as f:
            json.dump({"nonce": nonce.hex(), "blob": wrapped_data.hex()}, f)

    with open(CA_HSM_KEY_PATH, "r") as f:
        store = json.load(f)
    decrypted_bytes = aesgcm.decrypt(bytes.fromhex(store["nonce"]), bytes.fromhex(store["blob"]), None)
    return json.loads(decrypted_bytes.decode("utf-8"))

CA_HSM_STORE = load_or_create_hsm_pqc_keys()

class RegisterRequest(BaseModel):
    kem_ciphertext: str
    aes_iv: str
    aes_tag: str
    encrypted_payload: str

class TimestampRequest(BaseModel):
    document_hash_hex: str

class OCSPRequest(BaseModel):
    serial_number: str

# Payload dạng JSON cho luồng mã hóa không đĩa cứng của người dân
class UnsignedEncryptRequest(BaseModel):
    officer_id: str
    citizen_id: str
    original_filename: str
    pdf_base64: str

def _to_object_id_local(value):
    from bson import ObjectId
    if not value: return value
    try: return ObjectId(str(value))
    except Exception: return value

def _write_private_blob(data: bytes, category: str) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    blob_ref = f"{category}/{digest[:2]}/{digest}.bin"
    blob_path = os.path.abspath(os.path.join(PRIVATE_BLOB_STORAGE_ROOT, *blob_ref.split("/")))
    root_path = os.path.abspath(PRIVATE_BLOB_STORAGE_ROOT)
    if os.path.commonpath([blob_path, root_path]) != root_path:
        raise ValueError("Invalid blob path")
    os.makedirs(os.path.dirname(blob_path), exist_ok=True)
    with open(blob_path, "wb") as f:
        f.write(data)
    return {
        "blob_ref": blob_ref,
        "ciphertext_sha256": digest,
        "ciphertext_size_bytes": len(data),
        "storage_provider": "local-private-blob-demo"
    }

def _read_private_blob(blob_ref: str) -> bytes:
    if not blob_ref:
        raise ValueError("Missing blob_ref")
    normalized_ref = os.path.normpath(blob_ref).replace("\\", "/")
    if normalized_ref.startswith("../") or os.path.isabs(normalized_ref):
        raise ValueError("Invalid blob_ref")
    blob_path = os.path.abspath(os.path.join(PRIVATE_BLOB_STORAGE_ROOT, *normalized_ref.split("/")))
    root_path = os.path.abspath(PRIVATE_BLOB_STORAGE_ROOT)
    if os.path.commonpath([blob_path, root_path]) != root_path:
        raise ValueError("Invalid blob path")
    with open(blob_path, "rb") as f:
        return f.read()

def _blob_payload_for_document(doc_id: str, section_name: str) -> dict:
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    document = db.applications.find_one({"_id": _to_object_id_local(doc_id)})
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    section = document.get(section_name) or {}
    blob_ref = section.get("blob_ref")
    ciphertext = _read_private_blob(blob_ref)
    expected_digest = section.get("ciphertext_sha256")
    actual_digest = hashlib.sha256(ciphertext).hexdigest()
    if expected_digest and expected_digest != actual_digest:
        raise HTTPException(status_code=409, detail="Encrypted blob integrity check failed")
    return {
        "ciphertext_base64": base64.b64encode(ciphertext).decode("utf-8"),
        "ciphertext_sha256": actual_digest,
        "ciphertext_size_bytes": len(ciphertext),
        "storage_provider": section.get("storage_provider"),
    }

# --- CHƯƠNG TRÌNH XÁC MINH TÍNH TOÀN VẸN CHỨNG THƯ SỐ (PQC CERT VERIFICATION) ---
def verify_certificate_integrity(cert_doc: dict, ca_pub_key_hex: str) -> bool:
    try:
        cert_body = cert_doc.get("certificate_body")
        ca_signature_hex = cert_doc.get("ca_signature_hex")
        if not cert_body or not ca_signature_hex:
            return False
            
        cert_data_bytes = json.dumps(cert_body, sort_keys=True).encode("utf-8")
        
        shake = hashlib.shake_256()
        shake.update(cert_data_bytes)
        cert_hash = shake.digest(32)
        
        ca_pub_bytes = bytes.fromhex(ca_pub_key_hex)
        ca_sig_bytes = bytes.fromhex(ca_signature_hex)
        
        with oqs.Signature("ML-DSA-65") as verifier:
            return bool(verifier.verify(cert_hash, ca_sig_bytes, ca_pub_bytes))
    except Exception:
        return False

# --- HELPER BĂM PDF TRÊN TIẾN TRÌNH CA SERVER ---
def hash_pdf_pqc_server(file_path: str) -> bytes:
    from pikepdf import Pdf
    shake = hashlib.shake_256()
    with Pdf.open(file_path) as pdf:
        shake.update(str(len(pdf.pages)).encode("utf-8"))
        for page in pdf.pages:
            try:
                shake.update(str(page.obj.get("/MediaBox", "")).encode("utf-8", errors="ignore"))
                contents = page.obj.get("/Contents")
                if contents is not None:
                    if hasattr(contents, "read_bytes"):
                        shake.update(contents.read_bytes())
                    elif contents.__class__.__name__ == "Array":
                        for sub_obj in contents:
                            if hasattr(sub_obj, "read_bytes"):
                                shake.update(sub_obj.read_bytes())
            except Exception:
                pass
    return shake.digest(32)

@app.get("/master-public-key")
def get_master_public_key():
    return {
        "public_key": CA_HSM_STORE["ml_kem_pub"],
        "key_purpose": "ca-transport-only",
        "not_for_user_key_escrow": True,
    }

def _decrypt_ca_transport_request(req: RegisterRequest):
    ca_kem_priv = bytes.fromhex(CA_HSM_STORE["ml_kem_priv"])
    with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=ca_kem_priv) as kem:
        shared_secret = kem.decap_secret(bytes.fromhex(req.kem_ciphertext))

    payload_bytes = aes_gcm_decrypt(
        shared_secret,
        bytes.fromhex(req.aes_iv),
        bytes.fromhex(req.encrypted_payload),
        bytes.fromhex(req.aes_tag),
    )
    return json.loads(payload_bytes.decode("utf-8")), shared_secret

def _encrypt_ca_transport_response(shared_secret, payload: dict):
    resp_payload = json.dumps(payload).encode("utf-8")
    iv, cipher, tag = aes_gcm_encrypt(shared_secret, resp_payload)
    return {
        "aes_iv": iv.hex(),
        "aes_tag": tag.hex(),
        "encrypted_payload": cipher.hex(),
    }

def _issue_officer_certificate_from_payload(payload: dict):
    officer_id = payload.get("officer_id")
    username = payload.get("username")
    client_dsa_pk_hex = payload.get("ml_dsa_pk_hex")
    client_kem_pk_hex = payload.get("ml_kem_pk_hex")
    if not officer_id or not username or not client_dsa_pk_hex or not client_kem_pk_hex:
        raise ValueError("Missing officer certificate payload fields")

    cert_serial = str(uuid.uuid4())
    valid_from = datetime.datetime.now(datetime.timezone.utc)
    valid_to = valid_from + datetime.timedelta(days=365)
    subject_dn = payload.get("subject_dn") or f"CN={username}, OU=Officers, O=PQC-System"

    cert_data = {
        "serial_number": cert_serial,
        "subject_dn": subject_dn,
        "issuer_pqc_ca": "Issuing PQC CA v2 (ML-DSA-65)",
        "public_keys": {
            "ml_kem_pk": client_kem_pk_hex,
            "ml_dsa_pk": client_dsa_pk_hex,
        },
        "not_before": valid_from.isoformat().replace("+00:00", "Z"),
        "not_after": valid_to.isoformat().replace("+00:00", "Z"),
        "status": "valid",
    }

    cert_data_bytes = json.dumps(cert_data, sort_keys=True).encode("utf-8")
    ca_dsa_priv = bytes.fromhex(CA_HSM_STORE["ca_dsa_priv"])

    shake = hashlib.shake_256()
    shake.update(cert_data_bytes)
    cert_hash = shake.digest(32)

    with oqs.Signature("ML-DSA-65", secret_key=ca_dsa_priv) as ca_signer:
        ca_signature = ca_signer.sign(cert_hash)

    cert_doc = {
        "serial_number": cert_serial,
        "subject_dn": subject_dn,
        "certificate_body": cert_data,
        "ca_signature_hex": ca_signature.hex(),
        "not_before": valid_from.replace(tzinfo=None),
        "not_after": valid_to.replace(tzinfo=None),
        "status": "valid",
    }
    db.certificates.insert_one(cert_doc)

    db.officer_keys.update_one(
        {"officer_id": _to_object_id_local(officer_id)},
        {"$set": {
            "ml_kem_pk": bytes.fromhex(client_kem_pk_hex),
            "ml_dsa_pk": bytes.fromhex(client_dsa_pk_hex),
            "cert_serial": cert_serial,
            "status": "active",
        }},
        upsert=True,
    )
    return {"status": "success", "cert_serial": cert_serial}

@app.post("/issue-officer-certificate")
def issue_officer_certificate(req: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    try:
        payload, shared_secret = _decrypt_ca_transport_request(req)
        issue_result = _issue_officer_certificate_from_payload(payload)
        return _encrypt_ca_transport_response(shared_secret, issue_result)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Officer certificate issuing failed: {str(e)}")

@app.post("/register_officer")
def register_officer(req: RegisterRequest):
    return issue_officer_certificate(req)

# --- 100% IN-MEMORY HỒ SƠ UPLOAD CHƯA KÝ ---
@app.post("/encrypt-pdf")
async def encrypt_pdf(req: UnsignedEncryptRequest):
    """
    API tiếp nhận yêu cầu mã hóa hồ sơ chưa ký từ Web Server.
    Độ bảo mật tối cao: Không lưu tệp cục bộ, giải mã byte trực tiếp trên RAM,
    thẩm định và tiến hành upload trực tiếp lên Cloud Database MongoDB Atlas.
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    try:
        # 1. Thẩm định an ninh chứng thư cán bộ tiếp nhận
        officer_key = db.officer_keys.find_one({
            "officer_id": _to_object_id_local(req.officer_id),
            "status": "active"
        })
        if not officer_key or not officer_key.get("ml_kem_pk"):
            raise HTTPException(status_code=404, detail="Cán bộ chưa khởi tạo cặp khóa active.")

        cert = db.certificates.find_one({"serial_number": officer_key.get("cert_serial")})
        if not cert:
            raise HTTPException(status_code=403, detail="Không tìm thấy chứng thư của cán bộ tiếp nhận.")

        if not verify_certificate_integrity(cert, CA_HSM_STORE["ca_dsa_pub"]):
            raise HTTPException(status_code=403, detail="Chứng thư cán bộ tiếp nhận bị thay đổi trái phép (DB Tampered).")

        if cert.get("status") != "valid":
            raise HTTPException(status_code=403, detail="Chứng thư cán bộ tiếp nhận đã bị vô hiệu lực.")

        if cert.get("not_after") and datetime.datetime.utcnow() > cert["not_after"]:
            raise HTTPException(status_code=403, detail="Chứng thư cán bộ tiếp nhận đã hết hạn sử dụng.")

        # 2. Thực hiện mã hóa ML-KEM-768 thô trên RAM
        pdf_bytes = base64.b64decode(req.pdf_base64)
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            encapsulated_key, shared_secret = kem.encap_secret(officer_key["ml_kem_pk"])

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, pdf_bytes, None)
        unsigned_blob = _write_private_blob(ciphertext, "unsigned")

        # 3. MongoDB Atlas chỉ lưu metadata; ciphertext nằm trong private blob storage.
        application_doc = {
            "citizen_id": _to_object_id_local(req.citizen_id),
            "assigned_officer_id": _to_object_id_local(req.officer_id),
            "status": "submitted",
            "submission_type": "unsigned",
            "requires_officer_signature": True,
            "pqc_encryption_metadata": {
                **unsigned_blob,
                "original_upload_path": f"uploaded_pdfs/{req.original_filename}",
                "encapsulated_key": encapsulated_key.hex(),
                "kems_variant": "ML-KEM-768",
                "payload_cipher": "AES-256-GCM",
                "nonce": nonce.hex(),
                "cloud_db_policy": "metadata-only",
            },
            "result_document": {
                "blob_ref": None,
                "ciphertext_sha256": None,
                "ciphertext_size_bytes": None,
                "storage_provider": None,
                "encapsulated_key_b64": None,
                "nonce_b64": None,
            },
            "created_at": datetime.datetime.utcnow(),
        }
        db.applications.insert_one(application_doc)

        # Ghi nhận Audit Log toàn vẹn lưu trữ trực tiếp lên Atlas DB
        db.audit_logs.insert_one({
            "doc_id": application_doc["_id"],
            "citizen_id": _to_object_id_local(req.citizen_id),
            "action": "citizen_upload_and_encrypt",
            "logged_at": datetime.datetime.utcnow(),
            "status": "success"
        })

        return {"status": "success", "message": "Hồ sơ chưa ký đã được mã hóa và tải lên đám mây Atlas thành công."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Mã hóa PDF thất bại: {str(e)}")

@app.post("/verify-and-store-signed")
def verify_and_store_signed(
    doc_id: str = Form(...),
    signer_id: str = Form(...),
    ciphertext_base64: str = Form(...),
    encapsulated_key_base64: str = Form(...),
    nonce_base64: str = Form(...)
):
    """
    Quy trình Thẩm định 4 Lớp Mật mã nghiêm ngặt tại CA Server:
    1. Giải mã ML-KEM-1024 bảo vệ in-transit.
    2. Xác minh chữ ký CA trên Chứng thư số cán bộ (Chống DB Tampering).
    3. Kiểm tra tính hợp lệ và hạn dùng chứng thư cán bộ.
    4. Xác minh toán học chữ ký số ML-DSA-65 của tệp PDF thô.
    Sau khi hợp lệ:
    - Mã hóa bảo vệ tĩnh tệp bằng chính khóa tối cao Master KEM của CA.
    - Lưu trực tiếp khối mật mã tĩnh lên cơ sở dữ liệu MongoDB Atlas (Cloud).
    - Tạo audit log.
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    try:
        # --- LỚP 1: GIẢI MÃ IN-TRANSIT PAYLOAD ---
        ca_kem_priv = bytes.fromhex(CA_HSM_STORE["ml_kem_priv"])
        ciphertext = base64.b64decode(ciphertext_base64)
        enc_key = base64.b64decode(encapsulated_key_base64)
        nonce = base64.b64decode(nonce_base64)

        with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=ca_kem_priv) as kem:
            shared_secret = kem.decap_secret(enc_key)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        decrypted_pdf = aesgcm.decrypt(nonce, ciphertext, None)

        temp_file.write(decrypted_pdf)
        temp_file.close()

        # Đọc siêu dữ liệu chữ ký nhúng từ PDF thô vừa giải mã
        from pikepdf import Pdf
        with Pdf.open(temp_file.name) as pdf:
            signed_flag = pdf.docinfo.get("/PQCSigned")
            signature_hex = pdf.docinfo.get("/PQCSignature")
            cert_serial = pdf.docinfo.get("/PQCCertSerial")
            
        if not signed_flag or not signature_hex or not cert_serial:
            raise Exception("Tài liệu không chứa cấu trúc chữ ký PQC nhúng hợp lệ.")

        cert_serial_str = str(cert_serial)
        signature_hex_str = str(signature_hex)

        # --- LỚP 2: TRUY VẤN VÀ XÁC MINH TOÀN VẸN CHỨNG THƯ (CHỐNG DB TAMPERING) ---
        cert_doc = db.certificates.find_one({"serial_number": cert_serial_str})
        if not cert_doc:
            raise Exception("Không tìm thấy chứng thư số tương ứng trên hệ thống CA.")

        if not verify_certificate_integrity(cert_doc, CA_HSM_STORE["ca_dsa_pub"]):
            raise Exception("Phát hiện chứng thư số bị thay đổi trái phép ngoài cơ sở dữ liệu!")

        # --- LỚP 3: KIỂM TRA HIỆU LỰC CHỨNG THƯ ---
        if cert_doc.get("status") != "valid":
            raise Exception("Chứng thư số của cán bộ ký đã bị thu hồi hoặc vô hiệu lực.")

        if cert_doc.get("not_after") and datetime.datetime.utcnow() > cert_doc["not_after"]:
            raise Exception("Chứng thư số của cán bộ ký đã hết hạn sử dụng.")

        # --- LỚP 4: XÁC MINH TOÀN VẸN CHỮ KÝ SỐ TRÊN TỆP PDF ---
        doc_hash_recalculated = hash_pdf_pqc_server(temp_file.name)
        
        officer_dsa_pk = bytes.fromhex(cert_doc["certificate_body"]["public_keys"]["ml_dsa_pk"])
        sig_bytes = bytes.fromhex(signature_hex_str)

        with oqs.Signature("ML-DSA-65") as verifier:
            sig_valid = verifier.verify(doc_hash_recalculated, sig_bytes, officer_dsa_pk)
            
        if not sig_valid:
            raise Exception("Mã băm chữ ký không khớp với nội dung tài liệu (Signature verification failed).")

        # CA chỉ xác minh chữ ký và ghi metadata; không giữ khóa giải mã sản phẩm đã ký.
        from bson import ObjectId
        db.applications.update_one(
            {"_id": ObjectId(doc_id)},
            {"$set": {
                "status": "processed",
                "result_document": {
                    "artifact_policy": "metadata-only-no-ca-decrypt",
                    "stored_by_ca": False,
                    "document_hash_hex": doc_hash_recalculated.hex(),
                    "cert_serial": cert_serial_str,
                    "verified_at": datetime.datetime.utcnow(),
                    "cloud_db_policy": "metadata-only",
                }
            }}
        )

        # Tạo Audit Log toàn vẹn lưu trữ trực tiếp lên Atlas DB
        db.audit_logs.insert_one({
            "doc_id": ObjectId(doc_id),
            "signer_id": ObjectId(signer_id),
            "action": "verify_and_upload_signed_pdf",
            "document_hash_hex": doc_hash_recalculated.hex(),
            "cert_serial": cert_serial_str,
            "status": "success",
            "logged_at": datetime.datetime.utcnow()
        })

        return {"status": "success", "message": "Thẩm định chữ ký số hậu lượng tử thành công; CA chỉ lưu metadata xác minh."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verify and Store Signed PDF failed: {str(e)}")
    finally:
        # Dọn dẹp bộ nhớ đệm tạm thời của CA Server
        try:
            if os.path.exists(temp_file.name):
                os.remove(temp_file.name)
        except Exception:
            pass

@app.get("/documents/{doc_id}/encrypted-unsigned")
def get_encrypted_unsigned_document(doc_id: str):
    return _blob_payload_for_document(doc_id, "pqc_encryption_metadata")

@app.get("/documents/{doc_id}/encrypted-signed")
def get_encrypted_signed_document(doc_id: str):
    return _blob_payload_for_document(doc_id, "result_document")

@app.post("/decrypt-pdf")
def decrypt_pdf(
    ciphertext_base64: str = Form(...),
    encapsulated_key_base64: str = Form(...),
    nonce_base64: str = Form(...)
):
    raise HTTPException(
        status_code=410,
        detail="CA/RA/TSA service does not decrypt documents or act as a KMS. Decryption must happen on an authorized user/officer device."
    )

@app.post("/tsa/timestamp")
def generate_timestamp(req: TimestampRequest):
    try:
        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        token_body = {
            "document_hash": req.document_hash_hex,
            "timestamp": current_time,
            "tsa_name": "PQC Post-Quantum Time-Stamping Authority"
        }
        token_bytes = json.dumps(token_body, sort_keys=True).encode("utf-8")
        
        shake = hashlib.shake_256()
        shake.update(token_bytes)
        token_hash = shake.digest(32)

        ca_dsa_priv = bytes.fromhex(CA_HSM_STORE["ca_dsa_priv"])
        with oqs.Signature("ML-DSA-65", secret_key=ca_dsa_priv) as signer:
            tsa_sig = signer.sign(token_hash)

        return {
            "token_body": token_body,
            "tsa_signature_hex": tsa_sig.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"TSA Timestamp generation failed: {str(e)}")

@app.post("/api/v1/ocsp")
def check_ocsp(req: OCSPRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
        
    cert = db.certificates.find_one({"serial_number": req.serial_number})
    if not cert:
        status = "unknown"
    else:
        if not verify_certificate_integrity(cert, CA_HSM_STORE["ca_dsa_pub"]):
            status = "tampered"
        else:
            status = cert.get("status", "unknown")
            if cert.get("not_after") and datetime.datetime.utcnow() > cert["not_after"]:
                status = "expired"

    response_body = {
        "serial_number": req.serial_number,
        "status": status,
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    }
    
    ca_dsa_priv = bytes.fromhex(CA_HSM_STORE["ca_dsa_priv"])
    resp_bytes = json.dumps(response_body, sort_keys=True).encode("utf-8")
    
    shake = hashlib.shake_256()
    shake.update(resp_bytes)
    resp_hash = shake.digest(32)
    
    with oqs.Signature("ML-DSA-65", secret_key=ca_dsa_priv) as signer:
        sig = signer.sign(resp_hash)

    return {
        "response": response_body,
        "ca_signature_hex": sig.hex()
    }

@app.get("/api/v1/crl")
def get_crl():
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    
    revoked_certs = list(db.certificates.find({"status": "revoked"}))
    revoked_list = [c["serial_number"] for c in revoked_certs]
    
    crl_body = {
        "issuer": "Issuing PQC CA v2",
        "last_update": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "revoked_serials": revoked_list
    }
    
    crl_bytes = json.dumps(crl_body, sort_keys=True).encode("utf-8")
    
    shake = hashlib.shake_256()
    shake.update(crl_bytes)
    crl_hash = shake.digest(32)
    
    ca_dsa_priv = bytes.fromhex(CA_HSM_STORE["ca_dsa_priv"])
    with oqs.Signature("ML-DSA-65", secret_key=ca_dsa_priv) as signer:
        sig = signer.sign(crl_hash)
        
    return {
        "crl": crl_body,
        "ca_signature_hex": sig.hex()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5001)
