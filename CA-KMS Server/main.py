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

# Cấu hình nạp tệp DLL cục bộ trên Windows
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
    print(" ██████╗ ██████╗      ██╗  ██╗███╗   ███╗███████╗")
    print("██╔════╝██╔═══██╗     ██║ ██╔╝████╗ ████║██╔════╝")
    print("██║     ██║   ██║     █████╔╝ ██╔████╔██║███████╗")
    print("██║     ██║   ██║     ██╔═██╗ ██║╚██╔╝██║╚════██║")
    print("╚██████╗╚██████╔╝     ██║  ██╗██║ ╚═╝ ██║███████║")
    print(" ╚═════╝ ╚═════╝      ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝")
    print(" >> [SYSTEM STATE: CENTRAL CA-KMS & TSA SERVER IS RUNNING]")
    print(" >> Port: 5001 | Endpoint: http://127.0.0.1:5001")
    print("="*60 + "\n")
    yield

app = FastAPI(title="PQC CA-KMS & TSA Security Server", lifespan=lifespan)
db = get_db()

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

def _to_object_id_local(value):
    from bson import ObjectId
    if not value: return value
    try: return ObjectId(str(value))
    except Exception: return value

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
    return {"public_key": CA_HSM_STORE["ml_kem_pub"]}

@app.post("/register_officer")
def register_officer(req: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")
    try:
        ca_kem_priv = bytes.fromhex(CA_HSM_STORE["ml_kem_priv"])
        with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=ca_kem_priv) as kem:
            shared_secret = kem.decap_secret(bytes.fromhex(req.kem_ciphertext))
        
        payload_bytes = aes_gcm_decrypt(
            shared_secret, 
            bytes.fromhex(req.aes_iv), 
            bytes.fromhex(req.encrypted_payload), 
            bytes.fromhex(req.aes_tag)
        )
        payload = json.loads(payload_bytes.decode('utf-8'))
        officer_id = payload.get("officer_id")
        username = payload.get("username")
        
        client_dsa_pk_hex = payload.get("ml_dsa_pk_hex")
        client_kem_pk_hex = payload.get("ml_kem_pk_hex")

        cert_serial = str(uuid.uuid4())
        valid_from = datetime.datetime.now(datetime.timezone.utc)
        valid_to = valid_from + datetime.timedelta(days=365)
        
        cert_data = {
            "serial_number": cert_serial,
            "subject_dn": f"CN={username}, OU=Officers, O=PQC-System",
            "issuer_pqc_ca": "Issuing PQC CA v2 (ML-DSA-65)",
            "public_keys": {
                "ml_kem_pk": client_kem_pk_hex,
                "ml_dsa_pk": client_dsa_pk_hex
            },
            "not_before": valid_from.isoformat().replace("+00:00", "Z"),
            "not_after": valid_to.isoformat().replace("+00:00", "Z"),
            "status": "valid"
        }
        
        cert_data_bytes = json.dumps(cert_data, sort_keys=True).encode("utf-8")
        ca_dsa_priv = bytes.fromhex(CA_HSM_STORE["ca_dsa_priv"])
        
        shake = hashlib.shake_256()
        shake.update(cert_data_bytes)
        cert_hash = shake.digest(32)
        
        with oqs.Signature("ML-DSA-65", secret_key=ca_dsa_priv) as ca_signer:
            ca_signature = ca_signer.sign(cert_hash)

        valid_from_naive = valid_from.replace(tzinfo=None)
        valid_to_naive = valid_to.replace(tzinfo=None)

        cert_doc = {
            "serial_number": cert_serial,
            "certificate_body": cert_data,
            "ca_signature_hex": ca_signature.hex(),
            "not_before": valid_from_naive,
            "not_after": valid_to_naive,
            "status": "valid"
        }
        db.certificates.insert_one(cert_doc)

        from bson import ObjectId
        db.officer_keys.update_one(
            {"officer_id": ObjectId(officer_id)},
            {"$set": {
                "ml_kem_pk": bytes.fromhex(client_kem_pk_hex),
                "ml_dsa_pk": bytes.fromhex(client_dsa_pk_hex),
                "cert_serial": cert_serial,
                "status": "active"
            }},
            upsert=True
        )

        resp_payload = json.dumps({"status": "success", "cert_serial": cert_serial}).encode('utf-8')
        iv, cipher, tag = aes_gcm_encrypt(shared_secret, resp_payload)

        return {
            "aes_iv": iv.hex(),
            "aes_tag": tag.hex(),
            "encrypted_payload": cipher.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration and certification issuing failed: {str(e)}")

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
        # Tính toán lại mã băm ổn định của tệp PDF thô
        doc_hash_recalculated = hash_pdf_pqc_server(temp_file.name)
        
        # Lấy khóa công khai dsa của cán bộ từ thân chứng thư đã kiểm định toàn vẹn
        officer_dsa_pk = bytes.fromhex(cert_doc["certificate_body"]["public_keys"]["ml_dsa_pk"])
        sig_bytes = bytes.fromhex(signature_hex_str)

        with oqs.Signature("ML-DSA-65") as verifier:
            sig_valid = verifier.verify(doc_hash_recalculated, sig_bytes, officer_dsa_pk)
            
        if not sig_valid:
            raise Exception("Mã băm chữ ký không khớp với nội dung tài liệu (Signature verification failed).")

        # --- TÁI MÃ HÓA LƯU TRỮ TRỰC TIẾP LÊN CLOUD ATLAS DB (DÙNG MASTER KEM CỦA CA) ---
        ca_kem_pub = bytes.fromhex(CA_HSM_STORE["ml_kem_pub"])
        with oqs.KeyEncapsulation("ML-KEM-1024") as kem_storage:
            enc_key_store, shared_secret_store = kem_storage.encap_secret(ca_kem_pub)

        aes_key_store = shared_secret_store[:32]
        aesgcm_store = AESGCM(aes_key_store)
        nonce_store = os.urandom(12)
        
        # Mã hóa tệp đã được kiểm chứng
        ciphertext_storage = aesgcm_store.encrypt(nonce_store, decrypted_pdf, None)

        # Cập nhật trực tiếp kết quả mật mã tĩnh lên MongoDB Atlas
        from bson import ObjectId
        db.applications.update_one(
            {"_id": ObjectId(doc_id)},
            {"$set": {
                "status": "processed",
                "result_document": {
                    "ciphertext_b64": base64.b64encode(ciphertext_storage).decode("utf-8"),
                    "encapsulated_key_b64": base64.b64encode(enc_key_store).decode("utf-8"),
                    "nonce_b64": base64.b64encode(nonce_store).decode("utf-8"),
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

        return {"status": "success", "message": "Thẩm định chữ ký số hậu lượng tử và lưu trữ đám mây thành công."}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verify and Store Signed PDF failed: {str(e)}")
    finally:
        # Dọn dẹp bộ nhớ đệm tạm thời của CA Server
        try:
            if os.path.exists(temp_file.name):
                os.remove(temp_file.name)
        except Exception:
            pass

@app.post("/decrypt-pdf")
def decrypt_pdf(
    ciphertext_base64: str = Form(...),
    encapsulated_key_base64: str = Form(...),
    nonce_base64: str = Form(...)
):
    """
    API hỗ trợ giải mã luồng byte trực tuyến bằng khóa riêng Master KEM của CA.
    Dùng khi Django Web Server có phân quyền hợp lệ yêu cầu stream file cho người dùng tải.
    """
    try:
        ca_kem_priv = bytes.fromhex(CA_HSM_STORE["ml_kem_priv"])
        ciphertext = base64.b64decode(ciphertext_base64)
        encapsulated_key = base64.b64decode(encapsulated_key_base64)
        nonce = base64.b64decode(nonce_base64)

        with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=ca_kem_priv) as kem:
            shared_secret = kem.decap_secret(encapsulated_key)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return Response(
            content=plaintext,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=decrypted.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decrypt master KEM failed: {str(e)}")

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
        
        # Băm dấu thời gian bằng SHAKE-256 gốc
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
        # NÂNG CẤP AN NINH: Xác minh chữ ký CA trên tệp OCSP trước khi trả về trạng thái
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
    
    # Băm kết quả OCSP bằng SHAKE-256 gốc
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
    
    # Băm danh sách CRL bằng SHAKE-256 gốc
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