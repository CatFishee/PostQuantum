import os
import sys
import datetime
import json
import uuid
import base64

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
import uvicorn

# --- LOAD DLL ---
current_dir = os.path.dirname(os.path.abspath(__file__))
if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(current_dir)
os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

import oqs
from db_connection import get_db
from crypto_utils import (
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    encrypt_pdf_bytes_with_ml_kem,
    decrypt_pdf_bytes_with_ml_kem,
    sign_pdf_metadata,
    verify_pdf_signature_metadata,
)

try:
    from bson import ObjectId
except Exception:
    ObjectId = None

app = FastAPI(title="PQC CA Server")
db = get_db()

# --- MIDDLEWARE BẢO MẬT: IP WHITELIST ---
@app.middleware("http")
async def ip_whitelist_middleware(request: Request, call_next):
    client_ip = request.client.host
    if client_ip not in ("127.0.0.1", "::1", "localhost"):
        return JSONResponse(status_code=403, content={"detail": f"Forbidden IP: {client_ip}"})
    return await call_next(request)

# --- MASTER KEYS (ML-KEM-1024) ---
MASTER_PRIV_PATH = os.path.join(current_dir, "master_ca_private.key")
MASTER_PUB_PATH = os.path.join(current_dir, "master_ca_public.key")

def get_or_create_master_keys():
    kem_alg = 'ML-KEM-1024'
    if not os.path.exists(MASTER_PRIV_PATH):
        with oqs.KeyEncapsulation(kem_alg) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            with open(MASTER_PRIV_PATH, "wb") as f: f.write(private_key)
            with open(MASTER_PUB_PATH, "wb") as f: f.write(public_key)
    
    with open(MASTER_PRIV_PATH, "rb") as f: priv = f.read()
    with open(MASTER_PUB_PATH, "rb") as f: pub = f.read()
    return pub, priv

CA_MASTER_PUB, CA_MASTER_PRIV = get_or_create_master_keys()

def _to_object_id(value):
    if ObjectId is None or not value:
        return value

    if isinstance(value, ObjectId):
        return value

    try:
        return ObjectId(str(value))
    except Exception:
        return value
# --- SCHEMAS ---
class RegisterRequest(BaseModel):
    kem_ciphertext: str
    aes_iv: str
    aes_tag: str
    encrypted_payload: str

@app.get("/")
def status():
    return {"status": "CA Online", "database": "Connected" if db is not None else "Disconnected"}

@app.get("/master-public-key")
def get_master_public_key():
    return {"public_key": CA_MASTER_PUB.hex()}

@app.post("/register_officer")
def register_officer(req: RegisterRequest):
    if db is None: 
        raise HTTPException(status_code=500, detail="Database Offline")

    try:
        # 1. Dùng Master KEM Private Key giải Decapsulate để lấy lại Session Key
        # Bản vá lỗi liboqs: Truyền secret_key trực tiếp vào constructor
        with oqs.KeyEncapsulation("ML-KEM-1024", secret_key=CA_MASTER_PRIV) as kem:
            shared_secret = kem.decap_secret(bytes.fromhex(req.kem_ciphertext))
        
        # 2. Giải mã Payload từ Web gửi lên bằng AES-GCM
        payload_bytes = aes_gcm_decrypt(
            shared_secret, 
            bytes.fromhex(req.aes_iv), 
            bytes.fromhex(req.encrypted_payload), 
            bytes.fromhex(req.aes_tag)
        )
        payload = json.loads(payload_bytes.decode('utf-8'))
        officer_id = payload.get("officer_id")
        username = payload.get("username")

        # 3. Tạo 2 cặp khóa cho Cán Bộ (KEM và DSA)
        with oqs.KeyEncapsulation("ML-KEM-768") as kem768:
            kem_pub = kem768.generate_keypair()
            kem_priv = kem768.export_secret_key()
            
        with oqs.Signature("ML-DSA-65") as dsa65:
            dsa_pub = dsa65.generate_keypair()
            dsa_priv = dsa65.export_secret_key()

        # 4. Lưu vào Database chuẩn theo File PDF (officer_keys và certificates)
        cert_serial = str(uuid.uuid4())
        _oid = ObjectId(officer_id) if ObjectId else officer_id
        
        officer_key_doc = {
            "officer_id": _oid,
            "ml_kem_pk": kem_pub,  # binData trong DB
            "ml_dsa_pk": dsa_pub,  # binData trong DB
            "key_level": "ML-DSA-65 & ML-KEM-768",
            "cert_serial": cert_serial,
            "status": "active",
            "valid_until": datetime.datetime.utcnow() + datetime.timedelta(days=365)
        }
        db.officer_keys.insert_one(officer_key_doc)
        
        cert_doc = {
            "serial_number": cert_serial,
            "subject_dn": f"CN={username}, OU=Officers, O=PQC-System",
            "issuer_pqc_ca": "Issuing PQC CA v1",
            "public_keys": {
                "ml_kem_pk": kem_pub,
                "ml_dsa_pk": dsa_pub
            },
            "status": "valid",
            "not_before": datetime.datetime.utcnow(),
            "not_after": datetime.datetime.utcnow() + datetime.timedelta(days=365)
        }
        db.certificates.insert_one(cert_doc)

        # 5. Đóng gói Private Keys gửi trả Web (Tiếp tục mã hóa bằng AES-GCM Session Key)
        response_dict = {
            "ml_kem_priv": kem_priv.hex(),
            "ml_dsa_priv": dsa_priv.hex()
        }
        resp_payload = json.dumps(response_dict).encode('utf-8')
        iv, cipher, tag = aes_gcm_encrypt(shared_secret, resp_payload)

        return {
            "aes_iv": iv.hex(),
            "aes_tag": tag.hex(),
            "encrypted_payload": cipher.hex()
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")



@app.post("/encrypt-pdf")
async def encrypt_pdf(
    officer_id: str = Form(...),
    pdf_file: UploadFile = File(...),
):
    """
    Web gui PDF chua ky + officer_id sang CA.
    CA lay ml_kem_pk cua can bo va ma hoa PDF.
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database Offline")

    try:
        officer_key = db.officer_keys.find_one({
            "officer_id": _to_object_id(officer_id),
            "status": "active"
        })

        if not officer_key or not officer_key.get("ml_kem_pk"):
            raise HTTPException(status_code=404, detail="Can bo chua co ML-KEM public key active.")

        pdf_bytes = await pdf_file.read()

        result = encrypt_pdf_bytes_with_ml_kem(
            pdf_bytes,
            officer_key["ml_kem_pk"]
        )

        return {
            "ciphertext_b64": base64.b64encode(result["ciphertext"]).decode("utf-8"),
            "encapsulated_key_b64": base64.b64encode(result["encapsulated_key"]).decode("utf-8"),
            "nonce_b64": base64.b64encode(result["nonce"]).decode("utf-8"),
            "kems_variant": result["kems_variant"],
            "payload_cipher": result["payload_cipher"],
            "classical_public_key_algorithm": result["classical_public_key_algorithm"],
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Encrypt PDF failed: {str(e)}")
    
@app.post("/decrypt-pdf")
async def decrypt_pdf(
    encrypted_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    encapsulated_key_b64: str = Form(...),
    nonce_b64: str = Form(...),
):
    """
    Web gui file .enc + key JSON + encapsulated_key + nonce sang CA.
    CA giai ma va tra ve PDF goc.
    """
    try:
        ciphertext = await encrypted_file.read()

        key_json_text = (await key_file.read()).decode("utf-8")
        key_data = json.loads(key_json_text)

        ml_kem_priv = (
            key_data.get("ml_kem_priv")
            or key_data.get("ml_kem_sk")
            or key_data.get("ml_kem_private_key")
            or ""
        )

        if not ml_kem_priv:
            raise HTTPException(status_code=400, detail="File key JSON khong co ml_kem_priv.")

        plaintext_pdf = decrypt_pdf_bytes_with_ml_kem(
            ciphertext,
            base64.b64decode(encapsulated_key_b64),
            base64.b64decode(nonce_b64),
            bytes.fromhex("".join(str(ml_kem_priv).split())),
        )

        return Response(
            content=plaintext_pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=decrypted.pdf"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decrypt PDF failed: {str(e)}")

@app.post("/sign-pdf")
async def sign_pdf(
    pdf_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    doc_id: str = Form(""),
    signer_id: str = Form(""),
    public_key_hex: str = Form(""),
    pqc_cert_serial: str = Form(""),
):
    """
    Web gui PDF + key JSON sang CA.
    CA ky bang ML-DSA-65 va tra ve PDF da ky + metadata.
    """
    temp_input = None
    temp_output = None

    try:
        input_bytes = await pdf_file.read()
        key_json_text = (await key_file.read()).decode("utf-8")
        key_data = json.loads(key_json_text)

        ml_dsa_priv = (
            key_data.get("ml_dsa_priv")
            or key_data.get("ml_dsa_sk")
            or key_data.get("ml_dsa_private_key")
            or ""
        )

        ml_dsa_pub = (
            key_data.get("ml_dsa_pk")
            or key_data.get("ml_dsa_pub")
            or key_data.get("ml_dsa_public_key")
            or public_key_hex
            or ""
        )

        if not ml_dsa_priv:
            raise HTTPException(status_code=400, detail="File key JSON khong co ml_dsa_priv.")

        temp_input = os.path.join(current_dir, f"tmp_{uuid.uuid4().hex}.pdf")
        temp_output = os.path.join(current_dir, f"tmp_signed_{uuid.uuid4().hex}.pdf")

        with open(temp_input, "wb") as f:
            f.write(input_bytes)

        signature_result = sign_pdf_metadata(
            temp_input,
            temp_output,
            ml_dsa_priv,
            ml_dsa_pub,
            signer_id=signer_id,
            doc_id=doc_id,
            sig_alg="ML-DSA-65",
            pqc_cert_serial=pqc_cert_serial,
        )

        with open(temp_output, "rb") as f:
            signed_pdf_bytes = f.read()

        return {
            "signed_pdf_b64": base64.b64encode(signed_pdf_bytes).decode("utf-8"),
            "signature_result": signature_result,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Sign PDF failed: {str(e)}")

    finally:
        for path in (temp_input, temp_output):
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass


@app.post("/verify-pdf")
async def verify_pdf(
    pdf_file: UploadFile = File(...),
):
    """
    Web gui PDF da ky sang CA.
    CA verify chu ky trong metadata.
    """
    temp_input = None

    try:
        input_bytes = await pdf_file.read()
        temp_input = os.path.join(current_dir, f"tmp_verify_{uuid.uuid4().hex}.pdf")

        with open(temp_input, "wb") as f:
            f.write(input_bytes)

        result = verify_pdf_signature_metadata(temp_input)
        return result

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verify PDF failed: {str(e)}")

    finally:
        try:
            if temp_input and os.path.exists(temp_input):
                os.remove(temp_input)
        except Exception:
            pass

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5001)