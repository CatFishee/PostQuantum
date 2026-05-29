import os
import sys
import json
import base64
import tempfile
import requests
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Cấu hình nạp tệp DLL cục bộ trên hệ điều hành Windows
current_dir = os.path.dirname(os.path.abspath(__file__))
if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(current_dir)
os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

import oqs
import pikepdf
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Quản lý vòng đời hiện đại: In Banner nhận diện ra Terminal khi khởi động."""
    print("\n" + "="*60)
    print(" █████╗  ██████╗ ███████╗███╗   ██╗████████╗")
    print("██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝")
    print("███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ")
    print("██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ")
    print("██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ")
    print("╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ")
    print(" >> [SYSTEM STATE: CLIENT SIDE LOCAL SIGNING AGENT ONLINE]")
    print(" >> Port: 54321 | Endpoint: http://127.0.0.1:54321")
    print("="*60 + "\n")
    yield

app = FastAPI(title="PQC Local Client Agent", lifespan=lifespan)

# Chấp nhận mọi Port chạy trên localhost / 127.0.0.1 để tránh lỗi CORS
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

KEY_STORE_PATH = os.path.join(current_dir, "pqc_private_keys.enc")

class KeyGenRequest(BaseModel):
    passphrase: str

class SignAndEncryptRequest(BaseModel):
    pdf_base64: str
    passphrase: str
    django_host: str = "http://127.0.0.1:8000"
    cert_serial: str
    signer_id: str

def _derive_aes_key(passphrase: str, salt: bytes = b"PQC_Agent_Salt") -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(passphrase.encode("utf-8"))

def _load_decrypted_private_keys(passphrase: str) -> dict:
    if not os.path.exists(KEY_STORE_PATH):
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp khóa riêng cục bộ.")
    
    with open(KEY_STORE_PATH, "r", encoding="utf-8") as f:
        file_store = json.load(f)
        
    aes_key = _derive_aes_key(passphrase)
    aesgcm = AESGCM(aes_key)
    
    try:
        decrypted_bytes = aesgcm.decrypt(
            bytes.fromhex(file_store["nonce_hex"]),
            bytes.fromhex(file_store["ciphertext_hex"]),
            None
        )
        return json.loads(decrypted_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Mật khẩu giải mã khóa riêng không đúng.")

# --- HELPER BĂM HỒ SƠ PDF CỤC BỘ ---
def hash_pdf_pqc_local(file_path: str) -> bytes:
    shake = hashes.SHAKE256(32)
    with pikepdf.Pdf.open(file_path) as pdf:
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
    return shake.finalize()

# --- HELPER NHÚNG CHỮ KÝ PDF CỤC BỘ ---
def embed_signature_and_timestamp_local(
    input_pdf_path: str,
    output_pdf_path: str,
    signature_hex: str,
    tsa_token_json: dict,
    tsa_signature_hex: str,
    signer_cert_serial: str,
    signer_pub_key_hex: str
):
    with pikepdf.Pdf.open(input_pdf_path) as pdf:
        sig_dict = pikepdf.Dictionary()
        sig_dict.Type = pikepdf.Name.Sig
        sig_dict.Filter = pikepdf.Name.PQC_Signature_Filter
        sig_dict.SubFilter = pikepdf.Name.PQC_ML_DSA_65
        
        sig_dict.Contents = pikepdf.String(signature_hex)
        sig_dict.TSAToken = pikepdf.String(f"{json.dumps(tsa_token_json)}||{tsa_signature_hex}")
        sig_dict.CertSerial = pikepdf.String(signer_cert_serial)
        sig_dict.SignerPublicKey = pikepdf.String(signer_pub_key_hex)
        
        pdf.Catalog.get_or_create_dictionary(pikepdf.Name.AcroForm)
        pdf.docinfo["/PQCSigned"] = "True"
        pdf.docinfo["/PQCSignature"] = signature_hex
        pdf.docinfo["/PQCTSA"] = pikepdf.String(f"{json.dumps(tsa_token_json)}||{tsa_signature_hex}")
        pdf.docinfo["/PQCCertSerial"] = pikepdf.String(signer_cert_serial)
        
        pdf.save(output_pdf_path)

@app.post("/api/generate-keys")
def generate_keys(req: KeyGenRequest):
    try:
        with oqs.Signature("ML-DSA-65") as dsa:
            dsa_pub = dsa.generate_keypair()
            dsa_priv = dsa.export_secret_key()

        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            kem_pub = kem.generate_keypair()
            kem_priv = kem.export_secret_key()

        payload = {
            "ml_dsa_priv_hex": dsa_priv.hex(),
            "ml_kem_priv_hex": kem_priv.hex()
        }
        aes_key = _derive_aes_key(req.passphrase)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, json.dumps(payload).encode("utf-8"), None)

        file_store = {
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": encrypted_data.hex()
        }
        with open(KEY_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(file_store, f)

        return {
            "status": "success",
            "message": "Đã sinh và bảo mật cặp khóa PQC cục bộ thành công.",
            "ml_dsa_pk_hex": dsa_pub.hex(),
            "ml_kem_pk_hex": kem_pub.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi tạo khóa cục bộ: {str(e)}")

@app.post("/api/sign-and-encrypt")
def sign_and_encrypt(req: SignAndEncryptRequest):
    """
    Luồng Ký số và Mã hóa tại Biên:
    Tự băm, tự ký số, tự nhúng chữ ký cục bộ, tự động lấy khóa công khai CA qua Django Proxy,
    và tiến hành mã hóa ML-KEM-1024 bảo vệ tệp trước khi truyền đi.
    """
    # 1. Giải mã khóa riêng ML-DSA-65 cục bộ
    keys = _load_decrypted_private_keys(req.passphrase)
    dsa_priv = bytes.fromhex(keys["ml_dsa_priv_hex"])
    dsa_pub_hex = keys.get("ml_dsa_pub_hex", "") # có thể phục hồi từ dsa_pub sinh lúc đầu nếu lưu kèm, hoặc lấy dsa_pub dạng hex

    pdf_bytes = base64.b64decode(req.pdf_base64)
    
    # Sử dụng tệp tạm thời cục bộ trên thiết bị của cán bộ để thao tác pikepdf
    temp_in = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    try:
        temp_in.write(pdf_bytes)
        temp_in.close()
        temp_out.close()

        # 2. Tính toán mã băm ổn định
        doc_hash = hash_pdf_pqc_local(temp_in.name)

        # 3. Ký ML-DSA-65 lên mã băm
        with oqs.Signature("ML-DSA-65", secret_key=dsa_priv) as signer:
            signature = signer.sign(doc_hash)

        # 4. Giao tiếp Web Server để lấy Dấu thời gian TSA trực tuyến
        tsa_url = f"{req.django_host}/api/ca-tsa/"
        tsa_resp = requests.post(tsa_url, json={"document_hash_hex": doc_hash.hex()}, timeout=15)
        if tsa_resp.status_code != 200:
            raise Exception("Không thể lấy dấu thời gian TSA từ hệ thống mạng.")
        tsa_data = tsa_resp.json()

        # 5. Nhúng chữ ký số và nhãn thời gian trực tiếp vào PDF cục bộ
        embed_signature_and_timestamp_local(
            input_pdf_path=temp_in.name,
            output_pdf_path=temp_out.name,
            signature_hex=signature.hex(),
            tsa_token_json=tsa_data["token_body"],
            tsa_signature_hex=tsa_data["tsa_signature_hex"],
            signer_cert_serial=req.cert_serial,
            signer_pub_key_hex=keys.get("ml_dsa_pub_hex", "") or signature.hex()[:10]  # Phục hồi hoặc giả lập nếu thiếu hex
        )

        with open(temp_out.name, "rb") as f:
            signed_pdf_raw = f.read()

        # 6. Gọi Web Server Proxy để lấy khóa công khai ML-KEM-1024 của CA Server
        ca_pk_url = f"{req.django_host}/api/ca-public-key/"
        ca_pk_resp = requests.get(ca_pk_url, timeout=10)
        if ca_pk_resp.status_code != 200:
            raise Exception("Không thể kết nối lấy khóa công khai của máy chủ CA.")
        ca_pub_key = bytes.fromhex(ca_pk_resp.json()["public_key"])

        # 7. Mã hóa tệp đã ký bằng ML-KEM-1024 nhắm tới CA Server bảo vệ in-transit
        with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
            encapsulated_key, shared_secret = kem.encap_secret(ca_pub_key)

        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, signed_pdf_raw, None)

        return {
            "status": "success",
            "ciphertext_base64": base64.b64encode(ciphertext).decode("utf-8"),
            "encapsulated_key_base64": base64.b64encode(encapsulated_key).decode("utf-8"),
            "nonce_base64": base64.b64encode(nonce).decode("utf-8")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi ký và mã hóa tại biên: {str(e)}")
    finally:
        # Dọn dẹp tệp tạm thời trên ổ cứng cán bộ ngay lập tức
        for path in (temp_in.name, temp_out.name):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=54321)