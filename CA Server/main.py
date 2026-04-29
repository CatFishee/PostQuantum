import os
import sys
from fastapi import FastAPI, HTTPException
import uvicorn
import datetime

# --- PHẦN 1: LOAD DLL & IMPORT ---
current_dir = os.path.dirname(os.path.abspath(__file__))
try:
    os.add_dll_directory(current_dir)
except AttributeError:
    os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

import oqs
from db_connection import get_db
from crypto_utils import encapsulate_private_key, decapsulate_private_key

app = FastAPI(title="PQC Certificate Authority Server (Standard NIST 2024)")
db = get_db()

# --- PHẦN 2: QUẢN LÝ MASTER KYBER KEY (Lưu tại máy CA) ---
MASTER_PRIV_PATH = os.path.join(current_dir, "master_ca_private.key")
MASTER_PUB_PATH = os.path.join(current_dir, "master_ca_public.key")

def get_or_create_master_keys():
    kem_alg = 'ML-KEM-1024'
    if not os.path.exists(MASTER_PRIV_PATH):
        print("[!] Khởi tạo Master Kyber Keys lần đầu...")
        with oqs.KeyEncapsulation(kem_alg) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            with open(MASTER_PRIV_PATH, "wb") as f: f.write(private_key)
            with open(MASTER_PUB_PATH, "wb") as f: f.write(public_key)
    
    with open(MASTER_PRIV_PATH, "rb") as f: priv = f.read()
    with open(MASTER_PUB_PATH, "rb") as f: pub = f.read()
    return pub, priv

CA_MASTER_PUB, CA_MASTER_PRIV = get_or_create_master_keys()

# --- PHẦN 3: CÁC API ENDPOINT ---

@app.get("/")
def status():
    return {
        "status": "CA Server Online",
        "security": "Pure Post-Quantum Enabled",
        "master_key_status": "Loaded"
    }

@app.post("/register_officer")
def register_officer(username: str, full_name: str, position: str):
    """
    1. Sinh khóa Dilithium (ML-DSA) cho cán bộ.
    2. Dùng Master Kyber (ML-KEM) để khóa Private Key.
    3. Lưu bản backup đã khóa lên AtlasDB.
    4. Trả về khóa gốc cho cán bộ tải về (Dùng 1 lần).
    """
    if db is None: raise HTTPException(status_code=500, detail="Database Offline")

    sig_alg = 'ML-DSA-44'
    with oqs.Signature(sig_alg) as signer:
        # A. Sinh cặp khóa Dilithium
        pub_key_dilithium = signer.generate_keypair()
        priv_key_dilithium = signer.export_private_key()

        # B. Dùng Kyber bảo vệ Private Key (Pure PQC Wrapping)
        ciphertext, encrypted_pk = encapsulate_private_key(priv_key_dilithium, CA_MASTER_PUB)

        # C. Lưu vào AtlasDB
        officer_record = {
            "username": username,
            "full_name": full_name,
            "position": position,
            "role": "Officer",
            "public_key": pub_key_dilithium.hex(),
            "pqc_backup": {
                "encrypted_private_key": encrypted_pk,
                "kyber_ciphertext": ciphertext,
                "wrap_alg": "ML-KEM-1024 + SHA3-512"
            },
            "recovery_status": {"requested": False, "approved": False},
            "created_at": datetime.datetime.utcnow()
        }
        
        # Cập nhật users collection và pqc_keys (hoặc gộp chung vào 1 collection)
        db.officers.update_one({"username": username}, {"$set": officer_record}, upsert=True)

        return {
            "status": "Success",
            "officer": username,
            "public_key": pub_key_dilithium.hex(),
            "private_key_to_download": priv_key_dilithium.hex(), # Cán bộ lưu file .pqc
            "note": "Hệ thống không lưu trữ Private Key nguyên bản. Vui lòng tự bảo quản file khóa."
        }

@app.post("/recover_private_key")
def recover_key(username: str):
    """
    Giải mã khóa backup bằng Master Kyber Key (Chỉ khi Admin đã phê duyệt)
    """
    officer = db.officers.find_one({"username": username})
    if not officer: raise HTTPException(status_code=404, detail="User not found")
    
    if not officer['recovery_status']['approved']:
        raise HTTPException(status_code=403, detail="Yêu cầu khôi phục chưa được Admin phê duyệt")

    # Tiến hành giải mã bằng Master Key tại CA
    try:
        backup = officer['pqc_backup']
        original_pk_hex = decapsulate_private_key(
            backup['encrypted_private_key'], 
            backup['kyber_ciphertext'], 
            CA_MASTER_PRIV
        )
        
        # Reset trạng thái phê duyệt sau khi đã khôi phục
        db.officers.update_one({"username": username}, {"$set": {"recovery_status.approved": False, "recovery_status.requested": False}})
        
        return {"username": username, "recovered_private_key": original_pk_hex}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khôi phục: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5001)