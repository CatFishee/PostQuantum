import os
import sys
import datetime
from fastapi import FastAPI, HTTPException
import uvicorn

# --- PHẦN 1: LOAD DLL & IMPORT ---
current_dir = os.path.dirname(os.path.abspath(__file__))
# Ưu tiên tìm oqs.dll tại thư mục gốc của project
if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(current_dir)
os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

try:
    import oqs
except ImportError:
    print("[-] Lỗi: Không tìm thấy thư viện oqs. Hãy đảm bảo oqs.dll nằm trong thư mục CA Server.")
    sys.exit(1)

from db_connection import get_db
from crypto_utils import encapsulate_private_key, decapsulate_private_key

app = FastAPI(title="PQC CA Server (FIPS 203/204 Standard)")
db = get_db()

# --- PHẦN 2: QUẢN LÝ MASTER CA KEYS ---
MASTER_PRIV_PATH = os.path.join(current_dir, "master_ca_private.key")
MASTER_PUB_PATH = os.path.join(current_dir, "master_ca_public.key")

def get_or_create_master_keys():
    kem_alg = 'ML-KEM-1024'
    if not os.path.exists(MASTER_PRIV_PATH):
        print("[!] Khởi tạo Master CA (ML-KEM-1024) lần đầu...")
        with oqs.KeyEncapsulation(kem_alg) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key() # 0.14.1 dùng secret_key
            with open(MASTER_PRIV_PATH, "wb") as f: f.write(private_key)
            with open(MASTER_PUB_PATH, "wb") as f: f.write(public_key)
    
    with open(MASTER_PRIV_PATH, "rb") as f: priv = f.read()
    with open(MASTER_PUB_PATH, "rb") as f: pub = f.read()
    return pub, priv

CA_MASTER_PUB, CA_MASTER_PRIV = get_or_create_master_keys()

# --- PHẦN 3: ENDPOINTS ---

@app.get("/")
def status():
    return {
        "status": "Online",
        "pqc_algorithms": {
            "key_encapsulation": "ML-KEM-1024",
            "digital_signature": "ML-DSA-65"
        },
        "nist_standard": "FIPS 203/204 (2024)"
    }

@app.post("/register_officer")
async def register_officer(username: str, full_name: str, position: str):
    if db is None: raise HTTPException(status_code=500, detail="DB Connection Error")

    # Sử dụng ML-DSA-65 (Mức độ bảo mật trung bình - NIST khuyến nghị)
    sig_alg = 'ML-DSA-65' 
    try:
        with oqs.Signature(sig_alg) as signer:
            # 1. Sinh cặp khóa Dilithium cho cán bộ
            pub_key_dsa = signer.generate_keypair()
            priv_key_dsa = signer.export_secret_key()

            # 2. Bao gói (Wrap) Private Key bằng Master CA Public Key
            kem_ciphertext, encrypted_pk_dict = encapsulate_private_key(priv_key_dsa, CA_MASTER_PUB)

            # 3. Lưu hồ sơ cán bộ (Backup đã được mã hóa)
            officer_record = {
                "username": username,
                "full_name": full_name,
                "position": position,
                "public_key": pub_key_dsa.hex(),
                "pqc_backup": {
                    "encrypted_private_key": encrypted_pk_dict,
                    "kyber_ciphertext": kem_ciphertext,
                    "wrap_alg": "ML-KEM-1024"
                },
                "recovery_status": {"requested": False, "approved": False},
                "created_at": datetime.datetime.utcnow()
            }
            
            db.officers.update_one({"username": username}, {"$set": officer_record}, upsert=True)

            return {
                "status": "Success",
                "public_key": pub_key_dsa.hex(),
                "private_key_download": priv_key_dsa.hex(),
                "instructions": "Vui lòng lưu khóa bí mật này vào file .pqc. Hệ thống chỉ hiển thị 1 lần."
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/recover_private_key")
async def recover_key(username: str):
    officer = db.officers.find_one({"username": username})
    if not officer: raise HTTPException(status_code=404, detail="Không tìm thấy cán bộ")
    
    # Kiểm tra quyền phê duyệt (Mô phỏng quy trình 4 mắt)
    if not officer.get('recovery_status', {}).get('approved'):
        raise HTTPException(status_code=403, detail="Yêu cầu khôi phục chưa được Admin phê duyệt trên Atlas Dashboard")

    try:
        backup = officer['pqc_backup']
        # CA dùng Master Private Key giải mã khóa bí mật cho cán bộ
        original_pk_hex = decapsulate_private_key(
            backup['encrypted_private_key'], 
            backup['kyber_ciphertext'], 
            CA_MASTER_PRIV
        )
        
        # Reset trạng thái sau khi recovery
        db.officers.update_one({"username": username}, {"$set": {"recovery_status.approved": False, "recovery_status.requested": False}})
        
        return {"username": username, "recovered_private_key": original_pk_hex}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khôi phục: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5001)