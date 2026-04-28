import os
import sys
from fastapi import FastAPI
import uvicorn

# --- PHẦN LOAD DLL (Bắt buộc để import oqs) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
try:
    os.add_dll_directory(current_dir)
except AttributeError:
    os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

import oqs # Import sau khi đã set đường dẫn DLL

app = FastAPI(title="PQC Certificate Authority Server")

# API kiểm tra trạng thái
@app.get("/")
def read_root():
    sigs = oqs.get_enabled_sig_mechanisms()
    return {
        "status": "CA Server (Post-Quantum) is running",
        "nist_standard": "ML-DSA / ML-KEM support active",
        "available_sigs": sigs[:5]
    }

# API cấp cặp khóa Dilithium cho cán bộ
@app.get("/issue_officer_keys")
def issue_keys(officer_name: str):
    # Sử dụng ML-DSA-44 (Tên chuẩn NIST của Dilithium2) hoặc 'Dilithium2'
    sig_alg = 'ML-DSA-44' 
    with oqs.Signature(sig_alg) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_private_key()
        
        return {
            "officer": officer_name,
            "algorithm": sig_alg,
            "public_key_hex": public_key.hex(),
            "private_key_hex": private_key.hex()
        }

if __name__ == "__main__":
    # Chạy trên port 5001 cho CA
    uvicorn.run(app, host="127.0.0.1", port=5001)