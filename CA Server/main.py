import os
import sys
import datetime
from fastapi import FastAPI, HTTPException
import uvicorn

# --- LOAD DLL ---
current_dir = os.path.dirname(os.path.abspath(__file__))
if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(current_dir)
os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']

import oqs
from db_connection import get_db
from crypto_utils import encapsulate_private_key, decapsulate_private_key

app = FastAPI(title="PQC CA Server")
db = get_db()

# --- MASTER KEYS ---
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

@app.get("/")
def status():
    return {"status": "CA Online", "database": "Connected" if db is not None else "Disconnected"}

@app.post("/register_officer")
async def register_officer(username: str, full_name: str, position: str):
    if db is None: raise HTTPException(status_code=500, detail="Database Offline")

    sig_alg = 'ML-DSA-65' # Dùng bản ổn định nhất
    try:
        with oqs.Signature(sig_alg) as signer:
            pub_key_dsa = signer.generate_keypair()
            priv_key_dsa = signer.export_secret_key()

            kem_ciphertext, encrypted_pk_hex = encapsulate_private_key(priv_key_dsa, CA_MASTER_PUB)

            officer_record = {
                "username": username,
                "full_name": full_name,
                "position": position,
                "public_key": pub_key_dsa.hex(),
                "pqc_backup": {
                    "encrypted_private_key_hex": encrypted_pk_hex,
                    "kyber_ciphertext": kem_ciphertext
                },
                "recovery_status": {"requested": False, "approved": False},
                "created_at": datetime.datetime.utcnow()
            }
            
            db.officers.update_one({"username": username}, {"$set": officer_record}, upsert=True)

            return {
                "status": "Success",
                "public_key": pub_key_dsa.hex(),
                "private_key_download": priv_key_dsa.hex()
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5001)