import oqs
import hashlib
import os
from pikepdf import Pdf

def get_sha3_512_hash(data: bytes):
    return hashlib.sha3_512(data).digest()

def hash_pdf(file_path):
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    return sha3.digest()

def sign_pdf_metadata(input_pdf_path, output_pdf_path, private_key_hex, public_key_hex):
    file_hash = hash_pdf(input_pdf_path)
    sig_alg = 'ML-DSA-44' 
    try:
        with oqs.Signature(sig_alg) as signer:
            private_key = bytes.fromhex(private_key_hex)
            signature = signer.sign(file_hash, private_key)
            with Pdf.open(input_pdf_path) as pdf:
                with pdf.open_metadata() as meta:
                    meta['pqc:SignatureValue'] = signature.hex()
                    meta['pqc:SignerPublicKey'] = public_key_hex
                    meta['pqc:Algorithm'] = sig_alg
                pdf.save(output_pdf_path)
        return True
    except Exception as e:
        print(f"Lỗi ký số: {e}")
        return False

# --- PHẦN FIX LỖI "encaps_secret" TẠI ĐÂY ---

def encapsulate_private_key(private_key_to_protect: bytes, ca_public_key_kem: bytes):
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        # SỬA: encaps_secret -> encap_secret
        ciphertext, shared_secret = kem.encap_secret(ca_public_key_kem)
        
        mask = get_sha3_512_hash(shared_secret)
        extended_mask = (mask * ((len(private_key_to_protect) // len(mask)) + 1))[:len(private_key_to_protect)]
        encrypted_pk = bytes(a ^ b for a, b in zip(private_key_to_protect, extended_mask))
        
        return ciphertext.hex(), encrypted_pk.hex()

def decapsulate_private_key(encrypted_pk_hex: str, ciphertext_hex: str, ca_private_key_kem: bytes):
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        # SỬA: decaps_secret -> decap_secret
        shared_secret = kem.decap_secret(bytes.fromhex(ciphertext_hex), ca_private_key_kem)
        
        mask = get_sha3_512_hash(shared_secret)
        encrypted_pk = bytes.fromhex(encrypted_pk_hex)
        extended_mask = (mask * ((len(encrypted_pk) // len(mask)) + 1))[:len(encrypted_pk)]
        original_pk = bytes(a ^ b for a, b in zip(encrypted_pk, extended_mask))
        
        return original_pk.hex()