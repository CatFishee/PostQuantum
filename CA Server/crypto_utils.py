import oqs
import hashlib
import os
from pikepdf import Pdf

# --- 1. HASHING (Sử dụng SHA3-512 thay cho SHA256) ---

def get_sha3_512_hash(data: bytes):
    """Băm dữ liệu bằng SHA3-512 (Kháng lượng tử)"""
    return hashlib.sha3_512(data).digest()

def hash_pdf(file_path):
    """Tính mã băm SHA3-512 cho file PDF"""
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    return sha3.digest()


# --- 2. SIGNING (ML-DSA / Dilithium) ---

def sign_pdf_metadata(input_pdf_path, output_pdf_path, private_key_hex, public_key_hex):
    """Ký số ML-DSA và nhúng vào Metadata của PDF"""
    file_hash = hash_pdf(input_pdf_path)
    
    # NIST chuẩn hóa Dilithium2 là ML-DSA-44
    sig_alg = 'ML-DSA-44' 
    try:
        with oqs.Signature(sig_alg) as signer:
            private_key = bytes.fromhex(private_key_hex)
            signature = signer.sign(file_hash, private_key)
            
            with Pdf.open(input_pdf_path) as pdf:
                with pdf.meta_update() as meta:
                    meta['pqc:signature'] = signature.hex()
                    meta['pqc:publickey'] = public_key_hex
                    meta['pqc:algorithm'] = sig_alg
                pdf.save(output_pdf_path)
        return True
    except Exception as e:
        print(f"Lỗi ký số: {e}")
        return False


# --- 3. KEY PROTECTION (ML-KEM / Kyber) ---
# Dùng để bảo vệ Private Key của cán bộ trên Database

def encapsulate_private_key(private_key_to_protect: bytes, ca_public_key_kem: bytes):
    """
    Dùng Kyber (ML-KEM) để 'khóa' Private Key của cán bộ.
    Trả về: (ciphertext_kem, encrypted_private_key)
    """
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        # 1. Đóng gói khóa để tạo ra Shared Secret
        ciphertext, shared_secret = kem.encap_secret(ca_public_key_kem)
        
        # 2. Dùng Shared Secret băm qua SHA3 để tạo mặt nạ (Mask)
        mask = get_sha3_512_hash(shared_secret)
        
        # 3. XOR Private Key với Mask để bảo mật (Pure PQC Key Wrapping)
        # Lưu ý: Nếu PK dài hơn 64 bytes (SHA3-512), ta cần lặp lại mask
        encrypted_pk = bytes(a ^ b for a, b in zip(private_key_to_protect, mask * (len(private_key_to_protect)//64 + 1)))
        
        return ciphertext.hex(), encrypted_pk.hex()

def decapsulate_private_key(encrypted_pk_hex: str, ciphertext_hex: str, ca_private_key_kem: bytes):
    """
    Dùng Kyber Private Key của CA để giải mã lấy lại Private Key của cán bộ.
    """
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        # 1. Giải đóng gói lấy lại Shared Secret
        shared_secret = kem.decap_secret(bytes.fromhex(ciphertext_hex), ca_private_key_kem)
        
        # 2. Tạo lại Mask từ Shared Secret
        mask = get_sha3_512_hash(shared_secret)
        
        # 3. XOR ngược lại để lấy Private Key gốc
        encrypted_pk = bytes.fromhex(encrypted_pk_hex)
        original_pk = bytes(a ^ b for a, b in zip(encrypted_pk, mask * (len(encrypted_pk)//64 + 1)))
        
        return original_pk.hex()