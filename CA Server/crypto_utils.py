import oqs
import hashlib
import os
from pikepdf import Pdf

# --- 1. HASHING (Sử dụng SHA3-512 chuẩn NIST) ---

def get_sha3_512_hash(data: bytes):
    """Băm dữ liệu bằng SHA3-512 (Kháng lượng tử)"""
    return hashlib.sha3_512(data).digest()

def hash_pdf(file_path):
    """Tính mã băm SHA3-512 cho file PDF theo từng khối để tiết kiệm RAM"""
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    return sha3.digest()


# --- 2. SIGNING (ML-DSA / Dilithium) ---

def sign_pdf_metadata(input_pdf_path, output_pdf_path, private_key_hex, public_key_hex):
    """Ký số ML-DSA và nhúng vào Metadata của PDF bằng pikepdf"""
    file_hash = hash_pdf(input_pdf_path)
    
    # ML-DSA-44 (Dilithium 2) hoặc ML-DSA-65 (Dilithium 3)
    sig_alg = 'ML-DSA-44' 
    try:
        with oqs.Signature(sig_alg) as signer:
            private_key = bytes.fromhex(private_key_hex)
            signature = signer.sign(file_hash, private_key)
            
            with Pdf.open(input_pdf_path) as pdf:
                # Nhúng vào Document Info (Metadata cổ điển)
                with pdf.open_metadata() as meta:
                    # Nhúng vào XMP Metadata (đúng chuẩn báo cáo trang 3)
                    meta['pqc:SignatureValue'] = signature.hex()
                    meta['pqc:SignerPublicKey'] = public_key_hex
                    meta['pqc:Algorithm'] = sig_alg
                    meta['pqc:Timestamp'] = str(os.times())
                
                pdf.save(output_pdf_path)
        print(f"[+] Đã ký PDF thành công: {output_pdf_path}")
        return True
    except Exception as e:
        print(f"[-] Lỗi ký số PDF: {e}")
        return False


# --- 3. KEY PROTECTION (ML-KEM / Kyber) ---
# Cơ chế Wrapping khóa bí mật thuần PQC (Sử dụng XOR Mask)

def encapsulate_private_key(private_key_to_protect: bytes, ca_public_key_kem: bytes):
    """
    Dùng ML-KEM-1024 để bảo vệ Private Key của cán bộ.
    """
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        # 1. Đóng gói khóa: tạo Ciphertext và Shared Secret
        # liboqs-python 0.14.1 sử dụng encaps_secret
        ciphertext, shared_secret = kem.encap_secret(ca_public_key_kem)
        
        # 2. Dùng Shared Secret tạo ra Mask bằng SHA3-512
        mask = get_sha3_512_hash(shared_secret)
        
        # 3. Tạo Mask đủ độ dài cho Private Key (Repeating Mask)
        # Logic: Kéo dài mask cho đến khi lớn hơn hoặc bằng độ dài PK
        extended_mask = (mask * ((len(private_key_to_protect) // len(mask)) + 1))[:len(private_key_to_protect)]
        
        # 4. XOR để khóa (Wrapping)
        encrypted_pk = bytes(a ^ b for a, b in zip(private_key_to_protect, extended_mask))
        
        return ciphertext.hex(), encrypted_pk.hex()

def decapsulate_private_key(encrypted_pk_hex: str, ciphertext_hex: str, ca_private_key_kem: bytes):
    """
    Dùng ML-KEM Private Key của CA để giải mã lấy lại Private Key của cán bộ.
    """
    with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
        # 1. Giải đóng gói: dùng secret key của CA để lấy lại Shared Secret từ Ciphertext
        # liboqs-python 0.14.1 sử dụng decaps_secret
        shared_secret = kem.decap_secret(bytes.fromhex(ciphertext_hex), ca_private_key_kem)
        
        # 2. Tạo lại Mask từ Shared Secret tương ứng
        mask = get_sha3_512_hash(shared_secret)
        
        # 3. Tạo lại Extended Mask với độ dài của khóa bị mã hóa
        encrypted_pk = bytes.fromhex(encrypted_pk_hex)
        extended_mask = (mask * ((len(encrypted_pk) // len(mask)) + 1))[:len(encrypted_pk)]
        
        # 4. XOR ngược lại để lấy khóa gốc (Unwrapping)
        original_pk = bytes(a ^ b for a, b in zip(encrypted_pk, extended_mask))
        
        return original_pk.hex()