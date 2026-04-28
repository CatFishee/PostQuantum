import oqs
import hashlib
from pikepdf import Pdf

def hash_pdf(file_path):
    """Tính mã băm SHA3-512 cho file PDF (Chuẩn hậu lượng tử)"""
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    return sha3.digest()

def sign_pdf_metadata(input_pdf, output_pdf, private_key_hex, public_key_hex):
    """Ký số và nhúng vào Metadata"""
    file_hash = hash_pdf(input_pdf)
    
    # Thực hiện ký bằng Dilithium
    with oqs.Signature('ML-DSA-44') as signer:
        private_key = bytes.fromhex(private_key_hex)
        signature = signer.sign(file_hash, private_key)
        
        # Nhúng vào Metadata dùng pikepdf
        with Pdf.open(input_pdf) as pdf:
            with pdf.meta_update() as meta:
                meta['pqc:signature'] = signature.hex()
                meta['pqc:publickey'] = public_key_hex
                meta['pqc:algorithm'] = 'ML-DSA-44 (Dilithium)'
            pdf.save(output_pdf)
    return True