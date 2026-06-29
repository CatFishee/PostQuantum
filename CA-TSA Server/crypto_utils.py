import os
import sys
import json
import hashlib
import base64
from xml.etree import ElementTree
from pikepdf import Pdf, Name, Dictionary, String
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- AES-GCM CHO SESSION KEY (Kênh truyền Web Server <-> CA Server) ---
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Mã hóa đối xứng AES-GCM 256-bit sử dụng khóa phiên dẫn xuất từ KEM."""
    aesgcm = AESGCM(key[:32])  # ML-KEM shared_secret là 32 bytes
    iv = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return iv, ciphertext, tag

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Giải mã đối xứng AES-GCM 256-bit khôi phục dữ liệu ban đầu."""
    aesgcm = AESGCM(key[:32])
    return aesgcm.decrypt(iv, ciphertext + tag, None)

# --- HASHING SHAKE-256 ---
def get_shake_256_hash(data: bytes, length: int = 32) -> bytes:
    """Băm dữ liệu sử dụng hàm băm hậu lượng tử SHAKE-256."""
    return hashlib.shake_256(data).digest(length)

def hash_pdf_pqc(file_path: str) -> bytes:
    """Băm ổn định nội dung tệp tin PDF tránh các cấu trúc chữ ký nhúng."""
    shake = hashlib.shake_256()
    with Pdf.open(file_path) as pdf:
        shake.update(str(len(pdf.pages)).encode("utf-8"))
        for page in pdf.pages:
            try:
                shake.update(str(page.obj.get("/MediaBox", "")).encode("utf-8", errors="ignore"))
                # Đọc nội dung streams để băm
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
    return shake.digest(32)

# --- NHÚNG CHỮ KÝ SỐ & TIMESTAMP (PAdES Simulation) ---
def embed_signature_and_timestamp(
    input_pdf_path: str,
    output_pdf_path: str,
    signature_hex: str,
    tsa_token_json: dict,
    tsa_signature_hex: str,
    signer_cert_serial: str,
    signer_pub_key_hex: str
):
    """
    Giả lập nhúng thông tin chữ ký và TSA token vào cấu trúc từ điển chữ ký PDF 
    tương đương định dạng chuẩn PAdES để đảm bảo tính sẵn sàng xác minh dài hạn.
    """
    with Pdf.open(input_pdf_path) as pdf:
        sig_dict = Dictionary()
        sig_dict.Type = Name.Sig
        sig_dict.Filter = Name.PQC_Signature_Filter
        sig_dict.SubFilter = Name.PQC_ML_DSA_65
        
        # Nhúng chữ ký, nhãn thời gian và thông tin chứng thư số trực tiếp vào cấu trúc chữ ký PDF
        sig_dict.Contents = String(signature_hex)
        sig_dict.TSAToken = String(f"{json.dumps(tsa_token_json)}||{tsa_signature_hex}")
        sig_dict.CertSerial = String(signer_cert_serial)
        sig_dict.SignerPublicKey = String(signer_pub_key_hex)
        
        # Nhúng vào cấu trúc danh mục chính tài liệu (Document Catalog / Document Info)
        pdf.Catalog.get_or_create_dictionary(Name.AcroForm)
        pdf.docinfo["/PQCSigned"] = "True"
        pdf.docinfo["/PQCSignature"] = signature_hex
        pdf.docinfo["/PQCTSA"] = String(f"{json.dumps(tsa_token_json)}||{tsa_signature_hex}")
        pdf.docinfo["/PQCCertSerial"] = String(signer_cert_serial)
        
        pdf.save(output_pdf_path)