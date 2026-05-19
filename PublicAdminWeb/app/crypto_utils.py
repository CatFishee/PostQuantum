import datetime
import hashlib
import uuid
import os
from xml.etree import ElementTree

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pikepdf import Pdf


# --- Hashing: Chuyển sang SHAKE-256 theo đúng chuẩn Đồ án ---
def get_shake_256_hash(data: bytes, length: int = 32):
    return hashlib.shake_256(data).digest(length)


def hash_pdf(file_path):
    shake = hashlib.shake_256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            shake.update(chunk)
    return shake.digest(32)


# --- AES-GCM cho Session Key (Kênh truyền Web <-> CA) ---
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    aesgcm = AESGCM(key[:32]) # KEM shared_secret là 32 bytes
    iv = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return iv, ciphertext, tag


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    aesgcm = AESGCM(key[:32])
    return aesgcm.decrypt(iv, ciphertext + tag, None)


# --- KEM Encapsulation cho Web gửi lên CA ---
def web_encapsulate(ca_public_key: bytes):
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        ciphertext, shared_secret = kem.encap_secret(ca_public_key)
        return ciphertext, shared_secret


def _normalize_hex(hex_text: str) -> str:
    return "".join(str(hex_text or "").split())


def _sign_with_private_key(message: bytes, private_key: bytes, sig_alg: str) -> bytes:
    try:
        with oqs.Signature(sig_alg, secret_key=private_key) as signer:
            return signer.sign(message)
    except TypeError:
        with oqs.Signature(sig_alg) as signer:
            return signer.sign(message, private_key)


def build_pqc_signature_xml(
    *,
    doc_id: str,
    signer_id: str,
    algorithm: str,
    hash_function: str,
    signature_hex: str,
    public_key_hex: str,
    signed_at: str,
) -> str:
    root = ElementTree.Element("pqcSignature")
    fields = {
        "docId": doc_id,
        "signerId": signer_id,
        "algorithm": algorithm,
        "hashFunction": hash_function, # Mặc định sẽ là SHAKE-256
        "signatureValue": signature_hex,
        "signerPublicKey": public_key_hex,
        "signedAt": signed_at,
    }
    for key, value in fields.items():
        child = ElementTree.SubElement(root, key)
        child.text = str(value or "")
    return ElementTree.tostring(root, encoding="unicode")


def sign_pdf_metadata(
    input_pdf_path,
    output_pdf_path,
    private_key_hex,
    public_key_hex="",
    *,
    signer_id="",
    doc_id="",
    sig_alg="ML-DSA-65",
):
    private_key = bytes.fromhex(_normalize_hex(private_key_hex))
    file_hash = hash_pdf(input_pdf_path)
    signature = _sign_with_private_key(file_hash, private_key, sig_alg)
    signature_hex = signature.hex()
    
    # Định dạng ISO 8601
    signed_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    signature_id = str(uuid.uuid4())
    hash_function = "SHAKE-256"

    xmp_xml = build_pqc_signature_xml(
        doc_id=doc_id,
        signer_id=signer_id,
        algorithm=sig_alg,
        hash_function=hash_function,
        signature_hex=signature_hex,
        public_key_hex=public_key_hex,
        signed_at=signed_at,
    )

    with Pdf.open(input_pdf_path) as pdf:
        try:
            with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
                try:
                    meta.register_xml_namespace("pqc", "https://postquantum.local/ns/pqc/1.0/")
                except Exception:
                    pass
                meta["pqc:SignatureId"] = signature_id
                meta["pqc:Algorithm"] = sig_alg
                meta["pqc:HashFunction"] = hash_function
                meta["pqc:SignatureValue"] = signature_hex
                meta["pqc:SignerPublicKey"] = public_key_hex
                meta["pqc:SignatureXML"] = xmp_xml
        except Exception:
            pass
        pdf.docinfo["/PQCSignatureXML"] = xmp_xml
        pdf.save(output_pdf_path)

    return {
        "signature_id": signature_id,
        "algorithm": sig_alg,
        "hash_function": hash_function,
        "signature_value": signature_hex,
        "xmp_metadata_embedded": xmp_xml,
        "signed_at": signed_at,
        "output_pdf_path": output_pdf_path,
    }