import datetime
import hashlib
import uuid
import os
import base64
from xml.etree import ElementTree

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pikepdf import Pdf


# --- Hashing: Chuyển sang SHAKE-256 ---
def get_shake_256_hash(data: bytes, length: int = 32):
    return hashlib.shake_256(data).digest(length)


def _update_pdf_object_bytes(shake, obj):
    """
    Hash phần nội dung ổn định của PDF, tránh hash metadata chữ ký PQC.
    """
    if obj is None:
        return

    try:
        # Nếu là array stream
        if obj.__class__.__name__ == "Array":
            for item in obj:
                _update_pdf_object_bytes(shake, item)
            return

        # Nếu là stream object
        if hasattr(obj, "read_bytes"):
            shake.update(obj.read_bytes())
            return

        shake.update(str(obj).encode("utf-8", errors="ignore"))

    except Exception:
        shake.update(str(obj).encode("utf-8", errors="ignore"))


def hash_pdf(file_path):
    """
    Hash ổn định nội dung PDF để ký/verify.
    Không hash toàn bộ raw bytes vì sau khi nhúng metadata chữ ký,
    raw bytes của PDF sẽ thay đổi.
    """
    shake = hashlib.shake_256()

    with Pdf.open(file_path) as pdf:
        shake.update(str(len(pdf.pages)).encode("utf-8"))

        for page in pdf.pages:
            page_obj = page.obj

            for key in ("/MediaBox", "/CropBox", "/Rotate"):
                try:
                    shake.update(str(page_obj.get(key, "")).encode("utf-8", errors="ignore"))
                except Exception:
                    pass

            try:
                _update_pdf_object_bytes(shake, page_obj.get("/Contents"))
            except Exception:
                pass

            try:
                resources = page_obj.get("/Resources", {})
                xobjects = resources.get("/XObject", {}) if resources else {}
                for _, xobj in xobjects.items():
                    _update_pdf_object_bytes(shake, xobj)
            except Exception:
                pass

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
    document_hash_hex: str,
    signature_hex: str,
    public_key_hex: str,
    signed_at: str,
    pqc_cert_serial: str = "",
) -> str:
    root = ElementTree.Element("pqcSignature")
    fields = {
        "docId": doc_id,
        "signerId": signer_id,
        "algorithm": algorithm,
        "hashFunction": hash_function, # Mặc định sẽ là SHAKE-256
        "documentHash": document_hash_hex,
        "signatureValue": signature_hex,
        "signerPublicKey": public_key_hex,
        "signedAt": signed_at,
        "certSerial": pqc_cert_serial,
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
    pqc_cert_serial="",
):
    private_key = bytes.fromhex(_normalize_hex(private_key_hex))
    file_hash = hash_pdf(input_pdf_path)
    document_hash_hex = file_hash.hex()
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
    document_hash_hex=document_hash_hex,
    signature_hex=signature_hex,
    public_key_hex=public_key_hex,
    signed_at=signed_at,
    pqc_cert_serial=pqc_cert_serial,
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
                meta["pqc:DocumentHash"] = document_hash_hex
                meta["pqc:SignatureValue"] = signature_hex
                meta["pqc:SignerPublicKey"] = public_key_hex
                meta["pqc:SignatureXML"] = xmp_xml
                meta["pqc:CertSerial"] = pqc_cert_serial
        except Exception:
            pass
        pdf.docinfo["/PQCSignatureXML"] = xmp_xml
        pdf.docinfo["/PQCCertSerial"] = pqc_cert_serial
        pdf.save(output_pdf_path)

    return {
        "signature_id": signature_id,
        "algorithm": sig_alg,
        "hash_function": hash_function,
        "document_hash": document_hash_hex,
        "signature_value": signature_hex,
        "xmp_metadata_embedded": xmp_xml,
        "signed_at": signed_at,
        "output_pdf_path": output_pdf_path,
        "pqc_cert_serial": pqc_cert_serial,
    }

def _bytes_from_value(value):
    """
    Chuyen du lieu tu MongoDB / JSON / hex / base64 ve bytes.
    """
    if value is None:
        return b""

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, str):
        text = "".join(value.split())

        # Thu hex truoc
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass

        # Thu base64
        try:
            return base64.b64decode(text)
        except Exception:
            return text.encode("utf-8")

    try:
        return bytes(value)
    except Exception:
        return b""


def encrypt_pdf_bytes_with_ml_kem(pdf_bytes: bytes, officer_ml_kem_public_key):
    """
    CA Server ma hoa PDF bang ML-KEM-768 o tang khoa cong khai.

    - ML-KEM-768: encapsulate shared secret cho can bo.
    - AES-GCM: ma hoa noi dung PDF bang khoa phien sinh tu shared secret.
    - Khong dung RSA/ECC/ECDH.
    """
    public_key = _bytes_from_value(officer_ml_kem_public_key)

    if not public_key:
        raise ValueError("Khong tim thay ML-KEM public key cua can bo.")

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        encapsulated_key, shared_secret = kem.encap_secret(public_key)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, pdf_bytes, None)

    return {
        "ciphertext": ciphertext,
        "encapsulated_key": encapsulated_key,
        "nonce": nonce,
        "kems_variant": "ML-KEM-768",
        "payload_cipher": "AES-256-GCM",
        "classical_public_key_algorithm": None,
    }


def decrypt_pdf_bytes_with_ml_kem(ciphertext: bytes, encapsulated_key, nonce, officer_ml_kem_private_key):
    """
    CA Server giai ma PDF bang ML-KEM-768 private key cua can bo.
    """
    private_key = _bytes_from_value(officer_ml_kem_private_key)
    encapsulated_key_bytes = _bytes_from_value(encapsulated_key)
    nonce_bytes = _bytes_from_value(nonce)

    if not private_key:
        raise ValueError("Không tìm thấy ML-KEM private key của cán bộ.")
    if not encapsulated_key_bytes:
        raise ValueError("Thiếu encapsulated_key.")
    if not nonce_bytes:
        raise ValueError("Thiếu nonce.")

    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(encapsulated_key_bytes)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(nonce_bytes, ciphertext, None)
    return plaintext


def extract_pqc_signature_xml(pdf_path):
    """
    Doc XML chu ky PQC tu metadata PDF.
    """
    with Pdf.open(pdf_path) as pdf:
        try:
            with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
                xml_text = meta.get("pqc:SignatureXML", "")
                if xml_text:
                    return str(xml_text)
        except Exception:
            pass

        xml_text = pdf.docinfo.get("/PQCSignatureXML", "")
        return str(xml_text or "")


def parse_pqc_signature_xml(xml_text):
    if not xml_text:
        raise ValueError("PDF không có metadata chữ ký PQC.")

    root = ElementTree.fromstring(xml_text)
    values = {}

    for child in list(root):
        key = child.tag.rsplit("}", 1)[-1]
        values[key] = (child.text or "").strip()

    return values


def _verify_with_public_key(message: bytes, signature: bytes, public_key: bytes, sig_alg: str) -> bool:
    try:
        with oqs.Signature(sig_alg) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except TypeError:
        with oqs.Signature(sig_alg, public_key=public_key) as verifier:
            return bool(verifier.verify(message, signature))


def verify_pdf_signature_metadata(pdf_path):
    """
    Verify PDF da ky bang metadata PQC.
    """
    metadata = {}

    try:
        xml_text = extract_pqc_signature_xml(pdf_path)
        metadata = parse_pqc_signature_xml(xml_text)

        algorithm = metadata.get("algorithm") or metadata.get("Algorithm") or "ML-DSA-65"
        signature_hex = metadata.get("signatureValue") or metadata.get("SignatureValue") or ""
        public_key_hex = metadata.get("signerPublicKey") or metadata.get("SignerPublicKey") or ""

        if not signature_hex:
            return {
                "is_valid": False,
                "algorithm": algorithm,
                "metadata": metadata,
                "error": "Khong tim thay signatureValue trong metadata.",
            }

        if not public_key_hex:
            return {
                "is_valid": False,
                "algorithm": algorithm,
                "metadata": metadata,
                "error": "Khong tim thay signerPublicKey trong metadata.",
            }

        cert_serial = (
            metadata.get("certSerial")
            or metadata.get("CertSerial")
            or metadata.get("cert_serial")
            or ""
        )
        file_hash = hash_pdf(pdf_path)
        current_document_hash = file_hash.hex()

        embedded_document_hash = (
            metadata.get("documentHash")
            or metadata.get("DocumentHash")
            or metadata.get("document_hash")
            or ""
        )

        hash_match = True
        if embedded_document_hash:
            hash_match = embedded_document_hash == current_document_hash

        signature = bytes.fromhex(_normalize_hex(signature_hex))
        public_key = bytes.fromhex(_normalize_hex(public_key_hex))

        signature_valid = _verify_with_public_key(
            file_hash,
            signature,
            public_key,
            algorithm,
        )

        is_valid = bool(signature_valid and hash_match)

        return {
            "is_valid": is_valid,
            "signature_valid": bool(signature_valid),
            "hash_match": bool(hash_match),
            "algorithm": algorithm,
            "hash_function": "SHAKE-256",
            "document_hash_embedded": embedded_document_hash,
            "document_hash_current": current_document_hash,
            "cert_serial": cert_serial,
            "pqc_cert_serial": cert_serial,
            "metadata": metadata,
            "error": "" if is_valid else "Chữ ký hoặc documentHash không hợp lệ.",
        }

    except Exception as exc:
        return {
            "is_valid": False,
            "algorithm": metadata.get("algorithm", "ML-DSA-65") if metadata else "ML-DSA-65",
            "metadata": metadata,
            "error": str(exc),
        }