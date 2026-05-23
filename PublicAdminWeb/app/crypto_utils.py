import datetime
import hashlib
import os
import sys
import uuid
from xml.etree import ElementTree

_OQS_DLL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
    os.add_dll_directory(_OQS_DLL_DIR)
os.environ["PATH"] = _OQS_DLL_DIR + os.pathsep + os.environ.get("PATH", "")

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pikepdf import Array, Dictionary, Pdf, Stream


PQC_NAMESPACE = "https://postquantum.local/ns/pqc/1.0/"
PDF_HASH_LENGTH = 32

_PDF_HASH_SKIP_KEYS = {
    "/DecodeParms",
    "/Filter",
    "/Length",
    "/Metadata",
    "/ModDate",
    "/Parent",
    "/PieceInfo",
}


# --- Hashing: SHAKE-256 theo dung chuan do an ---
def get_shake_256_hash(data: bytes, length: int = PDF_HASH_LENGTH):
    return hashlib.shake_256(data).digest(length)


def _safe_attr(value, name, default=None):
    try:
        return object.__getattribute__(value, name)
    except Exception:
        return default


def _stable_pdf_update(shake, value, seen_objects):
    objgen = _safe_attr(value, "objgen")
    if objgen and objgen != (0, 0):
        if objgen in seen_objects:
            return
        seen_objects.add(objgen)

    page_obj = _safe_attr(value, "obj")
    if page_obj is not None:
        value = page_obj

    if isinstance(value, Stream):
        shake.update(b"<stream>")
        try:
            data = value.read_bytes()
        except Exception:
            data = value.read_raw_bytes()
        shake.update(len(data).to_bytes(8, "big"))
        shake.update(data)

        for key in sorted(value.keys(), key=str):
            key_text = str(key)
            if key_text in _PDF_HASH_SKIP_KEYS:
                continue
            shake.update(key_text.encode("utf-8"))
            _stable_pdf_update(shake, value[key], seen_objects)
        return

    if isinstance(value, Dictionary):
        shake.update(b"<dict>")
        for key in sorted(value.keys(), key=str):
            key_text = str(key)
            if key_text in _PDF_HASH_SKIP_KEYS:
                continue
            shake.update(key_text.encode("utf-8"))
            _stable_pdf_update(shake, value[key], seen_objects)
        return

    if isinstance(value, Array):
        shake.update(b"<array>")
        for item in value:
            _stable_pdf_update(shake, item, seen_objects)
        return

    if isinstance(value, (bytes, bytearray)):
        shake.update(b"<bytes>")
        shake.update(len(value).to_bytes(8, "big"))
        shake.update(bytes(value))
        return

    text = str(value or "")
    shake.update(b"<scalar>")
    shake.update(text.encode("utf-8", errors="surrogatepass"))


def hash_pdf_document_content(file_path):
    """Hash noi dung trang PDF, bo qua metadata de verify sau khi da nhung chu ky."""
    shake = hashlib.shake_256()
    with Pdf.open(file_path) as pdf:
        shake.update(f"pages:{len(pdf.pages)}".encode("utf-8"))
        for index, page in enumerate(pdf.pages):
            shake.update(f"page:{index}".encode("utf-8"))
            _stable_pdf_update(shake, page, set())
    return shake.digest(PDF_HASH_LENGTH)


def hash_pdf(file_path):
    return hash_pdf_document_content(file_path)


def hash_pdf_hex(file_path):
    return hash_pdf_document_content(file_path).hex()


# --- AES-GCM cho Session Key (Kenh truyen Web <-> CA) ---
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    aesgcm = AESGCM(key[:32])
    iv = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return iv, ciphertext, tag


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    aesgcm = AESGCM(key[:32])
    return aesgcm.decrypt(iv, ciphertext + tag, None)


# --- KEM Encapsulation cho Web gui len CA ---
def web_encapsulate(ca_public_key: bytes):
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        ciphertext, shared_secret = kem.encap_secret(ca_public_key)
        return ciphertext, shared_secret


def _normalize_hex(hex_text: str) -> str:
    text = "".join(str(hex_text or "").split())
    return text[2:] if text.lower().startswith("0x") else text


def _sign_with_private_key(message: bytes, private_key: bytes, sig_alg: str) -> bytes:
    try:
        with oqs.Signature(sig_alg, secret_key=private_key) as signer:
            return signer.sign(message)
    except TypeError:
        with oqs.Signature(sig_alg) as signer:
            return signer.sign(message, private_key)


def _verify_with_public_key(message: bytes, signature: bytes, public_key: bytes, sig_alg: str) -> bool:
    try:
        with oqs.Signature(sig_alg) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except TypeError:
        with oqs.Signature(sig_alg, public_key=public_key) as verifier:
            return bool(verifier.verify(message, signature))


def build_pqc_signature_xml(
    *,
    signature_id: str,
    doc_id: str,
    signer_id: str,
    algorithm: str,
    hash_function: str,
    document_hash: str,
    signature_hex: str,
    public_key_hex: str,
    signed_at: str,
    pqc_cert_serial: str = "",
) -> str:
    root = ElementTree.Element("pqcSignature")
    fields = {
        "signatureId": signature_id,
        "docId": doc_id,
        "signerId": signer_id,
        "algorithm": algorithm,
        "hashFunction": hash_function,
        "documentHash": document_hash,
        "signatureValue": signature_hex,
        "signerPublicKey": public_key_hex,
        "pqcCertSerial": pqc_cert_serial,
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
    pqc_cert_serial="",
):
    private_key = bytes.fromhex(_normalize_hex(private_key_hex))
    document_hash = hash_pdf_document_content(input_pdf_path)
    document_hash_hex = document_hash.hex()
    signature = _sign_with_private_key(document_hash, private_key, sig_alg)
    signature_hex = signature.hex()

    signed_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    signature_id = str(uuid.uuid4())
    hash_function = "SHAKE-256"

    xmp_xml = build_pqc_signature_xml(
        signature_id=signature_id,
        doc_id=doc_id,
        signer_id=signer_id,
        algorithm=sig_alg,
        hash_function=hash_function,
        document_hash=document_hash_hex,
        signature_hex=signature_hex,
        public_key_hex=_normalize_hex(public_key_hex),
        signed_at=signed_at,
        pqc_cert_serial=pqc_cert_serial,
    )

    with Pdf.open(input_pdf_path) as pdf:
        try:
            with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
                try:
                    meta.register_xml_namespace("pqc", PQC_NAMESPACE)
                except Exception:
                    pass
                meta["pqc:SignatureId"] = signature_id
                meta["pqc:Algorithm"] = sig_alg
                meta["pqc:HashFunction"] = hash_function
                meta["pqc:DocumentHash"] = document_hash_hex
                meta["pqc:SignatureValue"] = signature_hex
                meta["pqc:SignerPublicKey"] = _normalize_hex(public_key_hex)
                meta["pqc:PQCCertSerial"] = pqc_cert_serial
                meta["pqc:SignatureXML"] = xmp_xml
        except Exception:
            pass
        pdf.docinfo["/PQCSignatureXML"] = xmp_xml
        pdf.save(output_pdf_path)

    return {
        "signature_id": signature_id,
        "algorithm": sig_alg,
        "hash_function": hash_function,
        "document_hash": document_hash_hex,
        "signature_value": signature_hex,
        "pqc_cert_serial": pqc_cert_serial,
        "xmp_metadata_embedded": xmp_xml,
        "signed_at": signed_at,
        "output_pdf_path": output_pdf_path,
    }


def extract_pqc_signature_xml(pdf_path):
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


def _xml_local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_pqc_signature_xml(xml_text):
    if not xml_text:
        raise ValueError("PDF khong co metadata chu ky PQC.")

    root = ElementTree.fromstring(xml_text)
    field_map = {
        "signatureId": "signature_id",
        "docId": "doc_id",
        "signerId": "signer_id",
        "algorithm": "algorithm",
        "hashFunction": "hash_function",
        "documentHash": "document_hash",
        "signatureValue": "signature_value",
        "signerPublicKey": "signer_public_key",
        "pqcCertSerial": "pqc_cert_serial",
        "signedAt": "signed_at",
    }
    values = {}
    for child in list(root):
        key = field_map.get(_xml_local_name(child.tag))
        if key:
            values[key] = (child.text or "").strip()
    return values


def read_pqc_signature_metadata(pdf_path):
    xml_text = extract_pqc_signature_xml(pdf_path)
    values = parse_pqc_signature_xml(xml_text)
    values["xmp_metadata_embedded"] = xml_text
    return values


def verify_pdf_signature(pdf_path, public_key_hex=""):
    metadata = read_pqc_signature_metadata(pdf_path)
    algorithm = metadata.get("algorithm") or "ML-DSA-65"
    expected_hash = _normalize_hex(metadata.get("document_hash", "")).lower()
    actual_hash = hash_pdf_hex(pdf_path).lower()
    public_key_hex = _normalize_hex(public_key_hex or metadata.get("signer_public_key", ""))

    result = {
        **metadata,
        "algorithm": algorithm,
        "actual_document_hash": actual_hash,
        "document_hash_matches": bool(expected_hash and expected_hash == actual_hash),
        "signature_valid": False,
        "is_valid": False,
        "error": "",
    }

    if not expected_hash:
        result["error"] = "Metadata khong co documentHash."
        return result
    if not result["document_hash_matches"]:
        result["error"] = "documentHash khong khop voi noi dung PDF hien tai."
        return result
    if not public_key_hex:
        result["error"] = "Khong tim thay public key ML-DSA de verify."
        return result

    try:
        signature = bytes.fromhex(_normalize_hex(metadata.get("signature_value", "")))
        public_key = bytes.fromhex(public_key_hex)
        result["signature_valid"] = _verify_with_public_key(
            bytes.fromhex(expected_hash),
            signature,
            public_key,
            algorithm,
        )
        result["is_valid"] = result["document_hash_matches"] and result["signature_valid"]
    except Exception as exc:
        result["error"] = str(exc)

    return result

def _bytes_from_mongo_binary(value):
    """
    Chuyen public key lay tu MongoDB ve dang bytes.

    MongoDB co the luu key theo nhieu dang:
    - bytes / bytearray
    - Binary cua bson
    - hex string
    """
    if value is None:
        return b""

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, str):
        text = "".join(value.split())
        try:
            return bytes.fromhex(text)
        except ValueError:
            return text.encode("utf-8")

    try:
        return bytes(value)
    except Exception:
        return b""


def encrypt_pdf_with_ml_kem(input_pdf_path, output_encrypted_path, officer_ml_kem_public_key):
    """
    Ma hoa PDF theo huong post-quantum thuan o tang khoa cong khai.

    - ML-KEM-768 dung de encapsulate shared secret cho can bo.
    - AES-GCM dung de ma hoa noi dung PDF bang khoa phien sinh tu shared secret.
    - Khong su dung RSA, ECC, ECDH, ECDSA hoac thuat toan khoa cong khai co dien.
    """
    public_key = _bytes_from_mongo_binary(officer_ml_kem_public_key)

    if not public_key:
        raise ValueError("Khong tim thay ML-KEM public key cua can bo.")

    with open(input_pdf_path, "rb") as f:
        plaintext = f.read()

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        encapsulated_key, shared_secret = kem.encap_secret(public_key)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    output_dir = os.path.dirname(output_encrypted_path)
    os.makedirs(output_dir, exist_ok=True)

    with open(output_encrypted_path, "wb") as f:
        f.write(ciphertext)

    return {
        "ciphertext_path": output_encrypted_path,
        "encapsulated_key": encapsulated_key,
        "kems_variant": "ML-KEM-768",
        "payload_cipher": "AES-256-GCM",
        "nonce": nonce,
    }

def decrypt_pdf_with_ml_kem(
    encrypted_pdf_path,
    output_pdf_path,
    encapsulated_key,
    nonce,
    officer_ml_kem_private_key,
):
    """
    Giai ma PDF theo huong post-quantum o tang khoa cong khai.

    - ML-KEM-768 dung de decapsulate shared secret bang private key cua can bo.
    - AES-GCM dung de giai ma noi dung PDF bang khoa phien sinh tu shared secret.
    - Khong su dung RSA, ECC, ECDH, ECDSA hoac thuat toan khoa cong khai co dien.
    """
    private_key = _bytes_from_mongo_binary(officer_ml_kem_private_key)
    encapsulated_key_bytes = _bytes_from_mongo_binary(encapsulated_key)
    nonce_bytes = _bytes_from_mongo_binary(nonce)

    if not private_key:
        raise ValueError("Khong tim thay ML-KEM private key cua can bo.")

    if not encapsulated_key_bytes:
        raise ValueError("Ho so khong co encapsulated_key.")

    if not nonce_bytes:
        raise ValueError("Ho so khong co nonce.")

    with open(encrypted_pdf_path, "rb") as f:
        ciphertext = f.read()

    with oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(encapsulated_key_bytes)

    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(nonce_bytes, ciphertext, None)

    output_dir = os.path.dirname(output_pdf_path)
    os.makedirs(output_dir, exist_ok=True)

    with open(output_pdf_path, "wb") as f:
        f.write(plaintext)

    return {
        "decrypted_path": output_pdf_path,
        "kems_variant": "ML-KEM-768",
        "payload_cipher": "AES-256-GCM",
    }