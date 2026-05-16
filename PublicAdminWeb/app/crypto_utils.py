import datetime
import hashlib
import uuid
from xml.etree import ElementTree

import oqs
from pikepdf import Pdf


def get_sha3_512_hash(data: bytes):
    return hashlib.sha3_512(data).digest()


def hash_pdf(file_path):
    sha3 = hashlib.sha3_512()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    return sha3.digest()


def _normalize_hex(hex_text: str) -> str:
    return "".join(str(hex_text or "").split())


def _sign_with_private_key(message: bytes, private_key: bytes, sig_alg: str) -> bytes:
    """Support both common liboqs-python signing APIs."""
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
        "hashFunction": hash_function,
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
    signed_at = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    signature_id = str(uuid.uuid4())
    hash_function = "SHA3-512"

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
            # Some pikepdf versions reject custom XMP namespaces. DocInfo still
            # keeps the XML signature metadata inside the signed PDF.
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


def encapsulate_private_key(private_key_to_protect: bytes, ca_public_key_kem: bytes):
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        ciphertext, shared_secret = kem.encap_secret(ca_public_key_kem)

        mask = get_sha3_512_hash(shared_secret)
        extended_mask = (mask * ((len(private_key_to_protect) // len(mask)) + 1))[:len(private_key_to_protect)]
        encrypted_pk = bytes(a ^ b for a, b in zip(private_key_to_protect, extended_mask))

        return ciphertext.hex(), encrypted_pk.hex()


def decapsulate_private_key(encrypted_pk_hex: str, ciphertext_hex: str, ca_private_key_kem: bytes):
    with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
        shared_secret = kem.decap_secret(bytes.fromhex(ciphertext_hex), ca_private_key_kem)

        mask = get_sha3_512_hash(shared_secret)
        encrypted_pk = bytes.fromhex(encrypted_pk_hex)
        extended_mask = (mask * ((len(encrypted_pk) // len(mask)) + 1))[:len(encrypted_pk)]
        original_pk = bytes(a ^ b for a, b in zip(encrypted_pk, extended_mask))

        return original_pk.hex()
