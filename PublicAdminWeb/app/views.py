import os
import uuid
import json
from datetime import datetime

import requests
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.shortcuts import redirect, render
from django.utils.text import get_valid_filename

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .crypto_utils import (
    
    ca_decrypt_pdf,
    ca_encrypt_pdf,
    ca_sign_pdf,
    ca_verify_pdf,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    decrypt_pdf_with_ml_kem,
    encrypt_pdf_with_ml_kem,
    read_pqc_signature_metadata,
    sign_pdf_metadata,
    verify_pdf_signature,
    web_encapsulate,
)
from .db_connection import get_db
from .forms import SignatureForm, VerifySignatureForm, UploadPDFForm, DecryptApplicationForm

try:
    from bson import ObjectId
except Exception:
    ObjectId = None

db = get_db()
ph = PasswordHasher()


def _is_officer_role(role):
    return str(role or "").lower() == "officer"


def _to_mongo_id(value):
    if ObjectId is None or not value:
        return value
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(str(value))
    except Exception:
        return value


def _object_id_queries(doc_id):
    queries = []
    mongo_id = _to_mongo_id(doc_id)
    if mongo_id != doc_id:
        queries.append({"_id": mongo_id})
    queries.append({"_id": doc_id})
    return queries


def _find_document(doc_id):
    if db is None or not doc_id:
        return None

    for collection_name in ("applications", "documents"):
        collection = getattr(db, collection_name)
        for query in _object_id_queries(doc_id):
            found = collection.find_one(query)
            if found:
                found["_collection_name"] = collection_name
                return found
    return None


def _binary_to_hex(value):
    if not value:
        return ""
    if isinstance(value, str):
        return "".join(value.split())
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if hasattr(value, "hex"):
        return value.hex()
    return str(value)


def _get_officer_key_doc(user_id):
    if db is None or not user_id:
        return None

    queries = []
    mongo_id = _to_mongo_id(user_id)
    if mongo_id != user_id:
        queries.append({"officer_id": mongo_id, "status": "active"})
    queries.append({"officer_id": user_id, "status": "active"})
    queries.append({"officer_id": str(user_id), "status": "active"})

    for query in queries:
        officer_key = db.officer_keys.find_one(query)
        if officer_key:
            return officer_key
    return None


def _get_officer_public_key(user_id):
    officer_key = _get_officer_key_doc(user_id)
    if officer_key and "ml_dsa_pk" in officer_key:
        return _binary_to_hex(officer_key["ml_dsa_pk"])
    return ""


def _get_pqc_cert_serial(user_id):
    officer_key = _get_officer_key_doc(user_id)
    if officer_key:
        return str(officer_key.get("cert_serial", ""))
    return ""


def _save_uploaded_file(uploaded_file, folder):
    target_dir = os.path.join(settings.MEDIA_ROOT, folder)
    os.makedirs(target_dir, exist_ok=True)

    storage = FileSystemStorage(location=target_dir)
    safe_name = get_valid_filename(uploaded_file.name)
    file_name = f"{uuid.uuid4().hex}_{safe_name}"
    saved_name = storage.save(file_name, uploaded_file)
    relative_path = f"{folder}/{saved_name}".replace("\\", "/")
    return storage.path(saved_name), relative_path


def _update_signed_document(doc_id, signed_relative_path, signature_result, signer_id):
    if db is None or not doc_id:
        return

    # 1. Lưu vào collection `signatures` (theo chuẩn PDF)
    sig_doc = {
        "doc_id": _to_mongo_id(doc_id),
        "signer_id": _to_mongo_id(signer_id),
        "algorithm": signature_result["algorithm"],
        "signature_value": bytes.fromhex(signature_result["signature_value"]),
        "hash_function": signature_result["hash_function"],
        "document_hash": signature_result.get("document_hash", ""),
        "pqc_cert_serial": signature_result.get("pqc_cert_serial", ""),
        "xmp_metadata_embedded": signature_result["xmp_metadata_embedded"],
        "signed_at": datetime.strptime(signature_result["signed_at"], "%Y-%m-%dT%H:%M:%SZ"),
    }
    insert_res = db.signatures.insert_one(sig_doc)

    # 2. Cập nhật vào collection `applications`
    update_data = {
        "status": "processed",
        "result_document.signed_ciphertext_path": signed_relative_path,
        "result_document.pqc_signature_id": insert_res.inserted_id,
    }

    for collection_name in ("applications", "documents"):
        collection = getattr(db, collection_name)
        for query in _object_id_queries(doc_id):
            result = collection.update_one(query, {"$set": update_data})
            if result.matched_count:
                return


def _document_rows(raw_docs):
    rows = []
    for doc in raw_docs:
        citizen_id = doc.get("citizen_id", doc.get("owner", ""))
        officer_id = doc.get("assigned_officer_id", "")

        result_document = doc.get("result_document") or {}
        pqc_metadata = doc.get("pqc_encryption_metadata") or {}

        rows.append(
            {
                "id": str(doc.get("_id", "")),
                "status": doc.get("status", ""),
                "created_at": doc.get("created_at", ""),
                "assigned_officer_id": _get_user_display_name(officer_id) or str(officer_id),
                "citizen_id": _get_user_display_name(citizen_id) or str(citizen_id),

                # Dùng cho dashboard người dân tải file kết quả / file đã ký
                "submission_type": doc.get("submission_type", ""),
                "signed_file_path": result_document.get("signed_ciphertext_path", ""),
                "original_upload_path": pqc_metadata.get("original_upload_path", ""),
                "decrypted_path": pqc_metadata.get("decrypted_path", ""),
            }
        )
    return rows


def _get_user_display_name(user_id):
    if db is None or not user_id:
        return ""

    for query in _object_id_queries(user_id):
        user = db.users.find_one(query)
        if user:
            return user.get("full_name") or user.get("username") or str(user.get("_id", ""))
    return ""


def home(request):
    return render(request, "app/index.html", {"title": "Trang chủ PQC", "year": datetime.now().year})


def register(request):
    if request.method == "POST":
        if db is None:
            messages.error(request, "Database chưa kết nối, không thể đăng ký.")
            return redirect("register")

        username = request.POST["username"]
        role = request.POST["role"]
        password = request.POST["password"]
        full_name = request.POST["full_name"]

        if db.users.find_one({"username": username}):
            messages.error(request, "Tên đăng nhập đã tồn tại!")
            return redirect("register")

        pass_hash = ph.hash(password)

        user_data = {
            "username": username,
            "role": role,
            "password_hash": pass_hash,
            "full_name": full_name,
            "pqc_status": "active" if not _is_officer_role(role) else "inactive",
            "created_at": datetime.utcnow(),
        }

        result = db.users.insert_one(user_data)
        user_id = str(result.inserted_id)

        if _is_officer_role(role):
            try:
                # 1. Lấy Master KEM Public Key
                r_pub = requests.get("http://127.0.0.1:5001/master-public-key", timeout=10)
                r_pub.raise_for_status()
                master_pub = bytes.fromhex(r_pub.json()["public_key"])

                # 2. Encapsulate sinh Session Key
                kem_cipher, shared_secret = web_encapsulate(master_pub)

                # 3. Đóng gói Payload với AES-GCM
                payload_dict = {"officer_id": user_id, "username": username, "full_name": full_name}
                payload_bytes = json.dumps(payload_dict).encode('utf-8')
                iv, cipher, tag = aes_gcm_encrypt(shared_secret, payload_bytes)

                # 4. Gửi Request lên CA
                ca_req_data = {
                    "kem_ciphertext": kem_cipher.hex(),
                    "aes_iv": iv.hex(),
                    "aes_tag": tag.hex(),
                    "encrypted_payload": cipher.hex()
                }
                response = requests.post("http://127.0.0.1:5001/register_officer", json=ca_req_data, timeout=15)
                response.raise_for_status()
                ca_resp = response.json()

                # 5. Giải mã Response để lấy 2 Private Keys
                resp_bytes = aes_gcm_decrypt(
                    shared_secret,
                    bytes.fromhex(ca_resp["aes_iv"]),
                    bytes.fromhex(ca_resp["encrypted_payload"]),
                    bytes.fromhex(ca_resp["aes_tag"])
                )
                priv_keys_dict = json.loads(resp_bytes.decode('utf-8'))
                
                # Bật trạng thái active cho User
                db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"pqc_status": "active"}})
                
                # Lưu vào Session
                request.session["temp_private_keys"] = priv_keys_dict
                request.session["temp_username"] = username
                
                messages.success(request, "Tạo tài khoản Cán bộ thành công. Vui lòng tải file chứa bộ khóa bảo mật!")
                return redirect("download_key")

            except Exception as e:
                db.users.delete_one({"_id": ObjectId(user_id)})
                messages.error(request, f"Không thể kết nối tới CA Server hoặc lỗi bảo mật: {e}")
                return redirect("register")

        messages.success(request, "Đăng ký thành công!")
        return redirect("login")

    return render(request, "app/register.html", {"title": "Đăng ký", "year": datetime.now().year})


def download_key(request):
    priv_keys = request.session.pop("temp_private_keys", None)
    username = request.session.pop("temp_username", "Unknown")
    
    if not priv_keys:
        messages.warning(request, "Không tìm thấy khóa hoặc khóa đã được tải. Vui lòng đăng nhập.")
        return redirect("login")
    
    # Định dạng chuỗi JSON đẹp mắt để tải về dưới dạng file .json
    keys_json_str = json.dumps(priv_keys, indent=4)
        
    return render(request, "app/download_key.html", {
        "private_keys": keys_json_str,
        "username": username,
        "title": "Tải khóa",
        "year": datetime.now().year
    })


def login(request):
    if request.method == "POST":
        if db is None:
            messages.error(request, "Database chưa kết nối, không thể đăng nhập.")
            return render(request, "app/login.html", {"title": "Đăng nhập", "year": datetime.now().year})

        username = request.POST["username"]
        password_attempt = request.POST["password"]

        user = db.users.find_one({"username": username})
        if user:
            try:
                ph.verify(user["password_hash"], password_attempt)
                
                if ph.check_needs_rehash(user["password_hash"]):
                    db.users.update_one({"_id": user["_id"]}, {"$set": {"password_hash": ph.hash(password_attempt)}})
                
                if user.get("pqc_status") == "inactive":
                    messages.error(request, "Tài khoản của bạn bị lỗi hoặc chưa có khóa PQC hợp lệ.")
                    return redirect("login")

                request.session["user_id"] = str(user["_id"])
                request.session["user"] = user["username"]
                request.session["role"] = user["role"]
                return redirect("dashboard")
                
            except VerifyMismatchError:
                pass 

        messages.error(request, "Sai tên đăng nhập hoặc mật khẩu!")

    return render(request, "app/login.html", {"title": "Đăng nhập", "year": datetime.now().year})


def dashboard(request):
    if "user" not in request.session:
        return redirect("login")

    docs = []

    if db is None:
        messages.warning(request, "Database chưa kết nối nên chưa tải được danh sách hồ sơ.")

    elif _is_officer_role(request.session.get("role")):
        officer_id = request.session.get("user_id")

        docs = list(db.applications.find({
            "$or": [
                {"assigned_officer_id": _to_mongo_id(officer_id)},
                {"assigned_officer_id": officer_id},
                {"assigned_officer_id": request.session.get("user")}
            ]
        }))

    else:
        user_id = request.session.get("user_id")
        username = request.session.get("user")

        docs = list(db.applications.find({
            "$or": [
                {"citizen_id": _to_mongo_id(user_id)},
                {"citizen_id": user_id},
                {"citizen_id": username}
            ]
        }))

    return render(
        request,
        "app/dashboard.html",
        {
            "docs": _document_rows(docs),
            "title": "Dashboard",
            "year": datetime.now().year
        },
    )


def sign_document_view(request, doc_id=None):
    if not _is_officer_role(request.session.get("role")):
        messages.error(request, "Chỉ tài khoản cán bộ mới được ký tài liệu.")
        return redirect("login")

    document = _find_document(doc_id)
    document_context = _document_rows([document])[0] if document else None

    if request.method == "POST":
        form = SignatureForm(request.POST, request.FILES)

        if form.is_valid():
            pdf_path, pdf_relative_path = _save_uploaded_file(
                form.cleaned_data["pdf_file"],
                "pending_signatures"
            )

            key_file = form.cleaned_data["key_file"]
            key_data = key_file.read().decode("utf-8")

            key_public_key_hex = ""
            private_key_hex = ""

            try:
                keys_dict = json.loads(key_data)

                private_key_hex = (
                    keys_dict.get("ml_dsa_priv")
                    or keys_dict.get("ml_dsa_sk")
                    or keys_dict.get("ml_dsa_private_key")
                    or ""
                )

                key_public_key_hex = (
                    keys_dict.get("ml_dsa_pk")
                    or keys_dict.get("ml_dsa_pub")
                    or keys_dict.get("ml_dsa_public_key")
                    or ""
                )

            except json.JSONDecodeError:
                # Tương thích ngược nếu user upload file chỉ chứa private key hex
                private_key_hex = "".join(key_data.split())
                keys_dict = {
                    "ml_dsa_priv": private_key_hex
                }

            private_key_hex = "".join(str(private_key_hex or "").split())
            key_public_key_hex = "".join(str(key_public_key_hex or "").split())

            if not private_key_hex:
                messages.error(
                    request,
                    "File khóa không hợp lệ (Không tìm thấy chuỗi ml_dsa_priv)."
                )
                return render(
                    request,
                    "app/sign.html",
                    {
                        "form": form,
                        "document": document_context,
                        "title": "Ký tài liệu",
                        "year": datetime.now().year,
                    },
                )

            public_key_hex = (
                form.cleaned_data["public_key_hex"].strip()
                or key_public_key_hex
                or _get_officer_public_key(request.session["user_id"])
            )

            if public_key_hex:
                keys_dict["ml_dsa_pk"] = public_key_hex

            temp_key_dir = os.path.join(settings.MEDIA_ROOT, "temp_keys")
            os.makedirs(temp_key_dir, exist_ok=True)

            temp_key_path = os.path.join(
                temp_key_dir,
                f"{uuid.uuid4().hex}_{key_file.name}"
            )

            with open(temp_key_path, "w", encoding="utf-8") as f:
                json.dump(keys_dict, f)

            output_dir = os.path.join(settings.MEDIA_ROOT, "signed_documents")
            os.makedirs(output_dir, exist_ok=True)

            base_name = os.path.splitext(os.path.basename(pdf_relative_path))[0]
            output_name = f"{base_name}_signed.pdf"
            output_path = os.path.join(output_dir, output_name)
            signed_relative_path = f"signed_documents/{output_name}".replace("\\", "/")

            try:
                pqc_cert_serial = _get_pqc_cert_serial(request.session["user_id"])
                ca_result = ca_sign_pdf(
                    pdf_path,
                    temp_key_path,
                    doc_id=str(doc_id or ""),
                    signer_id=str(request.session.get("user_id") or ""),
                    public_key_hex=public_key_hex,
                    pqc_cert_serial=pqc_cert_serial,
                )

                with open(output_path, "wb") as f:
                    f.write(ca_result["signed_pdf"])

                signature_result = ca_result["signature_result"]

                _update_signed_document(
                    doc_id,
                    signed_relative_path,
                    signature_result,
                    request.session["user_id"]
                )

            except Exception as e:
                messages.error(request, f"Ký tài liệu thất bại: {e}")
                return render(
                    request,
                    "app/sign.html",
                    {
                        "form": form,
                        "document": document_context,
                        "title": "Ký tài liệu",
                        "year": datetime.now().year,
                    },
                )

            finally:
                try:
                    if os.path.exists(temp_key_path):
                        os.remove(temp_key_path)
                except Exception:
                    pass

            signed_url = settings.MEDIA_URL + signed_relative_path

            messages.success(request, "Đã ký PDF bằng chữ ký số hậu lượng tử (ML-DSA).")
            return render(
                request,
                "app/sign.html",
                {
                    "form": SignatureForm(),
                    "document": document_context,
                    "signed_url": signed_url,
                    "signature_result": signature_result,
                    "title": "Ký tài liệu",
                    "year": datetime.now().year,
                },
            )
    else:
        form = SignatureForm()

    return render(
        request,
        "app/sign.html",
        {
            "form": form,
            "document": document_context,
            "title": "Ký tài liệu",
            "year": datetime.now().year,
        },
    )

def decrypt_application_view(request, doc_id):
    if not _is_officer_role(request.session.get("role")):
        messages.error(request, "Chỉ tài khoản cán bộ mới được giải mã hồ sơ.")
        return redirect("login")

    document = _find_document(doc_id)
    if not document:
        messages.error(request, "Không tìm thấy hồ sơ cần giải mã.")
        return redirect("dashboard")

    assigned_officer_id = str(document.get("assigned_officer_id", ""))
    current_officer_id = str(request.session.get("user_id", ""))

    if assigned_officer_id != current_officer_id:
        messages.error(request, "Hồ sơ này không được gán cho cán bộ hiện tại.")
        return redirect("dashboard")

    metadata = document.get("pqc_encryption_metadata") or {}
    encrypted_relative_path = metadata.get("ciphertext_path", "")
    encapsulated_key = metadata.get("encapsulated_key")
    nonce = metadata.get("nonce")

    if not encrypted_relative_path or not encapsulated_key or not nonce:
        messages.error(request, "Hồ sơ chưa có đầy đủ metadata mã hóa.")
        return redirect("dashboard")

    if request.method == "POST":
        form = DecryptApplicationForm(request.POST, request.FILES)

        if form.is_valid():
            key_file = form.cleaned_data["key_file"]

            temp_key_dir = os.path.join(settings.MEDIA_ROOT, "temp_keys")
            os.makedirs(temp_key_dir, exist_ok=True)

            temp_key_path = os.path.join(
                temp_key_dir,
                f"{uuid.uuid4().hex}_{key_file.name}"
            )

            with open(temp_key_path, "wb+") as destination:
                for chunk in key_file.chunks():
                    destination.write(chunk)

            try:
                encrypted_path = os.path.join(
                    settings.MEDIA_ROOT,
                    encrypted_relative_path
                )

                decrypted_pdf_bytes = ca_decrypt_pdf(
                    encrypted_path,
                    temp_key_path,
                    encapsulated_key,
                    nonce,
                )

                decrypted_dir = os.path.join(
                    settings.MEDIA_ROOT,
                    "decrypted_uploads"
                )
                os.makedirs(decrypted_dir, exist_ok=True)

                output_name = f"{doc_id}_decrypted.pdf"
                output_path = os.path.join(decrypted_dir, output_name)
                decrypted_relative_path = (
                    f"decrypted_uploads/{output_name}".replace("\\", "/")
                )

                with open(output_path, "wb") as f:
                    f.write(decrypted_pdf_bytes)

                db.applications.update_one(
                    {"_id": _to_mongo_id(doc_id)},
                    {
                        "$set": {
                            "pqc_encryption_metadata.decrypted_path": decrypted_relative_path,
                            "pqc_encryption_metadata.decrypted_at": datetime.utcnow(),
                        }
                    },
                )

                decrypted_url = settings.MEDIA_URL + decrypted_relative_path

                messages.success(request, "Giải mã hồ sơ thành công.")
                return render(
                    request,
                    "app/decrypt_application.html",
                    {
                        "form": DecryptApplicationForm(),
                        "document": _document_rows([document])[0],
                        "decrypted_url": decrypted_url,
                        "title": "Giải mã hồ sơ",
                        "year": datetime.now().year,
                    },
                )

            except Exception as e:
                messages.error(request, f"Giải mã hồ sơ thất bại: {e}")

            finally:
                try:
                    if os.path.exists(temp_key_path):
                        os.remove(temp_key_path)
                except Exception:
                    pass
    else:
        form = DecryptApplicationForm()

    return render(
        request,
        "app/decrypt_application.html",
        {
            "form": form,
            "document": _document_rows([document])[0],
            "title": "Giải mã hồ sơ",
            "year": datetime.now().year,
        },
    )

def verify_document_view(request):
    verification_result = None

    if request.method == "POST":
        form = VerifySignatureForm(request.POST, request.FILES)

        if form.is_valid():
            pdf_path, _ = _save_uploaded_file(
                form.cleaned_data["pdf_file"],
                "verify_uploads"
            )

            try:
                verification_result = ca_verify_pdf(pdf_path)

                metadata = verification_result.get("metadata") or {}

                signer_id = (
                    verification_result.get("signer_id")
                    or metadata.get("signerId")
                    or metadata.get("signer_id")
                    or metadata.get("SignerId")
                    or ""
                )

                algorithm = (
                    verification_result.get("algorithm")
                    or metadata.get("algorithm")
                    or metadata.get("Algorithm")
                    or "ML-DSA-65"
                )

                hash_function = (
                    verification_result.get("hash_function")
                    or metadata.get("hashFunction")
                    or metadata.get("HashFunction")
                    or "SHAKE-256"
                )

                signed_at = (
                    verification_result.get("signed_at")
                    or metadata.get("signedAt")
                    or metadata.get("signed_at")
                    or metadata.get("SignedAt")
                    or "-"
                )

                document_hash_embedded = (
                    verification_result.get("document_hash_embedded")
                    or metadata.get("documentHash")
                    or metadata.get("DocumentHash")
                    or metadata.get("document_hash")
                    or ""
                )

                document_hash_current = (
                    verification_result.get("document_hash_current")
                    or verification_result.get("actual_document_hash")
                    or ""
                )

                hash_match = (
                    verification_result.get("hash_match")
                    if verification_result.get("hash_match") is not None
                    else verification_result.get("document_hash_matches")
                )

                signature_valid = verification_result.get("signature_valid")

                cert_serial = (
                    verification_result.get("cert_serial")
                    or metadata.get("certSerial")
                    or metadata.get("cert_serial")
                    or metadata.get("CertSerial")
                    or "-"
                )

                verification_result["signer_id"] = signer_id
                verification_result["signer_name"] = _get_user_display_name(signer_id) or "-"
                verification_result["algorithm"] = algorithm
                verification_result["hash_function"] = hash_function
                verification_result["signed_at"] = signed_at
                verification_result["public_key_source"] = (
                    verification_result.get("public_key_source")
                    or "PDF metadata"
                )

                # Field chuẩn từ CA
                verification_result["document_hash_embedded"] = document_hash_embedded
                verification_result["document_hash_current"] = document_hash_current
                verification_result["hash_match"] = hash_match
                verification_result["signature_valid"] = signature_valid
                verification_result["cert_serial"] = cert_serial

                # Field alias để khớp với verify.html hiện tại
                verification_result["document_hash"] = document_hash_embedded
                verification_result["actual_document_hash"] = document_hash_current
                verification_result["document_hash_matches"] = hash_match
                verification_result["pqc_cert_serial"] = cert_serial

                if verification_result.get("is_valid"):
                    messages.success(request, "Chữ ký PQC hợp lệ.")
                else:
                    messages.error(
                        request,
                        verification_result.get("error") or "Chữ ký PQC không hợp lệ."
                    )

            except Exception as e:
                messages.error(request, f"Kiểm tra chữ ký thất bại: {e}")

    else:
        form = VerifySignatureForm()

    return render(
        request,
        "app/verify.html",
        {
            "form": form,
            "verification_result": verification_result,
            "title": "Kiểm tra chữ ký",
            "year": datetime.now().year,
        },
    )

def upload_pdf(request):
    if "user" not in request.session:
        messages.error(request, "Vui lòng đăng nhập trước khi upload hồ sơ.")
        return redirect("login")

    if db is None:
        messages.error(request, "Database chưa kết nối, không thể upload hồ sơ.")
        return redirect("dashboard")

    officers = list(db.users.find({
        "role": "officer",
        "pqc_status": "active"
    }))

    if request.method == "POST":
        form = UploadPDFForm(request.POST, request.FILES, officers=officers)

        if form.is_valid():
            pdf_file = form.cleaned_data["pdf_file"]
            officer_id = form.cleaned_data.get("officer_id")
            upload_type = form.cleaned_data.get("upload_type", "unsigned")

            # ==========================================================
            # NHÁNH 1: NGƯỜI DÂN UPLOAD FILE ĐÃ KÝ
            # Web gửi PDF sang CA để verify. Hợp lệ mới lưu DB.
            # ==========================================================
            if upload_type == "signed":
                pdf_path, pdf_relative_path = _save_uploaded_file(
                    pdf_file,
                    "signed_uploads"
                )

                try:
                    verification_result = ca_verify_pdf(pdf_path)

                    if not verification_result.get("is_valid"):
                        messages.error(
                            request,
                            verification_result.get("error")
                            or "File PDF đã ký không hợp lệ, hệ thống không lưu hồ sơ."
                        )
                        return render(
                            request,
                            "app/upload_pdf.html",
                            {
                                "form": form,
                                "title": "Upload hồ sơ PDF",
                                "year": datetime.now().year,
                            },
                        )

                except Exception as e:
                    messages.error(request, f"Kiểm tra chữ ký file đã ký thất bại: {e}")
                    return render(
                        request,
                        "app/upload_pdf.html",
                        {
                            "form": form,
                            "title": "Upload hồ sơ PDF",
                            "year": datetime.now().year,
                        },
                    )

                application_doc = {
                    "citizen_id": _to_mongo_id(request.session.get("user_id")),
                    "assigned_officer_id": _to_mongo_id(officer_id) if officer_id else None,
                    "status": "verified",
                    "submission_type": "signed",
                    "requires_officer_signature": False,
                    "pqc_encryption_metadata": {
                        "ciphertext_path": None,
                        "original_upload_path": pdf_relative_path,
                        "encapsulated_key": None,
                        "kems_variant": None,
                        "payload_cipher": None,
                        "nonce": None,
                        "classical_public_key_algorithm": None,
                    },
                    "result_document": {
                        "signed_ciphertext_path": pdf_relative_path,
                        "pqc_signature_id": None,
                        "verification_result": verification_result,
                    },
                    "created_at": datetime.utcnow(),
                }

                db.applications.insert_one(application_doc)

                messages.success(
                    request,
                    "File đã ký hợp lệ. Hồ sơ đã được lưu vào hệ thống."
                )
                return redirect("dashboard")

            # ==========================================================
            # NHÁNH 2: NGƯỜI DÂN UPLOAD FILE CHƯA KÝ
            # Web gửi PDF sang CA để mã hóa bằng ML-KEM public key cán bộ.
            # ==========================================================
            if not officer_id:
                messages.error(request, "Vui lòng chọn cán bộ xử lý hồ sơ.")
                return render(
                    request,
                    "app/upload_pdf.html",
                    {
                        "form": form,
                        "title": "Upload hồ sơ PDF",
                        "year": datetime.now().year,
                    },
                )

            pdf_path, pdf_relative_path = _save_uploaded_file(
                pdf_file,
                "uploaded_pdfs"
            )

            encrypted_dir = os.path.join(settings.MEDIA_ROOT, "encrypted_uploads")
            os.makedirs(encrypted_dir, exist_ok=True)

            encrypted_file_name = f"{uuid.uuid4().hex}.enc"
            encrypted_path = os.path.join(encrypted_dir, encrypted_file_name)
            encrypted_relative_path = f"encrypted_uploads/{encrypted_file_name}".replace("\\", "/")

            try:
                encryption_result = ca_encrypt_pdf(
                    pdf_path,
                    officer_id
                )

                with open(encrypted_path, "wb") as f:
                    f.write(encryption_result["ciphertext"])

            except Exception as e:
                messages.error(request, f"Mã hóa PDF qua CA Server thất bại: {e}")
                return render(
                    request,
                    "app/upload_pdf.html",
                    {
                        "form": form,
                        "title": "Upload hồ sơ PDF",
                        "year": datetime.now().year,
                    },
                )

            application_doc = {
                "citizen_id": _to_mongo_id(request.session.get("user_id")),
                "assigned_officer_id": _to_mongo_id(officer_id),
                "status": "submitted",
                "submission_type": "unsigned",
                "requires_officer_signature": True,
                "pqc_encryption_metadata": {
                    "ciphertext_path": encrypted_relative_path,
                    "original_upload_path": pdf_relative_path,
                    "encapsulated_key": encryption_result["encapsulated_key"],
                    "kems_variant": encryption_result["kems_variant"],
                    "payload_cipher": encryption_result["payload_cipher"],
                    "nonce": encryption_result["nonce"],
                    "classical_public_key_algorithm": None,
                },
                "result_document": {
                    "signed_ciphertext_path": None,
                    "pqc_signature_id": None,
                },
                "created_at": datetime.utcnow(),
            }

            db.applications.insert_one(application_doc)

            messages.success(request, "Upload và mã hóa hồ sơ PDF thành công.")
            return redirect("dashboard")

    else:
        form = UploadPDFForm(officers=officers)

    return render(
        request,
        "app/upload_pdf.html",
        {
            "form": form,
            "title": "Upload hồ sơ PDF",
            "year": datetime.now().year,
        },
    )

def contact(request):
    return render(request, "app/contact.html", {"title": "Liên hệ", "year": datetime.now().year})


def about(request):
    return render(request, "app/about.html", {"title": "Giới thiệu", "year": datetime.now().year})
