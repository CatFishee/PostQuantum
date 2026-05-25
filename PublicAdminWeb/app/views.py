import os
import uuid
import json
import ipaddress
from datetime import datetime

import requests
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.shortcuts import redirect, render
from django.utils.text import get_valid_filename
from django.urls import reverse
from django.http import HttpResponse, HttpResponseForbidden, Http404

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .crypto_utils import (
    ca_decrypt_pdf,
    ca_encrypt_pdf,
    ca_sign_pdf,
    ca_verify_pdf,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
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

LOCAL_DEK_HEX = getattr(settings, "LOCAL_DEK_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
LOCAL_MASTER_KEY = bytes.fromhex(LOCAL_DEK_HEX)

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

def get_client_ip(request):
    return request.META.get('REMOTE_ADDR', '127.0.0.1')

def is_internal_ip(ip_str):
    try:
        ip_clean = ip_str.split('%')[0]
        ip = ipaddress.ip_address(ip_clean)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def officer_ip_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        if "user" not in request.session:
            return redirect("login")
        if not _is_officer_role(request.session.get("role")):
            return HttpResponseForbidden("Forbidden: Tài khoản của bạn không có quyền truy cập.")
        client_ip = get_client_ip(request)
        if not is_internal_ip(client_ip):
            return HttpResponseForbidden(f"Forbidden: Cán bộ không được thực hiện nghiệp vụ từ IP ngoài mạng nội bộ ({client_ip}).")
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def encrypt_bytes_to_file_at_rest(data_bytes, output_path):
    iv, cipher, tag = aes_gcm_encrypt(LOCAL_MASTER_KEY, data_bytes)
    payload = {
        "iv": iv.hex(),
        "tag": tag.hex(),
        "ciphertext": cipher.hex()
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)

def decrypt_file_at_rest_bytes(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        payload = json.load(f)
    iv = bytes.fromhex(payload["iv"])
    tag = bytes.fromhex(payload["tag"])
    cipher = bytes.fromhex(payload["ciphertext"])
    return aes_gcm_decrypt(LOCAL_MASTER_KEY, iv, cipher, tag)

def _update_signed_document(doc_id, signed_relative_path, signature_result, signer_id):
    if db is None or not doc_id:
        return
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
        doc_id = str(doc.get("_id", ""))
        signed_file_path = ""
        if result_document.get("signed_ciphertext_path"):
            signed_file_path = f"download/signed/{doc_id}/"
        rows.append(
            {
                "id": doc_id,
                "status": doc.get("status", ""),
                "created_at": doc.get("created_at", ""),
                "assigned_officer_id": _get_user_display_name(officer_id) or str(officer_id),
                "citizen_id": _get_user_display_name(citizen_id) or str(citizen_id),
                "submission_type": doc.get("submission_type", ""),
                "signed_file_path": signed_file_path,
                "original_upload_path": pqc_metadata.get("original_upload_path", ""),
                "decrypted_path": "",
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
        if _is_officer_role(role):
            client_ip = get_client_ip(request)
            if not is_internal_ip(client_ip):
                messages.error(request, f"Đăng ký tài khoản Cán bộ bị từ chối. IP của bạn ({client_ip}) nằm ngoài mạng nội bộ.")
                return redirect("register")
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
                r_pub = requests.get("http://127.0.0.1:5001/master-public-key", timeout=10)
                r_pub.raise_for_status()
                master_pub = bytes.fromhex(r_pub.json()["public_key"])
                kem_cipher, shared_secret = web_encapsulate(master_pub)
                payload_dict = {"officer_id": user_id, "username": username, "full_name": full_name}
                payload_bytes = json.dumps(payload_dict).encode('utf-8')
                iv, cipher, tag = aes_gcm_encrypt(shared_secret, payload_bytes)
                ca_req_data = {
                    "kem_ciphertext": kem_cipher.hex(),
                    "aes_iv": iv.hex(),
                    "aes_tag": tag.hex(),
                    "encrypted_payload": cipher.hex()
                }
                response = requests.post("http://127.0.0.1:5001/register_officer", json=ca_req_data, timeout=15)
                response.raise_for_status()
                ca_resp = response.json()
                resp_bytes = aes_gcm_decrypt(
                    shared_secret,
                    bytes.fromhex(ca_resp["aes_iv"]),
                    bytes.fromhex(ca_resp["encrypted_payload"]),
                    bytes.fromhex(ca_resp["aes_tag"])
                )
                priv_keys_dict = json.loads(resp_bytes.decode('utf-8'))
                db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"pqc_status": "active"}})
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
                if _is_officer_role(user.get("role")):
                    client_ip = get_client_ip(request)
                    if not is_internal_ip(client_ip):
                        messages.error(request, f"Đăng nhập bị từ chối. Tài khoản Cán bộ chỉ được phép đăng nhập từ mạng nội bộ (IP hiện tại: {client_ip}).")
                        return redirect("login")
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

@officer_ip_required
def sign_document_view(request, doc_id):
    document = _find_document(doc_id)
    if not document:
        messages.error(request, "Không tìm thấy hồ sơ!")
        return redirect("dashboard")
        
    if document.get("status") == "processed":
        messages.error(request, "Hồ sơ này đã được ký số và hoàn tất, không thể ký đè lại!")
        return redirect("dashboard")
        
    document_context = _document_rows([document])[0]
    
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
                private_key_hex = "".join(key_data.split())
                keys_dict = {"ml_dsa_priv": private_key_hex}
            private_key_hex = "".join(str(private_key_hex or "").split())
            key_public_key_hex = "".join(str(key_public_key_hex or "").split())
            if not private_key_hex:
                messages.error(request, "File khóa không hợp lệ (Không tìm thấy chuỗi ml_dsa_priv).")
                return render(
                    request,
                    "app/sign.html",
                    {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
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
            temp_key_path = os.path.join(temp_key_dir, f"{uuid.uuid4().hex}_{key_file.name}")
            with open(temp_key_path, "w", encoding="utf-8") as f:
                json.dump(keys_dict, f)
            try:
                pqc_cert_serial = _get_pqc_cert_serial(request.session["user_id"])
                ca_result = ca_sign_pdf(
                    pdf_path,
                    temp_key_path,
                    doc_id=str(doc_id),
                    signer_id=str(request.session.get("user_id") or ""),
                    public_key_hex=public_key_hex,
                    pqc_cert_serial=pqc_cert_serial,
                )
                output_dir = os.path.join(settings.MEDIA_ROOT, "signed_documents")
                os.makedirs(output_dir, exist_ok=True)
                base_name = os.path.splitext(os.path.basename(pdf_relative_path))[0]
                output_name = f"{base_name}_signed.enc"
                output_path = os.path.join(output_dir, output_name)
                signed_relative_path = f"signed_documents/{output_name}".replace("\\", "/")
                
                encrypt_bytes_to_file_at_rest(ca_result["signed_pdf"], output_path)
                _update_signed_document(
                    doc_id,
                    signed_relative_path,
                    ca_result["signature_result"],
                    request.session["user_id"]
                )
                signed_url = reverse("download_signed_pdf", args=[doc_id])
                signature_result = ca_result["signature_result"]
                messages.success(request, "Đã ký PDF bằng chữ ký số hậu lượng tử (ML-DSA) và mã hóa an toàn tại chỗ.")
                return render(
                    request,
                    "app/sign.html",
                    {"form": SignatureForm(), "document": document_context, "signed_url": signed_url, "signature_result": signature_result, "title": "Ký tài liệu", "year": datetime.now().year},
                )
            except Exception as e:
                error_msg = str(e)
                if "403" in error_msg:
                    messages.error(request, "Hệ thống PKI từ chối: Chứng thư số của đồng chí đã hết hạn hoặc bị thu hồi!")
                else:
                    messages.error(request, f"Ký tài liệu thất bại: {error_msg}")
                return render(
                    request,
                    "app/sign.html",
                    {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
                )
            finally:
                for path in (temp_key_path, pdf_path):
                    try:
                        if path and os.path.exists(path):
                            os.remove(path)
                    except Exception:
                        pass
    else:
        form = SignatureForm()
    return render(
        request,
        "app/sign.html",
        {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
    )

@officer_ip_required
def decrypt_application_view(request, doc_id):
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
            temp_key_path = os.path.join(temp_key_dir, f"{uuid.uuid4().hex}_{key_file.name}")
            with open(temp_key_path, "wb+") as destination:
                for chunk in key_file.chunks():
                    destination.write(chunk)
            try:
                encrypted_path = os.path.join(settings.MEDIA_ROOT, encrypted_relative_path)
                decrypted_pdf_bytes = ca_decrypt_pdf(
                    encrypted_path,
                    temp_key_path,
                    encapsulated_key,
                    nonce,
                )
                response = HttpResponse(decrypted_pdf_bytes, content_type="application/pdf")
                response["Content-Disposition"] = f"attachment; filename=decrypted_{doc_id}.pdf"
                return response
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
        {"form": form, "document": _document_rows([document])[0], "title": "Giải mã hồ sơ", "year": datetime.now().year},
    )

def download_signed_pdf(request, doc_id):
    if "user" not in request.session:
        return redirect("login")
    document = _find_document(doc_id)
    if not document:
        raise Http404("Hồ sơ không tồn tại hoặc đã bị xóa.")

    user_id = str(request.session.get("user_id", ""))
    user_role = str(request.session.get("role", "")).lower()
    citizen_id = str(document.get("citizen_id", ""))
    assigned_officer_id = str(document.get("assigned_officer_id", ""))
    if user_role == "officer":
        client_ip = get_client_ip(request)
        if not is_internal_ip(client_ip):
            return HttpResponseForbidden(f"Forbidden: Cán bộ không được phép tải hồ sơ từ IP ngoài mạng nội bộ ({client_ip}).")
        if assigned_officer_id != user_id:
            return HttpResponseForbidden("Forbidden: Bạn không được gán quyền xem hồ sơ này.")
    else:
        if citizen_id != user_id:
            return HttpResponseForbidden("Forbidden: Bạn không có quyền truy cập hồ sơ này.")
            
    result_document = document.get("result_document") or {}
    signed_ciphertext_path = result_document.get("signed_ciphertext_path", "")
    if not signed_ciphertext_path:
        raise Http404("Tài liệu chưa được ký số.")
    full_path = os.path.join(settings.MEDIA_ROOT, signed_ciphertext_path)
    if not os.path.exists(full_path):
        raise Http404("File lưu trữ không tồn tại.")
    try:
        pdf_plaintext_bytes = decrypt_file_at_rest_bytes(full_path)
        response = HttpResponse(pdf_plaintext_bytes, content_type="application/pdf")
        response["Content-Disposition"] = f"attachment; filename=signed_{doc_id}.pdf"
        return response
    except Exception as e:
        messages.error(request, f"Giải mã cục bộ và tải tệp lỗi: {e}")
        return redirect("dashboard")

def verify_document_view(request):
    verification_result = None
    if request.method == "POST":
        form = VerifySignatureForm(request.POST, request.FILES)
        if form.is_valid():
            pdf_path, _ = _save_uploaded_file(form.cleaned_data["pdf_file"], "verify_uploads")
            try:
                verification_result = ca_verify_pdf(pdf_path)
                metadata = verification_result.get("metadata") or {}
                signer_id = (verification_result.get("signer_id") or metadata.get("signerId") or metadata.get("signer_id") or "")
                algorithm = (verification_result.get("algorithm") or metadata.get("algorithm") or "ML-DSA-65")
                hash_function = (verification_result.get("hash_function") or metadata.get("hashFunction") or "SHAKE-256")
                signed_at = (verification_result.get("signed_at") or metadata.get("signedAt") or "-")
                document_hash_embedded = (verification_result.get("document_hash_embedded") or metadata.get("documentHash") or "")
                document_hash_current = (verification_result.get("document_hash_current") or verification_result.get("actual_document_hash") or "")
                hash_match = (verification_result.get("hash_match") if verification_result.get("hash_match") is not None else verification_result.get("document_hash_matches"))
                signature_valid = verification_result.get("signature_valid")
                cert_serial = (verification_result.get("cert_serial") or metadata.get("certSerial") or "-")
                
                verification_result["signer_id"] = signer_id
                verification_result["signer_name"] = _get_user_display_name(signer_id) or "-"
                verification_result["algorithm"] = algorithm
                verification_result["hash_function"] = hash_function
                verification_result["signed_at"] = signed_at
                verification_result["public_key_source"] = (verification_result.get("public_key_source") or "PDF metadata")
                verification_result["document_hash_embedded"] = document_hash_embedded
                verification_result["document_hash_current"] = document_hash_current
                verification_result["hash_match"] = hash_match
                verification_result["signature_valid"] = signature_valid
                verification_result["cert_serial"] = cert_serial
                verification_result["document_hash"] = document_hash_embedded
                verification_result["actual_document_hash"] = document_hash_current
                verification_result["document_hash_matches"] = hash_match
                verification_result["pqc_cert_serial"] = cert_serial
                
                if verification_result.get("is_valid"):
                    messages.success(request, "Chữ ký PQC hợp lệ.")
                else:
                    messages.error(request, verification_result.get("error") or "Chữ ký PQC không hợp lệ.")
            except Exception as e:
                messages.error(request, f"Kiểm tra chữ ký thất bại: {e}")
    else:
        form = VerifySignatureForm()
    return render(
        request,
        "app/verify.html",
        {"form": form, "verification_result": verification_result, "title": "Kiểm tra chữ ký", "year": datetime.now().year},
    )

def upload_pdf(request):
    if "user" not in request.session:
        messages.error(request, "Vui lòng đăng nhập trước khi upload hồ sơ.")
        return redirect("login")
    if db is None:
        messages.error(request, "Database chưa kết nối, không thể upload hồ sơ.")
        return redirect("dashboard")

    # LỌC DANH SÁCH CÁN BỘ: Chỉ đưa lên danh sách những Cán bộ có Chứng thư còn hạn hợp lệ.
    active_officers = []
    for user in db.users.find({"role": "officer", "pqc_status": "active"}):
        officer_key = db.officer_keys.find_one({"officer_id": user["_id"], "status": "active"})
        if officer_key:
            cert = db.certificates.find_one({"serial_number": officer_key.get("cert_serial"), "status": "valid"})
            if cert and cert.get("not_after") and datetime.utcnow() < cert.get("not_after"):
                active_officers.append(user)

    if request.method == "POST":
        form = UploadPDFForm(request.POST, request.FILES, officers=active_officers)
        if form.is_valid():
            pdf_file = form.cleaned_data["pdf_file"]
            officer_id = form.cleaned_data.get("officer_id")
            upload_type = form.cleaned_data.get("upload_type", "unsigned")
            
            if upload_type == "signed":
                pdf_path, pdf_relative_path = _save_uploaded_file(pdf_file, "signed_uploads")
                try:
                    verification_result = ca_verify_pdf(pdf_path)
                    if not verification_result.get("is_valid"):
                        messages.error(request, verification_result.get("error") or "File PDF đã ký không hợp lệ, hệ thống không lưu hồ sơ.")
                        return render(request, "app/upload_pdf.html", {"form": form, "title": "Upload hồ sơ PDF", "year": datetime.now().year})
                except Exception as e:
                    messages.error(request, f"Kiểm tra chữ ký file đã ký thất bại: {e}")
                    return render(request, "app/upload_pdf.html", {"form": form, "title": "Upload hồ sơ PDF", "year": datetime.now().year})
                try:
                    with open(pdf_path, "rb") as f:
                        signed_pdf_data = f.read()
                    encrypted_output_name = f"{uuid.uuid4().hex}.enc"
                    encrypted_dir = os.path.join(settings.MEDIA_ROOT, "signed_uploads")
                    os.makedirs(encrypted_dir, exist_ok=True)
                    encrypted_path = os.path.join(encrypted_dir, encrypted_output_name)
                    encrypted_relative_path = f"signed_uploads/{encrypted_output_name}".replace("\\", "/")
                    encrypt_bytes_to_file_at_rest(signed_pdf_data, encrypted_path)
                    if os.path.exists(pdf_path):
                        os.remove(pdf_path)
                except Exception as e:
                    messages.error(request, f"Mã hóa lưu trữ tệp tin thất bại: {e}")
                    return redirect("dashboard")
                    
                application_doc = {
                    "citizen_id": _to_mongo_id(request.session.get("user_id")),
                    "assigned_officer_id": _to_mongo_id(officer_id) if officer_id else None,
                    "status": "verified",
                    "submission_type": "signed",
                    "requires_officer_signature": False,
                    "pqc_encryption_metadata": {
                        "ciphertext_path": None, "original_upload_path": pdf_relative_path,
                        "encapsulated_key": None, "kems_variant": None, "payload_cipher": None,
                        "nonce": None, "classical_public_key_algorithm": None,
                    },
                    "result_document": {
                        "signed_ciphertext_path": encrypted_relative_path,
                        "pqc_signature_id": None, "verification_result": verification_result,
                    },
                    "created_at": datetime.utcnow(),
                }
                db.applications.insert_one(application_doc)
                messages.success(request, "File đã ký hợp lệ. Hồ sơ đã được mã hóa lưu trữ an toàn.")
                return redirect("dashboard")
                
            if not officer_id:
                messages.error(request, "Vui lòng chọn cán bộ xử lý hồ sơ.")
                return render(request, "app/upload_pdf.html", {"form": form, "title": "Upload hồ sơ PDF", "year": datetime.now().year})
                
            pdf_path, pdf_relative_path = _save_uploaded_file(pdf_file, "uploaded_pdfs")
            encrypted_dir = os.path.join(settings.MEDIA_ROOT, "encrypted_uploads")
            os.makedirs(encrypted_dir, exist_ok=True)
            encrypted_file_name = f"{uuid.uuid4().hex}.enc"
            encrypted_path = os.path.join(encrypted_dir, encrypted_file_name)
            encrypted_relative_path = f"encrypted_uploads/{encrypted_file_name}".replace("\\", "/")
            
            try:
                encryption_result = ca_encrypt_pdf(pdf_path, officer_id)
                with open(encrypted_path, "wb") as f:
                    f.write(encryption_result["ciphertext"])
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception as e:
                error_msg = str(e)
                if "403" in error_msg:
                    messages.error(request, "Lỗi từ máy chủ CA: Chứng thư của Cán bộ này đã hết hạn, không thể tiếp nhận hồ sơ!")
                else:
                    messages.error(request, f"Mã hóa PDF qua CA Server thất bại: {error_msg}")
                return render(request, "app/upload_pdf.html", {"form": form, "title": "Upload hồ sơ PDF", "year": datetime.now().year})
                
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
        form = UploadPDFForm(officers=active_officers)
    return render(
        request,
        "app/upload_pdf.html",
        {"form": form, "title": "Upload hồ sơ PDF", "year": datetime.now().year},
    )

def contact(request):
    return render(request, "app/contact.html", {"title": "Liên hệ", "year": datetime.now().year})

def about(request):
    return render(request, "app/about.html", {"title": "Giới thiệu", "year": datetime.now().year})