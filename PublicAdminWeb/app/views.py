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

from .crypto_utils import sign_pdf_metadata, web_encapsulate, aes_gcm_encrypt, aes_gcm_decrypt
from .db_connection import get_db
from .forms import SignatureForm

try:
    from bson import ObjectId
except Exception:
    ObjectId = None

db = get_db()
ph = PasswordHasher()


def _is_officer_role(role):
    return str(role or "").lower() == "officer"


def _object_id_queries(doc_id):
    queries = [{"_id": doc_id}]
    if ObjectId is not None:
        try:
            queries.insert(0, {"_id": ObjectId(doc_id)})
        except Exception:
            pass
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


def _get_officer_public_key(user_id):
    if db is None or not user_id:
        return ""
    
    _oid = ObjectId(user_id) if ObjectId else user_id
    officer_key = db.officer_keys.find_one({"officer_id": _oid, "status": "active"})
    
    if officer_key and "ml_dsa_pk" in officer_key:
        pk = officer_key["ml_dsa_pk"]
        return pk.hex() if isinstance(pk, bytes) else pk
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
        "doc_id": ObjectId(doc_id) if ObjectId else doc_id,
        "signer_id": ObjectId(signer_id) if ObjectId else signer_id,
        "algorithm": signature_result["algorithm"],
        "signature_value": bytes.fromhex(signature_result["signature_value"]),
        "hash_function": signature_result["hash_function"], # SHAKE-256
        "xmp_metadata_embedded": signature_result["xmp_metadata_embedded"],
        "signed_at": datetime.strptime(signature_result["signed_at"], "%Y-%m-%dT%H:%M:%SZ")
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
        rows.append(
            {
                "id": str(doc.get("_id", "")),
                "status": doc.get("status", ""),
                "created_at": doc.get("created_at", ""),
                "assigned_officer_id": doc.get("assigned_officer_id", ""),
                "citizen_id": doc.get("citizen_id", doc.get("owner", "")),
            }
        )
    return rows


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
        docs = list(db.applications.find({"status": {"$in": ["submitted", "Pending", "pending"]}}))
    else:
        docs = list(db.applications.find({"citizen_id": request.session["user"]}))

    return render(
        request,
        "app/dashboard.html",
        {"docs": _document_rows(docs), "title": "Dashboard", "year": datetime.now().year},
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
            pdf_path, pdf_relative_path = _save_uploaded_file(form.cleaned_data["pdf_file"], "pending_signatures")
            key_file = form.cleaned_data["key_file"]
            
            # Đọc file Json user vừa upload (chứa 2 khóa)
            key_data = key_file.read().decode("utf-8")
            try:
                keys_dict = json.loads(key_data)
                private_key_hex = keys_dict.get("ml_dsa_priv", "")
            except json.JSONDecodeError:
                # Tương thích ngược nếu user upload mỗi khóa hex
                private_key_hex = "".join(key_data.split())

            try:
                bytes.fromhex(private_key_hex)
            except ValueError:
                messages.error(request, "File khóa không hợp lệ (Không tìm thấy chuỗi ml_dsa_priv).")
                return render(
                    request, "app/sign.html",
                    {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
                )

            output_dir = os.path.join(settings.MEDIA_ROOT, "signed_documents")
            os.makedirs(output_dir, exist_ok=True)
            base_name = os.path.splitext(os.path.basename(pdf_relative_path))[0]
            output_name = f"{base_name}_signed.pdf"
            output_path = os.path.join(output_dir, output_name)
            signed_relative_path = f"signed_documents/{output_name}".replace("\\", "/")

            public_key_hex = form.cleaned_data["public_key_hex"].strip() or _get_officer_public_key(request.session["user_id"])

            try:
                signature_result = sign_pdf_metadata(
                    pdf_path,
                    output_path,
                    private_key_hex,
                    public_key_hex,
                    signer_id=request.session["user_id"],
                    doc_id=str(doc_id or ""),
                    sig_alg=form.cleaned_data["algorithm"],
                )
                _update_signed_document(doc_id, signed_relative_path, signature_result, request.session["user_id"])
            except Exception as e:
                messages.error(request, f"Ký tài liệu thất bại: {e}")
                return render(
                    request, "app/sign.html",
                    {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
                )

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
        {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
    )


def contact(request):
    return render(request, "app/contact.html", {"title": "Liên hệ", "year": datetime.now().year})


def about(request):
    return render(request, "app/about.html", {"title": "Giới thiệu", "year": datetime.now().year})