import os
import uuid
from datetime import datetime

import requests
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.shortcuts import redirect, render
from django.utils.text import get_valid_filename

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .crypto_utils import sign_pdf_metadata
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


def _get_officer_public_key(username):
    if db is None or not username:
        return ""

    officer = db.officers.find_one({"username": username})
    if not officer:
        return ""

    return officer.get("public_key") or officer.get("ml_dsa_pk") or ""


def _save_uploaded_file(uploaded_file, folder):
    target_dir = os.path.join(settings.MEDIA_ROOT, folder)
    os.makedirs(target_dir, exist_ok=True)

    storage = FileSystemStorage(location=target_dir)
    safe_name = get_valid_filename(uploaded_file.name)
    file_name = f"{uuid.uuid4().hex}_{safe_name}"
    saved_name = storage.save(file_name, uploaded_file)
    relative_path = f"{folder}/{saved_name}".replace("\\", "/")
    return storage.path(saved_name), relative_path


def _update_signed_document(doc_id, signed_relative_path, signature_result):
    if db is None or not doc_id:
        return

    update_data = {
        "status": "processed",
        "result_document.signed_ciphertext_path": signed_relative_path,
        "result_document.pqc_signature_id": signature_result["signature_id"],
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
                response = requests.post(
                    "http://127.0.0.1:5001/register_officer",
                    json={"officer_id": user_id, "username": username, "full_name": full_name},
                    timeout=15,
                )
                response.raise_for_status()
                ca_data = response.json()
                
                db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"pqc_status": "active"}})
                
                request.session["temp_private_key"] = ca_data.get("private_key_download") or ca_data.get("private_keys") or ca_data.get("private_key_to_download")
                request.session["temp_username"] = username
                
                messages.success(request, "Tạo tài khoản Cán bộ thành công. Vui lòng tải khóa bảo mật!")
                return redirect("download_key")

            except Exception as e:
                db.users.delete_one({"_id": ObjectId(user_id)})
                messages.error(request, f"Không thể kết nối tới CA Server hoặc có lỗi: {e}")
                return redirect("register")

        messages.success(request, "Đăng ký thành công!")
        return redirect("login")

    return render(request, "app/register.html", {"title": "Đăng ký", "year": datetime.now().year})


def download_key(request):
    private_key = request.session.pop("temp_private_key", None)
    username = request.session.pop("temp_username", "Unknown")
    
    if not private_key:
        messages.warning(request, "Không tìm thấy khóa hoặc khóa đã được tải. Vui lòng đăng nhập.")
        return redirect("login")
        
    return render(request, "app/download_key.html", {
        "private_keys": private_key,
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
            private_key_hex = "".join(key_file.read().decode("utf-8").split())

            try:
                bytes.fromhex(private_key_hex)
            except ValueError:
                messages.error(request, "Private key không phải chuỗi hex hợp lệ.")
                return render(
                    request,
                    "app/sign.html",
                    {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
                )

            output_dir = os.path.join(settings.MEDIA_ROOT, "signed_documents")
            os.makedirs(output_dir, exist_ok=True)
            base_name = os.path.splitext(os.path.basename(pdf_relative_path))[0]
            output_name = f"{base_name}_signed.pdf"
            output_path = os.path.join(output_dir, output_name)
            signed_relative_path = f"signed_documents/{output_name}".replace("\\", "/")

            public_key_hex = form.cleaned_data["public_key_hex"].strip() or _get_officer_public_key(request.session["user"])

            try:
                signature_result = sign_pdf_metadata(
                    pdf_path,
                    output_path,
                    private_key_hex,
                    public_key_hex,
                    signer_id=request.session["user"],
                    doc_id=str(doc_id or ""),
                    sig_alg=form.cleaned_data["algorithm"],
                )
                _update_signed_document(doc_id, signed_relative_path, signature_result)
            except Exception as e:
                messages.error(request, f"Ký tài liệu thất bại: {e}")
                return render(
                    request,
                    "app/sign.html",
                    {"form": form, "document": document_context, "title": "Ký tài liệu", "year": datetime.now().year},
                )

            signed_url = settings.MEDIA_URL + signed_relative_path
            messages.success(request, "Đã ký PDF bằng chữ ký số hậu lượng tử.")
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