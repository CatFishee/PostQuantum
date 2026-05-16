import os
import uuid
from datetime import datetime

import requests
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.shortcuts import redirect, render
from django.utils.text import get_valid_filename

from .crypto_utils import get_sha3_512_hash, sign_pdf_metadata
from .db_connection import get_db
from .forms import SignatureForm

try:
    from bson import ObjectId
except Exception:
    ObjectId = None


db = get_db()


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

        pass_hash = get_sha3_512_hash(password.encode()).hex()

        user_data = {
            "username": username,
            "role": role,
            "password_hash": pass_hash,
            "full_name": request.POST["full_name"],
            "pqc_status": "pending",
            "created_at": datetime.utcnow(),
        }

        if _is_officer_role(role):
            try:
                response = requests.post(
                    "http://127.0.0.1:5001/register_officer",
                    params={"username": username, "full_name": user_data["full_name"], "position": "Cán bộ"},
                    timeout=15,
                )
                response.raise_for_status()
                ca_data = response.json()
                user_data["pqc_status"] = "active"
                db.users.update_one({"username": username}, {"$set": user_data}, upsert=True)

                return render(
                    request,
                    "app/download_key.html",
                    {
                        "private_key": ca_data.get("private_key_download") or ca_data.get("private_key_to_download"),
                        "username": username,
                    },
                )
            except Exception as e:
                messages.error(request, f"Không thể kết nối tới CA Server: {e}")
                return redirect("register")

        db.users.update_one({"username": username}, {"$set": user_data}, upsert=True)
        messages.success(request, "Đăng ký thành công!")
        return redirect("login")

    return render(request, "app/register.html", {"title": "Đăng ký", "year": datetime.now().year})


def login(request):
    if request.method == "POST":
        if db is None:
            messages.error(request, "Database chưa kết nối, không thể đăng nhập.")
            return render(request, "app/login.html", {"title": "Đăng nhập", "year": datetime.now().year})

        username = request.POST["username"]
        password_attempt = request.POST["password"]

        user = db.users.find_one({"username": username})
        if user:
            attempt_hash = get_sha3_512_hash(password_attempt.encode()).hex()
            if attempt_hash == user["password_hash"]:
                request.session["user"] = user["username"]
                request.session["role"] = user["role"]
                return redirect("dashboard")

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
