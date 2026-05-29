import os
import uuid
import json
import ipaddress
import base64
import requests
from datetime import datetime

from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.shortcuts import redirect, render
from django.utils.text import get_valid_filename
from django.urls import reverse
from django.http import HttpResponse, HttpResponseForbidden, Http404, JsonResponse

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .crypto_utils import (
    hash_pdf_pqc,
    embed_signature_and_timestamp,
    aes_gcm_decrypt,
    aes_gcm_encrypt
)
from .db_connection import get_db

try:
    from bson import ObjectId
except Exception:
    ObjectId = None

db = get_db()
ph = PasswordHasher()

LOCAL_DEK_HEX = getattr(settings, "LOCAL_DEK_HEX", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
LOCAL_MASTER_KEY = bytes.fromhex(LOCAL_DEK_HEX)

# --- HELPER FUNCTIONS ---
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

def _document_rows(raw_docs):
    rows = []
    for doc in raw_docs:
        citizen_id = doc.get("citizen_id", doc.get("owner", ""))
        officer_id = doc.get("assigned_officer_id", "")
        result_document = doc.get("result_document") or {}
        pqc_metadata = doc.get("pqc_encryption_metadata") or {}
        doc_id = str(doc.get("_id", ""))
        signed_file_path = ""
        # SỬ DỤNG API DOWNLOAD TRỰC TUYẾN TỪ CLOUD DB THAY VÌ TỆP CỤC BỘ
        if result_document.get("ciphertext_b64"):
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

def ca_encrypt_pdf(pdf_path, officer_id):
    """
    Gọi API CA-KMS Server để thực hiện xác thực trạng thái chứng thư 
    và tiến hành mã hóa PDF thô bằng khóa công khai ML-KEM-768 của Cán bộ.
    """
    url = "http://127.0.0.1:5001/encrypt-pdf"
    with open(pdf_path, "rb") as f:
        files = {"pdf_file": f}
        data = {"officer_id": str(officer_id)}
        response = requests.post(url, files=files, data=data, timeout=25)
        
    if response.status_code == 403:
        raise Exception("403: Chứng thư số của cán bộ này đã hết hạn hoặc bị thu hồi trên hệ thống CA!")
    elif response.status_code != 200:
        raise Exception(f"Lỗi hệ thống CA Server: {response.text}")
        
    res = response.json()
    return {
        "ciphertext": base64.b64decode(res["ciphertext_b64"]),
        "encapsulated_key": base64.b64decode(res["encapsulated_key_b64"]),
        "nonce": base64.b64decode(res["nonce_b64"]),
        "kems_variant": res["kems_variant"],
        "payload_cipher": res["payload_cipher"]
    }

# --- DJANGO VIEWS ---

def home(request):
    return render(request, "app/index.html", {"title": "Trang chủ PQC", "year": datetime.now().year})

def contact(request):
    return render(request, "app/contact.html", {"title": "Liên hệ", "year": datetime.now().year})

def about(request):
    return render(request, "app/about.html", {"title": "Giới thiệu", "year": datetime.now().year})

def download_key(request):
    """
    Do đã nâng cấp lên chuẩn mật mã Zero-Trust, khóa riêng được mã hóa lưu trữ hoàn toàn cục bộ,
    Django view này hiển thị thông báo hướng dẫn bảo quản thay vì cho phép tải file thô.
    """
    return render(request, "app/download_key.html", {
        "title": "Tải khóa bảo mật",
        "message": "Cặp khóa PQC (ML-DSA / ML-KEM) của đồng chí đã được sinh ra trực tiếp và mã hóa lưu trữ an toàn dưới ổ đĩa cục bộ thông qua PQC Local Agent.",
        "year": datetime.now().year
    })

def register(request):
    if request.method == "POST":
        if db is None:
            messages.error(request, "Database chưa kết nối, không thể đăng ký.")
            return redirect("register")
        username = request.POST["username"]
        role = request.POST["role"]
        password = request.POST["password"]
        full_name = request.POST["full_name"]
        
        dsa_pk_hex = request.POST.get("ml_dsa_pk_hex")
        kem_pk_hex = request.POST.get("ml_kem_pk_hex")

        if _is_officer_role(role):
            client_ip = get_client_ip(request)
            if not is_internal_ip(client_ip):
                messages.error(request, f"Đăng ký tài khoản Cán bộ bị từ chối. IP của bạn ({client_ip}) nằm ngoài mạng nội bộ.")
                return redirect("register")
            if not dsa_pk_hex or not kem_pk_hex:
                messages.error(request, "Thiếu khóa công khai gửi lên từ PQC Local Agent cục bộ của cán bộ.")
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
                
                import oqs
                with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
                    kem_cipher, shared_secret = kem.encap_secret(master_pub)
                    
                payload_dict = {
                    "officer_id": user_id, 
                    "username": username,
                    "ml_dsa_pk_hex": dsa_pk_hex,
                    "ml_kem_pk_hex": kem_pk_hex
                }
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
                
                db.users.update_one({"_id": result.inserted_id}, {"$set": {"pqc_status": "active"}})
                messages.success(request, "Đăng ký thành công! Chứng thư số PQC đã được cấp phát an toàn.")
                return redirect("login")
            except Exception as e:
                db.users.delete_one({"_id": result.inserted_id})
                messages.error(request, f"Không thể kết nối hoặc chứng thực qua CA Server: {e}")
                return redirect("register")
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

# --- KHU VỰC API PROXY CHO LOCAL AGENT (KHÔNG CHO PHÉP LOCAL AGENT GỌI TRỰC TIẾP CA) ---

@officer_ip_required
def api_ca_public_key(request):
    """Proxy hỗ trợ Local Agent lấy khóa công khai ML-KEM-1024 tối cao của CA."""
    try:
        r = requests.get("http://127.0.0.1:5001/master-public-key", timeout=10)
        return JsonResponse(r.json())
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=500)

@officer_ip_required
def api_ca_tsa(request):
    """Proxy hỗ trợ Local Agent lấy dấu thời gian TSA từ máy chủ CA."""
    if request.method != "POST":
         return JsonResponse({"detail": "Method not allowed"}, status=405)
    try:
        req_data = json.loads(request.body.decode('utf-8'))
        r = requests.post("http://127.0.0.1:5001/tsa/timestamp", json=req_data, timeout=10)
        return JsonResponse(r.json())
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=500)

# --- END OF PROXY ---

@officer_ip_required
def sign_document_view(request, doc_id):
    """
    View chuẩn hóa: Nhận khối dữ liệu mã hóa từ trình duyệt sau khi ký biên cục bộ,
    chuyển tiếp sang CA Server xử lý giải mã, thẩm định 4 lớp và lưu trữ Cloud an toàn.
    """
    document = _find_document(doc_id)
    if not document:
        messages.error(request, "Không tìm thấy hồ sơ!")
        return redirect("dashboard")
        
    if document.get("status") == "processed":
        messages.error(request, "Hồ sơ này đã được ký số và hoàn tất!")
        return redirect("dashboard")
        
    document_context = _document_rows([document])[0]
    user_id = request.session.get("user_id")
    officer_key_doc = db.officer_keys.find_one({"officer_id": _to_mongo_id(user_id)})
    
    if not officer_key_doc:
        messages.error(request, "Không tìm thấy thông tin chứng thư PQC của bạn.")
        return redirect("dashboard")

    if request.method == "POST":
        # Nhận khối mật mã đã được ký và bảo vệ ngay tại Local Agent biên
        ciphertext_b64 = request.POST.get("ciphertext_base64")
        encapsulated_key_b64 = request.POST.get("encapsulated_key_base64")
        nonce_b64 = request.POST.get("nonce_base64")

        if not ciphertext_b64 or not encapsulated_key_b64 or not nonce_b64:
            messages.error(request, "Chưa nhận được khối mật mã ký số hợp lệ từ thiết bị của đồng chí.")
            return redirect("sign_document", doc_id=doc_id)

        try:
            # Chuyển tiếp luồng byte sang CA Server xử lý thẩm định 4 lớp trực tuyến
            ca_verify_url = "http://127.0.0.1:5001/verify-and-store-signed"
            payload = {
                "doc_id": str(doc_id),
                "signer_id": str(user_id),
                "ciphertext_base64": ciphertext_b64,
                "encapsulated_key_base64": encapsulated_key_b64,
                "nonce_base64": nonce_b64
            }
            res = requests.post(ca_verify_url, data=payload, timeout=25)
            if res.status_code != 200:
                raise Exception(f"CA Server từ chối thẩm định: {res.text}")

            messages.success(request, "Đã thẩm định chữ ký số hậu lượng tử và lưu trữ đám mây Atlas thành công!")
            return redirect("dashboard")
        except Exception as e:
            messages.error(request, f"Lỗi hoàn thiện tệp ký số: {e}")
            
    return render(
        request,
        "app/sign.html",
        {
            "document": document_context, 
            "cert_serial": officer_key_doc["cert_serial"],
            "signer_id": str(user_id),
            "title": "Ký tài liệu", 
            "year": datetime.now().year
        },
    )

@officer_ip_required
def decrypt_application_view(request, doc_id):
    """
    View hướng dẫn và truyền metadata mã hóa xuống trình duyệt để người dùng 
    tự gọi Local Agent giải mã tệp tin cục bộ, đạt chuẩn Zero-Trust tuyệt đối.
    """
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
        
    # Đọc tệp mã hóa và chuyển base64 để truyền sang Client-side JS giải mã
    try:
        encrypted_path = os.path.join(settings.MEDIA_ROOT, encrypted_relative_path)
        with open(encrypted_path, "rb") as f:
            ciphertext_bytes = f.read()
        ciphertext_base64 = base64.b64encode(ciphertext_bytes).decode("utf-8")
    except Exception as e:
        messages.error(request, f"Không thể đọc tệp mã hóa trên máy chủ: {e}")
        return redirect("dashboard")

    decryption_context = {
        "ciphertext_base64": ciphertext_base64,
        "encapsulated_key_base64": base64.b64encode(bytes.fromhex(encapsulated_key) if isinstance(encapsulated_key, str) else bytes(encapsulated_key)).decode("utf-8"),
        "nonce_base64": base64.b64encode(bytes.fromhex(nonce) if isinstance(nonce, str) else bytes(nonce)).decode("utf-8"),
    }
    
    return render(
        request,
        "app/decrypt_application.html",
        {
            "decryption_context": decryption_context,
            "document": _document_rows([document])[0],
            "title": "Giải mã hồ sơ",
            "year": datetime.now().year
        },
    )

def download_signed_pdf(request, doc_id):
    """
    Tải tệp đã ký dạng luồng bảo mật (In-memory streaming):
    Web server đọc thông tin mật mã từ MongoDB Atlas (không lưu file cục bộ),
    gửi sang CA Server giải mã bằng khóa Master CA, trả trực tiếp ra HttpResponse.
    """
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
    ciphertext_b64 = result_document.get("ciphertext_b64")
    enc_key_b64 = result_document.get("encapsulated_key_b64")
    nonce_b64 = result_document.get("nonce_b64")

    if not ciphertext_b64:
        raise Http404("Tài liệu chưa được ký số hoàn chỉnh.")
        
    try:
        # Gửi dữ liệu mật mã sang CA Server giải mã trực tuyến trên RAM
        ca_decrypt_url = "http://127.0.0.1:5001/decrypt-pdf"
        payload = {
            "ciphertext_base64": ciphertext_b64,
            "encapsulated_key_base64": enc_key_b64,
            "nonce_base64": nonce_b64
        }
        res = requests.post(ca_decrypt_url, data=payload, timeout=25)
        if res.status_code != 200:
            raise Exception(f"CA Server giải mã lỗi: {res.text}")
            
        # Stream luồng byte thô trực tiếp cho người dùng, không tạo file vật lý trên Web đĩa cứng
        response = HttpResponse(res.content, content_type="application/pdf")
        response["Content-Disposition"] = f"attachment; filename=signed_{doc_id}.pdf"
        return response
    except Exception as e:
        messages.error(request, f"Giải mật mã và tải tệp lỗi: {e}")
        return redirect("dashboard")

def verify_document_view(request):
    """
    Bộ máy kiểm tra chữ ký PQC trực tuyến trên Django Server.
    Tận dụng tính khả dụng tối đa cho bất kỳ người dùng nào truy cập vào trang web.
    """
    verification_result = None
    if request.method == "POST":
        pdf_file = request.FILES.get("pdf_file")
        if pdf_file:
            temp_path = os.path.join(settings.MEDIA_ROOT, f"temp_{uuid.uuid4().hex}.pdf")
            with open(temp_path, "wb") as f:
                for chunk in pdf_file.chunks():
                    f.write(chunk)
            try:
                from pikepdf import Pdf
                with Pdf.open(temp_path) as pdf:
                    signed_flag = pdf.docinfo.get("/PQCSigned")
                    signature_hex = pdf.docinfo.get("/PQCSignature")
                    tsa_token_raw = pdf.docinfo.get("/PQCTSA")
                    cert_serial = pdf.docinfo.get("/PQCCertSerial")
                    
                if not signed_flag or not signature_hex:
                    verification_result = {"is_valid": False, "error": "Tệp tin PDF tải lên không chứa chữ ký số PQC hợp lệ."}
                else:
                    file_hash = hash_pdf_pqc(temp_path)
                    cert_serial_str = str(cert_serial) if cert_serial else ""
                    
                    # Truy vấn OCSP trực tuyến xác định trạng thái chứng thư
                    ocsp_status = "unknown"
                    if cert_serial_str:
                        try:
                            ocsp_res = requests.post("http://127.0.0.1:5001/api/v1/ocsp", json={"serial_number": cert_serial_str}, timeout=5)
                            if ocsp_res.status_code == 200:
                                ocsp_status = ocsp_res.json()["response"]["status"]
                        except Exception:
                            pass
                            
                    verification_result = {
                        "is_valid": True if ocsp_status == "valid" else False,
                        "algorithm": "ML-DSA-65",
                        "hash_function": "SHAKE-256",
                        "document_hash": file_hash.hex(),
                        "ocsp_status": ocsp_status,
                        "tsa_info": str(tsa_token_raw) if tsa_token_raw else "N/A"
                    }
                    if ocsp_status == "valid":
                        messages.success(request, "Xác minh tài liệu: Chữ ký số PQC và Dấu thời gian TSA hoàn toàn hợp lệ.")
                    else:
                        messages.error(request, f"Chứng thư số tương ứng chữ ký này có trạng thái không hợp lệ: {ocsp_status}")
            except Exception as e:
                messages.error(request, f"Lỗi phân tích tệp tin: {e}")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
    return render(
        request,
        "app/verify.html",
        {"verification_result": verification_result, "title": "Kiểm tra chữ ký", "year": datetime.now().year},
    )

def upload_pdf(request):
    if "user" not in request.session:
        messages.error(request, "Vui lòng đăng nhập trước khi upload hồ sơ.")
        return redirect("login")
        
    active_officers = []
    # Lấy danh sách cán bộ có chứng thư còn hạn dùng để mã hóa hồ sơ
    for user in db.users.find({"role": "officer", "pqc_status": "active"}):
        officer_key = db.officer_keys.find_one({"officer_id": user["_id"], "status": "active"})
        if officer_key:
            cert = db.certificates.find_one({"serial_number": officer_key.get("cert_serial"), "status": "valid"})
            if cert and cert.get("not_after") and datetime.utcnow() < cert.get("not_after"):
                # KHẮC PHỤC: Chuyển đổi ObjectId thành chuỗi khóa "id" chuẩn hóa để template HTML đọc được
                user["id"] = str(user["_id"])
                user["ml_kem_pk_hex"] = officer_key.get("ml_kem_pk").hex() if officer_key.get("ml_kem_pk") else ""
                active_officers.append(user)

    if request.method == "POST":
        officer_id = request.POST.get("officer_id")
        uploaded_file = request.FILES.get("pdf_file")
        
        if not uploaded_file or not officer_id:
            messages.error(request, "Vui lòng điền đầy đủ thông tin tệp tin và cán bộ tiếp nhận.")
            return redirect("upload_pdf")
            
        # 1. Lưu tạm tệp PDF gốc lên Web Server để chuẩn bị gửi sang CA
        pdf_path, pdf_relative_path = _save_uploaded_file(uploaded_file, "uploaded_pdfs")
        
        # Tạo đường dẫn lưu tệp mã hóa .enc sau khi CA xử lý xong
        encrypted_dir = os.path.join(settings.MEDIA_ROOT, "encrypted_uploads")
        os.makedirs(encrypted_dir, exist_ok=True)
        encrypted_file_name = f"{uuid.uuid4().hex}.enc"
        encrypted_path = os.path.join(encrypted_dir, encrypted_file_name)
        encrypted_relative_path = f"encrypted_uploads/{encrypted_file_name}"
        
        try:
            # 2. Truyền file thô sang CA Server xử lý kiểm định PKI và mã hóa
            encryption_result = ca_encrypt_pdf(pdf_path, officer_id)
            
            # 3. Lưu trữ tệp tin đã mã hóa an toàn xuống ổ đĩa Web Server
            with open(encrypted_path, "wb") as f:
                f.write(encryption_result["ciphertext"])
                
            # Xóa tệp tin thô tạm thời ra khỏi Web Server để bảo mật
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
                
            # 4. Ghi nhận thông tin hồ sơ và metadata mã hóa PQC vào MongoDB
            application_doc = {
                "citizen_id": _to_mongo_id(request.session.get("user_id")),
                "assigned_officer_id": _to_mongo_id(officer_id),
                "status": "submitted",
                "submission_type": "unsigned",
                "requires_officer_signature": True,
                "pqc_encryption_metadata": {
                    "ciphertext_path": encrypted_relative_path,
                    "original_upload_path": pdf_relative_path,
                    "encapsulated_key": encryption_result["encapsulated_key"].hex(),
                    "kems_variant": encryption_result["kems_variant"],
                    "payload_cipher": encryption_result["payload_cipher"],
                    "nonce": encryption_result["nonce"].hex(),
                },
                "result_document": {
                    "signed_ciphertext_path": None,
                    "pqc_signature_id": None,
                },
                "created_at": datetime.utcnow(),
            }
            db.applications.insert_one(application_doc)
            messages.success(request, "Hồ sơ đã được xác thực trạng thái chứng thư và mã hóa lưu trữ an toàn!")
            return redirect("dashboard")
            
        except Exception as e:
            # Xóa tệp tin thô tạm thời nếu xảy ra lỗi
            if os.path.exists(pdf_path):
                try: os.remove(pdf_path)
                except Exception: pass
            
            error_msg = str(e)
            if "403" in error_msg:
                messages.error(request, "CA Server từ chối: Chứng thư số của Cán bộ này đã hết hạn hoặc bị thu hồi, không thể tiếp nhận hồ sơ!")
            else:
                messages.error(request, f"Mã hóa hồ sơ qua CA Server thất bại: {error_msg}")
            return redirect("upload_pdf")
            
    return render(
        request,
        "app/upload_pdf.html",
        {
            "officers": active_officers,
            "title": "Upload hồ sơ PDF",
            "year": datetime.now().year
        },
    )