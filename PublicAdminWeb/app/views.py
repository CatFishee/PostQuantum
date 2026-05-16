# app/views.py

import os
import requests
from datetime import datetime, timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from bson.objectid import ObjectId
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Import từ các module nội bộ của bạn
from .crypto_utils import sign_pdf_metadata  # Hàm ký bạn đã định nghĩa
from .db_connection import get_db            # Hàm lấy kết nối MongoDB Atlas

db = get_db()
ph = PasswordHasher()  # Khởi tạo bộ băm mật khẩu Argon2id (Kháng lượng tử)

# ==========================================
# CÁC TRANG CƠ BẢN
# ==========================================
def home(request):
    return render(request, 'app/index.html', {'title': 'Trang chủ PQC'})

def contact(request):
    return render(request, 'app/contact.html', {'title': 'Liên hệ', 'year': datetime.now().year})

def about(request):
    return render(request, 'app/about.html', {'title': 'Giới thiệu', 'year': datetime.now().year})


# ==========================================
# CHỨC NĂNG ĐĂNG KÝ VÀ CẤP KHÓA PQC
# ==========================================
def register(request):
    if request.method == "POST":
        username = request.POST['username']
        role = request.POST['role']  # 'citizen' hoặc 'officer'
        password = request.POST['password']
        full_name = request.POST['full_name']
        
        # 1. Kiểm tra User đã tồn tại chưa
        if db.users.find_one({"username": username}):
            messages.error(request, "Tên đăng nhập đã tồn tại!")
            return redirect('register')
        
        # 2. Băm mật khẩu bằng Argon2id
        pass_hash = ph.hash(password)
        
        # 3. Tạo record User mới (Mặc định: Citizen thì active, Officer thì inactive chờ cấp khóa)
        user_data = {
            "username": username,
            "password_hash": pass_hash,
            "full_name": full_name,
            "role": role,
            "pqc_status": "active" if role == "citizen" else "inactive", 
            "created_at": datetime.now(timezone.utc)
        }
        
        # Lưu vào MongoDB để lấy ObjectId
        result = db.users.insert_one(user_data)
        user_id = str(result.inserted_id)
        
        # 4. Phân luồng đăng ký cho Cán bộ (Officer)
        if role == "officer":
            try:
                # Gọi CA Server (FastAPI) để sinh khóa Kyber & Dilithium
                ca_payload = {
                    "officer_id": user_id, 
                    "username": username,
                    "full_name": full_name
                }
                # Thay URL bằng địa chỉ CA Server thật của bạn
                response = requests.post("http://127.0.0.1:5001/register_officer", json=ca_payload)
                
                if response.status_code == 200:
                    ca_data = response.json()
                    
                    # CA Server đã thành công, update trạng thái PQC của user lên active
                    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"pqc_status": "active"}})
                    
                    # Lưu tạm Private Key vào Session của Django (SQLite/Mem) để chuyển sang trang Download
                    request.session['temp_private_keys'] = ca_data['private_keys']
                    request.session['temp_username'] = username
                    
                    messages.success(request, "Tạo tài khoản Cán bộ thành công. Vui lòng tải khóa bảo mật!")
                    return redirect('download_key')
                else:
                    # Nếu CA API lỗi (vd: 500, 400), xóa user vừa tạo để Rollback
                    db.users.delete_one({"_id": ObjectId(user_id)})
                    messages.error(request, f"Lỗi từ CA Server khi tạo khóa: {response.text}")
                    return redirect('register')
                    
            except requests.exceptions.RequestException as e:
                # Nếu CA Server đang sập, xóa user để Rollback
                db.users.delete_one({"_id": ObjectId(user_id)}) 
                messages.error(request, "Không thể kết nối tới CA Server. Vui lòng thử lại sau.")
                return redirect('register')

        # 5. Phân luồng đăng ký cho Công dân (Citizen)
        messages.success(request, "Đăng ký tài khoản Công dân thành công!")
        return redirect('login')
        
    return render(request, 'app/register.html')


def download_key(request):
    """ View hiển thị màn hình tải file khóa cho Officer sau khi đăng ký """
    # Lấy key từ session ra và pop() để xóa ngay lập tức khỏi RAM Server
    private_keys = request.session.pop('temp_private_keys', None)
    username = request.session.pop('temp_username', "Unknown")
    
    # Nếu refesh trang hoặc vào lại thì không còn khóa nữa
    if not private_keys:
        messages.warning(request, "Không tìm thấy khóa hoặc khóa đã được tải. Vui lòng đăng nhập.")
        return redirect('login')
        
    return render(request, 'app/download_key.html', {
        'private_keys': private_keys,
        'username': username
    })


# ==========================================
# CHỨC NĂNG ĐĂNG NHẬP (XÁC THỰC)
# ==========================================
def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password_attempt = request.POST['password']
        
        # Tìm user trong MongoDB
        user = db.users.find_one({"username": username})
        if user:
            try:
                # Kiểm tra hash bằng Argon2
                ph.verify(user['password_hash'], password_attempt)
                
                # Check Rehash (Nếu thuật toán Argon2 được cấu hình mạnh lên trong tương lai)
                if ph.check_needs_rehash(user['password_hash']):
                    db.users.update_one({"_id": user['_id']}, {"$set": {"password_hash": ph.hash(password_attempt)}})
                
                # Kiểm tra trạng thái PQC của Cán bộ (Phải active)
                if user.get('pqc_status') == "inactive":
                    messages.error(request, "Tài khoản của bạn bị lỗi hoặc chưa có khóa PQC. Vui lòng liên hệ Admin.")
                    return redirect('login')

                # Lưu phiên đăng nhập (Lưu id dạng string để hàm ký dùng lại)
                request.session['user_id'] = str(user['_id'])
                request.session['user'] = user['username']
                request.session['role'] = user['role']
                
                messages.success(request, f"Xin chào {user['full_name']}!")
                return redirect('dashboard')
                
            except VerifyMismatchError:
                pass # Bỏ qua, hiển thị lỗi chung ở dưới
        
        messages.error(request, "Sai tên đăng nhập hoặc mật khẩu!")
        
    return render(request, 'app/login.html')


# ==========================================
# NGHIỆP VỤ HÀNH CHÍNH CÔNG (DASHBOARD & SIGN)
# ==========================================
def dashboard(request):
    if 'user' not in request.session: 
        return redirect('login')
    
    # Lấy danh sách văn bản dựa trên role (Collection 'applications' theo PDF của bạn)
    if request.session['role'] == "officer":
        # Cán bộ thấy các hồ sơ 'submitted'
        docs = db.applications.find({"status": "submitted"})
    else:
        # Công dân xem hồ sơ của mình
        user_id_obj = ObjectId(request.session['user_id'])
        docs = db.applications.find({"citizen_id": user_id_obj})
        
    return render(request, 'app/dashboard.html', {'docs': docs})


def sign_document_view(request, doc_id):
    if request.session.get('role') != "officer": 
        messages.error(request, "Chỉ cán bộ mới có quyền ký văn bản.")
        return redirect('home')
    
    if request.method == "POST":
        try:
            # 1. Cán bộ upload file .pqc chứa Private Key của họ
            key_file = request.FILES['key_file']
            private_key_hex = key_file.read().decode('utf-8').strip()
            
            # 2. Lấy thông tin Public Key từ DB (Collection 'officer_keys' theo thiết kế PDF)
            officer_id_obj = ObjectId(request.session['user_id'])
            officer_keys_doc = db.officer_keys.find_one({"officer_id": officer_id_obj, "status": "active"})
            
            if not officer_keys_doc:
                messages.error(request, "Không tìm thấy Public Key của bạn trên hệ thống!")
                return redirect('sign_document', doc_id=doc_id)
            
            ml_dsa_pk = officer_keys_doc['ml_dsa_pk'] # Lấy khóa công khai Dilithium
            
            # 3. Thực hiện ký văn bản bằng thuật toán PQC
            # Giả sử file PDF gốc và đích
            input_pdf = f"media/pending/{doc_id}.pdf"
            output_pdf = f"media/signed/{doc_id}_signed.pdf"
            
            # Hàm này trong crypto_utils.py của bạn (truyền cả private_key và public_key_dsa)
            success = sign_pdf_metadata(input_pdf, output_pdf, private_key_hex, ml_dsa_pk)
            
            if success:
                # Cập nhật trạng thái application trong DB
                db.applications.update_one(
                    {"_id": ObjectId(doc_id)}, 
                    {"$set": {
                        "status": "processed",
                        "result_document.signed_ciphertext_path": output_pdf
                    }}
                )
                messages.success(request, "Văn bản đã được ký điện tử Hậu lượng tử thành công!")
            else:
                messages.error(request, "Quá trình ký văn bản thất bại. Khóa PQC không hợp lệ.")
                
        except Exception as e:
            messages.error(request, f"Có lỗi xảy ra: {str(e)}")
            
    return render(request, 'app/sign.html')