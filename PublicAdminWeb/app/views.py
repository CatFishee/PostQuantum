import requests
import os
from django.shortcuts import render, redirect
from django.contrib import messages
from .crypto_utils import get_sha3_512_hash, sign_pdf_metadata
from .db_connection import get_db

db = get_db()

def home(request):
    return render(request, 'app/index.html', {'title': 'Trang chủ PQC'})

def register(request):
    if request.method == "POST":
        username = request.POST['username']
        role = request.POST['role'] # 'Civilian' hoặc 'Officer'
        password = request.POST['password']
        
        # 1. Băm mật khẩu bằng SHA3-512 (Pure PQC)
        pass_hash = get_sha3_512_hash(password.encode()).hex()
        
        user_data = {
            "username": username,
            "role": role,
            "password_hash": pass_hash,
            "full_name": request.POST['full_name']
        }
        
        # 2. Nếu là Officer, gọi CA Server để lấy khóa
        if role == "Officer":
            try:
                # Gọi sang FastAPI (CA Server)
                response = requests.post(
                    f"http://127.0.0.1:5001/register_officer",
                    params={"username": username, "full_name": user_data['full_name'], "position": "Cán bộ"}
                )
                if response.status_code == 200:
                    ca_data = response.json()
                    # Trả về khóa để cán bộ tải về file .pqc
                    return render(request, 'app/download_key.html', {
                        'private_key': ca_data['private_key_to_download'],
                        'username': username
                    })
            except Exception as e:
                messages.error(request, f"Không thể kết nối tới CA Server: {e}")
                return redirect('register')

        # 3. Lưu Civilian vào AtlasDB
        db.users.insert_one(user_data)
        messages.success(request, "Đăng ký thành công!")
        return redirect('login')
        
    return render(request, 'app/register.html')

def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password_attempt = request.POST['password']
        
        # Tìm user trong AtlasDB
        user = db.users.find_one({"username": username})
        if user:
            # Kiểm tra hash SHA3
            attempt_hash = get_sha3_512_hash(password_attempt.encode()).hex()
            if attempt_hash == user['password_hash']:
                request.session['user'] = user['username']
                request.session['role'] = user['role']
                return redirect('dashboard')
        
        messages.error(request, "Sai tên đăng nhập hoặc mật khẩu!")
    return render(request, 'app/login.html')

def dashboard(request):
    if 'user' not in request.session: return redirect('login')
    
    # Lấy danh sách văn bản dựa trên role
    if request.session['role'] == "Officer":
        docs = db.documents.find({"status": "Pending"})
    else:
        docs = db.documents.find({"owner": request.session['user']})
        
    return render(request, 'app/dashboard.html', {'docs': docs})

def sign_document_view(request, doc_id):
    if request.session.get('role') != "Officer": return redirect('home')
    
    if request.method == "POST":
        # Cán bộ upload file .pqc chứa Private Key của họ
        key_file = request.FILES['key_file']
        private_key_hex = key_file.read().decode().strip()
        
        # Lấy thông tin Public Key từ DB để nhúng vào metadata
        officer = db.officers.find_one({"username": request.session['user']})
        
        # Thực hiện ký văn bản (Logic trong crypto_utils)
        # Giả sử file PDF nằm ở thư mục media
        input_pdf = "path/to/pending/doc.pdf"
        output_pdf = "path/to/signed/doc_signed.pdf"
        
        success = sign_pdf_metadata(input_pdf, output_pdf, private_key_hex, officer['public_key'])
        
        if success:
            db.documents.update_one({"_id": doc_id}, {"$set": {"status": "Signed"}})
            messages.success(request, "Văn bản đã được ký Hậu lượng tử!")
            
    return render(request, 'app/sign.html')

def contact(request):
    return render(request, 'app/contact.html', {'title':'Liên hệ', 'year': datetime.now().year})

def about(request):
    return render(request, 'app/about.html', {'title':'Giới thiệu', 'year': datetime.now().year})