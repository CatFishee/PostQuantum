import urllib.parse
from pymongo import MongoClient
import ssl

# URI Cluster của bạn
password = urllib.parse.quote_plus("PostQuantumPassword")

# Thêm tlsAllowInvalidCertificates=True để bỏ qua lỗi bắt tay SSL nếu môi trường Python của bạn bị chặn
uri = f"mongodb+srv://Default:{password}@postquantum.qd987xk.mongodb.net/?retryWrites=true&w=majority&appName=postquantum"

def get_db():
    try:
        # Thêm các tham số cấu hình mạnh hơn
        client = MongoClient(
            uri, 
            serverSelectionTimeoutMS=10000, # Đợi 10s
            tls=True,
            tlsAllowInvalidCertificates=True # Bỏ qua lỗi SSL nội bộ của Python
        )
        
        # Ép buộc kết nối ngay lập tức để kiểm tra
        client.admin.command('ping')
        print("[+] Kết nối MongoDB Atlas thành công!")
        return client['PQC_Admin_System']
    except Exception as e:
        print(f"[-] Lỗi kết nối MongoDB: {e}")
        return None