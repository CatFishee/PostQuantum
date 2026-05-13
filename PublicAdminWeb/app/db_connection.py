import urllib.parse
from pymongo import MongoClient

# URI Cluster mới của bạn
password = urllib.parse.quote_plus("PostQuantumPassword")
uri = f"mongodb+srv://Default:{password}@postquantum.qd987xk.mongodb.net/?retryWrites=true&w=majority&appName=postquantum"

def get_db():
    try:
        # 1. Tăng timeout lên 15 giây để máy kịp phân giải DNS của Atlas
        # 2. tlsAllowInvalidCertificates=True để tránh lỗi bắt tay SSL do môi trường Python
        client = MongoClient(
            uri, 
            serverSelectionTimeoutMS=15000, 
            tlsAllowInvalidCertificates=True,
            connectTimeoutMS=15000
        )
        
        # Kiểm tra thực tế
        client.admin.command('ping')
        print("[+] Kết nối MongoDB Atlas (Cluster mới) thành công!")
        return client['PQC_Admin_System']
    except Exception as e:
        print(f"[-] Lỗi kết nối MongoDB: {e}")
        return None