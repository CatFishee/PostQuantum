import urllib.parse
from pymongo import MongoClient

# URI mới bạn vừa cung cấp
password = urllib.parse.quote_plus("PostQuantumPassword")
uri = f"mongodb+srv://Default:{password}@postquantum.qd987xk.mongodb.net/?retryWrites=true&w=majority&appName=postquantum"

def get_db():
    try:
        # Thêm timeout 5 giây để không bị "xoay hoài" nếu lỗi
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Kiểm tra kết nối thực tế
        client.admin.command('ping')
        print("[+] Kết nối MongoDB Atlas (Cluster mới) thành công!")
        return client['PQC_Admin_System']
    except Exception as e:
        print(f"[-] Lỗi kết nối MongoDB: {e}")
        return None