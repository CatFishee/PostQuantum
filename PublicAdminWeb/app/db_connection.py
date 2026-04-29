# db_connection.py
from pymongo import MongoClient
import urllib.parse

# 1. Thông tin kết nối
password = urllib.parse.quote_plus("PostQuantumPassword") # Bảo mật mật khẩu nếu có ký tự đặc biệt
uri = f"mongodb+srv://Default:{password}@postquantum.fu2sbf1.mongodb.net/?retryWrites=true&w=majority"

def get_db():
    try:
        client = MongoClient(uri)
        # Tên Database chúng ta sẽ dùng
        db = client['PQC_Admin_System']
        return db
    except Exception as e:
        print(f"Lỗi kết nối MongoDB: {e}")
        return None