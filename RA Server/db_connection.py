import urllib.parse
from pymongo import MongoClient


password = urllib.parse.quote_plus("PostQuantumPassword")
uri = f"mongodb+srv://Default:{password}@postquantum.qd987xk.mongodb.net/?retryWrites=true&w=majority&appName=postquantum"


def get_db():
    try:
        client = MongoClient(
            uri,
            serverSelectionTimeoutMS=15000,
            tlsAllowInvalidCertificates=True,
            connectTimeoutMS=15000,
        )
        client.admin.command("ping")
        print("[+] MongoDB Atlas connected.")
        return client["PQC_Admin_System"]
    except Exception as e:
        print(f"[-] MongoDB connection error: {e}")
        return None

