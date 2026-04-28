import os
# Nếu bạn đã tải file liboqs.dll và để trong cùng thư mục, hãy dùng dòng này:
# os.add_dll_directory(os.getcwd()) 

try:
    import oqs
    print("--- KẾT QUẢ ---")
    print("Môi trường Python PQC: ĐÃ SẴN SÀNG")
    print("Thuật toán Signature:", oqs.get_enabled_sig_mechanisms()[:3], "...") # Hiện vài cái tên
    print("Thuật toán KEM (Kyber):", oqs.get_enabled_kem_mechanisms()[:3], "...")
except Exception as e:
    print("--- LỖI ---")
    print("Thư viện Python đã cài nhưng thiếu file liboqs.dll gốc.")
    print("Chi tiết lỗi:", e)