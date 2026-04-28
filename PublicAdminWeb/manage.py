#!/usr/bin/env python
import os
import sys

def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PublicAdminWeb.settings')
    
    # --- PHẦN LOAD DLL CHO PQC ---
    current_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        # Ép Python nhận liboqs.dll ngay tại thư mục manage.py
        os.add_dll_directory(current_dir)
        print(f"[*] PQC DLL loaded from: {current_dir}")
    except Exception as e:
        print(f"[!] Warning: Could not set DLL directory: {e}")

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed..."
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()