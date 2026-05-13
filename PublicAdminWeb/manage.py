#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PublicAdminWeb.settings')

    # --- PHẦN FIX LOAD DLL CHO PQC (Giống hệt CA Server) ---
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Thêm đường dẫn vào PATH môi trường
    os.environ['PATH'] = current_dir + os.pathsep + os.environ['PATH']
    
    # 2. Xử lý đặc biệt cho Windows (Python 3.8+)
    if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
        try:
            os.add_dll_directory(current_dir)
            print(f"[*] PQC DLL directory added: {current_dir}")
        except Exception as e:
            print(f"[!] Warning: Could not add DLL directory: {e}")
    # ------------------------------------------------------

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == '__main__':
    main()