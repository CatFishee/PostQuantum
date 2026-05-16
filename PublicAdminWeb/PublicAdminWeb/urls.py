# PublicAdminWeb/urls.py (hoặc app/urls.py tùy thuộc vào cách bạn chia file)

from django.contrib import admin
from django.urls import path
from django.contrib.auth.views import LogoutView
from app import views  # Import views từ app

urlpatterns = [
    # --- Các trang cơ bản ---
    path('', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    
    # --- Các trang Xác thực & PQC ---
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('download-key/', views.download_key, name='download_key'),  # Mới thêm
    
    # --- Nghiệp vụ (Hồ sơ, Ký duyệt) ---
    path('dashboard/', views.dashboard, name='dashboard'),
    path('sign/<str:doc_id>/', views.sign_document_view, name='sign_document'),
    
    # --- Đăng xuất ---
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    
    # --- Trang admin mặc định của Django ---
    path('admin/', admin.site.urls),
]