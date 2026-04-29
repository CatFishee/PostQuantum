from datetime import datetime
from django.urls import path
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from app import views # Import views từ app

urlpatterns = [
    # Các trang cơ bản
    path('', views.home, name='home'),
    
    # Các trang chức năng PQC mới
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('sign/<str:doc_id>/', views.sign_document_view, name='sign_document'),
    
    # Đăng xuất
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    
    # Trang admin mặc định của Django
    path('admin/', admin.site.urls),
]