from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import path

from app import views

urlpatterns = [
    path("", views.home, name="home"),
    path("contact/", views.contact, name="contact"),
    path("about/", views.about, name="about"),
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("download-key/", views.download_key, name="download_key"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("ra/requests/", views.ra_requests, name="ra_requests"),
    path("ra/requests/<str:request_id>/approve/", views.ra_approve_request, name="ra_approve_request"),
    path("ra/requests/<str:request_id>/reject/", views.ra_reject_request, name="ra_reject_request"),
    path("upload/", views.upload_pdf, name="upload_pdf"),
    
    path("decrypt/<str:doc_id>/", views.decrypt_application_view, name="decrypt_application"),
    
    path("media/download/signed/<str:doc_id>/", views.download_signed_pdf, name="download_signed_pdf"),
    
    path("sign/<str:doc_id>/", views.sign_document_view, name="sign_document"),
    path("verify/", views.verify_document_view, name="verify_document"),
    
    # --- ENDPOINTS PROXY CHO LOCAL AGENT ---
    path("api/ca-public-key/", views.api_ca_public_key, name="api_ca_public_key"),
    path("api/ca-tsa/", views.api_ca_tsa, name="api_ca_tsa"),
    path("api/device-challenge/", views.api_device_challenge, name="api_device_challenge"),
    path("api/device-verify/", views.api_device_verify, name="api_device_verify"),
    
    path("logout/", LogoutView.as_view(next_page="/"), name="logout"),
    path("admin/", admin.site.urls),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
