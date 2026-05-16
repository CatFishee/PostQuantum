"""
Definition of forms.
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext_lazy as _


class SignatureForm(forms.Form):
    """Form can bo dung de ky PDF bang khoa ML-DSA."""

    pdf_file = forms.FileField(
        label="File PDF cần ký",
        widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": "application/pdf,.pdf"}),
    )
    key_file = forms.FileField(
        label="Private key .pqc",
        widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": ".pqc,.key,.txt"}),
    )
    public_key_hex = forms.CharField(
        label="Public key của cán bộ",
        required=False,
        help_text="Có thể bỏ trống nếu public key đã có trong database officers.",
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 4}),
    )
    algorithm = forms.ChoiceField(
        label="Thuật toán ký",
        choices=(("ML-DSA-65", "ML-DSA-65"), ("ML-DSA-44", "ML-DSA-44"), ("ML-DSA-87", "ML-DSA-87")),
        initial="ML-DSA-65",
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    def clean_pdf_file(self):
        pdf_file = self.cleaned_data["pdf_file"]
        if not pdf_file.name.lower().endswith(".pdf"):
            raise forms.ValidationError("Chỉ nhận file PDF.")
        return pdf_file

    def clean_key_file(self):
        key_file = self.cleaned_data["key_file"]
        allowed_suffixes = (".pqc", ".key", ".txt")
        if not key_file.name.lower().endswith(allowed_suffixes):
            raise forms.ValidationError("Private key nên là file .pqc, .key hoặc .txt.")
        return key_file

class BootstrapAuthenticationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""
    username = forms.CharField(max_length=254,
                               widget=forms.TextInput({
                                   'class': 'form-control',
                                   'placeholder': 'User name'}))
    password = forms.CharField(label=_("Password"),
                               widget=forms.PasswordInput({
                                   'class': 'form-control',
                                   'placeholder':'Password'}))
