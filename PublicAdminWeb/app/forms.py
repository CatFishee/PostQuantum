"""
Definition of forms.
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext_lazy as _


class SignatureForm(forms.Form):
    """Form can bo dung de ky PDF bang khoa ML-DSA."""

    pdf_file = forms.FileField(
        label="File PDF can ky",
        widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": "application/pdf,.pdf"}),
    )
    key_file = forms.FileField(
        label="File key JSON cua can bo",
        widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": ".json,.pqc,.key,.txt"}),
    )
    public_key_hex = forms.CharField(
        label="Public key cua can bo",
        required=False,
        help_text="Co the bo trong neu public key da co trong database officer_keys.",
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 4}),
    )
    algorithm = forms.ChoiceField(
        label="Thuat toan ky",
        choices=(("ML-DSA-65", "ML-DSA-65"),),
        initial="ML-DSA-65",
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    def clean_pdf_file(self):
        pdf_file = self.cleaned_data["pdf_file"]
        if not pdf_file.name.lower().endswith(".pdf"):
            raise forms.ValidationError("Chi nhan file PDF.")
        return pdf_file

    def clean_key_file(self):
        key_file = self.cleaned_data["key_file"]
        allowed_suffixes = (".json", ".pqc", ".key", ".txt")
        if not key_file.name.lower().endswith(allowed_suffixes):
            raise forms.ValidationError("File khoa nen la .json, .pqc, .key hoac .txt.")
        return key_file


class VerifySignatureForm(forms.Form):
    """Form upload PDF da ky de kiem tra chu ky PQC."""

    pdf_file = forms.FileField(
        label="File PDF da ky",
        widget=forms.ClearableFileInput(attrs={"class": "form-control", "accept": "application/pdf,.pdf"}),
    )

    def clean_pdf_file(self):
        pdf_file = self.cleaned_data["pdf_file"]
        if not pdf_file.name.lower().endswith(".pdf"):
            raise forms.ValidationError("Chi nhan file PDF.")
        return pdf_file


class BootstrapAuthenticationForm(AuthenticationForm):
    """Authentication form which uses boostrap CSS."""

    username = forms.CharField(
        max_length=254,
        widget=forms.TextInput({"class": "form-control", "placeholder": "User name"}),
    )
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput({"class": "form-control", "placeholder": "Password"}),
    )
