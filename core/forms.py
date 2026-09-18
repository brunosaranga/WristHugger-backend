from django import forms

from .models import Client


class ClientRegistrationForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = ["name", "client_type", "redirect_uris"]
        widgets = {
            "redirect_uris": forms.Textarea(
                attrs={"rows": 4, "placeholder": "https://example.com/callback"}
            ),
        }

    def clean_redirect_uris(self):
        raw = self.cleaned_data["redirect_uris"]
        uris = [line.strip() for line in raw.splitlines() if line.strip()]
        if not uris:
            raise forms.ValidationError("At least one redirect URI is required.")
        url_field = forms.URLField()
        for uri in uris:
            try:
                url_field.clean(uri)
            except forms.ValidationError:
                raise forms.ValidationError(f"'{uri}' is not a valid URL.")
        return "\n".join(uris)