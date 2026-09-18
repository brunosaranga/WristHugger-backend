import hashlib
import secrets


from django.db import models
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone



# Create your models here.



class Client(models.Model):
    """A registered app allowed to request tokens (the \"App\" box in the diagram)"""

    class ClientType(models.TextChoices):
        CONFIDENTIAL = "confidential", "Confidential"
        PUBLIC = "public", "Public"

    client_id = models.CharField(max_length=48, unique=True, editable=False)
    client_secret_hash = models.CharField(
        max_length=128,
        blank=True,
        help_text="Empty for public clients. Set via set_client_secret(), never edited directly."
    )
    name = models.CharField(max_length=100)
    client_type = models.CharField(
        max_length=20, choices=ClientType.choices, default=ClientType.CONFIDENTIAL
    )
    redirect_uris = models.TextField(help_text="One exact redirect URI per line.")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="oauth_clients",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.client_id:
            self.client_id = secrets.token_urlsafe(24)
        super().save(*args, **kwargs)

    def redirect_uri_listed(self):
        return [uri.strip() for uri in self.redirect_uris.splitlines() if uri.strip()]

    def set_client_secret(self, raw_secret):
        # Slow hash (PBKDF2 via Django's hasher) is correct here: a client
        # secret can be a human-chosen or short value, so it needs the same brute-force resistance as a password.
        self.client_secret_hash = make_password(raw_secret)

    def check_client_secret(self, raw_secret):
        if not self.client_secret_hash:
            return False
        return check_password(raw_secret, self.client_secret_hash)







class Scope(models.Model):
    """One permission a client can request. Powers the consent screen text."""

    key = models.CharField(max_length=50, unique=True, help_text="e.g. read:profile")
    description = models.CharField(
        max_length=255, help_text="Plain-language line shown to the user, e.g. 'View your name and email.'"
    )

    def __str__(self):
        return self.key








class AuthorizationCode(models.Model):
    """Short-lived, single-use. Stores the code_challenge from PKCE."""

    code = models.CharField(max_length=64, unique=True, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="authorization_codes")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    redirect_uri = models.URLField()
    scopes = models.ManyToManyField(Scope, blank=True)
    code_challenge = models.CharField(max_length=128)
    code_challenge_method = models.CharField(max_length=10, default="S256")
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(
        null=True, blank=True, help_text="Set the moment it's redeemed. A second use attempt is compromise signal."
    )
    issued_refresh_token = models.OneToOneField(
        "RefreshToken",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="source_code",
        help_text="Set once this code is redeemed, so a replay of the same code can revoke what ut already issued."
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=1)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def is_used(self):
        return self.used_at is not None

    def __str__(self):
        return f"{self.code[:8]}... for {self.client.name}"





class RefreshToken(models.Model):
    """The long-lived credential. Only its hash is stored, same principle as a password."""

    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="refresh_tokens")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    scopes = models.ManyToManyField(Scope, blank=True)
    rotated_from = models.OneToOneField(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="rotated_to"
    )
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def hash_token(raw_token):
        # Plain SHA-256, not PBKDF2, on purpose: the raw token is already 256+ bits of secrets.token_urlsafe randomness, not a guessable password, so we don't need a slow hash - we need a fast stable lookup key so we can find this row by the token a client sends us.
        return hashlib.sha256(raw_token.encode()).hexdigest()

    def is_expired(self):
        return self.revoked_at is not None

    def __str__(self):
        return f"refresh token · {self.user} · {self.client.name}"





class Consent(models.Model):
    """What a user has already approved for a client, so you can skip re-prompting."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="consents")
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name="consents")
    scopes = models.ManyToManyField(Scope, blank=True)
    granted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "client")

    def __str__(self):
        return f"{self.user} → {self.client.name}"


