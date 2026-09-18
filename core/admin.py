from django.contrib import admin

from .models import AuthorizationCode, Client, Consent, RefreshToken, Scope

# Register your models here.



@admin.register(Client)
class CilentAdmin(admin.ModelAdmin):
    list_display = ("name", "client_id", "client_type", "is_active", "created_at")
    list_filter = ("client_type", "is_active")
    readonly_fields = ("client_id", "client_secret_hash", "created_at")
    search_fields = ("name", "client_id")


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    list_display = ("key", "description")
    search_fields = ("key",)


@admin.register(AuthorizationCode)
class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ("code", "client", "user", "expires_at", "used_at", "created_at")
    list_filter = ("client",)
    readonly_fields = ("code", "created_at")


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("client", "user", "expires_at", "revoked_at", "created_at")
    list_filter = ("client",)
    readonly_fields = ("token_hash", "created_at")


@admin.register(Consent)
class ConsentAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "granted_at", "updated_at")