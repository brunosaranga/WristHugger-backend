import base64
import hashlib
import hmac
import secrets
from urllib.parse import quote

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.edit import CreateView

from .forms import ClientRegistrationForm
from .jwt_utils import issue_access_token
from .models import Client, AuthorizationCode, Client, Consent, Scope, RefreshToken

# Create your views here.

class RegisterClientView(LoginRequiredMixin, CreateView):
    model = Client
    form_class = ClientRegistrationForm
    template_name = "core/client_form.html"

    def form_valid(self, form):
        client = form.save(commit=False)
        client.owner = self.request.user

        raw_secret = None
        if client.client_type == Client.ClientType.CONFIDENTIAL:
            raw_secret = secrets.token_urlsafe(32)
            client.set_client_secret(raw_secret)

        client.save()
        self.object = client

        # Rendered directly, never redirected: this response is the only place the raw secret will ever exist outside the developer's clipboard. No sesion flash, no log line, no second view.
        return render(
            self.request,
            "core/client_created.html",
            {"client": client, "raw_secret": raw_secret}
        )





class AuthorizeError(Exception):
    """

    Carries an OAuth error code plus everything needed to report it.

    safe_redirect=False means we don't yet trust redirect_uri enough to send the browser there - that only happens for client_id or redirect_uri problems, which are exactly the checks that stand between this endpoint and being an open redirect. Everything after that check passes is safe to report back to the client normally.

    """

    def __init__(self, error, description, *, safe_redirect, client=None, redirect_uri=None, state=""):
        super().__init__(description)
        self.error = error
        self.description = description
        self.safe_redirect = safe_redirect
        self.client = client
        self.redirect_uri = redirect_uri
        self.state = state



class AuthorizeView(LoginRequiredMixin, View):
    def get(self, request):
        try:
            context = self._validate(request, request.GET)
        except AuthorizeError as exc:
            return self._handle_error(request, exc)

        existing = Consent.objects.filter(user=request.user, client=context["client"]).first()
        already_granted = existing and set(context["scopes"]) <= set(existing.scopes.all())
        if already_granted:
            return self._issue_code(request, context)

        return render(request, "core/authorize.html", context)

    def post(self, request):
        try:
            context = self._validate(request, request.POST)
        except AuthorizeError as exc:
            return self._handle_error(request, exc)

        if request.POST.get("decision") != "approve":
            denial = AuthorizeError(
                "access_denied",
                "The user denied the request.",
                safe_redirect=True,
                client=context["client"],
                redirect_uri=context["redirect_uri"],
                state=context["state"],
            )
            return self._handle_error(request, denial)

        consent, _ = Consent.objects.get_or_create(user=request.user, client=context["client"])
        consent.scopes.add(*context["scopes"])

        return self._issue_code(request, context)

    def _validate(self, request, params):
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")

        client = Client.objects.filter(client_id=client_id, is_active=True).first()
        if not client:
            raise AuthorizeError("invalid_client", "Unknown or inactive client_id.", safe_redirect=False)

        # Exact match against the registred list, not a prefix or domain check - a client that registered one callback path shouldn't be able to redirect users to some other path on request.
        if redirect_uri not in client.redirect_uri_list():
            raise AuthorizeError(
                "invalid_request", "redirect_uri is not registered for this client.", safe_redirect=False
            )

        # redirect_uri is now verified against the client's own registration, so it's safe to send the browser there for every error from here on.
        state = params.get("state", "")

        if params.get("response_type") != "code":
            raise AuthorizeError(
                "unsupported_response_type",
                "Only the authorization code flow is supported.",
                safe_redirect= True,
                client=client,
                redirect_uri=redirect_uri,
                state=state,
            )

        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "")
        if not code_challenge or code_challenge_method != "S256":
            raise AuthorizeError(
                "invalid_request",
                "PKCE with S256 is required.",
                safe_redirect=True,
                client=client,
                redirect_uri=redirect_uri,
                state=state,
            )

        requested_keys = [key for key in params.get("scope", "").split() if key]
        scopes = list(Scope.objects.filter(key__in=requested_keys))
        if len(scopes) != len(set(requested_keys)):
            raise AuthorizeError(
                "invalid_scope",
                "One or more requested scopes do not exist.",
                safe_redirect=True,
                client=client,
                redirect_uri=redirect_uri,
                state=state,
            )

        return {
            "client": client,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "state": state,
            "scopes": scopes,
        }

    def _issue_code(self, request, context):
        code = AuthorizationCode.objects.create(
            client=context["client"],
            user=request.user,
            redirect_uri=context["redirect_uri"],
            code_challenge=context["code_challenge"],
            code_challenge_method=context["code_challenge_method"],
        )
        code.scopes.set(context["scopes"])

        return redirect(self._build_redirect(context["redirect_uri"], code=code.code, state=context["state"]))

    def _handle_error(self, request, exc):
        if not exc.safe_redirect:
            return render(
                request,
                "core/authorize_error.html",
                {"error": exc.error, "description": exc.description},
                status=400,
            )
        return redirect(self._build_redirect(exc.redirect_uri, error=exc.error, state=exc.state))


    @staticmethod
    def _build_redirect(redirect_uri, **params):
        query = "&".join(f"{key}={quote(str(value))}" for key, value in params.items() if value)
        separator = "&" if "?" in redirect_uri else "?"
        return f"{redirect_uri}{separator}{query}"



class TokenError(Exception):
    def __init__(self, error, description, status=400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status



def _pkce_matches(code_verifier, code_challenge):
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b="=").decode()
    return hmac.compare_digest(computed, code_challenge)

def _create_refresh_token(client, user, scopes, rotated_from=None):
    raw_token = secrets.token_urlsafe(48)
    token = RefreshToken.objects.create(
        token_hash=RefreshToken.hash_token(raw_token),
        client=client,
        user=user,
        rotated_from=rotated_from,
        expires_at=timezone.now() + timezone.timedelta(seconds=settings.OAUTH_REFRESH_TOKEN_LIFETIME),
    )
    token.scopes.set(scopes)
    return token, raw_token

def _revoke_chain(token):
    """A reused refresh token means the whole rotatio chain from here is suspect - walk forward through rotated_from links and kill every descendant, not just the one that was replayed."""
    now = timezone.now()
    current = token
    while current is not None:
        if not current.is_revoked():
            current.revoked_at = now
            current.save(update_fields=["revoked_at"])
        current = RefreshToken.objects.filter(rotated_from=current).first()

@method_decorator(csrf_exempt, name="dispatch")
class TokenView(View):
    """The back-channel exchange. Every outcome here is JSON - this endpoint never redirects, since the caller is a server, not a browser."""

    def post(self, request):
        try:
            grant_type = request.POST.get("grant_type")
            if grant_type == "authorization_code":
                payload = self._authorization_code_grant(request)
            elif grant_type == "refresh_token":
                payload = self._refresh_token_grant(request)
            else:
                raise TokenError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token.")
        except TokenError as exc:
            status = 401 if exc.error == "invalid_client" else exc.status
            return JsonResponse({"error": exc.error, "error_description": exc.description}, status=status)

        return JsonResponse(payload)

    def _authenticate_client(self, request):
        client_id = request.POST.get("client_id")
        client_secret = request.POST.get("client_secret")

        if not client_id:
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_header[6:].decode())
                    client_id, client_secret = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError):
                    raise TokenError("invalid_client", "Malformed Authorization header.")

        if not client_id:
            raise TokenError("invalid_client", "client_id is required")

        client = Client.objects.filter(client_id=client_id, is_active=True).first()
        if not client:
            raise TokenError("invalid_client", "Unknown or inactive client.")

        if client.client_type == Client.ClientType.CONFIDENTIAL:
            if not client_secret or not client.check_client_secret(client_secret):
                raise TokenError("invalid_client", "Client authentication failed.")

        return client

    def _authorization_code_grant(self, request):
        client = self._authenticate_client(request)

        code_value = request.POST.get("code")
        redirect_uri = request.POST.get("redirect_uri")
        code_verifier = request.POST.get("code_verifier")

        if not (code_value and redirect_uri and code_verifier):
            raise TokenError("invalid_request", "code, redirect_uri, and code_verifier are all required.")

        with transaction.atomic():
            code = (
                AuthorizationCode.objects.select_for_update()
                .filter(code=code_value, client=client)
                .first()
            )

            if not code:
                raise TokenError('invalid_grant', "Authorization code not found for client.")

            if code.is_used():
                if code.issued_refresh_token_id:
                    code.issued_refresh_token.revoked_at = timezone.now()
                    code.issued_refresh_token.save(update_fields=["revoked_at"])
                raise TokenError("invalid_grant", "This authorization code has already been used.")

            if code.is_expired():
                raise TokenError("invalid_grant", "Authorization code has expired.")

            if code.redirect_uri != redirect_uri:
                raise TokenError("invalid_grant", "redirect_uri does not match the origiginal request.")

            if not _pkce_matches(code_verifier, code.code_challenge):
                raise TokenError("invalid_grant", "code_verifier does not match code_challenge.")

            scopes = list(code.scopes.all())
            refresh_token, raw_refresh = _create_refresh_token(client, code.user, scopes)

            code.used_at = timezone.now()
            code.issued_refresh_token = refresh_token
            code.save(update_fields=["used_at", "issued_refresh_token"])

        access_token = issue_access_token(code.user, client, scopes)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.OAUTH_ACCESS_TOKEN_LIFETIME,
            "refresh_token": raw_refresh,
            "scope": " ".join(sorted(scope.key for scope in scopes)),
        }

    def _refresh_token_grant(self, request):
        client = self._authenticate_client(request)

        raw_token = request.POST.get("refresh_token")
        if not raw_token:
            raise TokenError("invalid_request", "refresh_token is required.")

        token_hash = RefreshToken.hash_token(raw_token)

        with transaction.atomic():
            old_token = (
                RefreshToken.objects.select_for_update()
                .filter(token_hash=token_hash, client=client)
                .first()
            )

            if not old_token:
                raise TokenError("invalid_grant", "Refresh token not recognized for this client.")

            if old_token.is_revoked():
                _revoke_chain(old_token)
                raise TokenError("invalid_grant", "This refresh token is no longer valid.")

            if old_token.is_expired():
                raise TokenError("invalid_grant", "Refresh token has expired.")

            scopes = list(old_token.scopes.all())
            new_token, raw_new = _create_refresh_token(client, old_token.user, scopes, rotated_from=old_token)

            old_token.revoked_at = timezone.now()
            old_token.save(update_fields=["revoked_at"])

        access_token = issue_access_token(old_token.user, client, scopes)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.OAUTH_ACCESS_TOKEN_LIFETIME,
            "refresh_token": raw_new,
            "scope": " ".join(sorted(scope.key for scope in scopes))
        }
