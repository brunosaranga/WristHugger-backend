import jwt
from django.http import JsonResponse
from django.views import View

from .jwt_utils import decode_access_token


class ProtectedResourceView(View):
    """
    Stands in for a resource server. Verifies the token's signature itself, with no call back to the authorization server at all - that's the whole point of the design.
    """

    def get(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Bearer "):
            return JsonResponse(
                {"error": "invalid_token", "error_description": "Missing bearer token."}, status=401
            )

        token = auth_header[len("Bearer "):]

        try:
            claims = decode_access_token(token)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "invalid_token", "error_description": "Token has expired."}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"error": "invalid_token", "error_description": "Token signature is invalid."}, status=401
            )

        return JsonResponse(
            {
                "message": "Access granted without ever calling the authorization server.",
                "user_id": claims["sub"],
                "client_id": claims["client_id"],
                "scope": claims["scope"],
                "issued_at": claims["iat"],
                "expires_at": claims["exp"],
            }
        )