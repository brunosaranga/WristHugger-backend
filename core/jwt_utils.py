import time
import uuid
from pathlib import Path

import jwt
from django.conf import settings

def _read_key(path):
    return Path(path).read_text()

def load_private_key():
    return _read_key(settings.OAUTH_PRIVATE_KEY_PATH)

def load_public_key():
    return _read_key(settings.OAUTH_PUBLIC_KEY_PATH)

def issue_access_token(user, client, scopes):
    now = int(time.time())
    payload = {
        "iss": settings.OAUTH_ISSUER,
        "sub": str(user.pk),
        "client_id": client.client_id,
        "scope": " ".join(sorted(scope.key for scope in scopes)),
        "iat": now,
        "exp": now + settings.OAUTH_ACCESS_TOKEN_LIFETIME,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, load_private_key(), algorithm="RS256")

def decode_access_token(token):
    """
    For a resource server (or a protected endpoint on this server) to verify a token. The algorithm is pinned explicitly here, never read from the tokein;s own header - that's what closes the classic alg=none downgrade attack.
    """
    return jwt.decode(token, load_public_key(), algorithms=["RS256"], issuer=settings.OAUTH_ISSUER)