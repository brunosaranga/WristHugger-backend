"""
End-to-end smoke test for the WristHugger Oauth2 flow.

Logs in, generates a real PKCE pair, gets an authorization code, exchanges it for tokens, calls the protected resource, refreshes, then deliberately tries to break two things to prove the design holds: replaying the spent code, and reusing the rotated refresh token.

Fill in the constants below, then run:
    pipenv run python scripts/test_oauth_flow.py
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import requests

BASE_URL = "http://127.0.0.1:8000"
USERNAME = "admin"              # a superuser you can log in as
PASSWORD = "1imeIs VanGogh*"           # its password
CLIENT_ID = "Hab6QmaYjqp5SoL0b5bdoZ1Uqtl5Ruwe"
CLIENT_SECRET = "plJtaqiYB8V27wq6jl0BRELg6vDCTeqrcBctgK851bg"
REDIRECT_URI = "http://127.0.0.1:8000/callback"
SCOPES = ""                     # space-separated scope keys, or leave blank

def log(step, detail=""):
    print(f"\n--- {step} " + "-" * max(0, 50 - len(step)))
    if detail:
        print(detail)


def csrf_header(session):
    return {"X-CSRFToken": session.cookies.get("csrftoken", "")}


def make_pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge

# def login(session):
#     session.get(f"{BASE_URL}/admin/login") # sets the csrf token cookie
#     response = session.post(
#         f"{BASE_URL}/admin/login",
#         data={"username": USERNAME, "password": PASSWORD, "next": "/admin"},
#         headers=csrf_header(session)
#     )
#     if "errornote" in response.text or response.url.endswith("/login"):
#         raise SystemExit("Login failed - check USERNAME/PASSWORD at the top of this script.")
#     log("Logged in", f"as {USERNAME}")


def login(session):
    session.get(f"{BASE_URL}/login/")  # sets the csrf token cookie
    response = session.post(
        f"{BASE_URL}/login/",
        data={"username": USERNAME, "password": PASSWORD},
        headers=csrf_header(session),
    )

    if response.status_code == 200 and "didn't match" in response.text:
        raise SystemExit(
            "Login failed: form rejected the username/password. "
            "Double check USERNAME/PASSWORD at the top of this script match a real user."
        )
    if response.url.rstrip("/").endswith("/login"):
        raise SystemExit(
            f"Login didn't redirect away from the login page (status {response.status_code}, "
            f"final URL {response.url}).\nFirst 300 chars of response:\n{response.text[:300]}"
        )

    log("Logged in", f"as {USERNAME}")


def get_authorization_code(session, challenge):
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "smoke-test-state",
        "scope": SCOPES,
    }

    # allow_redirects=False on purpose: if this client+scope combo was
    # already approved in an earlier run, /authorize skips consent and
    # redirects straight to a code. Letting requests follow that
    # automatically would try to GET the client's own callback page,
    # which this server was never meant to serve.
    first = session.get(f"{BASE_URL}/authorize/", params=params, allow_redirects=False)

    if first.status_code == 302:
        code = _extract_code(first, "GET /authorize/")
        log("Authorization code issued (consent already on file)", code)
        return code

    if first.status_code != 200:
        raise SystemExit(f"GET /authorize/ failed: {first.status_code} {first.text[:300]}")
    log("Consent screen rendered", f"status {first.status_code}")

    approve = session.post(
        f"{BASE_URL}/authorize/",
        data={**params, "decision": "approve"},
        headers=csrf_header(session),
        allow_redirects=False,
    )
    code = _extract_code(approve, "POST /authorize/")
    log("Authorization code issued", code)
    return code


def _extract_code(response, label):
    location = response.headers.get("Location")
    if not location:
        raise SystemExit(f"{label} did not redirect: {response.status_code} {response.text[:300]}")

    query = parse_qs(urlparse(location).query)
    if "error" in query:
        raise SystemExit(f"Authorization denied: {query}")

    return query["code"][0]


def exchange_code(session, code, verifier):
    response = session.post(
        f"{BASE_URL}/token/",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    # payload = response.json()
    if not response.text:
        raise SystemExit(f"POST /token/ returned an empty body. Status: {response.status_code}")
    try:
        payload = response.json()
    except:
        raise SystemExit(f"POST /token/ returned non-JSON. Status: {response.status_code}\nBody:\n{response.text[:500]}")

    if response.status_code != 200:
        raise SystemExit(f"Tpken exchange failed: {payload}")
    log("Tokens issued", f"access_token expires in {payload['expires_in']}s")
    return payload


def call_protected_resource(access_token, label):
    response = requests.get(f"{BASE_URL}/api/me", headers={"Authorization": f"Bearer {access_token}"})
    log(label, f"{response.status_code} {response.json()}")


def refresh(session, refresh_token):
    response = session.post(
        f"{BASE_URL}/token/",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    payload = response.json()
    log("Refresh_grant", f"{response.status_code} {payload}")
    return payload



def main():
    session = requests.Session()
    login(session)

    verifier, challenge = make_pkce_pair()
    code = get_authorization_code(session, challenge)
    tokens = exchange_code(session, code, verifier)

    call_protected_resource(tokens["access_token"], "Resouce call with fresh access token")

    refreshed = refresh(session, tokens["refresh_token"])
    call_protected_resource(refreshed["access_token"], "Resource call after refresh")

    log("Replaying the original authorization code (should fail)")
    replay = session.post(
        f"{BASE_URL}/token/",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    log("Replay result", f"{replay.status_code} {replay.json()}")

    log("Reusing the original, now-rotated refresh token (should fail)")
    refresh(session, tokens["refresh_token"])

if __name__ == "__main__":
    main()