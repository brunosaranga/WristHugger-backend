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
USERNAME = "admin"
PASSWORD = "changeme"
CLIENT_ID = "PASTE_CLIENT_ID_HERE"
CLIENT_SECRET = "PASTE_CLIENT_SECRET_HERE"
REDIRECT_URI = "http://127.0.0.1:8000/callback"

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

def login(session):
    session.get(f"{BASE_URL}/admin/login") # sets the csrf token cookie
    response = session.post(
        f"{BASE_URL}/admin/login",
        data={"username": USERNAME, "password": PASSWORD, "next": "/admin"},
        headers=csrf_header(session)
    )
    if "errornote" in response.text or response.url.endswith("/login"):
        raise SystemExit("Login failed - check USERNAME/PASSWORD at the top of this script.")
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

    consent_page = session.get(f"{BASE_URL}/authorize/", params=params)
    if consent_page.status_code != 200:
        raise SystemExit(f"GET /authorize/ failed: {consent_page.status_code} {consent_page.text[:300]}")
    log("Consent screen rendered", f"status {consent_page.status_code}")

    approve = session.post(
        f"{BASE_URL}/authorize/",
        data={**params, "decision": "approve"},
        headers=csrf_header(session),
        allow_redirects=False,
    )
    location = approve.headers.get("Location")
    if not location:
        raise SystemExit(f"POST /authorize/ did not redirect: {approve.status_code} {approve.text[:300]}")

    query = parse_qs(urlparse(location).query)
    if "error" in query:
        raise SystemExit(f"Authorization denied: {query}")

    code = query["code"][0]
    log("Authorization code issued", code)
    return code


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
    payload = response.json()
    if response.status_code != 200:
        raise SystemExit(f"Tpken exchange failed: {payload}")
    log