# WristHugger — progress log

## Status: backend v1 done

Every core flow has been run end to end against a live server and verified,
not just reviewed by reading the code: login, consent, PKCE-protected code
issuance, token exchange, resource access, refresh rotation, and both
replay-attack rejections. Two known limitations remain, named below rather
than left silent.

## What this is

WristHugger is an OAuth2 authorization server built from primitives in
Django, not wrapped around an existing OAuth library. The point isn't to
reinvent OAuth2 for production use — it's a portfolio project that proves
out real understanding of the protocol: token issuance, PKCE, replay
protection, consent, and the specific security failure modes each of those
pieces prevents. Scoped deliberately smaller than Shovl: no frontend to
speak of, no payments, no scan engine. The whole surface area is protocol
correctness.

The mental model driving the design: a front desk (this server) checks your
ID once, then hands your app a signed card (a JWT) instead of your
password. Any vault (resource server) can check that card itself, since
it's self-verifying, without ever calling the front desk back.

## Models

Five models, deliberately no sixth:

- **`Client`** — a registered app. Public or confidential. Confidential
  clients get a secret, hashed with PBKDF2 (`set_client_secret` /
  `check_client_secret`) — never stored or displayed in plaintext after
  registration.
- **`Scope`** — one requestable permission, with a plain-language
  `description` used to render the consent screen (so a client can never
  supply its own consent-screen copy).
- **`AuthorizationCode`** — short-lived (1 minute), single-use. Stores the
  PKCE `code_challenge`. `used_at` is a timestamp, not a boolean — a second
  redemption attempt is a replay signal, not just a rejected request.
  `issued_refresh_token` links to what it produced, so a replay can revoke
  what was already issued.
- **`RefreshToken`** — long-lived. Stored as a SHA-256 hash. `rotated_from`
  links each refresh to the one it replaced, so reuse detection has a chain
  to walk and revoke forward through.
- **`Consent`** — what a user has already approved for a client, so
  `/authorize` can skip re-prompting when the requested scopes are already
  covered.

No `AccessToken` table — access tokens are JWTs, verified by signature, not
looked up.

## Client registration (`RegisterClientView`)

A `CreateView` that overrides `form_valid()` to render the result directly
instead of redirecting. The raw client secret exists in exactly one HTTP
response, generated with `secrets.token_urlsafe(32)`, hashed before
`client.save()`, and never logged, sessioned, or retrievable again after
that page loads. Verified end to end against the database.

## Login (`LoginView` / `LogoutView`)

Django's built-in class-based auth views, pointed at a custom template.
`LOGIN_URL` is what `LoginRequiredMixin` reads when `/authorize` finds no
session — this is what makes the whole flow usable by a real user rather
than only by an admin-session workaround.

## `/authorize` endpoint (`AuthorizeView`)

Handles both halves of the authorization request:

- **GET** — validates `client_id` and `redirect_uri`, then either renders
  the consent screen or skips straight to issuing a code if the user has
  already granted every requested scope.
- **POST** — on approval, records a `Consent` and issues the
  `AuthorizationCode`. On denial, redirects back with `error=access_denied`.

`client_id` and `redirect_uri` are checked *first*, before anything else,
and only once that redirect URI is confirmed to belong to the registered
client does the endpoint trust it enough to redirect errors there. A bad
`redirect_uri` gets a plain error page instead — never a redirect — because
redirecting somewhere unverified is exactly the open-redirect vulnerability
this check exists to close.

PKCE (`code_challenge` + `S256`) is required unconditionally for every
client, confidential or public.

## `/token` endpoint (`TokenView`)

Handles both grant types, each inside a `select_for_update()` transaction to
close the race window on double-redemption:

- **`authorization_code`** — verifies the submitted `code_verifier` against
  the stored `code_challenge`, issues a signed access token and a refresh
  token, marks the code used.
- **`refresh_token`** — rotates: issues a new refresh token, revokes the
  old one, links them via `rotated_from`.

Reuse of a spent code or an already-rotated refresh token is treated as a
compromise signal, not just a rejected request — `_revoke_chain` walks
forward through every descendant token and kills the whole chain, not just
the one that was replayed.

## JWT signing (`jwt_utils.py`)

RS256, so any resource server can verify a token with the public key alone,
no callback to this server. The algorithm is pinned explicitly on decode,
never read from the token's own header — that's what closes the classic
`alg=none` downgrade attack.

## Resource server (`ProtectedResourceView`)

A small `/api/me/` endpoint standing in for a real resource server. Verifies
a bearer token's signature itself, with zero calls back to the
authorization server — the actual payoff of the whole design.

## Verified end to end, in one live run

- Registration → login → consent → code issuance → token exchange, all
  working together in a single pass, not just individually
- Resource call with a fresh access token succeeds
- Refresh grant issues a genuinely new access token and refresh token, not
  a reissue of the old ones
- Resource call after refresh succeeds with the new token
- Replaying the original authorization code is rejected: `invalid_grant`
- Reusing the original, now-rotated refresh token is rejected:
  `invalid_grant`, "no longer valid" — the actual replay-detection design
  firing for real, not just reachable in code

## Known limitations (named on purpose, not fixed in v1)

- **No gatekeeping on client registration.** Any logged-in user can
  currently register a `Client`. Fine while testing solo; would need an
  `is_staff` check or an approval step before this saw any other traffic.
- **The resource server checks signature validity but not scope.** Any
  valid access token can currently call `/api/me/` regardless of what
  scopes it actually carries. A real resource server would check the
  token's `scope` claim contains what that specific endpoint requires.

## Design decisions worth calling out in an interview

- Hashed client secrets and hashed refresh tokens, with different hashing
  strategies for each and a stated reason why (slow hash for a
  human-influenced secret, fast hash for an already-random token).
- Authorization codes are both time-limited and single-use, with the
  double-use case treated as a security event rather than a plain error.
- The `/authorize` endpoint never redirects to an unverified destination,
  even to report an error.
- PKCE required for every client type, not just public ones.
- Replay of a spent code or a rotated refresh token revokes the whole
  downstream chain, not just the single request.

## Not yet built (beyond the two limitations above)

- A demo client app (something that actually plays the "App" role from the
  mental model, rather than the test script standing in for it)
- Automated tests (`core/tests.py` is still empty) — the manual script
  proves the flow works once, interactively; real `pytest`/Django test
  cases covering PKCE mismatch, expired codes, and replay chains would be a
  stronger artifact than a script transcript
- Deployment anywhere beyond localhost
