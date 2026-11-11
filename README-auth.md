# Authentication starter

A small FastAPI + SQLite authentication API. This repository was previously a README-only scaffold. The implementation is in `app/main.py`.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Visit http://127.0.0.1:8000/docs for interactive API documentation. SQLite is created at `data/auth.sqlite3` on first request. Set `AUTH_DB_PATH` in the environment to override. The example .env file is not loaded automatically.

## API request flow

1. `POST /auth/register` with JSON `{"email":"user@example.com","password":"a-long-password"}` creates an account.
2. `POST /auth/login` with the same JSON checks the salted password hash and returns `{"access_token":"...","token_type":"bearer","expires_in":3600}`.
3. For `GET /auth/me`, send `Authorization: Bearer <access_token>`. The API hashes the presented token and looks up a non-expired session in SQLite.
4. `POST /auth/logout` with the same Authorization header deletes that session, invalidating the token. Expired sessions are rejected; cleanup can be scheduled separately.

## Components and credential handling

- `Credentials`, `TokenResponse`: input/output schemas, defined in `app/main.py`.
- `register`, `login`, `me`, `logout`: HTTP endpoints.
- `current_user`: protected-route dependency enforcing bearer token authentication.
- `db`: SQLite setup and connection context; `users` and `sessions` tables.
- Passwords are **never stored as plaintext**. Each account uses a random 16-byte salt and PBKDF2-HMAC-SHA256 with 600,000 iterations.
- Tokens are 32 cryptographically random bytes encoded URL-safe, **not JWTs**. The client receives the original token once; the server stores only its SHA-256 digest, user ID and expiry.
- Tokens expire after 1 hour. There is no refresh-token feature and no browser-cookie handling. Clients must keep tokens confidential, avoid putting them into URLs or logs, and discard them on logout.
- No real credentials, tokens, or secrets are committed to Git. Local databases and .env files are ignored.

## Test

```bash
pytest -q
```

## Production checklist

This is a starter, **not production-ready**. Before exposing it publicly: enforce HTTPS; implement per-IP/account rate limits and login abuse protection; add email verification, password reset and recovery; add logging with credential/token redaction; use migrations and a production database; configure CORS deliberately; consider Argon2id for password hashing; implement token cleanup/rotation, account/session management and monitoring. For browser apps, evaluate secure HttpOnly/SameSite cookies plus CSRF protection rather than storing bearer tokens in localStorage.
