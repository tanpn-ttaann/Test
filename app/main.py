"""Minimal FastAPI authentication API.

Bearer tokens are random opaque strings. Only SHA-256 digests are persisted.
Passwords are PBKDF2-HMAC-SHA256 hashes with per-user random salts.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Authentication Starter", version="0.1.0")
ITERATIONS = 600_000
SESSION_SECONDS = 60 * 60
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def database_path() -> str:
    return os.environ.get("AUTH_DB_PATH", "data/auth.sqlite3")


@contextmanager
def db():
    path = database_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        )""")
        yield connection
        connection.commit()
    finally:
        connection.close()


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    ).hex()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = SESSION_SECONDS


def normalized_email(email: str) -> str:
    value = email.strip().lower()
    if not EMAIL_RE.fullmatch(value):
        raise HTTPException(status_code=422, detail="Invalid email")
    return value


def issue_token(connection: sqlite3.Connection, user_id: int) -> TokenResponse:
    token = secrets.token_urlsafe(32)
    connection.execute(
        "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES(?, ?, ?)",
        (token_digest(token), user_id, int(time.time()) + SESSION_SECONDS),
    )
    return TokenResponse(access_token=token)


def current_user(authorization: str | None = Header(default=None)) -> dict:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 256:
        raise HTTPException(status_code=401, detail="Invalid bearer token")
    try:
        digest = token_digest(token)
    except UnicodeEncodeError:
        raise HTTPException(status_code=401, detail="Invalid bearer token") from None
    with db() as connection:
        row = connection.execute(
            """SELECT users.id, users.email FROM sessions
               JOIN users ON users.id = sessions.user_id
               WHERE token_hash = ? AND expires_at > ?""",
            (digest, int(time.time())),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"id": row["id"], "email": row["email"]}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(credentials: Credentials):
    email = normalized_email(credentials.email)
    salt = secrets.token_bytes(16)
    digest = hash_password(credentials.password, salt)
    with db() as connection:
        try:
            connection.execute(
                "INSERT INTO users(email, salt, password_hash) VALUES(?, ?, ?)",
                (email, salt.hex(), digest),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Account already exists") from None
    return {"message": "Account created"}


@app.post("/auth/login", response_model=TokenResponse)
def login(credentials: Credentials):
    email = normalized_email(credentials.email)
    with db() as connection:
        row = connection.execute(
            "SELECT id, salt, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()
        # Compute a hash even for absent accounts to reduce timing differences.
        salt = bytes.fromhex(row["salt"]) if row else bytes(16)
        expected = row["password_hash"] if row else "0" * 64
        valid = hmac.compare_digest(hash_password(credentials.password, salt), expected)
        if not row or not valid:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return issue_token(connection, row["id"])


@app.get("/auth/me")
def me(user: dict = Depends(current_user)):
    return user


@app.post("/auth/logout")
def logout(authorization: str | None = Header(default=None), user: dict = Depends(current_user)):
    token = (authorization or "").partition(" ")[2]
    with db() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
    return {"message": "Logged out"}
