import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.sqlite3"))
    with TestClient(app) as api:
        yield api


def test_register_login_me_logout(client):
    payload = {"email": "Example@Example.com", "password": "correct horse battery staple"}
    assert client.post("/auth/register", json=payload).status_code == 201
    assert client.post("/auth/register", json=payload).status_code == 409
    bad = {**payload, "password": "another-wrong-password"}
    assert client.post("/auth/login", json=bad).status_code == 401
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 200
    token = response.json()["access_token"]
    header = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers=header).json()["email"] == "example@example.com"
    assert client.post("/auth/logout", headers=header).status_code == 200
    assert client.get("/auth/me", headers=header).status_code == 401


def test_validation(client):
    assert client.post("/auth/register", json={
        "email": "not-email", "password": "long-enough-password"
    }).status_code == 422
    assert client.post("/auth/register", json={
        "email": "a@b.co", "password": "short"
    }).status_code == 422
