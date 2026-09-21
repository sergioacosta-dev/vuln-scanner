import base64
import pytest
from app import create_app


@pytest.fixture
def authed_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("AUTH_USER", "admin")
    monkeypatch.setenv("AUTH_PASSWORD", "correct-horse")
    app = create_app(testing=False)
    with app.test_client() as c:
        yield c


def _basic_auth_header(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_no_credentials_returns_401(authed_client):
    resp = authed_client.get("/")
    assert resp.status_code == 401


def test_wrong_password_returns_401(authed_client):
    resp = authed_client.get("/", headers=_basic_auth_header("admin", "wrong"))
    assert resp.status_code == 401


def test_wrong_username_returns_401(authed_client):
    resp = authed_client.get("/", headers=_basic_auth_header("someoneelse", "correct-horse"))
    assert resp.status_code == 401


def test_correct_credentials_returns_200(authed_client):
    resp = authed_client.get("/", headers=_basic_auth_header("admin", "correct-horse"))
    assert resp.status_code == 200
