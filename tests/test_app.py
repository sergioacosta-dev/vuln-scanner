import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app(testing=True)
    with app.test_client() as c:
        yield c

def test_home_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200

def test_findings_returns_200(client):
    resp = client.get("/findings")
    assert resp.status_code == 200

def test_targets_returns_200(client):
    resp = client.get("/targets")
    assert resp.status_code == 200

def test_history_returns_200(client):
    resp = client.get("/history")
    assert resp.status_code == 200

def test_add_target_redirects(client):
    resp = client.post("/targets", data={"host": "10.0.0.1", "ports": "80,443"})
    assert resp.status_code == 302

def test_manual_scan_without_target_id_redirects(client):
    resp = client.post("/scan")
    assert resp.status_code == 302