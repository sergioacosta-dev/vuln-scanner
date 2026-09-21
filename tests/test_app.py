import pytest
from app import create_app, run_target_scan

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


def test_manual_scan_with_non_numeric_target_id_redirects(client):
    resp = client.post("/scan", data={"target_id": "not-a-number"})
    assert resp.status_code == 302


def test_run_target_scan_rejects_target_no_longer_private(client):
    # Simulates DNS-rebinding: the target was private/loopback when added,
    # but no longer resolves that way by the time a scan actually runs.
    client.get("/")  # forces get_db() to initialize the in-memory test DB
    conn = client.application._test_db
    target = {"id": 1, "host": "8.8.8.8", "ports": "80"}
    status, findings, error = run_target_scan(conn, target)
    assert status == "rejected"
    assert findings == []