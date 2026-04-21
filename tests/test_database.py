import sqlite3
import pytest
from database import (
    init_db, add_target, get_targets, delete_target,
    add_scan, update_scan, add_finding, get_findings,
    get_scan_history, resolve_finding
)

@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    yield conn
    conn.close()

def test_init_db_creates_tables(db):
    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    names = [t["name"] for t in tables]
    assert "targets" in names
    assert "scans" in names
    assert "findings" in names

def test_add_and_get_target(db):
    add_target(db, "192.168.1.1", "22,80")
    targets = get_targets(db)
    assert len(targets) == 1
    assert targets[0]["host"] == "192.168.1.1"
    assert targets[0]["ports"] == "22,80"
    assert targets[0]["enabled"] == 1

def test_delete_target(db):
    add_target(db, "10.0.0.1", "443")
    target_id = get_targets(db)[0]["id"]
    delete_target(db, target_id)
    assert get_targets(db) == []

def test_add_scan_and_update_status(db):
    add_target(db, "10.0.0.1", "80")
    target_id = get_targets(db)[0]["id"]
    scan_id = add_scan(db, target_id)
    update_scan(db, scan_id, "done")
    history = get_scan_history(db)
    assert len(history) == 1
    assert history[0]["status"] == "done"

def test_add_finding_returns_true_for_new(db):
    add_target(db, "10.0.0.1", "80")
    target_id = get_targets(db)[0]["id"]
    scan_id = add_scan(db, target_id)
    is_new = add_finding(db, scan_id, target_id, 80, "http-vuln-test", "VULNERABLE", "high")
    assert is_new is True

def test_add_finding_returns_false_for_duplicate(db):
    add_target(db, "10.0.0.1", "80")
    target_id = get_targets(db)[0]["id"]
    scan_id = add_scan(db, target_id)
    add_finding(db, scan_id, target_id, 80, "http-vuln-test", "VULNERABLE", "high")
    scan_id2 = add_scan(db, target_id)
    is_new = add_finding(db, scan_id2, target_id, 80, "http-vuln-test", "VULNERABLE", "high")
    assert is_new is False

def test_get_findings_returns_active(db):
    add_target(db, "10.0.0.1", "80")
    target_id = get_targets(db)[0]["id"]
    scan_id = add_scan(db, target_id)
    add_finding(db, scan_id, target_id, 80, "http-vuln-cve2017-5638", "VULNERABLE: CVE-2017-5638", "high")
    findings = get_findings(db)
    assert len(findings) == 1
    assert findings[0]["script_name"] == "http-vuln-cve2017-5638"

def test_resolve_finding(db):
    add_target(db, "10.0.0.1", "80")
    target_id = get_targets(db)[0]["id"]
    scan_id = add_scan(db, target_id)
    add_finding(db, scan_id, target_id, 80, "test-script", "output", "info")
    finding_id = get_findings(db)[0]["id"]
    resolve_finding(db, finding_id)
    assert get_findings(db) == []