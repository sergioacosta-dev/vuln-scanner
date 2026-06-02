# Vuln Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone Flask web app that scans configured network targets with Nmap NSE vulnerability scripts, stores results in SQLite, displays findings on a dashboard, and sends email + desktop notifications when new vulnerabilities are discovered.

**Architecture:** Flask app with four modules (database, scanner, notifier, scheduler) wired together. APScheduler runs scans in the background every 6 hours; new findings trigger Gmail email + Windows desktop alerts. All state stored in SQLite.

**Tech Stack:** Python 3, Flask, python-nmap, APScheduler, plyer, python-dotenv, sqlite3 (stdlib), smtplib (stdlib), pytest

---

## File Map

| File | Responsibility |
|---|---|
| `database.py` | SQLite schema + all query functions |
| `scanner.py` | Nmap NSE wrapper, output parsing, severity inference |
| `notifier.py` | Gmail SMTP email + plyer desktop notification |
| `scheduler.py` | APScheduler setup, scan job orchestration |
| `app.py` | Flask routes, wires all modules together |
| `templates/base.html` | Shared nav layout |
| `templates/index.html` | Home summary cards + recent scans |
| `templates/findings.html` | Active findings table with resolve button |
| `templates/targets.html` | Add/remove targets + manual scan trigger |
| `templates/history.html` | Scan history list |
| `tests/test_database.py` | Database layer unit tests |
| `tests/test_scanner.py` | Scanner parsing unit tests |
| `tests/test_notifier.py` | Notifier dry-run unit tests |
| `tests/test_app.py` | Flask route tests |
| `.env` | Credentials — never committed |
| `.gitignore` | Excludes .env, venv, *.db, __pycache__ |
| `requirements.txt` | Pinned dependencies |

---

### Task 1: Project setup

**Files:**
- Create: `F:/IT_Proj/vuln-scanner/` (new directory)
- Create: `F:/IT_Proj/vuln-scanner/.gitignore`
- Create: `F:/IT_Proj/vuln-scanner/.env`
- Create: `F:/IT_Proj/vuln-scanner/requirements.txt`

- [x] **Step 1: Verify nmap is installed**

```bash
nmap --version
```
Expected: `Nmap 7.x` or similar. If not found, download from https://nmap.org/download.html and install before continuing.

- [x] **Step 2: Create project directory**

Run from `F:/IT_Proj/`:
```bash
mkdir vuln-scanner && cd vuln-scanner
```

- [x] **Step 3: Create and activate virtual environment**

```bash
python -m venv venv
source venv/Scripts/activate
```
Expected: prompt changes to show `(venv)` prefix.

- [x] **Step 4: Install dependencies**

```bash
pip install flask python-nmap apscheduler plyer python-dotenv pytest
```

- [x] **Step 5: Save requirements.txt**

```bash
pip freeze > requirements.txt
```

- [x] **Step 6: Create .gitignore**

Create `F:/IT_Proj/vuln-scanner/.gitignore`:
```
venv/
.env
*.db
__pycache__/
*.pyc
*.log
```

- [x] **Step 7: Create .env**

Create `F:/IT_Proj/vuln-scanner/.env`:
```
GMAIL_USER=your_email@gmail.com
GMAIL_APP_PASSWORD=your_app_password_here
NOTIFY_EMAIL=your_email@gmail.com
SCAN_INTERVAL_HOURS=6
```

- [x] **Step 8: Initialize git and commit**

```bash
git init
git add .gitignore requirements.txt
git commit -m "feat: project setup with dependencies"
```

---

### Task 2: Database layer

**Files:**
- Create: `database.py`
- Create: `tests/__init__.py`
- Create: `tests/test_database.py`

- [x] **Step 1: Create tests/test_database.py**

```bash
mkdir tests && touch tests/__init__.py
```

Create `tests/test_database.py`:
```python
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
```

- [x] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_database.py -v
```
Expected: all tests FAIL with `ModuleNotFoundError: No module named 'database'`

- [x] **Step 3: Create database.py**

Create `database.py`:
```python
import sqlite3
from datetime import datetime

DB_PATH = "vuln_scanner.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn=None):
    close = conn is None
    if conn is None:
        conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            ports TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            finished_at DATETIME,
            status TEXT NOT NULL DEFAULT 'running',
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            script_name TEXT NOT NULL,
            output TEXT NOT NULL,
            severity TEXT NOT NULL,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
    """)
    conn.commit()
    if close:
        conn.close()

def add_target(conn, host, ports):
    conn.execute("INSERT INTO targets (host, ports) VALUES (?, ?)", (host, ports))
    conn.commit()

def get_targets(conn):
    return conn.execute(
        "SELECT * FROM targets WHERE enabled=1 ORDER BY created_at DESC"
    ).fetchall()

def delete_target(conn, target_id):
    conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
    conn.commit()

def add_scan(conn, target_id):
    cur = conn.execute("INSERT INTO scans (target_id) VALUES (?)", (target_id,))
    conn.commit()
    return cur.lastrowid

def update_scan(conn, scan_id, status):
    conn.execute(
        "UPDATE scans SET status=?, finished_at=? WHERE id=?",
        (status, datetime.now().isoformat(), scan_id)
    )
    conn.commit()

def add_finding(conn, scan_id, target_id, port, script_name, output, severity):
    existing = conn.execute(
        "SELECT id FROM findings WHERE target_id=? AND port=? AND script_name=? AND resolved=0",
        (target_id, port, script_name)
    ).fetchone()
    if existing:
        return False
    conn.execute(
        "INSERT INTO findings (scan_id, target_id, port, script_name, output, severity) VALUES (?,?,?,?,?,?)",
        (scan_id, target_id, port, script_name, output, severity)
    )
    conn.commit()
    return True

def get_findings(conn, resolved=False):
    return conn.execute(
        """SELECT f.*, t.host
           FROM findings f
           JOIN targets t ON f.target_id=t.id
           WHERE f.resolved=?
           ORDER BY f.first_seen DESC""",
        (1 if resolved else 0,)
    ).fetchall()

def get_scan_history(conn):
    return conn.execute(
        """SELECT s.*, t.host,
           (SELECT COUNT(*) FROM findings WHERE scan_id=s.id) AS finding_count
           FROM scans s
           JOIN targets t ON s.target_id=t.id
           ORDER BY s.started_at DESC"""
    ).fetchall()

def resolve_finding(conn, finding_id):
    conn.execute("UPDATE findings SET resolved=1 WHERE id=?", (finding_id,))
    conn.commit()
```

- [x] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_database.py -v
```
Expected: all 8 tests PASS.

- [x] **Step 5: Commit**

```bash
git add database.py tests/
git commit -m "feat: database layer with targets, scans, findings tables"
```

---

### Task 3: Scanner

**Files:**
- Create: `scanner.py`
- Create: `tests/test_scanner.py`

- [x] **Step 1: Create tests/test_scanner.py**

Create `tests/test_scanner.py`:
```python
from scanner import infer_severity, parse_nmap_results

def test_infer_severity_high():
    assert infer_severity("VULNERABLE: some exploit found") == "high"

def test_infer_severity_medium():
    assert infer_severity("references: CVE-2021-12345") == "medium"

def test_infer_severity_info():
    assert infer_severity("State: open | filtered") == "info"

def test_parse_nmap_results_extracts_findings():
    fake_scan = {
        "192.168.1.1": {
            "tcp": {
                80: {
                    "script": {
                        "http-vuln-cve2017-5638": "VULNERABLE: Apache Struts RCE\nReferences: CVE-2017-5638"
                    }
                },
                22: {"script": {}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, "192.168.1.1")
    assert len(findings) == 1
    assert findings[0]["port"] == 80
    assert findings[0]["script_name"] == "http-vuln-cve2017-5638"
    assert findings[0]["severity"] == "high"

def test_parse_nmap_results_empty_scripts():
    fake_scan = {
        "10.0.0.1": {
            "tcp": {
                443: {"script": {}}
            }
        }
    }
    findings = parse_nmap_results(fake_scan, "10.0.0.1")
    assert findings == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_scanner.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner'`

- [x] **Step 3: Create scanner.py**

Create `scanner.py`:
```python
import nmap

def infer_severity(output):
    upper = output.upper()
    if "VULNERABLE" in upper:
        return "high"
    if "CVE-" in upper:
        return "medium"
    return "info"

def parse_nmap_results(scan_data, host):
    findings = []
    host_data = scan_data.get(host, {})
    for proto in ("tcp", "udp"):
        for port, port_data in host_data.get(proto, {}).items():
            for script_name, output in port_data.get("script", {}).items():
                findings.append({
                    "port": port,
                    "script_name": script_name,
                    "output": output,
                    "severity": infer_severity(output)
                })
    return findings

def run_scan(host, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=ports, arguments="--script vuln -sV")
    return parse_nmap_results(nm._scan_result.get("scan", {}), host)
```

- [x] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_scanner.py -v
```
Expected: all 5 tests PASS.

- [x] **Step 5: Commit**

```bash
git add scanner.py tests/test_scanner.py
git commit -m "feat: nmap NSE scanner with severity inference"
```

---

### Task 4: Notifier

**Files:**
- Create: `notifier.py`
- Create: `tests/test_notifier.py`

- [x] **Step 1: Create tests/test_notifier.py**

Create `tests/test_notifier.py`:
```python
from notifier import build_email_body, notify

def test_build_email_body_contains_key_fields():
    findings = [
        {"host": "192.168.1.1", "port": 80, "script_name": "http-vuln-test", "severity": "high", "output": "VULNERABLE"}
    ]
    body = build_email_body(findings)
    assert "192.168.1.1" in body
    assert "port 80" in body
    assert "http-vuln-test" in body
    assert "high" in body

def test_notify_dry_run_does_not_raise():
    findings = [
        {"host": "10.0.0.1", "port": 22, "script_name": "ssh-test", "severity": "medium", "output": "CVE-2021-0001"}
    ]
    notify(findings, dry_run=True)

def test_notify_empty_findings_does_nothing():
    notify([], dry_run=True)
```

- [x] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_notifier.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'notifier'`

- [x] **Step 3: Create notifier.py**

Create `notifier.py`:
```python
import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

try:
    from plyer import notification as _desktop
    PLYER_AVAILABLE = True
except Exception:
    PLYER_AVAILABLE = False

def build_email_body(findings):
    lines = [f"Vuln Scanner found {len(findings)} new vulnerability(s):\n"]
    for f in findings:
        lines.append(f"  Host:     {f['host']}")
        lines.append(f"  Port:     port {f['port']}")
        lines.append(f"  Script:   {f['script_name']}")
        lines.append(f"  Severity: {f['severity']}")
        lines.append(f"  Output:   {f['output'][:300]}")
        lines.append("")
    return "\n".join(lines)

def send_email(findings):
    user = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_APP_PASSWORD")
    to = os.getenv("NOTIFY_EMAIL")
    if not all([user, password, to]):
        print("[notifier] Email credentials not configured, skipping.")
        return
    msg = EmailMessage()
    msg["Subject"] = f"[Vuln Scanner] {len(findings)} new finding(s) detected"
    msg["From"] = user
    msg["To"] = to
    msg.set_content(build_email_body(findings))
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(user, password)
        smtp.send_message(msg)

def send_desktop(count):
    if not PLYER_AVAILABLE:
        print(f"[notifier] Desktop: {count} new finding(s) detected.")
        return
    _desktop.notify(
        title="Vuln Scanner Alert",
        message=f"{count} new vulnerability(s) detected. Check the dashboard.",
        timeout=10
    )

def notify(findings, dry_run=False):
    if not findings:
        return
    if dry_run:
        print(f"[notifier] dry_run: would notify about {len(findings)} finding(s).")
        return
    send_email(findings)
    send_desktop(len(findings))
```

- [x] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_notifier.py -v
```
Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add notifier.py tests/test_notifier.py
git commit -m "feat: email and desktop notifier with dry_run mode"
```

---

### Task 5: Scheduler

**Files:**
- Create: `scheduler.py`

- [x] **Step 1: Create scheduler.py**

Create `scheduler.py`:
```python
import os
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

load_dotenv()

_scheduler = None

def start(scan_job_fn):
    global _scheduler
    interval_hours = int(os.getenv("SCAN_INTERVAL_HOURS", "6"))
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(scan_job_fn, "interval", hours=interval_hours, id="vuln_scan")
    _scheduler.start()
    print(f"[scheduler] Scan job scheduled every {interval_hours} hour(s).")

def stop():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)

def next_run_time():
    if _scheduler:
        job = _scheduler.get_job("vuln_scan")
        if job and job.next_run_time:
            return job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
    return "not scheduled"
```

- [ ] **Step 2: Verify import works**

```bash
python -c "from scheduler import start, stop, next_run_time; print('scheduler OK')"
```
Expected: `scheduler OK`

- [ ] **Step 3: Commit**

```bash
git add scheduler.py
git commit -m "feat: APScheduler background job for periodic scans"
```

---

### Task 6: Flask app

**Files:**
- Create: `app.py`
- Create: `tests/test_app.py`

- [x] **Step 1: Create tests/test_app.py**

Create `tests/test_app.py`:
```python
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
```

- [x] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_app.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'app'`

- [x] **Step 3: Create app.py**

Create `app.py`:
```python
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from database import (
    init_db, get_connection, add_target, get_targets, delete_target,
    add_scan, update_scan, add_finding, get_findings, get_scan_history, resolve_finding
)
from scanner import run_scan
from notifier import notify
import scheduler


def run_scheduled_scan(app):
    with app.app_context():
        conn = get_connection()
        for target in get_targets(conn):
            scan_id = add_scan(conn, target["id"])
            try:
                raw_findings = run_scan(target["host"], target["ports"])
                new_findings = []
                for f in raw_findings:
                    is_new = add_finding(conn, scan_id, target["id"], f["port"], f["script_name"], f["output"], f["severity"])
                    if is_new:
                        new_findings.append({**f, "host": target["host"]})
                update_scan(conn, scan_id, "done")
                if new_findings:
                    notify(new_findings)
            except Exception as e:
                update_scan(conn, scan_id, "failed")
                print(f"[scheduler] Scan failed for {target['host']}: {e}")


def create_app(testing=False):
    app = Flask(__name__)
    app.secret_key = "vuln-scanner-secret"

    if not testing:
        conn = get_connection()
        init_db(conn)
        conn.close()

    def get_db():
        if testing:
            if not hasattr(app, "_test_db"):
                conn = sqlite3.connect(":memory:")
                conn.row_factory = sqlite3.Row
                init_db(conn)
                app._test_db = conn
            return app._test_db
        return get_connection()

    @app.route("/")
    def index():
        conn = get_db()
        return render_template("index.html",
            target_count=len(get_targets(conn)),
            finding_count=len(get_findings(conn)),
            recent_scans=get_scan_history(conn)[:5],
            next_scan=scheduler.next_run_time()
        )

    @app.route("/findings")
    def findings():
        return render_template("findings.html", findings=get_findings(get_db()))

    @app.route("/targets", methods=["GET", "POST"])
    def targets():
        conn = get_db()
        if request.method == "POST":
            host = request.form.get("host", "").strip()
            ports = request.form.get("ports", "").strip()
            if host and ports:
                add_target(conn, host, ports)
                flash(f"Target {host} added.")
            return redirect(url_for("targets"))
        return render_template("targets.html", targets=get_targets(conn))

    @app.route("/targets/delete/<int:target_id>", methods=["POST"])
    def delete_target_route(target_id):
        delete_target(get_db(), target_id)
        flash("Target removed.")
        return redirect(url_for("targets"))

    @app.route("/history")
    def history():
        return render_template("history.html", scans=get_scan_history(get_db()))

    @app.route("/scan", methods=["POST"])
    def manual_scan():
        conn = get_db()
        target_id = request.form.get("target_id")
        if not target_id:
            flash("No target selected.")
            return redirect(url_for("targets"))
        all_targets = get_targets(conn)
        target = next((t for t in all_targets if t["id"] == int(target_id)), None)
        if not target:
            flash("Target not found.")
            return redirect(url_for("targets"))
        scan_id = add_scan(conn, target["id"])
        try:
            raw_findings = run_scan(target["host"], target["ports"])
            new_findings = []
            for f in raw_findings:
                is_new = add_finding(conn, scan_id, target["id"], f["port"], f["script_name"], f["output"], f["severity"])
                if is_new:
                    new_findings.append({**f, "host": target["host"]})
            update_scan(conn, scan_id, "done")
            if new_findings:
                notify(new_findings)
            flash(f"Scan complete. {len(new_findings)} new finding(s).")
        except Exception as e:
            update_scan(conn, scan_id, "failed")
            flash(f"Scan failed: {e}")
        return redirect(url_for("findings"))

    @app.route("/findings/resolve/<int:finding_id>", methods=["POST"])
    def resolve(finding_id):
        resolve_finding(get_db(), finding_id)
        flash("Finding marked resolved.")
        return redirect(url_for("findings"))

    return app


if __name__ == "__main__":
    app = create_app()
    scheduler.start(lambda: run_scheduled_scan(app))
    app.run(debug=True, use_reloader=False)
```

- [x] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_app.py -v
```
Expected: all 6 tests PASS.

- [x] **Step 5: Commit**

```bash
git add app.py tests/test_app.py
git commit -m "feat: flask app with all routes and manual scan trigger"
```

---

### Task 7: HTML templates

**Files:**
- Create: `templates/base.html`
- Create: `templates/index.html`
- Create: `templates/findings.html`
- Create: `templates/targets.html`
- Create: `templates/history.html`

- [x] **Step 1: Create templates directory**

```bash
mkdir templates
```

- [x] **Step 2: Create templates/base.html**

Create `templates/base.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vuln Scanner</title>
    <style>
        body { font-family: monospace; max-width: 960px; margin: 40px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }
        nav a { margin-right: 20px; color: #58a6ff; text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        h1, h2 { color: #f0f6fc; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px; }
        th, td { padding: 8px 12px; border: 1px solid #30363d; text-align: left; }
        th { background: #161b22; }
        pre { margin: 0; font-size: 11px; max-width: 320px; overflow: auto; white-space: pre-wrap; }
        .high { color: #f85149; font-weight: bold; }
        .medium { color: #e3b341; }
        .info { color: #58a6ff; }
        .card { background: #161b22; border: 1px solid #30363d; padding: 16px 20px; margin: 0 8px 8px 0; display: inline-block; min-width: 160px; border-radius: 6px; vertical-align: top; }
        .card h3 { margin: 0 0 8px 0; font-size: 13px; color: #8b949e; }
        .card p { margin: 0; font-size: 26px; }
        input[type=text] { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; padding: 6px 10px; border-radius: 4px; margin-right: 6px; }
        button, .btn { background: #238636; color: #fff; border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2ea043; }
        .btn-red { background: #b62324; }
        .btn-red:hover { background: #da3633; }
        .flash { background: #1f6feb; color: #fff; padding: 10px 16px; border-radius: 4px; margin-bottom: 16px; }
        hr { border-color: #30363d; margin: 16px 0; }
    </style>
</head>
<body>
    <nav>
        <a href="/">Home</a>
        <a href="/findings">Findings</a>
        <a href="/targets">Targets</a>
        <a href="/history">History</a>
    </nav>
    <hr>
    {% with messages = get_flashed_messages() %}
      {% if messages %}{% for msg in messages %}<div class="flash">{{ msg }}</div>{% endfor %}{% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
</body>
</html>
```

- [x] **Step 3: Create templates/index.html**

Create `templates/index.html`:
```html
{% extends "base.html" %}
{% block content %}
<h1>Vuln Scanner</h1>
<div>
    <div class="card"><h3>Targets</h3><p>{{ target_count }}</p></div>
    <div class="card"><h3>Active Findings</h3><p>{{ finding_count }}</p></div>
    <div class="card"><h3>Next Scan</h3><p style="font-size:14px;margin-top:4px;">{{ next_scan }}</p></div>
</div>
<h2>Recent Scans</h2>
{% if recent_scans %}
<table>
    <tr><th>Host</th><th>Started</th><th>Status</th><th>Findings</th></tr>
    {% for s in recent_scans %}
    <tr>
        <td>{{ s.host }}</td>
        <td>{{ s.started_at }}</td>
        <td>{{ s.status }}</td>
        <td>{{ s.finding_count }}</td>
    </tr>
    {% endfor %}
</table>
{% else %}
<p>No scans yet. Add a target on the <a href="/targets">Targets</a> page and run a scan.</p>
{% endif %}
{% endblock %}
```

- [x] **Step 4: Create templates/findings.html**

Create `templates/findings.html`:
```html
{% extends "base.html" %}
{% block content %}
<h1>Active Findings</h1>
{% if findings %}
<table>
    <tr><th>Host</th><th>Port</th><th>Script</th><th>Severity</th><th>First Seen</th><th>Output</th><th></th></tr>
    {% for f in findings %}
    <tr>
        <td>{{ f.host }}</td>
        <td>{{ f.port }}</td>
        <td>{{ f.script_name }}</td>
        <td class="{{ f.severity }}">{{ f.severity }}</td>
        <td>{{ f.first_seen }}</td>
        <td><pre>{{ f.output[:300] }}</pre></td>
        <td>
            <form method="post" action="/findings/resolve/{{ f.id }}">
                <button class="btn-red" type="submit">Resolve</button>
            </form>
        </td>
    </tr>
    {% endfor %}
</table>
{% else %}
<p>No active findings. Run a scan from the <a href="/targets">Targets</a> page.</p>
{% endif %}
{% endblock %}
```

- [x] **Step 5: Create templates/targets.html**

Create `templates/targets.html`:
```html
{% extends "base.html" %}
{% block content %}
<h1>Targets</h1>
<h2>Add Target</h2>
<form method="post">
    <input type="text" name="host" placeholder="192.168.1.1" required>
    <input type="text" name="ports" placeholder="22,80,443" required>
    <button type="submit">Add</button>
</form>
<h2>Configured Targets</h2>
{% if targets %}
<table>
    <tr><th>Host</th><th>Ports</th><th>Added</th><th>Scan</th><th>Remove</th></tr>
    {% for t in targets %}
    <tr>
        <td>{{ t.host }}</td>
        <td>{{ t.ports }}</td>
        <td>{{ t.created_at }}</td>
        <td>
            <form method="post" action="/scan">
                <input type="hidden" name="target_id" value="{{ t.id }}">
                <button type="submit">Scan Now</button>
            </form>
        </td>
        <td>
            <form method="post" action="/targets/delete/{{ t.id }}">
                <button class="btn-red" type="submit">Delete</button>
            </form>
        </td>
    </tr>
    {% endfor %}
</table>
{% else %}
<p>No targets yet. Add one above.</p>
{% endif %}
{% endblock %}
```

- [x] **Step 6: Create templates/history.html**

Create `templates/history.html`:
```html
{% extends "base.html" %}
{% block content %}
<h1>Scan History</h1>
{% if scans %}
<table>
    <tr><th>Host</th><th>Started</th><th>Finished</th><th>Status</th><th>Findings</th></tr>
    {% for s in scans %}
    <tr>
        <td>{{ s.host }}</td>
        <td>{{ s.started_at }}</td>
        <td>{{ s.finished_at or "—" }}</td>
        <td>{{ s.status }}</td>
        <td>{{ s.finding_count }}</td>
    </tr>
    {% endfor %}
</table>
{% else %}
<p>No scan history yet.</p>
{% endif %}
{% endblock %}
```

- [x] **Step 7: Run full test suite**

```bash
pytest -v
```
Expected: all tests PASS.

- [x] **Step 8: Commit**

```bash
git add templates/
git commit -m "feat: dashboard templates for all four pages"
```

---

### Task 8: Configure Gmail and verify notifications

**Files:**
- Modify: `.env`

- [x] **Step 1: Generate a Gmail App Password**

1. Go to https://myaccount.google.com/security
2. Confirm 2-Step Verification is enabled
3. Search "App passwords" in the search bar at the top of the page
4. Select app: Mail → Generate
5. Copy the 16-character password shown (it's only shown once)

- [x] **Step 2: Fill in .env**

Edit `.env`:
```
GMAIL_USER=sergiogabrielacosta7@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
NOTIFY_EMAIL=sergiogabrielacosta7@gmail.com
SCAN_INTERVAL_HOURS=6
```
Replace `xxxx xxxx xxxx xxxx` with your generated app password.

- [x] **Step 3: Test email manually**

```bash
python -c "
from dotenv import load_dotenv; load_dotenv()
from notifier import notify
notify([{'host':'192.168.1.1','port':80,'script_name':'http-vuln-test','severity':'high','output':'VULNERABLE: test'}])
print('done')
"
```
Expected: no errors printed, and an email arrives in your inbox within 1 minute.

- [x] **Step 4: Test desktop notification manually**

```bash
python -c "from notifier import send_desktop; send_desktop(2)"
```
Expected: a Windows toast notification appears in the bottom-right corner of the screen.

---

### Task 9: End-to-end test

- [x] **Step 1: Start the app**

```bash
python app.py
```
Expected output includes:
```
[scheduler] Scan job scheduled every 6 hour(s).
 * Running on http://127.0.0.1:5000
```

- [x] **Step 2: Add a target**

Open http://127.0.0.1:5000/targets in your browser.
- Host: `127.0.0.1`
- Ports: `22,80,443`
- Click Add

Expected: target appears in the table.

- [x] **Step 3: Run a manual scan**

Click "Scan Now" next to the target.

Note: Nmap `--script vuln` takes 1–5 minutes per host — the browser tab will appear to hang while the scan runs. This is normal.

Expected: page redirects to /findings with a flash message like `Scan complete. 0 new finding(s).`

- [x] **Step 4: Verify the home dashboard**

Open http://127.0.0.1:5000 and confirm:
- Targets shows `1`
- Active Findings shows the correct count
- Recent Scans shows the scan you just ran with status `done`

- [x] **Step 5: Verify scan history**

Open http://127.0.0.1:5000/history and confirm the scan row shows status `done` and a finished_at timestamp.

---

### Task 10: README and GitHub

**Files:**
- Create: `README.md`

- [x] **Step 1: Create README.md**

Create `README.md`:
```markdown
# Vuln Scanner

A standalone Flask web app that scans configured network targets using Nmap NSE vulnerability scripts, stores results in SQLite, and sends email + desktop notifications when new vulnerabilities are discovered.

## What It Does

- Add target hosts and ports via a web dashboard
- Scans with Nmap `--script vuln` to detect known vulnerabilities
- Stores all findings in SQLite and deduplicates across scans
- Sends Gmail email + Windows desktop notification on new findings
- Scheduled scans run automatically every 6 hours in the background

## Architecture

```
User → Flask Dashboard
          ↓
   [Targets DB] → Scanner (Nmap NSE) → [Findings DB]
                                             ↓
                                       Notifier (Email + Desktop)
          ↑
   APScheduler (every 6h)
```

## Tech Stack

- Python 3 / Flask
- python-nmap (Nmap wrapper)
- APScheduler (background scan jobs)
- SQLite (built-in, no server needed)
- plyer (Windows desktop notifications)
- smtplib (Gmail SMTP, stdlib)
- python-dotenv

## Setup

### Prerequisites

- Python 3.10+
- Nmap installed: https://nmap.org/download.html
- Gmail account with 2-Step Verification enabled

### Install

```bash
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
```

### Configure

Edit `.env` with your credentials:
```
GMAIL_USER=your@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
NOTIFY_EMAIL=your@gmail.com
SCAN_INTERVAL_HOURS=6
```

To generate a Gmail App Password: Google Account → Security → 2-Step Verification → App passwords.

### Run

```bash
python app.py
```

Dashboard at http://127.0.0.1:5000

## What I Learned

- **Security:** How Nmap NSE scripts detect known vulnerabilities, CVE-based severity inference
- **Flask:** Multi-route apps, Jinja2 templates, flash messages, test client
- **Scheduling:** APScheduler background jobs running inside a Flask app
- **Notifications:** Gmail SMTP with app passwords, Windows desktop toasts via plyer
- **SQLite:** Relational schema design, deduplication logic, cross-table joins
```

- [x] **Step 2: Run full test suite one final time**

```bash
pytest -v
```
Expected: all tests PASS.

- [x] **Step 3: Create GitHub repo**

Go to https://github.com/new and create a public repo named `vuln-scanner` with no README and no .gitignore.

- [x] **Step 4: Push to GitHub**

```bash
git add README.md
git commit -m "docs: add README with setup and architecture"
git remote add origin https://github.com/sergioacosta-dev/vuln-scanner.git
git branch -M main
git push -u origin main
```

Expected:
```
Branch 'main' set up to track remote branch 'main' from 'origin'.
```
