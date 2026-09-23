import ipaddress
import logging
import os
import secrets
import socket
import sqlite3
import threading
from dotenv import load_dotenv
from flask import Flask, Response, render_template, request, redirect, url_for, flash
from database import (
    init_db, get_connection, add_target, get_targets, delete_target,
    add_scan, update_scan, add_finding, get_findings, get_scan_history, resolve_finding
)
from scanner import run_scan
from notifier import notify
import scheduler

load_dotenv()

logger = logging.getLogger("vuln_scanner")

# ponytail: process-wide, not per-target-fair; fine at this scale (one admin, handful of targets)
_scanning_targets = set()
_scanning_lock = threading.Lock()


def is_authorized_target(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError):
            return False
    return ip.is_private or ip.is_loopback


def _try_claim_scan(target_id):
    with _scanning_lock:
        if target_id in _scanning_targets:
            return False
        _scanning_targets.add(target_id)
        return True


def _release_scan(target_id):
    with _scanning_lock:
        _scanning_targets.discard(target_id)


def run_target_scan(conn, target):
    """Re-validates the target, runs the nmap scan, and stores findings.

    Returns (status, new_findings, error) — status is "done", "failed", "rejected",
    or "busy". Notification is the caller's job so a failed email never marks a
    successful scan as failed.
    """
    if not is_authorized_target(target["host"]):
        return "rejected", [], "target no longer resolves to a private/loopback address"
    if not _try_claim_scan(target["id"]):
        return "busy", [], "a scan for this target is already running"
    scan_id = add_scan(conn, target["id"])
    try:
        raw_findings = run_scan(target["host"], target["ports"], timeout=900)
        new_findings = []
        for f in raw_findings:
            is_new = add_finding(conn, scan_id, target["id"], f["port"], f["script_name"], f["output"], f["severity"])
            if is_new:
                new_findings.append({**f, "host": target["host"]})
        update_scan(conn, scan_id, "done")
        return "done", new_findings, None
    except Exception as e:
        update_scan(conn, scan_id, "failed")
        return "failed", [], str(e)
    finally:
        _release_scan(target["id"])


def run_scheduled_scan(app):
    with app.app_context():
        conn = get_connection()
        for target in get_targets(conn):
            status, new_findings, error = run_target_scan(conn, target)
            if status not in ("done",):
                logger.warning("[scheduler] Scan %s for %s: %s", status, target["host"], error)
            if new_findings:
                try:
                    notify(new_findings)
                except Exception:
                    logger.exception("[scheduler] Notification failed for %s", target["host"])


def create_app(testing=False):
    app = Flask(__name__)
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        if testing:
            secret_key = "test-secret-key"
        else:
            raise RuntimeError(
                "SECRET_KEY environment variable is required. "
                "Set it in .env (see .env.example) — generate one with: "
                "python -c \"import secrets; print(secrets.token_hex(32))\""
            )
    app.secret_key = secret_key

    auth_user = os.getenv("AUTH_USER")
    auth_password = os.getenv("AUTH_PASSWORD")
    if not testing and not (auth_user and auth_password):
        raise RuntimeError(
            "AUTH_USER and AUTH_PASSWORD environment variables are required. "
            "Set them in .env (see .env.example)."
        )

    @app.before_request
    def require_auth():
        if testing:
            return
        creds = request.authorization
        valid = (
            creds is not None
            and secrets.compare_digest(creds.username, auth_user)
            and secrets.compare_digest(creds.password, auth_password)
        )
        if not valid:
            return Response(
                "Authentication required.", 401,
                {"WWW-Authenticate": 'Basic realm="Vuln Scanner"'}
            )

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
                if is_authorized_target(host):
                    add_target(conn, host, ports)
                    flash(f"Target {host} added.")
                else:
                    flash(f"Target {host} rejected: only private/LAN addresses are allowed.")
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
        target_id = request.form.get("target_id", "")
        try:
            target_id = int(target_id)
        except ValueError:
            flash("No target selected.")
            return redirect(url_for("targets"))
        target = next((t for t in get_targets(conn) if t["id"] == target_id), None)
        if not target:
            flash("Target not found.")
            return redirect(url_for("targets"))
        status, new_findings, error = run_target_scan(conn, target)
        if status == "rejected":
            flash(f"Scan blocked: {target['host']} {error}.")
        elif status == "busy":
            flash(f"Scan already running for {target['host']}.")
        elif status == "failed":
            flash(f"Scan failed: {error}")
        else:
            flash(f"Scan complete. {len(new_findings)} new finding(s).")
        if new_findings:
            try:
                notify(new_findings)
            except Exception:
                logger.exception("Notification failed for %s", target["host"])
                flash("Findings saved, but the notification email failed to send.")
        return redirect(url_for("findings"))

    @app.route("/findings/resolve/<int:finding_id>", methods=["POST"])
    def resolve(finding_id):
        resolve_finding(get_db(), finding_id)
        flash("Finding marked resolved.")
        return redirect(url_for("findings"))

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app()
    scheduler.start(lambda: run_scheduled_scan(app))
    app.run(host="0.0.0.0", debug=False, use_reloader=False, port=5002, threaded=True)
