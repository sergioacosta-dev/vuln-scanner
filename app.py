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
    app.run(debug=True, use_reloader=False, port=5001)