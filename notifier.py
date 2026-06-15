import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

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

def notify(findings, dry_run=False):
    if not findings:
        return
    if dry_run:
        print(f"[notifier] dry_run: would notify about {len(findings)} finding(s).")
        return
    send_email(findings)
    print(f"[notifier] {len(findings)} new finding(s) detected. Email sent.")