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
source venv/Scripts/activate   # Windows Git Bash
# or on PowerShell:
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configure

Copy `.env.example` to `.env` and fill in your credentials:

```
GMAIL_USER=your@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
NOTIFY_EMAIL=your@gmail.com
SCAN_INTERVAL_HOURS=6
```

To generate a Gmail App Password: Google Account → Security → 2-Step Verification → App passwords.

### Run

```powershell
python app.py
```

Dashboard at http://127.0.0.1:5000

> If port 5000 is in use, change the port in the last line of `app.py`: `app.run(debug=True, use_reloader=False, port=5001)`

## What I Learned

- **Security:** How Nmap NSE scripts detect known vulnerabilities, CVE-based severity inference
- **Flask:** Multi-route apps, Jinja2 templates, flash messages, test client
- **Scheduling:** APScheduler background jobs running inside a Flask app
- **Notifications:** Gmail SMTP with app passwords, Windows desktop toasts via plyer
- **SQLite:** Relational schema design, deduplication logic, cross-table joins

## Screenshot

<img width="1054" height="545" alt="image" src="https://github.com/user-attachments/assets/19afa345-cb26-4e25-86a6-0da99cb8f3f0" />

