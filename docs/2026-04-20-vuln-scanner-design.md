
3# Vuln Scanner — Design Spec

**Date:** 2026-04-20
**Project:** vuln-scanner (standalone, separate repo from HomeWatch)

---

## Overview

A standalone Flask web app that scans a user-configured list of network targets using Nmap NSE vulnerability scripts, stores results in SQLite, displays findings on a dashboard, and sends email + desktop notifications when new vulnerabilities are discovered.

---

## Architecture

Four main components work together:

- **Scheduler** — APScheduler runs a scan job on a configurable interval (default: every 6 hours)
- **Scanner** — python-nmap invokes Nmap with `--script vuln` against each enabled target
- **Database** — SQLite persists targets, scan history, and individual findings
- **Notifier** — fires a Gmail SMTP email and a Windows desktop toast notification when a new finding is detected

The Flask app serves the dashboard and wires all components together.

---

## Data Model

**targets**
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| host | TEXT | IP or hostname |
| ports | TEXT | comma-separated, e.g. "22,80,443" |
| enabled | BOOLEAN | skip disabled targets during scheduled scans |
| created_at | DATETIME | |

**scans**
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| target_id | INTEGER FK | |
| started_at | DATETIME | |
| finished_at | DATETIME | nullable until complete |
| status | TEXT | running / done / failed |

**findings**
| column | type | notes |
|---|---|---|
| id | INTEGER PK | |
| scan_id | INTEGER FK | |
| target_id | INTEGER FK | |
| port | INTEGER | |
| script_name | TEXT | NSE script that fired |
| output | TEXT | raw Nmap script output |
| severity | TEXT | info / medium / high — inferred from output keywords: "VULNERABLE" → high, CVE present → medium, otherwise info |
| first_seen | DATETIME | |
| resolved | BOOLEAN | manually marked resolved on dashboard |

A finding is "new" when the combo `(target_id, port, script_name)` has not appeared in any previous scan. New findings trigger notifications.

---

## Dashboard Pages

| Route | Page | Description |
|---|---|---|
| `/` | Home | Summary cards: total targets, findings this week, last scan time, next scan time |
| `/findings` | Findings | Table of active vulnerabilities grouped by target, with severity and raw Nmap output |
| `/targets` | Targets | Add/remove targets, enable/disable, trigger manual scan |
| `/history` | Scan History | List of past scans with status, duration, finding count |

---

## Notifications

**Email** — sent via Gmail SMTP using an app password. Credentials stored in `.env` (never committed). One email per scan that contains new findings, listing each new finding with host, port, script name, and severity.

**Desktop** — Windows toast notification via `plyer`, fires at the same time as the email with a summary count (e.g., "3 new vulnerabilities found on 192.168.12.1").

---

## File Structure

```
vuln-scanner/
├── app.py              # Flask app + routes
├── scanner.py          # Nmap wrapper (python-nmap)
├── scheduler.py        # APScheduler setup
├── notifier.py         # Email + desktop alerts
├── database.py         # SQLite setup + queries
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── findings.html
│   ├── targets.html
│   └── history.html
├── .env                # Email credentials (not committed)
├── .gitignore
└── requirements.txt
```

---

## Tech Stack

- Python 3
- Flask (web framework)
- python-nmap (Nmap wrapper)
- APScheduler (scheduled scan jobs)
- SQLite + sqlite3 (built-in, no extra install)
- plyer (Windows desktop notifications)
- smtplib + email (stdlib, Gmail SMTP)
- python-dotenv (load .env credentials)

---

## Success Criteria

- Add a target (host + ports) via the dashboard and trigger a manual scan
- Scan runs Nmap NSE vuln scripts and stores findings in SQLite
- Dashboard shows findings grouped by target with severity
- New finding triggers both an email and a desktop notification
- Scheduled scan runs automatically every 6 hours without manual intervention
