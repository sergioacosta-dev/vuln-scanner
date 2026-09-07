# vuln-scanner — Project Rules

Flask vulnerability scanner (`python-nmap` NSE scripts + SQLite findings store). Runs on **Homeserver**, not Omarchy — this local copy is for editing; the live instance is a separate, non-git deployment.

---

## Deploy Pattern (no git repo on Homeserver)

The live copy at `~/Projects/active/vuln-scanner/` on Homeserver is a plain file deployment, not a git checkout. After editing locally:

```bash
scp app.py database.py notifier.py scanner.py scheduler.py homeserver:/home/sergi/Projects/active/vuln-scanner/
```

Then restart the systemd service — this needs `sudo`, which Claude can't run over SSH, so hand the exact command to the user:
```bash
sudo systemctl restart vuln-scanner
```

## Required Environment Variables

`create_app()` fails fast if `SECRET_KEY` is missing (real fix, 2026-09-02 — it used to be a hardcoded string). `testing=True` (used by the test suite) gets a safe fallback so tests don't need real env vars.

```
GMAIL_USER              # notification sender
GMAIL_APP_PASSWORD      # Gmail app password, not the account password
NOTIFY_EMAIL            # notification recipient
SCAN_INTERVAL_HOURS     # default 6
SECRET_KEY              # Flask session signing — generate: python -c "import secrets; print(secrets.token_hex(32))"
```

Loaded via `python-dotenv` from `.env` (see `.env.example`). Unlike homewatch, this one does use plain `.env` and dotenv, not a systemd `EnvironmentFile`.

## Structure

- `app.py` — `create_app(testing=False)` factory, routes
- `database.py` — SQLite access (`vuln_scanner.db`)
- `scanner.py` — `python-nmap` scan execution
- `scheduler.py` — APScheduler background job, runs every `SCAN_INTERVAL_HOURS`
- `notifier.py` — email alerts on new findings

## Testing

```bash
source venv/bin/activate
python -m pytest -q
```

Tests call `create_app(testing=True)`, which uses an in-memory SQLite DB and the safe `SECRET_KEY` fallback — no real `.env` needed to run the suite.

---

## 7 Deadly Sins of Vibecoding

Verify all 7 before marking any task complete.

### 1. Safe Defaults
**Never ship permissive configs.** Production code must be locked down from the start.
- ❌ `CORS: *`, `DEBUG=True`, open firewall rules, world-readable file permissions, default admin credentials
- ✅ Allowlist specific origins, disable debug in prod, least-privilege on all configs and file permissions

### 2. Logging & Monitoring
**Silent code is blind code.** Every meaningful action and failure must leave a trace.
- ❌ Empty `except`/`catch` blocks, no request logging, swallowed errors, no alerting on failures
- ✅ Structured logs with severity levels, trace IDs on requests, log errors with context — never log secrets or PII

### 3. Dependency Hygiene
**Every package is a liability.** Vet before you install; pin what you keep.
- ❌ Unpinned versions (`requests`, `^1.0.0`), abandoned packages, unaudited installs, unnecessary dependencies
- ✅ Pin exact versions, run `pip audit` / `npm audit`, remove unused deps, prefer stdlib over micro-packages

### 4. Secrets
**A secret in code is already leaked.** Zero tolerance.
- ❌ Hardcoded API keys, passwords in source, `.env` committed to git, secrets appearing in logs or error messages
- ✅ Environment variables or a secrets manager, `.env` in `.gitignore`, startup validation that required secrets exist

### 5. Input Handling
**Never trust the caller.** Validate and sanitize at every system boundary.
- ❌ Raw user input passed to queries/shell/file paths, trusting client-side validation alone, no length limits
- ✅ Schema validation on entry, parameterized queries, path canonicalization, reject-early with clear error messages

### 6. Authentication
**Prove identity before anything else.** Use proven libraries — never roll your own.
- ❌ Unprotected endpoints, custom session token logic, plain-text password storage, no token expiry
- ✅ Established auth libraries (OAuth 2.0, JWT with short TTLs), bcrypt/argon2 for passwords, re-auth on sensitive actions

### 7. Authorization
**Authentication ≠ Authorization.** Verify permissions at every layer, default to deny.
- ❌ Checking auth but not ownership (IDOR), admin logic gated only on the frontend, assuming logged-in = permitted
- ✅ Server-side permission checks on every action, resource ownership validated, least-privilege roles, deny by default

---

### Pre-Completion Checklist

Before marking any task done:
- [ ] **Safe defaults** — no permissive configs shipped
- [ ] **Logging** — errors and key actions are logged; no secrets in logs
- [ ] **Dependencies** — all new packages vetted, pinned, and necessary
- [ ] **Secrets** — zero hardcoded credentials; `.env` excluded from git
- [ ] **Input handling** — all external input validated at the boundary
- [ ] **Authentication** — all endpoints that need auth have it
- [ ] **Authorization** — permission checks happen server-side, deny by default

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- ALWAYS read graphify-out/GRAPH_REPORT.md before reading any source files, running grep/glob searches, or answering codebase questions. The graph is your primary map of the codebase.
- IF graphify-out/wiki/index.md EXISTS, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
