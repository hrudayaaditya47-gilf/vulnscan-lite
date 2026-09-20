# VulnScan Lite

A passive, on-demand web vulnerability scanner. Submit a URL, get a security
"Health Report" covering HTTP security headers, SSL/TLS configuration, and
CMS/software fingerprinting — no active attacks, safe and legal to run
against any site you're authorized to scan.

> **Only scan websites you own.** This tool performs passive analysis only.

## Project layout

```
vulnscan-lite/
├── scanner/              # Core check modules (pure Python, no web framework deps)
│   ├── __init__.py
│   ├── headers.py        # Module 1: security header analysis
│   ├── ssl_check.py      # Module 2: SSL/TLS certificate inspection
│   ├── cms_detect.py     # Module 3: CMS/version fingerprinting
│   └── scoring.py        # Combines all 3 into a 0-100 score + letter grade
├── api/                   # Flask web server + Celery task queue
│   ├── app.py               # all endpoints — see below
│   ├── celery_app.py         # Celery instance (Redis broker/backend)
│   ├── celery_worker.py      # run_scan task — orchestrates all 3 modules + scoring
│   ├── pdf_report.py         # generates a PDF from a scan result
│   ├── db.py                 # SQLite — users + scan_history tables
│   ├── auth.py                # registration/login/session logic
│   ├── Dockerfile             # shared image for the api + worker services
│   └── requirements.txt
├── docs/
│   ├── SCANNING_LOGIC.md    # what each check does and how scoring works
│   └── DEPLOYMENT.md        # how to actually put this online
├── tests/                 # pytest — 102 tests, deterministic (mocked network)
│                             plus several live-network flows verified manually
├── frontend/               # React (Vite) — scan form, polling, auth, history, PDF links
│   ├── Dockerfile            # multi-stage build -> nginx
│   └── nginx.conf
├── docker-compose.yml     # redis + worker + api + frontend, wired together
├── .env.example           # required env vars for docker-compose
└── README.md
```

## API endpoints

| Endpoint | Auth? | What it does |
|---|---|---|
| `GET /api/health` | no | liveness check |
| `POST /api/scan` | no | queue a scan (rate-limited, SSRF-guarded), returns `scan_id` |
| `GET /api/scan/<id>/status` | no | poll status — `PENDING`/`PROGRESS`/`SUCCESS`/`FAILURE` |
| `GET /api/scan/<id>/pdf` | no | download the PDF report for a completed scan |
| `POST /api/auth/register` | no | create an account, logs you in |
| `POST /api/auth/login` | no | log in |
| `POST /api/auth/logout` | no | log out |
| `GET /api/auth/me` | no | check current login state |
| `POST /api/history` | yes | save a completed scan (`{"scan_id": ...}`) to your history |
| `GET /api/history` | yes | list your saved scans |
| `GET /api/history/<id>` | yes | full stored result for one history entry |
| `GET /api/history/<id>/pdf` | yes | PDF for a history entry (works even after the original scan result expired from Redis) |

## Status

- [x] Scanner core: headers, SSL/TLS, CMS detection — 32 tests
- [x] Scoring engine — 0-100 + letter grade + remediation tips — 10 tests
- [x] Redis + Celery async queue — verified end-to-end with a real worker
- [x] Scan API — SSRF protection, rate limiting — 30 tests (incl. auth/history)
- [x] PDF export — visually verified, including real multi-page output
- [x] Scan history + lightweight auth (sessions, SQLite) — 19 tests (db + auth)
- [x] React frontend — scan form, 2s polling, score gauge, auth, history view, PDF links
      — builds and lints clean, **but not yet visually verified in a real browser**
      (see Known Gaps below)
- [x] Scanning logic documentation (`docs/SCANNING_LOGIC.md`)
- [x] Docker + docker-compose + deployment guide written
      (**not build-tested** — no Docker available in the sandbox this was built in;
      see Known Gaps below)
- [ ] Actually deployed live somewhere — not done; needs your hosting account
- [ ] Pushed to an actual GitHub repository — you'll need to do this yourself

**102/102 automated tests passing** as of the last full run.

## Known gaps — read this before treating it as "done"

1. **The frontend has never been visually rendered.** Every backend flow it
   calls has been proven live with real `curl` requests carrying real
   cookies, so the *logic* is solid — but I have not personally seen the
   page in a browser (the sandbox this was built in has no working
   Chromium/Playwright, confirmed after trying both Playwright and apt).
   Open `npm run dev` yourself and actually look at it before assuming the
   layout is correct.
2. **The Docker setup is unverified.** No Docker daemon is available in
   the sandbox this was built in, so `docker-compose.yml` and both
   Dockerfiles have been reasoned through carefully (and the compose YAML
   has been syntax/structure-validated) but never actually built or run.
   Try `docker compose up --build` yourself and tell me what breaks, if
   anything.
3. **No live deployment.** The brief's "Deployed" + disclaimer-banner
   deliverable isn't satisfied yet. See `docs/DEPLOYMENT.md`.
4. **Not pushed to GitHub.** The brief's "GitHub Repository" deliverable
   needs you to actually create the repo and push this — commands are in
   `docs/DEPLOYMENT.md`.
5. **The Flask secret key defaults to a hardcoded dev value.** Set a real
   `FLASK_SECRET_KEY` before deploying anywhere real, or every login
   session can be forged. `docker-compose.yml` already refuses to start
   without one being set.

## Running locally (without Docker)

You need 4 terminals running at once: Redis, the Celery worker, the Flask
API, and the Vite dev server.

**1. Redis** (install via `brew install redis` / `apt install redis-server`):
```bash
redis-server
```

**2. Python env + Celery worker:**
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r api/requirements.txt
cd api
celery -A celery_worker worker --loglevel=info
```

**3. Flask API** (new terminal, same venv):
```bash
source venv/bin/activate   # from project root
cd api
python app.py               # http://localhost:5000
```

**4. React frontend** (new terminal):
```bash
cd frontend
npm install
npm run dev                 # http://localhost:5173
```

Then open http://localhost:5173.

## Running locally (with Docker — unverified, see Known Gaps)

```bash
cp .env.example .env
# edit .env — set a real FLASK_SECRET_KEY
docker compose up --build
```
Frontend on http://localhost:8080, API on http://localhost:5000.

## Running the tests

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

## Deploying for real

See `docs/DEPLOYMENT.md`.
