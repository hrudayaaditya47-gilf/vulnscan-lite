# VulnScan Lite

A passive, on-demand web vulnerability scanner. Submit a URL, get a security
"Health Report" covering HTTP security headers, SSL/TLS configuration, and
CMS/software fingerprinting — no active attacks, safe and legal to run
against any site you're authorized to scan.

> **Only scan websites you own.** This tool performs passive analysis only.

**Live demo:** https://vulnscan-lite-theta.vercel.app/
**API:** https://vulnscan-lite-5dzk.onrender.com

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
      — builds and lints clean, and verified working in a real browser on the live deployment
- [x] Scanning logic documentation (`docs/SCANNING_LOGIC.md`)
- [x] Docker + docker-compose + deployment guide written
      (the API image builds and runs on Render; the full `docker-compose.yml`
      stack has not been build-tested — see Known Gaps below)
- [x] Deployed live — frontend on Vercel, API + worker on Render, Redis on Upstash (free tiers)
- [x] Pushed to GitHub

**102/102 automated tests passing** as of the last full run.

## Known gaps

1. **docker-compose.yml is still untested.** The API image (`api/Dockerfile`) builds and runs on Render, but the full `docker compose up` stack has not been run.
2. **Free-tier limits.** The Render server sleeps after about 15 minutes idle, so the first request can take up to a minute. Users and saved history live in SQLite on Render's temporary disk, so they are erased on every redeploy or restart.
3. **Cross-site cookies.** Login cookies use `SameSite=None; Secure` because the frontend (Vercel) and API (Render) are on different domains. Browsers that block third-party cookies can break login.

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

## Live deployment setup

| Part | Where | Notes |
|---|---|---|
| Redis | Upstash | URL starts with `rediss://` and ends with `?ssl_cert_reqs=CERT_NONE` |
| API + Celery worker | Render (Docker, `api/Dockerfile`) | One service runs both. Env vars: `REDIS_URL`, `FLASK_SECRET_KEY`, `CORS_ORIGINS`, `RATELIMIT_STORAGE_URI=memory://` |
| Frontend | Vercel (root directory `frontend`) | Build env var `VITE_API_BASE` is the Render URL |

## Deploying for real

See `docs/DEPLOYMENT.md`.
