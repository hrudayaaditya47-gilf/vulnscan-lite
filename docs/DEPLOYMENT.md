# Deployment Guide

## Honest scope of this document

I (Claude) cannot actually deploy this anywhere live — that requires an
account and credentials on a hosting provider that only you have access
to. What I *can* do is give you a deploy-ready setup and the exact
commands to run. The Docker/compose files in this repo have **not been
build-tested** — my sandbox has no Docker available — so treat them as
a solid, carefully-reasoned starting point, not a guarantee. If a build
fails, share the error with me and I'll fix it.

## Option A: one VPS, docker-compose (simplest)

Works on any VPS (DigitalOcean, Linode, a $6/mo droplet, etc.) with
Docker and Docker Compose installed.

1. Push this repo to GitHub (see below), then on the server:
   ```bash
   git clone <your-repo-url>
   cd vulnscan-lite
   cp .env.example .env
   ```
2. Edit `.env` — set a real `FLASK_SECRET_KEY` (generate one with
   `python3 -c "import secrets; print(secrets.token_hex(32))"`), and set
   `CORS_ORIGINS`/`VITE_API_BASE` to your actual domain(s) once you have
   them (e.g. `https://scan.yourdomain.com`).
3. ```bash
   docker compose up -d --build
   ```
4. The frontend is on port 8080, the API on port 5000. Put a reverse
   proxy (nginx, Caddy, or the platform's own load balancer) in front of
   both with a real TLS certificate — don't expose port 5000 directly
   to the internet over plain HTTP in production.
5. Add the disclaimer banner check: confirm the frontend shows "Only
   scan websites you own" (it already does, in `App.jsx`'s header) —
   this satisfies deliverable #2's disclaimer requirement.

## Option B: managed platforms (Render / Railway / Fly.io)

These platforms deploy from a Dockerfile directly, which this repo now
has. Rough shape (specifics vary by platform — check their current
docs, since these change):

1. Create a **Redis** instance (most of these platforms offer a managed
   Redis add-on — use that instead of running your own).
2. Create a **worker** service from `api/Dockerfile`, overriding the
   start command to:
   ```
   celery -A celery_worker worker --loglevel=info
   ```
3. Create a **web** service from `api/Dockerfile` (uses the default
   gunicorn CMD). Set env vars: `REDIS_URL` (from step 1),
   `FLASK_SECRET_KEY` (a real random value), `CORS_ORIGINS` (your
   frontend's URL once you know it), `VULNSCAN_DB_PATH` (a path on a
   persistent disk/volume if the platform offers one — otherwise scan
   history won't survive a redeploy).
4. Create a **static site** service from `frontend/Dockerfile` (or just
   `frontend/dist` after running `npm run build` with `VITE_API_BASE`
   set to your web service's URL — check whether the platform supports
   Docker build args for static sites; some don't, in which case build
   locally and upload `dist/`).
5. Point `CORS_ORIGINS` on the API back at the frontend's final URL —
   there's a chicken-and-egg step here since you need the frontend's
   URL before you know it; most platforms assign a URL immediately on
   creation, before the first deploy finishes, so you can grab it early.

## Before you go live — checklist

- [ ] `FLASK_SECRET_KEY` is a real random value, not the dev default
- [ ] `CORS_ORIGINS` is set to your actual frontend URL, not `*`
- [ ] Redis and the SQLite DB are on persistent storage (not lost on redeploy)
- [ ] Everything is served over HTTPS (both the API and the frontend)
- [ ] The rate limits in `api/app.py` (5/min scans, 10/hr registrations)
      still make sense for your expected traffic
- [ ] You've actually run a scan against the live URL and confirmed it
      works end-to-end, same as we verified locally

## Pushing to GitHub

```bash
cd vulnscan-lite
git init
git add .
git commit -m "Initial commit — VulnScan Lite"
git branch -M main
git remote add origin <your-empty-github-repo-url>
git push -u origin main
```

One thing to double check before your first commit: `.gitignore` should
already exclude `venv/`, `node_modules/`, `__pycache__/`, and
`api/vulnscan.db` (the frontend's own `.gitignore` covers its half;
confirm the root one covers the Python side too before pushing).
