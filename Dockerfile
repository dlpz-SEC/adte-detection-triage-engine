# syntax=docker/dockerfile:1
#
# Railway build for ADTE (triage-only Detection & Triage Engine).
#
# Two stages because the app is polyglot: a Python/gunicorn web service that
# serves a frontend bundle produced by esbuild (Node). Railway's default
# Nixpacks builder provisions one primary language, so it will not put Node and
# Python in the same build environment — this Dockerfile does it explicitly.
#
# Mirrors the original Render build (Render is now parked; Railway is live):
#   build : pip install . && cd frontend && npm install && npm run build
#   start : gunicorn adte.server:app --bind 0.0.0.0:$PORT --workers 1 --threads 8
#           --worker-class gthread --timeout 60

# ---- Stage 1: build the frontend bundle (esbuild) -------------------------
FROM node:20-slim AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
# esbuild src/app.jsx --bundle --minify -> bundle.js (gitignored, so it MUST
# be rebuilt here; the GitHub clone Railway builds from has no bundle.js).
RUN npm run build

# ---- Stage 2: Python runtime (gunicorn) -----------------------------------
FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app

# Install dependencies + the adte package first for layer caching. README.md is
# referenced by pyproject's `readme` field, so it must be present at build time.
COPY pyproject.toml README.md ./
COPY adte/ ./adte/
RUN pip install .

# Bring in the rest of the source tree. gunicorn runs from /app (the repo
# root), so the server reads frontend/index.html and any data files relative
# to cwd.
COPY . .

# Overlay the freshly built bundle from the frontend stage (the COPY above
# carried no bundle.js because it is gitignored).
COPY --from=frontend /build/bundle.js ./frontend/bundle.js

# Triage-only safety defaults — overridable in the Railway dashboard.
ENV ADTE_DRY_RUN=true \
    ADTE_EXECUTION_ENABLED=false \
    ADTE_KILL_SWITCH=false

# Railway injects $PORT at runtime; default to 8080 for local `docker run`.
#
# One worker process with 8 threads (gthread), not several processes. ADTE
# keeps rate-limit counters, threat-intel quotas and spacing, and its caches
# in process memory; with --workers 2 each process kept its own copy, so every
# documented rate limit and quota was really up to 2x. One process makes them
# exact. The work is I/O-bound (threat-intel HTTP, Claude, SQLite), so threads
# carry the concurrency. Under gthread, --timeout only catches a wedged worker,
# it no longer ends a slow request: every outbound call sets its own timeout
# (threat intel 10 s, Wazuh and Sentinel 30 s, Claude 30 s).
EXPOSE 8080
CMD ["sh", "-c", "gunicorn adte.server:app --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 8 --worker-class gthread --timeout 60"]
