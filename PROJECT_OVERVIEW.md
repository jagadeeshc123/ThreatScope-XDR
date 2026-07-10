# VulnScope Project Overview

VulnScope is the Web Exposure module inside ThreatScope XDR. It performs authorized, non-destructive web posture assessments and stores all operational data in the FastAPI backend.

## Current Scope

- Authorized target management
- Passive, standard safe, and full safe scans
- Security header, cookie, CORS, TLS, exposure, technology, form, and authentication checks
- Crawl maps and redacted evidence artifacts
- Risk and posture scoring
- Scan-to-scan posture drift
- Policy pack evaluation
- HTML report generation and download
- Dashboard, search, profile, settings, and notifications

API Security, SOC Monitor, Document Threats, and Phishing Defense are not part of the current module.

## Architecture

```text
React frontend (5173)
        |
        v
FastAPI backend (8000)
        |
        +-- SQLAlchemy / SQLite
        +-- Safe HTTP scanner
        +-- Crawler and checks
        +-- Policy evaluator
        +-- Report generator
```

The frontend uses `frontend/src/api/vulnscope.ts` for all application data. There is no bundled static fallback dataset.

## Main Directories

```text
backend/
  app/
    routers/              API endpoints
    scanner/              Scanner orchestration and checks
    policies/             Policy pack JSON files
  tests/                  Isolated API tests
  scripts/                Verification utilities

frontend/
  src/
    api/                  Typed backend service layer
    components/           Shared UI and layout
    pages/                Web Exposure routes
  MANUAL_TEST_CHECKLIST.md

test-target/              Authorized local scanner test fixture
docker-compose.yml
```

## Running Locally

```bash
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- Authorized local test target: `http://localhost:8081`

When the backend runs in Docker, targets using `localhost`, `127.0.0.1`, or `::1` are routed through the Docker host bridge while retaining their original Host header.

## Verification

Frontend:

```bash
npm run lint
npm run build
```

Backend:

```bash
python -m compileall app tests
python -m unittest discover -s tests -v
python scripts/verify_vulnscope.py
```

Docker:

```bash
docker compose config
docker compose up --build
```

## Safety

Only scan systems you own or are explicitly authorized to assess. VulnScope uses controlled request rates, bounded crawling, redacted evidence, and non-destructive checks.
