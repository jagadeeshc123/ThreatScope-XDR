# ThreatScope XDR

ThreatScope XDR is a self-contained local security assessment, SOC simulation, incident-correlation, governance, and reporting platform. Release candidate `1.0.0-rc1` adds authenticated operational health, diagnostics, consistent SQLite backup, staged restore, safe export validation, retention preview/apply, synthetic demo management, local inventory, and bounded release packaging.

Start with [Installation](docs/INSTALLATION.md), then read the [Operations Guide](docs/OPERATIONS_GUIDE.md) and [Security Model](docs/SECURITY_MODEL.md). No cloud service, external telemetry, deployment, or automatic update is included.

Quick local verification:

```text
cd backend
python -m pip install -r requirements.txt
python scripts/create_admin.py
uvicorn app.main:app --reload
```

In another terminal run `cd frontend`, `npm ci`, and `npm run dev`. Docker users may configure `.env` from `.env.example` and run `docker compose up --build -d`.

This is a locally verified release candidate, not a production certification or compliance claim.
