# VulnScope
**Web Application Exposure & Security Posture Assessment Platform**

VulnScope is not an API security scanner. It focuses on browser-facing web applications, client-side exposure, security header posture, cookie safety, public resource exposure, crawl mapping, visual evidence, posture scoring, and scan-to-scan drift detection.

## Core Differentiators
- **No API Focus**: Specifically ignores OpenAPI/Swagger parsing and API-centric workflows, focusing on browser interactions.
- **Posture-Centric**: Scores targets across Transport Security, Browser Defenses, Session Safety, Exposure Hygiene, and Auth Surface out of 100.
- **Drift Detection**: Tracks security posture changes and new/resolved findings scan-to-scan.
- **Visual Evidence**: Captures response headers and HTML snippets of sensitive pages (e.g., login forms) as proof of exposure.
- **Crawl Maps**: Visualizes the site hierarchy, forms, and login input presence across depth levels.
- **Policy Compliance**: Ships with JSON-based compliance packs (e.g., Web Baseline, Browser Hardening, Public Exposure) to map findings to desired states.

## Technology Stack
- **Frontend**: React (Vite), TypeScript, Tailwind CSS, Recharts, Lucide React.
- **Backend**: FastAPI (Python), SQLite (SQLAlchemy), BeautifulSoup4, Pydantic, httpx, Jinja2.
- **Deployment**: Docker, Docker Compose.

## Key Features
1. **Web Crawl Map**: Visual representation of the application structure, tracking where forms and password fields are located.
2. **Posture Score Breakdown**: Detailed 0-100 scoring across 5 key client-side security domains.
3. **Posture Drift**: Identifies exactly what degraded or improved between the latest and previous scan.
4. **Evidence Collection**: Lightweight artifacts that prove the presence of misconfigurations.
5. **Compliance Policies**: Automatic evaluation of findings against JSON policy definitions.
6. **Executive Reports**: HTML-based report generation for executive summaries.

## Running VulnScope
Use Docker Compose to run the full stack:
```bash
docker-compose up --build
```
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

> Note: For testing the scanner inside Docker, add the local target as `http://demo-target:8081`. If running locally without Docker, use `http://localhost:8081`.

## Repository Structure
- `/frontend`: React dashboard application.
- `/backend`: FastAPI service and scanner engine.
- `/backend/app/scanner/orchestrator.py`: Core scan logic, crawl processing, diff generation, and evidence capture.
- `/backend/app/policies/`: JSON compliance packs.
- `/docker-compose.yml`: Local environment setup.
