# VulnScope Project Overview

## 1. Project Name

**VulnScope - Automated Web Application Security Assessment Platform**

VulnScope is a web application security assessment platform. In simple words, it helps a security analyst add a website, run a safe scan, review security findings, understand the risk level, and generate a report.

It is designed for browser-facing web applications. That means it focuses on things a normal website visitor's browser would see, such as HTTP security headers, cookies, HTTPS usage, exposed files, forms, login pages, and public web pages.

It is not built as an offensive exploitation tool. It does not try to hack accounts, brute force passwords, exploit systems, or perform destructive testing. The platform is meant for authorized, safe, defensive security assessment.

---

## 2. One-Minute Explanation For An Interview

VulnScope is a full-stack cybersecurity dashboard that automates safe web application security checks.

The user adds an authorized target website, selects a scan profile, and starts a scan. The backend scanner fetches the website, checks common browser-facing security controls, crawls pages depending on the scan type, records findings, calculates a risk score, calculates a posture score, stores evidence, compares the scan with previous scans, and can generate an HTML report.

The frontend presents the results in a professional dashboard with targets, scans, findings, severity distribution, scan history, policy checks, reports, notifications, settings, and profile pages.

The goal is to make security posture easy to understand for technical and non-technical users.

---

## 3. Problem This Project Solves

Security teams often need to answer simple questions:

- Which web applications are being monitored?
- Are these applications using safe browser security settings?
- Are cookies configured securely?
- Is HTTPS being used correctly?
- Are sensitive files accidentally public?
- Did the latest scan become better or worse than the previous scan?
- Which findings are critical, high, medium, low, or informational?
- Can we generate a clean report for stakeholders?

VulnScope solves this by providing one platform where a user can:

- Register web targets.
- Confirm authorization before scanning.
- Run safe scans.
- View findings with evidence.
- Track posture and risk.
- Compare scan-to-scan drift.
- Review policy coverage.
- Export or view reports.

---

## 4. Target Users

VulnScope is useful for:

- Security analysts.
- SOC analysts.
- Application security interns.
- Web developers who want basic security visibility.
- College project evaluators.
- Interviewers reviewing a cybersecurity full-stack project.
- Small teams that need a simple web security posture dashboard.

For an HR interviewer, the simple explanation is:

> This project helps companies check whether their websites follow important security best practices and presents the result in a clean dashboard and report.

For a technical interviewer, the explanation is:

> This project combines a React frontend, FastAPI backend, SQLite database, background scan orchestration, passive web checks, crawl mapping, evidence storage, posture scoring, risk scoring, drift detection, policy mapping, and report generation.

---

## 5. Main Features

### 5.1 Dashboard

The dashboard gives the user a quick overview of the whole system.

It shows:

- Total targets.
- Total scans.
- Total findings.
- Critical and high findings.
- Reports generated.
- Overall posture score.
- Scan trend chart.
- Severity distribution chart.
- Recent scans.
- Recent findings.
- Policy coverage.

Purpose:

The dashboard is the first screen an analyst uses to understand the current security condition of the monitored web applications.

Input:

- Stored target records.
- Stored scan records.
- Stored finding records.
- Stored report records.
- Stored policy definitions.

Output:

- Visual summary cards.
- Charts.
- Recent activity tables.
- Security posture overview.

---

### 5.2 Targets

Targets are the websites or web applications that the user wants to assess.

Each target stores:

- Target name.
- Base URL.
- Domain.
- Environment, such as local, staging, production, or public.
- Authorization confirmation.
- Created date.

Important safety rule:

The user must confirm that they own the target or have permission to test it. The backend also rejects target creation or scanning if authorization is not confirmed.

Input:

```json
{
  "name": "Demo Target",
  "base_url": "http://localhost:8081",
  "environment": "local",
  "authorization_confirmed": true
}
```

Output:

```json
{
  "id": 1,
  "name": "Demo Target",
  "base_url": "http://localhost:8081",
  "domain": "localhost:8081",
  "environment": "local",
  "authorization_confirmed": true,
  "created_at": "date-time"
}
```

What the page shows:

- Target cards.
- Selected target details.
- Scan count.
- Findings count.
- Reports count.
- Latest scan.
- Risk score.
- Authorization status.

---

### 5.3 Scans

A scan is an assessment run against one target.

The user selects:

- Target.
- Scan profile.

Supported scan profiles:

1. **Passive Scan**
   - Checks the base URL.
   - Looks at response headers, cookies, HTTPS, CORS, and technology disclosure.
   - Does not crawl deeply.

2. **Standard Safe Scan**
   - Includes passive checks.
   - Checks exposed files.
   - Crawls a limited number of pages.
   - Checks forms and login surfaces.

3. **Full Safe Scan**
   - Includes passive checks.
   - Performs a deeper safe crawl.
   - Checks more pages than Standard Safe Scan.
   - Still avoids destructive behavior.

Input:

```json
{
  "target_id": 1,
  "profile": "Standard Safe Scan"
}
```

Output:

```json
{
  "id": 10,
  "target_id": 1,
  "profile": "Standard Safe Scan",
  "status": "queued",
  "started_at": "date-time",
  "completed_at": null,
  "total_findings": 0,
  "risk_score": 0.0,
  "overall_posture_score": 100
}
```

Scan status values:

- `queued`: Scan was created and is waiting to run.
- `running`: Scanner is actively working.
- `completed`: Scanner finished successfully.
- `failed`: Scanner could not complete.

Output after completion:

- Findings.
- Crawl map.
- Evidence artifacts.
- Risk score.
- Posture score.
- Posture drift compared with previous scan.
- Notifications.

---

### 5.4 Findings

A finding is a security issue or observation discovered during a scan.

Each finding stores:

- Title.
- Severity.
- Category.
- Affected URL.
- Description.
- Evidence.
- Impact.
- Remediation.
- Confidence.
- Risk score.
- Created date.

Severity levels:

- Critical: most urgent.
- High: serious risk.
- Medium: important but less urgent.
- Low: minor weakness.
- Info: informational observation.

Example output:

```json
{
  "id": 5,
  "scan_id": 2,
  "target_id": 1,
  "title": "Missing Content Security Policy",
  "severity": "high",
  "category": "Browser Defenses",
  "affected_url": "https://example.com",
  "description": "The response does not set a Content Security Policy header.",
  "evidence": "Content-Security-Policy header missing from the response.",
  "impact": "Injected JavaScript would have a wider attack surface.",
  "remediation": "Add a restrictive Content Security Policy header.",
  "confidence": "high",
  "risk_score": 7.4
}
```

What the UI shows:

- Finding title.
- Severity badge.
- Category.
- Affected asset.
- Confidence.
- Evidence.
- Impact.
- Remediation.
- OWASP-style mapping text.
- Status or retest note.

---

### 5.5 Risk Score

The risk score is a number from 0 to 10.

Purpose:

It helps the user quickly understand how risky a scan result is.

How it works:

- Each severity has a weight.
- Critical is weighted highest.
- High is below critical.
- Medium, low, and info have smaller weights.
- The score uses the highest severity plus a small increase based on the average weight of all findings.

Severity weights:

```text
critical = 10
high     = 8
medium   = 5
low      = 2
info     = 0
```

Example:

If a scan has one critical finding and several medium findings, the score will be close to 10 because the highest issue is critical.

Output:

```json
{
  "risk_score": 8.6
}
```

---

### 5.6 Posture Score

The posture score is a number from 0 to 100.

Purpose:

It shows how healthy the target is from a security configuration point of view.

Categories:

- Transport Security.
- Browser Defense.
- Session Safety.
- Exposure Hygiene.
- Authentication Surface.

The scan starts from 100. Findings reduce the score based on severity.

Penalty example:

```text
critical = -30
high     = -20
medium   = -10
low      = -5
info     = 0
```

Output:

```json
{
  "overall_posture_score": 75,
  "posture_transport_security": 80,
  "posture_browser_defense": 70,
  "posture_session_safety": 85,
  "posture_exposure_hygiene": 70,
  "posture_authentication_surface": 72
}
```

Simple explanation:

Risk score answers: "How dangerous are the findings?"

Posture score answers: "How healthy is the application overall?"

---

### 5.7 Crawl Map

The crawl map stores pages visited during a safe scan.

Each crawl node stores:

- URL.
- Path.
- HTTP status code.
- Content type.
- Page title.
- Depth.
- Parent URL.
- Whether the page has forms.
- Whether the page has a password field.
- Finding count.

Example output:

```json
{
  "url": "https://example.com/login",
  "path": "/login",
  "status_code": 200,
  "content_type": "text/html",
  "page_title": "Login",
  "depth": 1,
  "parent_url": "https://example.com/",
  "has_forms": true,
  "has_password_field": true,
  "finding_count": 2
}
```

Purpose:

The crawl map helps the analyst understand what pages were discovered and where forms or login fields exist.

---

### 5.8 Evidence Artifacts

Evidence artifacts are stored proof that a finding or observation was real.

Current evidence types:

- Header snapshot.
- HTML snippet.
- Related URL.

Example:

```json
{
  "artifact_type": "header_snapshot",
  "title": "Base URL Response Headers",
  "redacted_text": "{ 'server': 'nginx', 'content-type': 'text/html' }",
  "related_url": "https://example.com"
}
```

Purpose:

Evidence makes reports more trustworthy because the user can see what the scanner observed.

Important:

Evidence is redacted or limited. The scanner stores lightweight proof, not sensitive secrets.

---

### 5.9 Posture Drift

Posture drift compares the current scan with the previous completed scan for the same target.

It tracks:

- New findings.
- Resolved findings.
- Unchanged findings.
- Risk score change.
- Posture score change.
- Summary text.

Example output:

```json
{
  "current_scan_id": 5,
  "previous_scan_id": 3,
  "new_findings_count": 2,
  "resolved_findings_count": 1,
  "unchanged_findings_count": 3,
  "risk_score_delta": 1.2,
  "posture_score_delta": -8,
  "summary": "Posture worsened (2 new issues)"
}
```

Simple explanation:

Posture drift tells the user whether the application became safer or weaker since the last scan.

---

### 5.10 Reports

Reports are generated from completed scan data.

Each report stores:

- Report title.
- Executive summary.
- HTML content.
- Scan ID.
- Target ID.
- Created date.

Input:

```text
POST /api/reports/generate/{scan_id}
```

Output:

```json
{
  "id": 1,
  "scan_id": 3,
  "target_id": 1,
  "title": "Security Assessment Report - Demo Target",
  "executive_summary": "Automated assessment resulted in 4 findings.",
  "html_content": "<html>...</html>",
  "created_at": "date-time"
}
```

Purpose:

Reports are meant for sharing assessment results with stakeholders, managers, or developers.

---

### 5.11 Policies

Policies are JSON-based security baselines.

They describe expected security conditions, such as:

- HSTS should exist.
- Session cookies should be secure.
- Content Security Policy should exist.
- Backup files should not be public.
- CORS should not be overly permissive.

Policy files live in:

```text
backend/app/policies/
```

Example policy check:

```json
{
  "id": "hsts",
  "title": "Strict-Transport-Security present",
  "expected_state": "All public pages should send HSTS with a long max-age.",
  "severity_impact": "high",
  "related_finding_titles": ["Missing HSTS"]
}
```

How policy results work:

- The backend loads policy JSON files.
- It compares policy check related titles with scan findings.
- If related findings exist, the check fails.
- If no related finding exists, the check passes.

Output:

```json
{
  "policy_id": "web-baseline",
  "title": "Web Baseline",
  "checks": [
    {
      "check_id": "hsts",
      "title": "Strict-Transport-Security present",
      "status": "failed",
      "violating_findings": ["Missing HSTS"]
    }
  ]
}
```

---

### 5.12 Notifications

Notifications inform the user when important things happen.

Examples:

- Scan started.
- Scan completed.
- Scan failed.
- Critical findings detected.
- Report generated.

Each notification stores:

- Title.
- Message.
- Type.
- Related entity type.
- Related entity ID.
- Read/unread status.
- Created date.

---

### 5.13 Search

Search helps users quickly find targets, scans, findings, and reports.

Input:

```text
query = "orion"
```

Output:

```json
{
  "targets": [],
  "scans": [],
  "findings": [],
  "reports": []
}
```

Purpose:

Instead of manually opening every page, the user can search globally.

---

### 5.14 Profile And Settings

Profile stores user information:

- Full name.
- Email.
- Organization.
- Role.
- Avatar initials.

Settings stores scanner and report preferences:

- Theme.
- Default scan profile.
- Request timeout.
- Max pages for Standard Scan.
- Max pages for Full Scan.
- Max crawl depth.
- Rate limit delay.
- Report company name.
- Report footer text.
- Auto-generate report flag.

---

## 6. Technology Stack

### Frontend

```text
React
TypeScript
Vite
Tailwind CSS
Recharts
Lucide React
Sonner
React Router
```

Frontend responsibility:

- Display dashboard.
- Show targets.
- Start scans.
- Show scan records.
- Show findings.
- Show reports.
- Show policies.
- Show notifications.
- Provide profile and settings forms.

### Backend

```text
Python
FastAPI
SQLAlchemy
SQLite
Pydantic
httpx
BeautifulSoup
Jinja2
```

Backend responsibility:

- Store data.
- Expose REST API endpoints.
- Run scanner logic.
- Calculate risk and posture.
- Generate reports.
- Store findings and evidence.
- Load policy files.

### Deployment

```text
Docker
Docker Compose
```

Docker Compose starts:

- Backend API.
- Frontend app.
- Demo target web application.

---

## 7. Repository Structure

```text
vulnscope/
  backend/
    app/
      main.py
      models.py
      schemas.py
      database.py
      routers/
      scanner/
      policies/
    requirements.txt
    Dockerfile

  frontend/
    src/
      App.tsx
      main.tsx
      pages/
      components/
      data/
      types/
    package.json
    Dockerfile

  demo-target/
    main.py
    Dockerfile

  docker-compose.yml
  PROJECT_OVERVIEW.md
```

---

## 8. Important Backend Files

### `backend/app/main.py`

This is the backend entry point.

It:

- Creates the FastAPI app.
- Enables CORS.
- Creates database tables.
- Seeds default settings and profile.
- Registers routers.
- Provides health check endpoint.

Important routes are mounted here:

```text
/api/targets
/api/scans
/api/reports
/api/dashboard
/api/policies
/api/notifications
/api/profile
/api/settings
/api/search
```

---

### `backend/app/models.py`

This defines database tables.

Main tables:

- `targets`
- `scans`
- `findings`
- `crawl_nodes`
- `posture_diffs`
- `evidence_artifacts`
- `reports`
- `notifications`
- `user_profiles`
- `app_settings`

Simple explanation:

Models describe how data is saved in the database.

---

### `backend/app/schemas.py`

This defines API request and response shapes using Pydantic.

Simple explanation:

Schemas describe what data the API accepts and returns.

Example:

- `TargetCreate` describes input for creating a target.
- `ScanCreate` describes input for starting a scan.
- `Finding` describes output for a finding.
- `DashboardSummary` describes output for dashboard data.

---

### `backend/app/scanner/orchestrator.py`

This is the main scanner workflow.

It does the following:

1. Loads the scan from the database.
2. Marks scan as running.
3. Loads the target.
4. Creates a "Scan Started" notification.
5. Fetches the base URL.
6. Captures response header evidence.
7. Runs passive checks.
8. If profile allows, checks exposed files.
9. If profile allows, crawls pages.
10. Checks forms and login surfaces.
11. Saves crawl map nodes.
12. Saves HTML snippet evidence for login-like pages.
13. Saves findings.
14. Updates crawl node finding counts.
15. Calculates risk score.
16. Calculates posture scores.
17. Marks scan as completed.
18. Compares with previous scan.
19. Stores posture drift.
20. Creates completion and critical finding notifications.
21. If an error occurs, marks scan as failed.

Simple explanation:

This file is the brain of the scanner.

---

## 9. Important Frontend Files

### `frontend/src/App.tsx`

This defines frontend routing and layout.

Routes:

```text
/                Landing page
/dashboard       Main dashboard
/targets         Target management
/scans           Scan records and scan details
/scans/new       New scan form
/reports         Report listing and preview
/policies        Policy packs
/search          Search results
/profile         User profile
/notifications   Notifications
/settings        App settings
```

---

### `frontend/src/components/layout/Sidebar.tsx`

This displays the left navigation.

It contains:

- Logo/title.
- Dashboard link.
- Targets link.
- Scans link.
- Reports link.
- Policies link.
- Settings link.

---

### `frontend/src/components/layout/Topbar.tsx`

This displays the top navigation bar.

It contains:

- Search box.
- Notification menu.
- Profile menu.

---

### `frontend/src/components/ui.tsx`

This contains reusable UI components.

Examples:

- `PageShell`
- `PageHeader`
- `SectionCard`
- `StatCard`
- `SeverityBadge`
- `StatusBadge`
- `RiskScoreBadge`
- `FindingCard`
- `PolicyCard`
- `EmptyState`

Purpose:

These components keep the UI consistent and professional.

---

### `frontend/src/data/demoData.ts`

This file contains demo data and local demo functions used by the frontend.

It allows the UI to work as a polished demo even without relying on a live backend call for every screen.

It includes demo versions of:

- Targets.
- Scans.
- Findings.
- Crawl nodes.
- Evidence.
- Reports.
- Notifications.
- Policies.
- Profile.
- Settings.

Important note:

The project also has a real FastAPI backend and scanner. The demo data layer makes the frontend interview/demo experience smooth and predictable.

---

## 10. Scanner Checks

The backend scanner includes checks for:

### Security Headers

Checks whether important browser security headers are present.

Examples:

- Content Security Policy.
- X-Frame-Options.
- X-Content-Type-Options.
- Referrer Policy.

### Cookies

Checks cookie safety.

Examples:

- Secure flag.
- HttpOnly flag.
- SameSite flag.

### CORS

Checks whether Cross-Origin Resource Sharing is too permissive.

Example problem:

```text
Access-Control-Allow-Origin: *
```

### TLS / HTTPS

Checks HTTPS-related posture.

Examples:

- Whether HTTPS is used.
- Whether mixed content appears.

### Exposed Files

Checks for publicly exposed sensitive paths.

Examples:

- `.git`
- backup files
- config-like files

### Technology Disclosure

Checks whether the application leaks technology details.

Examples:

- Server header.
- Framework header.
- Version disclosure.

### Forms And Authentication Surface

Checks pages for:

- Forms.
- Password fields.
- Login-related exposure.
- Missing defensive attributes.

---

## 11. Full User Flow

### Step 1: User Opens The App

The user sees the landing page or dashboard.

### Step 2: User Adds A Target

The user enters:

- Name.
- Base URL.
- Environment.
- Authorization confirmation.

The platform saves the target.

### Step 3: User Starts A Scan

The user selects:

- Target.
- Scan profile.

The backend creates a scan record.

### Step 4: Backend Runs Scanner

The scanner:

- Fetches the website.
- Runs security checks.
- Crawls pages if applicable.
- Saves findings.
- Saves evidence.
- Saves crawl map.
- Calculates scores.
- Creates notifications.

### Step 5: User Reviews Results

The user can open:

- Scan details.
- Findings.
- Crawl map.
- Evidence.
- Policy results.
- Drift comparison.

### Step 6: User Generates Or Views Report

The report page shows:

- Title.
- Target.
- Scan profile.
- Date.
- Findings count.
- Risk score.
- Export/view action.

### Step 7: User Tracks Improvement

After more scans, VulnScope compares scan results and shows whether posture improved or worsened.

---

## 12. Main Inputs And Outputs

### Target Input

```json
{
  "name": "My Website",
  "base_url": "https://mywebsite.com",
  "environment": "production",
  "authorization_confirmed": true
}
```

Target Output:

```json
{
  "id": 1,
  "name": "My Website",
  "base_url": "https://mywebsite.com",
  "domain": "mywebsite.com",
  "environment": "production",
  "authorization_confirmed": true,
  "created_at": "date-time"
}
```

### Scan Input

```json
{
  "target_id": 1,
  "profile": "Full Safe Scan"
}
```

Scan Output:

```json
{
  "id": 1,
  "target_id": 1,
  "profile": "Full Safe Scan",
  "status": "completed",
  "total_findings": 5,
  "risk_score": 6.8,
  "overall_posture_score": 65
}
```

### Finding Output

```json
{
  "title": "Weak session cookie flags",
  "severity": "critical",
  "category": "Session Safety",
  "affected_url": "https://mywebsite.com/login",
  "evidence": "Set-Cookie header observed without Secure and SameSite flags.",
  "impact": "Session hijacking and cross-site request abuse become easier.",
  "remediation": "Set Secure, HttpOnly, and SameSite on session cookies."
}
```

### Report Output

```json
{
  "title": "Security Assessment Report - My Website",
  "executive_summary": "Automated assessment resulted in 5 findings.",
  "html_content": "<html>...</html>"
}
```

---

## 13. API Endpoints

### Health

```text
GET /health
```

Returns:

```json
{
  "status": "ok"
}
```

### Targets

```text
GET    /api/targets
POST   /api/targets
GET    /api/targets/{target_id}
DELETE /api/targets/{target_id}
```

### Scans

```text
POST /api/scans/start
GET  /api/scans
GET  /api/scans/{scan_id}
GET  /api/scans/{scan_id}/findings
GET  /api/scans/{scan_id}/crawl-map
GET  /api/scans/{scan_id}/diff
GET  /api/scans/{scan_id}/evidence
GET  /api/scans/{scan_id}/policy-results
```

### Reports

```text
POST /api/reports/generate/{scan_id}
GET  /api/reports
GET  /api/reports/{report_id}
GET  /api/reports/{report_id}/download
```

### Dashboard

```text
GET /api/dashboard/summary
```

### Policies

```text
GET /api/policies
```

### Other App Routes

```text
/api/notifications
/api/profile
/api/settings
/api/search
```

---

## 14. Database Tables Explained Simply

### `targets`

Stores websites that can be scanned.

### `scans`

Stores scan runs and scan scores.

### `findings`

Stores discovered security issues.

### `crawl_nodes`

Stores pages discovered during crawling.

### `evidence_artifacts`

Stores proof such as response headers or HTML snippets.

### `posture_diffs`

Stores comparison between current and previous scans.

### `reports`

Stores generated HTML reports.

### `notifications`

Stores alerts shown to the user.

### `user_profiles`

Stores analyst profile information.

### `app_settings`

Stores scanner and report settings.

---

## 15. How To Run The Project

### Option 1: Run With Docker Compose

From the project root:

```bash
docker-compose up --build
```

This starts:

- Frontend on `http://localhost:5173`
- Backend API on `http://localhost:8000`
- API docs on `http://localhost:8000/docs`
- Demo target on `http://localhost:8081`

For Docker-based scanning, use this target URL:

```text
http://demo-target:8080
```

From the host browser, the demo target is available at:

```text
http://localhost:8081
```

---

### Option 2: Run Frontend Locally

```bash
cd frontend
npm install
npm run dev
```

If PowerShell blocks `npm`, use:

```bash
npm.cmd run dev
```

Frontend default URL:

```text
http://localhost:5173
```

If port `5173` is busy, Vite may start on another port such as `5174`.

---

### Option 3: Run Backend Locally

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Backend URL:

```text
http://localhost:8000
```

API documentation:

```text
http://localhost:8000/docs
```

---

## 16. How To Test The Project

### Frontend Build

```bash
cd frontend
npm.cmd run build
```

Expected result:

- TypeScript compiles.
- Vite creates production build.

### Frontend Lint

```bash
cd frontend
npm.cmd run lint
```

Expected result:

- No lint errors.

### Backend Health Check

After starting backend:

```text
GET http://localhost:8000/health
```

Expected output:

```json
{
  "status": "ok"
}
```

---

## 17. How To Explain The Implementation

### Simple Explanation

The project has three main parts:

1. **Frontend**
   - The user interface.
   - Built with React.
   - Shows dashboards, tables, cards, charts, and forms.

2. **Backend**
   - The API and scanner.
   - Built with FastAPI.
   - Stores data, runs scans, and returns results.

3. **Database**
   - Stores targets, scans, findings, reports, and settings.
   - Uses SQLite through SQLAlchemy.

### Technical Explanation

When a scan starts, the frontend sends target ID and scan profile to the backend. The backend creates a scan row with `queued` status. Then a background task runs the scanner. The scanner fetches the target, performs safe checks, crawls pages when allowed, records findings, calculates risk and posture, saves evidence, compares with previous scans, updates scan status, and creates notifications.

The frontend then displays this stored data through dashboard cards, scan tables, finding cards, policy results, charts, and reports.

---

## 18. Why This Project Is Useful In An Interview

This project demonstrates:

- Full-stack development.
- Cybersecurity domain knowledge.
- REST API design.
- Database modeling.
- Background task processing.
- Risk scoring logic.
- Security posture scoring.
- Report generation.
- Dashboard design.
- Safe scanning principles.
- Docker-based deployment.
- Clean UI/UX thinking.

It is not just a CRUD app. It has real workflow logic:

```text
Target -> Scan -> Findings -> Evidence -> Scores -> Drift -> Report
```

That workflow is what makes it a complete cybersecurity product prototype.

---

## 19. Safety And Ethical Limits

VulnScope is designed for authorized testing only.

It includes authorization confirmation before target scanning.

It does not include:

- Password attacks.
- Exploit execution.
- Shell access.
- Malware behavior.
- Account takeover.
- Destructive scanning.
- Fake offensive exploitation features.

The project focuses on defensive assessment and visibility.

---

## 20. Current Limitations

Current limitations:

- The frontend currently includes a demo data layer for smooth presentation.
- The scanner focuses on safe web posture checks, not deep exploitation.
- SQLite is suitable for demo and local use, but production would usually use PostgreSQL.
- Authentication and role-based access control are not fully implemented.
- Report export is HTML-based.
- Some checks are simplified for educational and demo purposes.

These are acceptable for a college, portfolio, or interview project because the goal is to show a complete, safe, understandable security assessment platform.

---

## 21. Future Improvements

Possible future improvements:

- Add user authentication.
- Add role-based access control.
- Connect frontend directly to every backend endpoint instead of using demo data for some screens.
- Add PostgreSQL for production.
- Add PDF report export.
- Add scheduled scans.
- Add email notifications.
- Add scan comparison charts.
- Add more policy packs.
- Add asset grouping by organization or team.
- Add CI/CD deployment.

---

## 22. Final Interview Summary

VulnScope is a full-stack web application security assessment platform. It lets a user add authorized web targets, run safe scan profiles, detect browser-facing security weaknesses, store findings and evidence, calculate risk and posture scores, compare scans over time, map findings to policies, and generate reports.

The frontend is built with React, TypeScript, Tailwind CSS, and Recharts. The backend is built with FastAPI, SQLAlchemy, SQLite, and Python scanner modules. Docker Compose can run the frontend, backend, and demo target together.

The main value of the project is that it turns raw web security checks into an understandable security dashboard for both technical and non-technical users.

