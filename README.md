# VulnScope - Automated Web Application Security Assessment Platform

VulnScope is a modern, independent cybersecurity assessment platform designed for safe, authorized web application security scanning and report generation. It performs reconnaissance, passive vulnerability checks, risk analysis, and structured reporting to identify security weaknesses before attackers do.

## Features

- **Safe Reconnaissance**: Uses passive and non-destructive checks (no brute-force, no exploit payloads).
- **Comprehensive Checks**: Identifies exposed services, missing security headers, insecure cookies, CORS misconfigurations, mixed content, and more.
- **Risk Scoring**: Automatically calculates CVSS-inspired risk scores based on finding severity.
- **Remediation Engine**: Provides actionable remediation advice for identified vulnerabilities.
- **Professional Reporting**: Generates detailed HTML/PDF reports with executive summaries and evidence.
- **Modern UI**: A sleek, dark-themed dashboard built with React, Tailwind CSS, and Recharts.

## Architecture & Tech Stack

- **Frontend**: React + Vite, TypeScript, Tailwind CSS, Recharts, React Router
- **Backend**: Python FastAPI, SQLite, SQLAlchemy ORM, Pydantic, httpx, BeautifulSoup4, Jinja2
- **Deployment**: Docker, Docker Compose

## Quick Start (Docker)

1. Clone the repository and navigate to the root directory.
2. Ensure you have Docker and Docker Compose installed.
3. Run the following command:

   ```bash
   docker-compose up --build
   ```

4. Open `http://localhost:5173` in your browser to access the VulnScope dashboard.
5. The backend API is available at `http://localhost:8000/docs` (Swagger UI).

## Safe Scanning Disclaimer

VulnScope is built exclusively for **authorized** web application security scanning. It requires explicit confirmation of authorization before a target can be added. Do not use this tool against systems you do not own or have explicit permission to test.

## Resume Bullet Point

*“Developed an automated web security assessment platform that performs reconnaissance, vulnerability scanning, and security analysis to identify exposed services, insecure configurations, authentication weaknesses, and common web application vulnerabilities. Designed the platform to generate structured assessment reports and remediation recommendations, streamlining vulnerability assessment and penetration testing workflows.”*
