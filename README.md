# ShieldScan

**AI-Assisted Web Application Vulnerability Assessment Tool for Small Businesses**

[![CI](https://github.com/BreachDirect/shieldscan/actions/workflows/ci.yml/badge.svg)](https://github.com/BreachDirect/shieldscan/actions/workflows/ci.yml)

ShieldScan is a practical web-based security assessment tool built for the [Stellar Wave 7](https://www.drips.network/wave/stellar) program. It combines automated vulnerability scanning (OWASP ZAP or built-in scanner) with AI-generated plain-English reports and remediation guidance.

**Organisation:** [BreachDirect](https://github.com/BreachDirect) · **Sibling tool:** [RytScan](https://github.com/BreachDirect/RytScan) (Soroban contract scanner)

📄 [Product Requirements](docs/prd.md) · 🏗 [Architecture](docs/architecture.md)

## Features

- Web dashboard — enter a URL and start scanning
- **Broad built-in assessment** — crawls pages, checks headers, TLS, CORS, cookies, CSRF, sensitive paths, directory listing, mixed content, open redirects, SQLi/XSS on forms and URL parameters, technology fingerprinting
- OWASP ZAP integration for full DAST scanning (when Docker is running)
- Built-in scanner works without Docker — automatically used alongside ZAP or standalone
- AI-powered security reports (Claude API) with template fallback
- OWASP Top 10 category mapping
- Risk grading (A–F)
- HTML and Markdown report export
- Scan history

## Quick Start

```bash
cd shieldscan
chmod +x start.sh
./start.sh
```

Open **http://127.0.0.1:8000** in your browser.

## Full Setup (with OWASP ZAP + DVWA)

### 1. Install Docker

```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in for group change
```

### 2. Start lab targets and ZAP

```bash
./start-lab.sh full
docker compose ps
```

Verify all three containers (`shieldscan-zap`, `shieldscan-dvwa`, `shieldscan-juiceshop`) show `Up` in `docker compose ps` before running a full ZAP DAST scan.

| Service | URL |
|---------|-----|
| ShieldScan | http://127.0.0.1:8000 |
| OWASP ZAP API | http://127.0.0.1:8081 |
| DVWA | http://127.0.0.1:4280 |
| Juice Shop | http://127.0.0.1:3000 |

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
SCANNER_MODE=zap
ZAP_API_URL=http://127.0.0.1:8081
ZAP_API_KEY=changeme
ANTHROPIC_API_KEY=sk-ant-...   # optional — uses template report if empty
```

### 4. Start ShieldScan

```bash
./start.sh
```

## Demo Workflow (Presentation)

1. Start Docker services: `docker compose up -d`
2. Start ShieldScan: `./start.sh`
3. Open http://127.0.0.1:8000
4. Enter `http://127.0.0.1:4280` (DVWA) or `http://127.0.0.1:3000` (Juice Shop)
5. Check the authorisation box → **Start Security Scan**
6. Watch real-time progress
7. Show findings table, risk grade, and AI report
8. Export HTML report

## Scanner Modes

| Mode | When to use |
|------|-------------|
| `zap` | Docker + ZAP running — full DAST scan |
| `builtin` | No Docker — header checks + form injection probes |

Set in `.env`: `SCANNER_MODE=builtin` for quick testing without Docker.

## Project Structure

```
shieldscan/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Settings
│   ├── models.py            # Database models
│   ├── routers/scans.py     # API endpoints
│   └── services/
│       ├── zap_client.py    # OWASP ZAP API
│       ├── builtin_scanner.py
│       ├── passive_checks.py
│       ├── scan_orchestrator.py
│       └── ai_reporter.py
├── static/                  # Web dashboard
├── docker-compose.yml       # ZAP + DVWA + Juice Shop
└── start.sh
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| POST | `/api/scans` | Start scan |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/{id}` | Scan details |
| GET | `/api/scans/{id}/progress` | Live progress |
| GET | `/api/scans/{id}/report/html` | HTML report |
| GET | `/api/scans/{id}/report/download` | Markdown download |

## Development

```bash
make install-dev   # venv + prod + dev deps
make test          # pytest contract + health tests
make security-ci   # bandit + pip-audit
make ci            # lint + test + security-ci
make run           # start on :8000
```

## Ethics

Only scan systems you own or have **written permission** to test. DVWA and Juice Shop are deliberately vulnerable lab apps for education.

## Author

Michael Victory Osisienimo — [BreachDirect](https://github.com/BreachDirect)
