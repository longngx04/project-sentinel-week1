# Project Sentinel — Week 1

SAST/DAST CI/CD integration & security baseline for a staging web application.

## What this repo does

1. Deploys **OWASP Juice Shop** (company web app replica) + a small vulnerable **demo_app** via Docker Compose
2. Runs **Semgrep** (SAST), **Trivy** (container), **OWASP ZAP** (DAST) — all in Docker
3. Aggregates JSON reports into **Postgres** (`scan_findings` data lake)
4. Automates the same pipeline on **GitHub Actions**

## Prerequisites

- Ubuntu (or WSL2 + Debian/Ubuntu on Windows)
- Docker Engine + Docker Compose plugin
- `curl`

## Quick start

```bash
# Start staging stack
docker compose up -d

# Juice Shop:  http://localhost:3000
# Demo app:    http://localhost:8080
# Postgres:    localhost:5432  (user/pass/db: sentinel/sentinel/findings)

# Run full SAST + DAST + ingest pipeline
./scripts/run_scans.sh
```

## Query the data lake

```bash
docker compose exec db psql -U sentinel -d findings -c \
  "SELECT tool, severity, COUNT(*) AS n FROM scan_findings GROUP BY 1,2 ORDER BY 1,2;"
```

## CI/CD

Workflow: [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)

Triggers on `push` / `pull_request` to `main`, and `workflow_dispatch`.

## Layout

```
docker-compose.yml              # juice-shop, demo-app, postgres, ingest
demo_app/                       # intentionally vulnerable Python app (SAST target)
db/init.sql                     # scan_findings schema
scripts/run_scans.sh            # local automated scans
scripts/ingest_results.py       # JSON → Postgres
.github/workflows/security-scan.yml
docs/attack-surface.md          # manual attack-surface notes
REPORT.md                       # Week 1 completion report
```

## Docs

- [Attack surface analysis](docs/attack-surface.md)
- [Week 1 report](REPORT.md)
