# Week 1 Report — SAST/DAST CI/CD & Baseline Analysis

**Project:** Project Sentinel  
**Phase:** Phase 1 — Infrastructure & Cyber Security Baseline  
**Week:** 1 — SAST/DAST CI/CD Integration & Baseline Analysis  
**Environment:** Ubuntu + Docker  

---

## Mapping to mentor tasks

| # | Requirement | What we did |
|---|-------------|-------------|
| **(1) Context** | Build CI/CD foundation | GitHub Actions workflow [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) runs Semgrep + Trivy + ZAP + Postgres ingest on push/PR/`workflow_dispatch` |
| **(2) Deliverable** | Deploy staging web app; integrate SAST & DAST into CI/CD | OWASP Juice Shop on Docker (`:3000`); Semgrep (SAST), Trivy (image), ZAP (DAST) wired into local script and GitHub Actions |
| **(3) Practical** | Automate scans; aggregate JSON into a data lake; manual attack-surface analysis | [`scripts/run_scans.sh`](scripts/run_scans.sh) → JSON in `results/` → [`scripts/ingest_results.py`](scripts/ingest_results.py) → Postgres `scan_findings`; analysis in [`docs/attack-surface.md`](docs/attack-surface.md) |

Mentor step checklist:

1. **Docker** — Compose stack for Juice Shop, demo app, Postgres, ingest
2. **CI/CD** — GitHub Actions free runners (practice pipeline)
3. **Vulnerability scanners in Docker** — Semgrep / Trivy / ZAP images
4. **Run + integrate** — `./scripts/run_scans.sh` and CI workflow
5. **Output → database** — unified `scan_findings` table with `raw_json` JSONB

---

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Juice Shop     │     │  Semgrep     │     │  Postgres       │
│  :3000 staging  │◄────│  Trivy       │────►│  findings DB    │
│  demo_app :8080 │     │  ZAP         │     │  scan_findings  │
└─────────────────┘     └──────────────┘     └─────────────────┘
        ▲                      ▲
        │                      │
   docker compose        run_scans.sh /
                         GitHub Actions
```

---

## What was implemented (from scratch)

Workspace was rebuilt (previous code replaced):

| Component | Path |
|-----------|------|
| Staging Compose | `docker-compose.yml` |
| Vulnerable demo (SAST target) | `demo_app/app.py` + Dockerfile |
| Data lake schema | `db/init.sql` |
| Local automation | `scripts/run_scans.sh` |
| JSON → DB normalizer | `scripts/ingest_results.py` |
| Ingest container | `scripts/Dockerfile.ingest` |
| CI/CD | `.github/workflows/security-scan.yml` |
| Attack surface notes | `docs/attack-surface.md` |

---

## How to reproduce

```bash
docker compose up -d
./scripts/run_scans.sh
```

Verify:

```bash
docker compose exec db psql -U sentinel -d findings -c \
  "SELECT tool, severity, COUNT(*) AS n FROM scan_findings GROUP BY 1,2 ORDER BY 1,2;"
```

---

## Baseline scan results (local run)

Verified after a clean ingest (`scan_id` generated per run). Totals from this Week 1 baseline:

| Tool | Role | Findings ingested |
|------|------|-------------------|
| **Semgrep** | SAST on `demo_app` | **4** |
| **Trivy** | Container image CVEs (`juice-shop`) | **84** |
| **ZAP** | DAST baseline on Juice Shop | **10** |
| | **Total** | **98** |

### By severity

| Tool | Severity | Count |
|------|----------|------:|
| semgrep | ERROR | 2 |
| semgrep | WARNING | 2 |
| trivy | CRITICAL | 6 |
| trivy | HIGH | 37 |
| trivy | MEDIUM | 30 |
| trivy | LOW | 11 |
| zap | Medium | 2 |
| zap | Low | 5 |
| zap | Informational | 3 |

Artifacts: `results/semgrep.json`, `results/trivy.json`, `results/zap.json`, `results/zap.html`.

---

## Manual analysis summary

See [`docs/attack-surface.md`](docs/attack-surface.md). Short version:

- Juice Shop presents a large SPA + REST attack surface; ZAP crawled ~158 URLs.
- Baseline DAST highlights missing CSP / COEP-style headers and related passive findings.
- Trivy shows many dependency/OS CVEs — primary volume of the data lake.
- Demo app confirms SAST catches injection / unsafe patterns end-to-end into Postgres.

---

## CI/CD status

Workflow ready on GitHub:

- Starts Juice Shop + Postgres as job services
- Runs Semgrep (Docker), Trivy Action, ZAP baseline (Docker)
- Ingests reports into Postgres
- Uploads JSON/HTML as workflow artifacts (14-day retention)

Push this repo to GitHub and open/merge to `main` (or use **Actions → Security Scan → Run workflow**) to execute on free runners.

---

## Conclusion

Week 1 deliverables are complete: staging app on Docker, automated SAST/DAST in local + GitHub CI/CD, JSON aggregated into a Postgres data lake, and an initial attack-surface write-up for the staging application.
