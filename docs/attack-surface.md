# Attack Surface Analysis — Week 1 Baseline

Manual review of the staging environment after deploying OWASP Juice Shop and the local demo app.

## Scope

| Asset | URL / location | Role |
|-------|----------------|------|
| OWASP Juice Shop | `http://localhost:3000` | Staging replica of a company e-commerce web app (intentionally vulnerable) |
| Demo app | `http://localhost:8080` | Small Python service used as a SAST target |
| Postgres data lake | `localhost:5432` / db `findings` | Aggregates scanner JSON (not an attack target for this week) |

## Juice Shop — entry points

Observed via browser, `robots.txt`, `sitemap.xml`, and ZAP baseline crawl (~158 URLs).

### Public / unauthenticated

- **SPA frontend** (`/`) — Angular single-page app; most UI routes are client-side
- **Static assets** — JS chunks, CSS, favicon (cacheable; ZAP flagged cache / CSP issues)
- **`/robots.txt`**, **`/sitemap.xml`** — disclose paths of interest to scanners
- **`/ftp`** and related paths — directory-style endpoints (several returned 403 in baseline; still part of the surface)
- **Product / search / basket APIs** under `/rest/` and `/api/` (typical Juice Shop surface: login, search, feedback, file upload challenges)

### Authentication & session

- Login / registration flows (JWT-based in Juice Shop)
- Cookie and local-storage session material — ZAP baseline checks cookie flags / SameSite (many were PASS on this run; still review when auth is exercised)

### Sensitive or high-value areas (for follow-up DAST / manual tests)

| Area | Why it matters |
|------|----------------|
| Login / JWT | Broken auth, weak secrets, token leakage |
| Search / feedback forms | XSS, injection |
| File / FTP challenges | Path traversal, sensitive file disclosure |
| Admin / scoring / challenge APIs | Privilege escalation |
| Payment / basket | Business-logic abuse |

## Demo app — endpoints

Intentionally unsafe routes (for Semgrep / teaching only):

| Endpoint | Issue class |
|----------|-------------|
| `GET /user?name=` | SQL injection |
| `GET /ping?host=` | OS command injection |
| `GET /calc?expr=` | Code injection (`eval`) |
| `GET /file?name=` | Path traversal |
| `GET /hash?password=` | Weak hashing (MD5) |
| Hardcoded secrets in source | Credential exposure |

## Tool coverage vs surface

| Layer | Tool | What it covers |
|-------|------|----------------|
| Source code | Semgrep | OWASP Top 10 / Python rules on `demo_app` |
| Container image | Trivy | OS + Node dependency CVEs in `bkimminich/juice-shop` |
| Running HTTP app | ZAP baseline | Passive / light active checks on Juice Shop (headers, CSP, JS risks, etc.) |

## Baseline takeaways

1. **Staging is reachable** and crawlable; Juice Shop exposes a broad SPA + REST surface suitable for ongoing DAST.
2. **Missing / weak browser security headers** (CSP, COEP) showed up in ZAP WARN findings — easy hardening wins later.
3. **Image CVEs** dominate volume (Trivy); treat CRITICAL/HIGH dependency upgrades as a Week 1 backlog item.
4. **SAST on demo_app** confirms the pipeline can catch injection / unsafe APIs before deploy.
5. Next weeks (gateway / IAM) should sit **in front of** this staging app so agent and human traffic share one controlled entry point.

## References

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- Scan artifacts: `results/semgrep.json`, `results/trivy.json`, `results/zap.json`, `results/zap.html`
