#!/usr/bin/env bash
# Run SAST (Semgrep) + container scan (Trivy) + DAST (ZAP), then ingest into Postgres.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULTS_DIR="$ROOT/results"
mkdir -p "$RESULTS_DIR"

echo "==> [1/6] Starting staging stack (Juice Shop + Postgres + demo-app)"
docker compose up -d juice-shop db demo-app

echo "==> Waiting for Juice Shop..."
for i in $(seq 1 60); do
  if curl -sf http://127.0.0.1:3000/ >/dev/null 2>&1; then
    echo "Juice Shop is ready"
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    echo "Juice Shop did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

echo "==> Waiting for Postgres..."
for i in $(seq 1 30); do
  if docker compose exec -T db pg_isready -U sentinel -d findings >/dev/null 2>&1; then
    echo "Postgres is ready"
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    echo "Postgres did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

echo "==> [2/6] Semgrep SAST (demo_app)"
run_semgrep() {
  docker run --rm \
    -v "$ROOT/demo_app:/src:ro" \
    -v "$RESULTS_DIR:/out" \
    "$@"
}
if docker image inspect semgrep/semgrep:latest >/dev/null 2>&1; then
  run_semgrep semgrep/semgrep:latest \
    semgrep --config=p/owasp-top-ten --config=p/python --json --output=/out/semgrep.json /src || true
elif docker pull semgrep/semgrep:latest; then
  run_semgrep semgrep/semgrep:latest \
    semgrep --config=p/owasp-top-ten --config=p/python --json --output=/out/semgrep.json /src || true
elif [[ -x "$ROOT/.venv/bin/semgrep" ]]; then
  echo "Using local .venv Semgrep"
  "$ROOT/.venv/bin/semgrep" --config=p/owasp-top-ten --config=p/python --json --output="$RESULTS_DIR/semgrep.json" demo_app || true
else
  echo "semgrep image unavailable; using python:3.12-slim + pip"
  run_semgrep python:3.12-slim \
    bash -c 'pip install --quiet semgrep && semgrep --config=p/owasp-top-ten --config=p/python --json --output=/out/semgrep.json /src' || true
fi

echo "==> [3/6] Trivy container image scan (Juice Shop)"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$RESULTS_DIR:/out" \
  -v trivy-cache:/root/.cache/ \
  aquasec/trivy:latest \
  image \
    --format json \
    --output /out/trivy.json \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    --exit-code 0 \
    bkimminich/juice-shop:latest

echo "==> [4/6] ZAP DAST baseline against Juice Shop"
# ZAP writes into /zap/wrk; mount results dir there.
# Use compose network so hostname juice-shop resolves.
NETWORK="$(docker inspect sentinel-juice-shop -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
docker run --rm \
  --network "$NETWORK" \
  -v "$RESULTS_DIR:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
    -t http://juice-shop:3000 \
    -J zap.json \
    -r zap.html \
    -I || true

echo "==> [5/6] Ingest findings into Postgres"
docker compose --profile tools build ingest
docker compose --profile tools run --rm ingest /results

echo "==> [6/6] Summary from data lake"
docker compose exec -T db \
  psql -U sentinel -d findings -c \
  "SELECT tool, severity, COUNT(*) AS n FROM scan_findings GROUP BY tool, severity ORDER BY tool, severity;"

echo ""
echo "Done. Reports in $RESULTS_DIR"
echo "Query DB: docker compose exec db psql -U sentinel -d findings"
