#!/usr/bin/env python3
"""Normalize Semgrep / Trivy / ZAP JSON reports into Postgres scan_findings."""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from pathlib import Path

import psycopg2
from psycopg2.extras import Json

DB = dict(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "5432")),
    dbname=os.getenv("DB_NAME", "findings"),
    user=os.getenv("DB_USER", "sentinel"),
    password=os.getenv("DB_PASSWORD", "sentinel"),
)

INSERT_SQL = """
    INSERT INTO scan_findings
      (scan_id, tool, severity, rule_id, title, file_path, line_start, description, raw_json)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

ZAP_RISK = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}


def insert_finding(
    cur,
    scan_id,
    tool,
    *,
    severity=None,
    rule_id=None,
    title=None,
    file_path=None,
    line_start=None,
    description=None,
    raw=None,
):
    cur.execute(
        INSERT_SQL,
        (
            scan_id,
            tool,
            severity,
            rule_id,
            title,
            file_path,
            line_start,
            description,
            Json(raw),
        ),
    )


def strip_html(text: str | None) -> str | None:
    if not text:
        return text
    return re.sub(r"<[^>]+>", "", text).strip()


def ingest_semgrep(data: dict, scan_id: str, cur) -> int:
    count = 0
    for r in data.get("results", []):
        extra = r.get("extra") or {}
        start = r.get("start") or {}
        insert_finding(
            cur,
            scan_id,
            "semgrep",
            severity=(extra.get("severity") or "UNKNOWN").upper(),
            rule_id=r.get("check_id"),
            title=r.get("check_id"),
            file_path=r.get("path"),
            line_start=start.get("line"),
            description=extra.get("message"),
            raw=r,
        )
        count += 1
    return count


def ingest_trivy(data: dict, scan_id: str, cur) -> int:
    count = 0
    for result in data.get("Results") or []:
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            insert_finding(
                cur,
                scan_id,
                "trivy",
                severity=vuln.get("Severity"),
                rule_id=vuln.get("VulnerabilityID"),
                title=vuln.get("Title") or vuln.get("VulnerabilityID"),
                file_path=target,
                line_start=None,
                description=vuln.get("Description"),
                raw=vuln,
            )
            count += 1
        for mis in result.get("Misconfigurations") or []:
            insert_finding(
                cur,
                scan_id,
                "trivy",
                severity=mis.get("Severity"),
                rule_id=mis.get("ID"),
                title=mis.get("Title"),
                file_path=target,
                line_start=None,
                description=mis.get("Description") or mis.get("Message"),
                raw=mis,
            )
            count += 1
        for secret in result.get("Secrets") or []:
            insert_finding(
                cur,
                scan_id,
                "trivy",
                severity=secret.get("Severity"),
                rule_id=secret.get("RuleID"),
                title=secret.get("Title"),
                file_path=target,
                line_start=secret.get("StartLine"),
                description=secret.get("Match"),
                raw=secret,
            )
            count += 1
    return count


def ingest_zap(data: dict, scan_id: str, cur) -> int:
    count = 0
    for site in data.get("site") or []:
        for alert in site.get("alerts") or []:
            riskcode = str(alert.get("riskcode", "0"))
            insert_finding(
                cur,
                scan_id,
                "zap",
                severity=ZAP_RISK.get(riskcode, alert.get("riskdesc")),
                rule_id=str(alert.get("pluginid") or alert.get("alertRef") or ""),
                title=alert.get("alert") or alert.get("name"),
                file_path=(alert.get("instances") or [{}])[0].get("uri"),
                line_start=None,
                description=strip_html(alert.get("desc")),
                raw=alert,
            )
            count += 1
    return count


def detect_and_ingest(path: Path, scan_id: str, cur) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    name = path.name.lower()

    if "semgrep" in name or ("results" in data and "errors" in data):
        return ingest_semgrep(data, scan_id, cur)
    if "trivy" in name or "Results" in data:
        return ingest_trivy(data, scan_id, cur)
    if "zap" in name or "site" in data:
        return ingest_zap(data, scan_id, cur)

    # Fallback heuristics
    if isinstance(data, dict) and "results" in data:
        return ingest_semgrep(data, scan_id, cur)
    raise ValueError(f"Unrecognized report format: {path}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "Usage: ingest_results.py <report.json> [more.json ...]",
            file=sys.stderr,
        )
        print(
            "       ingest_results.py /results   # ingest all *.json in dir",
            file=sys.stderr,
        )
        return 2

    paths: list[Path] = []
    for arg in argv[1:]:
        p = Path(arg)
        if p.is_dir():
            paths.extend(sorted(p.glob("*.json")))
        else:
            paths.append(p)

    if not paths:
        print("No JSON reports found", file=sys.stderr)
        return 1

    scan_id = str(uuid.uuid4())
    conn = psycopg2.connect(**DB)
    total = 0
    try:
        with conn:
            with conn.cursor() as cur:
                for path in paths:
                    if not path.is_file():
                        print(f"Skip missing: {path}", file=sys.stderr)
                        continue
                    n = detect_and_ingest(path, scan_id, cur)
                    print(f"{path.name}: ingested {n} findings")
                    total += n
        print(f"Done. scan_id={scan_id} total={total}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
