#!/usr/bin/env python3
"""Ingest scanner result JSON files into Postgres (scan_findings)."""

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
        message = extra.get("message")
        insert_finding(
            cur,
            scan_id,
            "semgrep",
            severity=extra.get("severity"),
            rule_id=r.get("check_id"),
            title=message,
            file_path=r.get("path"),
            line_start=start.get("line"),
            description=message,
            raw=r,
        )
        count += 1
    return count


def ingest_trivy(data: dict, scan_id: str, cur) -> int:
    count = 0
    for result in data.get("Results", []):
        target = result.get("Target")

        for vuln in result.get("Vulnerabilities") or []:
            insert_finding(
                cur,
                scan_id,
                "trivy",
                severity=vuln.get("Severity"),
                rule_id=vuln.get("VulnerabilityID"),
                title=vuln.get("Title") or vuln.get("VulnerabilityID"),
                file_path=vuln.get("PkgName") or target,
                description=vuln.get("Description"),
                raw=vuln,
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
                description=secret.get("Category"),
                raw=secret,
            )
            count += 1

        for misconfig in result.get("Misconfigurations") or []:
            cause = misconfig.get("CauseMetadata") or {}
            insert_finding(
                cur,
                scan_id,
                "trivy",
                severity=misconfig.get("Severity"),
                rule_id=misconfig.get("ID") or misconfig.get("AVDID"),
                title=misconfig.get("Title"),
                file_path=target,
                line_start=cause.get("StartLine"),
                description=misconfig.get("Description") or misconfig.get("Message"),
                raw=misconfig,
            )
            count += 1

    return count


def ingest_zap(data: dict, scan_id: str, cur) -> int:
    count = 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = ZAP_RISK.get(str(alert.get("riskcode")), alert.get("riskdesc"))
            title = alert.get("name") or alert.get("alert")
            rule_id = alert.get("alertRef") or alert.get("pluginid")
            description = strip_html(alert.get("desc"))
            instances = alert.get("instances") or [{}]

            for inst in instances:
                insert_finding(
                    cur,
                    scan_id,
                    "zap",
                    severity=severity,
                    rule_id=rule_id,
                    title=title,
                    file_path=inst.get("uri"),
                    description=description,
                    raw={"alert": alert, "instance": inst},
                )
                count += 1
    return count


def detect_tool(path: str, data: dict) -> str:
    name = Path(path).name.lower()
    if "semgrep" in name:
        return "semgrep"
    if "trivy" in name:
        return "trivy"
    if "zap" in name:
        return "zap"

    if "ArtifactName" in data or data.get("SchemaVersion") is not None:
        return "trivy"
    if isinstance(data.get("site"), list) or data.get("@programName") == "ZAP":
        return "zap"
    if isinstance(data.get("results"), list):
        return "semgrep"

    raise ValueError(f"Cannot detect scanner tool for {path}")


INGESTERS = {
    "semgrep": ingest_semgrep,
    "trivy": ingest_trivy,
    "zap": ingest_zap,
}


def default_paths() -> list[str]:
    results_dir = Path("results")
    candidates = [
        results_dir / "semgrep.json",
        results_dir / "trivy-juice.json",
        results_dir / "zap-juice.json",
    ]
    return [str(p) for p in candidates if p.is_file()]


def main() -> None:
    paths = sys.argv[1:] or default_paths()
    if not paths:
        print("No result files found. Pass JSON paths as arguments.", file=sys.stderr)
        sys.exit(1)

    scan_id = str(uuid.uuid4())
    conn = psycopg2.connect(**DB)
    cur = conn.cursor()

    print(f"scan_id={scan_id}")
    for path in paths:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        tool = detect_tool(path, data)
        count = INGESTERS[tool](data, scan_id, cur)
        print(f"{path}: ingested {count} {tool} finding(s)")

    conn.commit()
    cur.execute(
        """
        SELECT tool, severity, count(*)
        FROM scan_findings
        WHERE scan_id = %s
        GROUP BY 1, 2
        ORDER BY 1, 2
        """,
        (scan_id,),
    )
    print("Inserted. Summary:")
    for row in cur.fetchall():
        print(row)

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
