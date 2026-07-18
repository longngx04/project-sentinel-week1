CREATE TABLE IF NOT EXISTS scan_findings (
  id            SERIAL PRIMARY KEY,
  scan_id       UUID NOT NULL,
  tool          TEXT NOT NULL,          -- semgrep | trivy | zap
  severity      TEXT,
  rule_id       TEXT,
  title         TEXT,
  file_path     TEXT,
  line_start    INT,
  description   TEXT,
  raw_json      JSONB NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_tool ON scan_findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON scan_findings(severity);