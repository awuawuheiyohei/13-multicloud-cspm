-- MultiCloud CSPM CIS Compliance - SQLite schema (v1.0)
-- 依据 Security_and_GRC_14_Projects_Plan #13 PRD

-- ============================================
-- 云资产快照 (Asset)
-- ============================================
CREATE TABLE IF NOT EXISTS cloud_assets (
    asset_id         TEXT PRIMARY KEY,                  -- A-001
    asset_name       TEXT NOT NULL,
    resource_type    TEXT NOT NULL,                     -- S3_BUCKET / EC2_SG / EBS / RDS / IAM_USER
    cloud_provider   TEXT NOT NULL DEFAULT 'AWS',     -- AWS / AZURE / GCP
    region           TEXT,
    account_id       TEXT NOT NULL,
    raw_config       TEXT NOT NULL,                     -- JSON 完整配置
    business_unit    TEXT NOT NULL DEFAULT 'platform',
    criticality      TEXT NOT NULL DEFAULT 'NORMAL',   -- CRITICAL / HIGH / NORMAL / LOW
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_asset_type ON cloud_assets(resource_type);
CREATE INDEX IF NOT EXISTS idx_asset_provider ON cloud_assets(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_asset_unit ON cloud_assets(business_unit);

-- ============================================
-- 评估扫描 (Scan)
-- ============================================
CREATE TABLE IF NOT EXISTS cspm_scans (
    scan_id          TEXT PRIMARY KEY,                  -- SCN-{ts}
    scan_name        TEXT NOT NULL,
    started_at       TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at      TEXT,
    assets_scanned   INTEGER NOT NULL DEFAULT 0,
    findings_total   INTEGER NOT NULL DEFAULT 0,
    findings_pass    INTEGER NOT NULL DEFAULT 0,
    findings_fail    INTEGER NOT NULL DEFAULT 0,
    compliance_rate  REAL NOT NULL DEFAULT 0.0,
    weighted_risk    REAL NOT NULL DEFAULT 0.0,
    status           TEXT NOT NULL DEFAULT 'IN_PROGRESS'  -- IN_PROGRESS / COMPLETED / FAILED
);

CREATE INDEX IF NOT EXISTS idx_scan_status ON cspm_scans(status);
CREATE INDEX IF NOT EXISTS idx_scan_started ON cspm_scans(started_at);

-- ============================================
-- 合规发现 (Finding)
-- ============================================
CREATE TABLE IF NOT EXISTS cspm_findings (
    finding_id         TEXT PRIMARY KEY,                  -- F-{ts}-{n}
    scan_id            TEXT NOT NULL,
    rule_id            TEXT NOT NULL,                     -- CIS-AWS-2.1.1
    rule_title         TEXT NOT NULL,
    asset_id           TEXT NOT NULL,
    asset_name         TEXT NOT NULL,
    resource_type      TEXT NOT NULL,
    cloud_provider     TEXT NOT NULL,
    status             TEXT NOT NULL,                     -- PASS / FAIL
    severity           TEXT NOT NULL,                     -- CRITICAL / HIGH / MEDIUM / LOW
    framework_iso27001 TEXT,                              -- ISO 27001 控制点映射
    framework_soc2     TEXT,
    framework_pci_dss  TEXT,
    finding_details    TEXT NOT NULL,
    remediation_aws_cli TEXT,
    remediation_boto3   TEXT,
    remediation_tf     TEXT,
    remediation_status TEXT NOT NULL DEFAULT 'OPEN',      -- OPEN / REMEDIATED / ACCEPTED / SUPPRESSED
    detected_at        TEXT NOT NULL DEFAULT (datetime('now')),
    remediated_at      TEXT,
    FOREIGN KEY (scan_id) REFERENCES cspm_scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_scan ON cspm_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_finding_status ON cspm_findings(status);
CREATE INDEX IF NOT EXISTS idx_finding_remediation ON cspm_findings(remediation_status);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON cspm_findings(severity);

-- ============================================
-- 审计 trail
-- ============================================
CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    entity_type   TEXT,
    entity_id     TEXT,
    details       TEXT,
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
