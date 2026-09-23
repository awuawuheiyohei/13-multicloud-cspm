"""Seed 15 cloud assets + initial scan"""
import json
from datetime import datetime, timezone, timedelta

from .db import get_conn, init_db
from .cis_rules import evaluate_asset, compute_scorecard


# ============================================
# 15 Mock Cloud Assets
# ============================================
def _make_assets():
    today = datetime.now(timezone.utc)

    return [
        # S3 Buckets (5)
        {"asset_id": "A-001", "asset_name": "tripbiz-customer-pii",
         "resource_type": "S3_BUCKET", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "CRITICAL",
         "raw_config": {
             "Name": "tripbiz-customer-pii",
             "PublicAccessBlockConfiguration": {
                 "BlockPublicAcls": True, "IgnorePublicAcls": True,
                 "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
             },
             "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
             "Versioning": "Enabled",
         }},
        {"asset_id": "A-002", "asset_name": "legacy-public-bucket",
         "resource_type": "S3_BUCKET", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "data", "criticality": "HIGH",
         "raw_config": {
             "Name": "legacy-public-bucket",
             # ⚠️ Public Access Block 全部 False — 违规
             "PublicAccessBlockConfiguration": {
                 "BlockPublicAcls": False, "IgnorePublicAcls": False,
                 "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
             },
             "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
         }},
        {"asset_id": "A-003", "asset_name": "marketing-assets",
         "resource_type": "S3_BUCKET", "cloud_provider": "AWS", "region": "us-west-2",
         "account_id": "111111111111", "business_unit": "marketing", "criticality": "NORMAL",
         "raw_config": {
             "Name": "marketing-assets",
             "PublicAccessBlockConfiguration": {
                 "BlockPublicAcls": True, "IgnorePublicAcls": True,
                 "BlockPublicPolicy": False, "RestrictPublicBuckets": True,
             },  # ⚠️ BlockPublicPolicy=False — 部分违规
         }},
        {"asset_id": "A-004", "asset_name": "azure-blob-logs",
         "resource_type": "S3_BUCKET", "cloud_provider": "AZURE", "region": "eastus",
         "account_id": "sub-12345", "business_unit": "platform", "criticality": "NORMAL",
         "raw_config": {
             "Name": "azure-blob-logs",
             "PublicAccessBlockConfiguration": {
                 "BlockPublicAcls": True, "IgnorePublicAcls": True,
                 "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
             },
         }},
        {"asset_id": "A-005", "asset_name": "gcp-backups",
         "resource_type": "S3_BUCKET", "cloud_provider": "GCP", "region": "us-central1",
         "account_id": "gcp-project-1", "business_unit": "platform", "criticality": "HIGH",
         "raw_config": {
             "Name": "gcp-backups",
             "PublicAccessBlockConfiguration": {
                 "BlockPublicAcls": True, "IgnorePublicAcls": True,
                 "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
             },
             "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
         }},

        # EC2 Security Groups (4)
        {"asset_id": "A-006", "asset_name": "web-sg-public-22",
         "resource_type": "EC2_SG", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "CRITICAL",
         "raw_config": {
             "GroupId": "sg-web-public",
             "GroupName": "web-public",
             # ⚠️ 22 + 0.0.0.0/0
             "IpPermissions": [{
                 "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
             }],
         }},
        {"asset_id": "A-007", "asset_name": "db-sg-public-3306",
         "resource_type": "EC2_SG", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "CRITICAL",
         "raw_config": {
             "GroupId": "sg-db-public",
             "GroupName": "db-public",
             # ⚠️ 3306 + 0.0.0.0/0
             "IpPermissions": [{
                 "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
             }],
         }},
        {"asset_id": "A-008", "asset_name": "rdp-sg-public-3389",
         "resource_type": "EC2_SG", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "HIGH",
         "raw_config": {
             "GroupId": "sg-rdp-public",
             "GroupName": "rdp-public",
             "IpPermissions": [{
                 "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
             }],
         }},
        {"asset_id": "A-009", "asset_name": "web-sg-restricted",
         "resource_type": "EC2_SG", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "NORMAL",
         "raw_config": {
             "GroupId": "sg-web-restricted",
             "GroupName": "web-restricted",
             # ✅ 只允许公司 CIDR
             "IpPermissions": [{
                 "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                 "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
             }],
         }},

        # EBS Volumes (3)
        {"asset_id": "A-010", "asset_name": "db-volume-encrypted",
         "resource_type": "EBS", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "CRITICAL",
         "raw_config": {"VolumeId": "vol-db-encrypted", "Encrypted": True, "Size": 500}},
        {"asset_id": "A-011", "asset_name": "log-volume-unencrypted",
         "resource_type": "EBS", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "NORMAL",
         # ⚠️ 未加密
         "raw_config": {"VolumeId": "vol-log-unencrypted", "Encrypted": False, "Size": 200}},
        {"asset_id": "A-012", "asset_name": "app-volume-encrypted",
         "resource_type": "EBS", "cloud_provider": "AWS", "region": "us-east-1",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "HIGH",
         "raw_config": {"VolumeId": "vol-app-encrypted", "Encrypted": True, "Size": 100}},

        # IAM Users (3)
        {"asset_id": "A-013", "asset_name": "alice-admin",
         "resource_type": "IAM_USER", "cloud_provider": "AWS", "region": "global",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "CRITICAL",
         "raw_config": {
             "UserName": "alice-admin",
             "HasLoginProfile": True,
             "MFADevices": [{"SerialNumber": "arn:aws:iam::111:mfa/alice"}],
             # ✅ MFA configured
         }},
        {"asset_id": "A-014", "asset_name": "bob-engineer",
         "resource_type": "IAM_USER", "cloud_provider": "AWS", "region": "global",
         "account_id": "111111111111", "business_unit": "platform", "criticality": "HIGH",
         "raw_config": {
             "UserName": "bob-engineer",
             "HasLoginProfile": True,
             "MFADevices": [],
             # ⚠️ 无 MFA
         }},
        {"asset_id": "A-015", "asset_name": "carle-readonly",
         "resource_type": "IAM_USER", "cloud_provider": "AWS", "region": "global",
         "account_id": "111111111111", "business_unit": "data", "criticality": "NORMAL",
         "raw_config": {
             "UserName": "carol-readonly",
             "HasLoginProfile": False,  # 无 console access
             "MFADevices": [],
         }},
    ]


# ============================================
# Seed
# ============================================
def seed_assets(verbose=False):
    init_db()
    conn = get_conn()
    conn.execute("DELETE FROM cspm_findings")
    conn.execute("DELETE FROM cspm_scans")
    conn.execute("DELETE FROM cloud_assets")
    conn.execute("DELETE FROM audit_trail")

    assets = _make_assets()
    for a in assets:
        conn.execute(
            """INSERT INTO cloud_assets (asset_id, asset_name, resource_type, cloud_provider,
               region, account_id, raw_config, business_unit, criticality)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (a["asset_id"], a["asset_name"], a["resource_type"], a["cloud_provider"],
             a["region"], a["account_id"], json.dumps(a["raw_config"], ensure_ascii=False),
             a["business_unit"], a["criticality"])
        )
    conn.commit()
    if verbose:
        print(f"[+] Seeded {len(assets)} cloud assets")
    return len(assets)


def seed_initial_scan(verbose=False):
    """跑一次完整评估作为 seed scan"""
    conn = get_conn()
    assets = conn.execute("SELECT * FROM cloud_assets").fetchall()
    if not assets:
        return None

    scan_id = f"SCN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    conn.execute(
        """INSERT INTO cspm_scans (scan_id, scan_name, started_at, finished_at, status,
           assets_scanned, findings_total, findings_pass, findings_fail, compliance_rate, weighted_risk)
           VALUES (?, ?, datetime('now'), datetime('now'), 'COMPLETED', ?, 0, 0, 0, 0, 0)""",
        (scan_id, "Initial baseline scan", len(assets))
    )

    all_findings = []
    for row in assets:
        asset = {k: row[k] for k in row.keys()}
        try:
            asset["raw_config"] = json.loads(asset["raw_config"]) if isinstance(asset["raw_config"], str) else asset["raw_config"]
        except Exception:
            pass
        findings = evaluate_asset(asset)
        for f in findings:
            all_findings.append(f)
            # 写 finding
            conn.execute(
                """INSERT INTO cspm_findings
                   (finding_id, scan_id, rule_id, rule_title, asset_id, asset_name, resource_type, cloud_provider,
                    status, severity, framework_iso27001, framework_soc2, framework_pci_dss,
                    finding_details, remediation_aws_cli, remediation_boto3, remediation_tf, remediation_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')""",
                (f"{scan_id}-{len(all_findings):04d}", scan_id, f["rule_id"], f["rule_title"],
                 asset["asset_id"], asset["asset_name"], f["resource_type"], asset["cloud_provider"],
                 f["status"], f["severity"],
                 f["framework_mapping"].get("iso27001", ""),
                 f["framework_mapping"].get("soc2", ""),
                 f["framework_mapping"].get("pci_dss", ""),
                 f["finding_details"], f["remediation_aws_cli"], f["remediation_boto3"], f["remediation_tf"])
            )

    scorecard = compute_scorecard(all_findings)
    conn.execute(
        """UPDATE cspm_scans SET findings_total=?, findings_pass=?, findings_fail=?, compliance_rate=?, weighted_risk=?
           WHERE scan_id=?""",
        (scorecard["total_findings"], scorecard["pass"], scorecard["fail"],
         scorecard["compliance_rate_pct"], scorecard["weighted_risk_score"], scan_id)
    )
    conn.commit()
    if verbose:
        print(f"[+] Seeded scan {scan_id}: {scorecard['compliance_rate_pct']}% compliance, "
              f"weighted risk={scorecard['weighted_risk_score']}")
    return {"scan_id": scan_id, "scorecard": scorecard}


def seed_all(verbose=False):
    n = seed_assets(verbose=verbose)
    s = seed_initial_scan(verbose=verbose)
    return {"assets": n, "scan": s}


if __name__ == "__main__":
    print(seed_all(verbose=True))
