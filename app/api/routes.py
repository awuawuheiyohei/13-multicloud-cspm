"""
MultiCloud CSPM API Routes
- Assets / Scans / Findings / Scorecard / Remediation / Report / Audit
"""
import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Body, Query
from pydantic import BaseModel, Field

from ..models.db import get_conn, init_db, row_to_dict, rows_to_dicts, write_audit
from ..models.cis_rules import evaluate_asset, compute_scorecard
from ..models.seed import seed_all, _make_assets

router = APIRouter()


# ============================================
# Pydantic
# ============================================
class ScanRequest(BaseModel):
    scan_name: str = "Manual scan"


# ============================================
# Dashboard / Scorecard
# ============================================
@router.get("/dashboard/summary")
async def dashboard_summary():
    init_db()
    conn = get_conn()
    n_assets = conn.execute("SELECT COUNT(*) FROM cloud_assets").fetchone()[0]
    n_scans = conn.execute("SELECT COUNT(*) FROM cspm_scans").fetchone()[0]
    last_scan = conn.execute("SELECT * FROM cspm_scans ORDER BY started_at DESC LIMIT 1").fetchone()
    last = row_to_dict(last_scan) if last_scan else None
    n_open_findings = conn.execute(
        "SELECT COUNT(*) FROM cspm_findings WHERE status='FAIL' AND remediation_status='OPEN'"
    ).fetchone()[0]
    by_sev = rows_to_dicts(conn.execute(
        """SELECT severity, COUNT(*) as cnt FROM cspm_findings
           WHERE status='FAIL' AND remediation_status='OPEN' GROUP BY severity"""
    ).fetchall())
    by_provider = rows_to_dicts(conn.execute(
        "SELECT cloud_provider, COUNT(*) as cnt FROM cloud_assets GROUP BY cloud_provider"
    ).fetchall())
    by_unit = rows_to_dicts(conn.execute(
        """SELECT a.business_unit as business_unit, COUNT(*) as cnt
           FROM cspm_findings f JOIN cloud_assets a ON f.asset_id = a.asset_id
           WHERE f.status='FAIL' AND f.remediation_status='OPEN'
           GROUP BY a.business_unit ORDER BY cnt DESC LIMIT 5"""
    ).fetchall())
    return {
        "assets": n_assets,
        "scans": n_scans,
        "latest_scan": last,
        "open_findings": n_open_findings,
        "by_severity": by_sev,
        "by_provider": by_provider,
        "by_unit_top5": by_unit,
    }


@router.get("/scorecard/{scan_id}")
async def scorecard(scan_id: str):
    conn = get_conn()
    scan = conn.execute("SELECT * FROM cspm_scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not scan:
        raise HTTPException(404, f"Scan not found: {scan_id}")
    findings = rows_to_dicts(conn.execute(
        "SELECT * FROM cspm_findings WHERE scan_id=? AND status='FAIL' ORDER BY severity",
        (scan_id,)
    ).fetchall())
    return {
        "scan": row_to_dict(scan),
        "open_failures": findings,
        "open_count": len(findings),
    }


# ============================================
# Assets
# ============================================
@router.get("/assets")
async def list_assets(resource_type: Optional[str] = None,
                     cloud_provider: Optional[str] = None,
                     business_unit: Optional[str] = None):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM cloud_assets WHERE 1=1"
    params = []
    if resource_type:
        sql += " AND resource_type=?"
        params.append(resource_type)
    if cloud_provider:
        sql += " AND cloud_provider=?"
        params.append(cloud_provider)
    if business_unit:
        sql += " AND business_unit=?"
        params.append(business_unit)
    sql += " ORDER BY asset_id"
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    return {"count": len(rows), "items": rows}


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM cloud_assets WHERE asset_id=?", (asset_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Asset not found: {asset_id}")
    d = row_to_dict(row)
    try:
        d["raw_config"] = json.loads(d["raw_config"]) if d["raw_config"] else {}
    except Exception:
        d["raw_config"] = {}
    # 最近一次 finding（最新 scan）
    last = conn.execute(
        """SELECT f.* FROM cspm_findings f JOIN cspm_scans s ON f.scan_id = s.scan_id
           WHERE f.asset_id=? ORDER BY s.started_at DESC LIMIT 5""",
        (asset_id,)
    ).fetchall()
    d["recent_findings"] = rows_to_dicts(last)
    return d


# ============================================
# Scans
# ============================================
@router.get("/scans")
async def list_scans(limit: int = Query(20, ge=1, le=100)):
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        "SELECT * FROM cspm_scans ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/scans/run")
async def run_scan(req: ScanRequest = Body(...), actor: str = "cspm-bot"):
    """跑一次完整评估（用 DB 当前 assets）"""
    init_db()
    conn = get_conn()
    assets = conn.execute("SELECT * FROM cloud_assets").fetchall()
    if not assets:
        raise HTTPException(400, "No assets to scan")

    scan_id = f"SCN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    conn.execute(
        """INSERT INTO cspm_scans (scan_id, scan_name, status, assets_scanned,
           findings_total, findings_pass, findings_fail, compliance_rate, weighted_risk)
           VALUES (?, ?, 'COMPLETED', ?, 0, 0, 0, 0, 0)""",
        (scan_id, req.scan_name, len(assets))
    )

    all_findings = []
    for row in assets:
        asset = {k: row[k] for k in row.keys()}
        try:
            asset["raw_config"] = json.loads(asset["raw_config"]) if isinstance(asset["raw_config"], str) else asset["raw_config"]
        except Exception:
            pass
        fs = evaluate_asset(asset)
        for f in fs:
            all_findings.append(f)
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

    sc = compute_scorecard(all_findings)
    conn.execute(
        """UPDATE cspm_scans SET findings_total=?, findings_pass=?, findings_fail=?,
           compliance_rate=?, weighted_risk=?, finished_at=datetime('now') WHERE scan_id=?""",
        (sc["total_findings"], sc["pass"], sc["fail"], sc["compliance_rate_pct"], sc["weighted_risk_score"], scan_id)
    )
    write_audit(conn, actor=actor, action="run_scan",
                entity_type="cspm_scans", entity_id=scan_id,
                details={"assets": len(assets), "compliance": sc["compliance_rate_pct"]})
    conn.commit()
    return {"scan_id": scan_id, "scorecard": sc}


# ============================================
# Findings
# ============================================
@router.get("/findings")
async def list_findings(severity: Optional[str] = None,
                       resource_type: Optional[str] = None,
                       cloud_provider: Optional[str] = None,
                       status: Optional[str] = "FAIL",
                       remediation_status: Optional[str] = "OPEN",
                       limit: int = Query(100, ge=1, le=500)):
    init_db()
    conn = get_conn()
    sql = "SELECT * FROM cspm_findings WHERE 1=1"
    params = []
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if resource_type:
        sql += " AND resource_type=?"
        params.append(resource_type)
    if cloud_provider:
        sql += " AND cloud_provider=?"
        params.append(cloud_provider)
    if status:
        sql += " AND status=?"
        params.append(status)
    if remediation_status:
        sql += " AND remediation_status=?"
        params.append(remediation_status)
    sql += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END LIMIT ?"
    params.append(limit)
    rows = rows_to_dicts(conn.execute(sql, params).fetchall())
    return {"count": len(rows), "items": rows}


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM cspm_findings WHERE finding_id=?", (finding_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Finding not found: {finding_id}")
    return row_to_dict(row)


@router.patch("/findings/{finding_id}/remediation")
async def update_remediation(finding_id: str, status: str, actor: str = "engineer"):
    if status not in ("OPEN", "REMEDIATED", "ACCEPTED", "SUPPRESSED"):
        raise HTTPException(400, "Invalid status")
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM cspm_findings WHERE finding_id=?", (finding_id,)).fetchone():
        raise HTTPException(404, f"Finding not found: {finding_id}")
    today = datetime.now().isoformat() if status == "REMEDIATED" else None
    conn.execute(
        """UPDATE cspm_findings SET remediation_status=?, remediated_at=? WHERE finding_id=?""",
        (status, today, finding_id)
    )
    write_audit(conn, actor=actor, action="update_remediation",
                entity_type="cspm_findings", entity_id=finding_id, details={"status": status})
    conn.commit()
    return {"finding_id": finding_id, "remediation_status": status}


# ============================================
# SOC 2 / ISO 27001 Audit Report
# ============================================
@router.get("/report/soc2")
async def report_soc2():
    init_db()
    conn = get_conn()
    today = datetime.now().strftime("%Y-%m-%d")
    last_scan = conn.execute("SELECT * FROM cspm_scans ORDER BY started_at DESC LIMIT 1").fetchone()
    if not last_scan:
        return {"report_date": today, "framework": "SOC 2 + ISO 27001", "status": "no scans yet"}

    sd = row_to_dict(last_scan)
    # 按 framework 控制点分组
    findings_by_iso = rows_to_dicts(conn.execute(
        """SELECT framework_iso27001 as control, COUNT(*) as cnt FROM cspm_findings
           WHERE status='FAIL' AND remediation_status='OPEN'
           GROUP BY framework_iso27001"""
    ).fetchall())
    findings_by_soc2 = rows_to_dicts(conn.execute(
        """SELECT framework_soc2 as control, COUNT(*) as cnt FROM cspm_findings
           WHERE status='FAIL' AND remediation_status='OPEN'
           GROUP BY framework_soc2"""
    ).fetchall())
    findings_by_pci = rows_to_dicts(conn.execute(
        """SELECT framework_pci_dss as control, COUNT(*) as cnt FROM cspm_findings
           WHERE status='FAIL' AND remediation_status='OPEN'
           GROUP BY framework_pci_dss"""
    ).fetchall())

    return {
        "report_date": today,
        "framework": "SOC 2 + ISO 27001 + PCI DSS",
        "latest_scan": {
            "scan_id": sd["scan_id"],
            "scan_name": sd["scan_name"],
            "compliance_rate_pct": sd["compliance_rate"],
            "weighted_risk_score": sd["weighted_risk"],
            "findings_total": sd["findings_total"],
            "findings_fail": sd["findings_fail"],
            "findings_pass": sd["findings_pass"],
        },
        "control_mapping": {
            "iso27001": findings_by_iso,
            "soc2": findings_by_soc2,
            "pci_dss": findings_by_pci,
        },
    }


# ============================================
# Audit + Admin
# ============================================
@router.get("/audit")
async def list_audit(limit: int = Query(50, ge=1, le=500)):
    init_db()
    conn = get_conn()
    rows = rows_to_dicts(conn.execute(
        "SELECT * FROM audit_trail ORDER BY occurred_at DESC LIMIT ?", (limit,)).fetchall())
    return {"count": len(rows), "items": rows}


@router.post("/admin/seed")
async def admin_seed(actor: str = "grc-team"):
    init_db()
    stats = seed_all(verbose=False)
    conn = get_conn()
    write_audit(conn, actor=actor, action="reseed",
                entity_type="system", entity_id="all", details=stats)
    conn.commit()
    return {"status": "ok", "stats": stats}
