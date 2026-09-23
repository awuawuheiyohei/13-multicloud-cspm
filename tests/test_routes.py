"""
MultiCloud CSPM - FastAPI route tests
- 用 TestClient + function-scoped fixture (reseed per test, 避免 SQLite WAL lock)
"""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# 确保 import app.* 找到
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.main import app  # noqa: E402


@pytest.fixture
def client():
    """每次 reseed + new TestClient"""
    # 清掉旧 db，避免污染
    db = ROOT / "data" / "cspm.db"
    for ext in ("", "-wal", "-shm"):
        p = Path(str(db) + ext)
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

    with TestClient(app) as c:
        # 启动时 init_db 跑过；这里强制 reseed 拿到 15 assets + 一个 scan
        r = c.post("/api/admin/seed")
        assert r.status_code == 200, r.text
        yield c


# ============================================
# Health
# ============================================
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["service"] == "cspm-cis"


# ============================================
# Admin / Seed
# ============================================
def test_admin_seed(client):
    r = client.post("/api/admin/seed")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["stats"]["assets"] == 15
    assert "scan_id" in data["stats"]["scan"]


# ============================================
# Dashboard
# ============================================
def test_dashboard_summary(client):
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    d = r.json()
    assert d["assets"] == 15
    assert d["scans"] >= 1
    assert d["latest_scan"] is not None
    assert d["by_provider"]  # 至少一个 provider


# ============================================
# Scorecard
# ============================================
def test_scorecard(client):
    # 拿最近一次 scan_id
    s = client.get("/api/scans?limit=1").json()
    scan_id = s["items"][0]["scan_id"]
    r = client.get(f"/api/scorecard/{scan_id}")
    assert r.status_code == 200
    d = r.json()
    assert d["scan"]["scan_id"] == scan_id
    assert "open_failures" in d
    assert "open_count" in d


def test_scorecard_404(client):
    r = client.get("/api/scorecard/DOES-NOT-EXIST")
    assert r.status_code == 404


# ============================================
# Assets
# ============================================
def test_list_assets_all(client):
    r = client.get("/api/assets")
    assert r.status_code == 200
    d = r.json()
    assert d["count"] == 15


def test_list_assets_filter_provider(client):
    r = client.get("/api/assets?cloud_provider=AWS")
    assert r.status_code == 200
    for a in r.json()["items"]:
        assert a["cloud_provider"] == "AWS"


def test_list_assets_filter_type(client):
    r = client.get("/api/assets?resource_type=S3_BUCKET")
    assert r.status_code == 200
    for a in r.json()["items"]:
        assert a["resource_type"] == "S3_BUCKET"


def test_get_asset(client):
    r = client.get("/api/assets/A-001")
    assert r.status_code == 200
    d = r.json()
    assert d["asset_id"] == "A-001"
    assert "recent_findings" in d


def test_get_asset_404(client):
    r = client.get("/api/assets/A-999")
    assert r.status_code == 404


# ============================================
# Scans
# ============================================
def test_list_scans(client):
    r = client.get("/api/scans?limit=10")
    assert r.status_code == 200
    assert r.json()["count"] >= 1


def test_run_scan(client):
    r = client.post("/api/scans/run", json={"scan_name": "test scan"})
    assert r.status_code == 200
    d = r.json()
    assert d["scan_id"].startswith("SCN-")
    sc = d["scorecard"]
    assert sc["total_findings"] >= 1
    assert 0 <= sc["compliance_rate_pct"] <= 100
    assert sc["weighted_risk_score"] >= 0


# ============================================
# Findings
# ============================================
def test_list_findings_default(client):
    r = client.get("/api/findings")
    assert r.status_code == 200
    d = r.json()
    # 默认 status=FAIL, remediation_status=OPEN
    for f in d["items"]:
        assert f["status"] == "FAIL"
        assert f["remediation_status"] == "OPEN"


def test_list_findings_filter_severity(client):
    r = client.get("/api/findings?severity=CRITICAL")
    assert r.status_code == 200
    for f in r.json()["items"]:
        assert f["severity"] == "CRITICAL"


def test_get_finding_404(client):
    r = client.get("/api/findings/F-DOES-NOT-EXIST")
    assert r.status_code == 404


def test_update_remediation(client):
    # 拿一个 finding
    f = client.get("/api/findings?limit=1").json()["items"][0]
    fid = f["finding_id"]
    r = client.patch(
        f"/api/findings/{fid}/remediation",
        params={"status": "REMEDIATED", "actor": "test-engineer"},
    )
    assert r.status_code == 200
    assert r.json()["remediation_status"] == "REMEDIATED"
    # 验证 DB
    r2 = client.get(f"/api/findings/{fid}")
    assert r2.json()["remediation_status"] == "REMEDIATED"
    assert r2.json()["remediated_at"] is not None


def test_update_remediation_invalid_status(client):
    f = client.get("/api/findings?limit=1").json()["items"][0]
    r = client.patch(
        f"/api/findings/{f['finding_id']}/remediation",
        params={"status": "BOGUS"},
    )
    assert r.status_code == 400


def test_update_remediation_404(client):
    r = client.patch(
        "/api/findings/F-MISSING/remediation",
        params={"status": "REMEDIATED"},
    )
    assert r.status_code == 404


# ============================================
# Audit
# ============================================
def test_audit_trail_after_seed_and_scan(client):
    # seed 已写一条；再 run scan 写一条
    client.post("/api/scans/run", json={"scan_name": "audit-test"})
    r = client.get("/api/audit?limit=10")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 2
    actions = {it["action"] for it in items}
    assert "reseed" in actions
    assert "run_scan" in actions


# ============================================
# SOC 2 / ISO 27001 Report
# ============================================
def test_report_soc2(client):
    r = client.get("/api/report/soc2")
    assert r.status_code == 200
    d = r.json()
    assert "latest_scan" in d
    assert d["framework"].startswith("SOC 2")
    cm = d["control_mapping"]
    assert "iso27001" in cm
    assert "soc2" in cm
    assert "pci_dss" in cm


# ============================================
# Static Dashboard
# ============================================
def test_static_dashboard_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "CSPM" in r.text or "cspm" in r.text.lower()