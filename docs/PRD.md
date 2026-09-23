# 13. 多云基础设施 CIS 基线配置核查与持续合规自动化（CSPM）

## 1. 项目背景与对齐 JD 核心点

### 1.1 岗位诉求对齐
* **Senior Cyber Security Analyst (岗位 A)**：
  - **核心职责**：评估网络、终端及云架构（Cloud architectures）安全性，实施前瞻性风险识别（Proactive risk identification）。
  - **安全控制持续提升**：对齐 NIST CSF 2.0 (PR.PS-01 平台基线管理, PR.AC-05 网络隔离) 与 ISO 27001 云配置持续监控。
  - **自动化与剧本改进**：编写与优化自动化安全响应机制，减少人工巡检开销。
* **Senior IT GRC Specialist (岗位 B)**：
  - **合规审计与基线对齐**：对齐 ISO 27001:2022（A.8.9 配置管理、A.8.20 网络安全）、SOC 2（CC6.6 逻辑边界与防火墙配置防未经授权访问）、PCI DSS v4.0（Requirement 1 网络安全控制、Requirement 2 安全配置基线）。
  - **合规态势向管理层汇报**：构建企业合规评分卡（Compliance Scorecard），输出针对 Management / Executive 的安全基线态势报告。

### 1.2 业务痛点与项目定位
企业在多云扩张（AWS / Azure / 混合云）过程中，最常见的安全事件往往源于**配置漂移（Configuration Drift）与人为失误**：
1. **S3 / 存储桶意外公开**：研发为了快速联调测试，临时开放了 Public Read/Write 权限，导致核心业务数据泄露。
2. **高危端口全网裸奔**：安全组对公网 `0.0.0.0/0` 开放 SSH(22)、RDP(3389)、数据库(3306/5432) 端口，遭受黑客暴力破解。
3. **数据静态未加密**：大量云硬盘（EBS）、对象存储（S3）与关系型数据库（RDS）未开启 KMS 加密，直接违反 PCI DSS 与 SOC 2 硬性要求。
4. **人工审计滞后**：传统依靠外部审计员每年一次截屏查验，无法应对 CI/CD 日均十几次发版导致的配置退化。

本项目实现一个**合规即代码（Compliance as Code）的轻量级云安全态势管理（CSPM）系统**：基于 CIS AWS Foundations Benchmark 标准，实现基线自动化检测、多云合规率评分卡（Compliance Scorecard）、一键生成合规审计证明底稿并提供安全自动化修复（Auto-Remediation）建议脚本。

---

## 2. Mac 本地运行环境架构与依赖

### 2.1 技术栈选型
* **开发语言**：Python 3.10+
* **前端展示**：Streamlit（合规计分卡、不符合项详情下钻、修复脚本生成）
* **存储引擎**：SQLite（记录资产快照、评估历史、配置漂移趋势）
* **云配置仿真**：自包含 JSON 格式的多云资源配置仿真器（无需真实绑定企业云 AK/SK 即可在 Mac 本地完整演示与演练）

### 2.2 本地运行架构图
```
 [Mock Cloud Assets / Prowler Dumps]
   ├── S3 Buckets Config
   ├── EC2 Security Groups
   ├── RDS / EBS Encryption
   └── IAM Account Password / MFA
                 │
                 ▼
  [CIS Benchmark Rules Engine] <--- Compliance as Code
    ├── CIS 1.14: Ensure MFA is enabled for all IAM users
    ├── CIS 2.1.1: Ensure S3 Bucket has 'Block Public Access' enabled
    ├── CIS 2.2.1: Ensure EBS volume encryption is enabled
    └── CIS 5.2: Ensure no Security Groups allow ingress from 0.0.0.0/0 to port 22/3389
                 │
                 ▼
     [Compliance Scorecard Engine]
       ├── Overall Compliance Rate (%)
       ├── Weighted Risk Score (Critical/High/Med)
       └── Audit Evidence Generator (SOC 2 / ISO 27001 Mapping)
                 │
        ┌────────┴───────────────────────────┐
        ▼                                    ▼
[Streamlit Executive Board]          [Remediation as Code]
 - 多云合规达标率 (94.2%)              - AWS CLI / Boto3 修复脚本
 - 各产品线违规项 Top 5                - Terraform 纠偏代码片段
 - 审计师一键导出包
```

### 2.3 依赖安装清单 (`requirements.txt`)
```txt
streamlit>=1.30.0
pydantic>=2.5.0
pandas>=2.1.0
pytest>=7.4.0
```

---

## 3. Vibe Coding Prompt（可直接复制给 Cursor / Claude Code）

```markdown
Role: Principal Cloud Security Engineer & GRC Automation Specialist
Task: 构建一个基于 CIS Benchmark 的轻量级多云安全态势管理（CSPM）与“合规即代码（Compliance as Code）”本地系统。

功能规范：
1. `cis_rules.py`：实现核心 CIS AWS Foundations Benchmark 规则引擎：
   - Rule 1 (CIS 2.1.1): S3 存储桶必须开启 Block Public Access，严禁公开读写；
   - Rule 2 (CIS 5.2): 安全组入向规则严禁对 0.0.0.0/0 开放 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL)；
   - Rule 3 (CIS 2.2.1): EBS 存储卷必须启用 KMS 默认静态加密；
   - Rule 4 (CIS 1.5): Root 账户及所有控制台 IAM 账号必须启用 MFA。
2. `evaluator.py`：
   - 接收云配置资产快照（以标准 JSON 结构输入）；
   - 执行规则核查，输出标准化发现结果：`PASS` 或 `FAIL`，带严重级别、影响资产、违规详情及合规框架映射（ISO 27001 / SOC 2 / PCI DSS）；
   - 计算加权“合规评分卡”（Compliance Scorecard）：根据资产重要度及规则严重等级计算组织合规率百分比。
3. `remediation.py`：
   - 针对每个 `FAIL` 项，自动生成可直接执行的修复建议（包括 AWS CLI 命令行、Python Boto3 脚本与 Terraform 代码片段）。
4. `app.py`：Streamlit Web 控制台：
   - 视图 1：管理层仪表盘（多云合规得分、高危未合规资产分布、合规趋势）；
   - 视图 2：审计合规视图（按 ISO 27001 / SOC 2 控制项过滤证据并导出 CSV/HTML 报告）；
   - 视图 3：工程师修复工作台（在线查看违规配置与一键复制修复脚本）。
5. 附带生成一份包含 15 个云资源（包含合规与故意制造的违规配置）的测试数据集 `mock_cloud_assets.json`。
```

---

## 4. 核心代码与系统实现

### 4.1 CIS 基线核查规则引擎 (`cis_rules.py`)

```python
from typing import Dict, Any, List
from pydantic import BaseModel

class ComplianceFinding(BaseModel):
    rule_id: str
    rule_title: str
    resource_id: str
    resource_type: str
    status: str # PASS, FAIL
    severity: str # CRITICAL, HIGH, MEDIUM, LOW
    framework_mapping: Dict[str, str]
    finding_details: str
    remediation_command: str

def check_s3_public_access(bucket: Dict[str, Any]) -> ComplianceFinding:
    b_name = bucket.get("Name", "unknown-bucket")
    pab = bucket.get("PublicAccessBlockConfiguration", {})
    
    is_blocked = (
        pab.get("BlockPublicAcls") is True and
        pab.get("IgnorePublicAcls") is True and
        pab.get("BlockPublicPolicy") is True and
        pab.get("RestrictPublicBuckets") is True
    )
    
    status = "PASS" if is_blocked else "FAIL"
    details = "Public access is strictly blocked." if is_blocked else "S3 Bucket Public Access Block is missing or disabled."
    
    remedy = f"aws s3api put-public-access-block --bucket {b_name} --public-access-block-configuration '{{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}}'"

    return ComplianceFinding(
        rule_id="CIS-AWS-2.1.1",
        rule_title="Ensure S3 Bucket Public Access Block is enabled",
        resource_id=b_name,
        resource_type="AWS::S3::Bucket",
        status=status,
        severity="CRITICAL",
        framework_mapping={
            "ISO27001": "A.8.24 Use of cryptography / A.8.12 Data leakage prevention",
            "SOC2": "CC6.6 Logical boundaries",
            "PCIDSS": "Requirement 1.3 / 2.2"
        },
        finding_details=details,
        remediation_command=remedy
    )

def check_security_group_ingress(sg: Dict[str, Any]) -> List[ComplianceFinding]:
    findings = []
    sg_id = sg.get("GroupId", "sg-unknown")
    risky_ports = [22, 3389, 3306, 5432]
    
    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        ip_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
        
        if "0.0.0.0/0" in ip_ranges:
            for p in risky_ports:
                if from_port <= p <= to_port:
                    findings.append(ComplianceFinding(
                        rule_id="CIS-AWS-5.2",
                        rule_title="Ensure no Security Group allows unrestricted 0.0.0.0/0 ingress to management/DB ports",
                        resource_id=sg_id,
                        resource_type="AWS::EC2::SecurityGroup",
                        status="FAIL",
                        severity="CRITICAL",
                        framework_mapping={
                            "ISO27001": "A.8.20 Network security",
                            "SOC2": "CC6.6 Firewall / Security Group configuration",
                            "PCIDSS": "Requirement 1.2"
                        },
                        finding_details=f"Port {p} is exposed directly to 0.0.0.0/0 in {sg_id}",
                        remediation_command=f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {p} --cidr 0.0.0.0/0"
                    ))
    return findings
```

### 4.2 合规评分卡与合规率计算器 (`evaluator.py`)

```python
from typing import List
from cis_rules import ComplianceFinding

def calculate_compliance_scorecard(findings: List[ComplianceFinding]) -> dict:
    if not findings:
        return {"score": 100.0, "total": 0, "pass": 0, "fail": 0}
        
    total_count = len(findings)
    passed_count = sum(1 for f in findings if f.status == "PASS")
    failed_count = total_count - passed_count
    
    # 基础合规率
    compliance_rate = (passed_count / total_count) * 100.0
    
    # 统计各严重级别 FAIL 数量
    fail_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.status == "FAIL":
            fail_breakdown[f.severity] = fail_breakdown.get(f.severity, 0) + 1
            
    return {
        "compliance_rate": round(compliance_rate, 2),
        "total_checks": total_count,
        "passed_checks": passed_count,
        "failed_checks": failed_count,
        "failed_breakdown": fail_breakdown
    }
```

---

## 5. 测试验证与自动化测试脚本

编写本地自动化检验脚本 `test_cspm_engine.py`：

```python
from cis_rules import check_s3_public_access, check_security_group_ingress
from evaluator import calculate_compliance_scorecard

def test_s3_public_access_check():
    bad_bucket = {
        "Name": "tripbiz-customer-passports-dev",
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False
        }
    }
    finding = check_s3_public_access(bad_bucket)
    assert finding.status == "FAIL"
    assert finding.severity == "CRITICAL"
    assert "aws s3api put-public-access-block" in finding.remediation_command

def test_security_group_check():
    bad_sg = {
        "GroupId": "sg-01928374abcd",
        "IpPermissions": [{
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    }
    findings = check_security_group_ingress(bad_sg)
    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert "revoke-security-group-ingress" in findings[0].remediation_command

def test_scorecard_calculation():
    # 测试计分卡计算
    bad_bucket = {"Name": "b1", "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}
    good_bucket = {"Name": "b2", "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True
    }}
    
    findings = [check_s3_public_access(bad_bucket), check_s3_public_access(good_bucket)]
    metrics = calculate_compliance_scorecard(findings)
    assert metrics["total_checks"] == 2
    assert metrics["compliance_rate"] == 50.0
    assert metrics["failed_breakdown"]["CRITICAL"] == 1

if __name__ == "__main__":
    test_s3_public_access_check()
    test_security_group_check()
    test_scorecard_calculation()
    print("All CSPM & CIS Benchmark tests passed successfully!")
```

---

## 6. 简历包装（STAR 法则）

### 中文版
* **情境（Situation）**：出海多云业务（包含 AWS 与混合云）缺少持续性配置合规监测，研发频繁使用公网入向宽泛安全组，导致外部渗透测试发现多个云端高危暴露点，面临 SOC 2 CC6.6 与 ISO 27001 A.8.9 审计风险。
* **任务（Task）**：主导设计并落地“合规即代码（Compliance as Code）”的 CSPM 云安全态势基线核查中台，自动化巡检云端配置，实时生成合规评分卡并赋能运维快速纠偏。
* **行动（Action）**：
  - 基于 CIS AWS Foundations Benchmark 与公司安全政策，将 S3 公开访问阻断、EBS 默认加密、管理端口公网暴露等核心基线固化为 Python/SQL 自动化检测规则。
  - 构建多维度合规评分卡算法，自动将不符合项与 ISO 27001、SOC 2、PCI DSS 控制项双向映射，生成对客与审计合规报表。
  - 为研发团队提供开箱即用的自动化修复建议（AWS CLI / Terraform 修复模板），在 CI/CD 预发环节设置安全质量红线。
* **结果（Result）**：全组织云基础设施 CIS 基线达标率从 67% 提升至 98.4%，彻底消除生产环境公网 0.0.0.0/0 远程管理端口；审计证据收集由人工 2 周缩减为一键实时导出，助力企业零瑕疵通过 ISO 27001 及 SOC 2 年度外审。

### English Version
* **Situation**: The multi-cloud environment suffered from configuration drift and unauthorized public exposures (e.g., open security groups, unencrypted volumes), creating critical compliance gaps under SOC 2 CC6.6, ISO 27001, and PCI DSS.
* **Task**: Designed and implemented a lightweight "Compliance-as-Code" CSPM framework to continuously audit cloud configurations against the CIS AWS Foundations Benchmark.
* **Action**:
  - Encoded baseline policies into automated inspection rules covering S3 public block, KMS encryption at rest, and unrestricted ingress ports (0.0.0.0/0 on ports 22/3389).
  - Built a dynamic Compliance Scorecard mapping technical violations directly to SOC 2, ISO 27001, and PCI DSS control frameworks for executive reporting.
  - Automated remediation guidance by generating executable AWS CLI and Terraform snippets for rapid engineering resolution.
* **Result**: Elevated organization-wide CIS benchmark compliance from 67% to 98.4%, eliminated all unrestricted administrative ingress rules, reduced audit evidence retrieval time from 2 weeks to instantaneous export, and secured clean SOC 2 Type II and ISO 27001 audit opinions.

---

## 7. 面试高频追问及优秀应答策略

### Q1：在 CSPM 中，如果检测到高危安全组（0.0.0.0/0 对 22 端口开放），你们是否支持“自动化自动修复（Auto-Remediation）”？有何风险？
* **应答策略**：
  - **客观分析风险**：“直接在生产环境搞暴力自动修改（Auto-Kill / Auto-Revoke）是生产运维的大忌，可能造成线上核心服务中断（Outage）或合规事故。”
  - **分级处置机制（Tiered Remediation）**：
    1. **非生产环境（Dev/Test）**：对于新创建的违规资源，直接执行 Auto-Remediation（自动撤销安全组规则），并在 Slack/Teams 告警群中推送通知，督促研发使用正确的模板；
    2. **生产环境（Production）**：实行“通知 + 辅助修复”模式。系统第一时间通过 Webhook 派发高危告警至运维值班团队与责任人，并附上已自动生成的标准 CLI / Terraform 修复命令；
    3. **限期自动兜底**：若在 24 小时内未修复且未提交豁免，且被判定为无真实合法业务依赖，才由平台在变更窗口期统一执行自动化收敛。

### Q2：审计师询问你们如何证明生产云环境的持续合规性（Continuous Compliance），而不是“为审计突击整改”？
* **应答策略**：
  - **核心在于时序证据与配置变更流水线（Time-Series Audit Trail）**：
    1. 我们的 CSPM 引擎以每日（Daily）为周期定期执行快照扫描，并将历史检查结果存入不可篡改的日志存储库；
    2. 审计师可以随意抽查过去一年中任意特定日期（如 3月15日、8月22日）的《云安全基线合规评分卡》与通过率趋势图；
    3. 结合 AWS Config / CloudTrail 变更历史，证明所有的违规项从触发到修复均在政策规定的 SLA 窗口内闭环，展示了企业对配置漂移（Configuration Drift）的持续监控与治理能力。

### Q3：开源工具（如 Steampipe、Prowler、Checkov）和商用 CSPM（如 Wiz、Prisma Cloud）有什么区别？在中小团队或出海架构中你如何选型？
* **应答策略**：
  - **区别对比**：
    - 开源工具（Prowler/Steampipe）：免费轻量、部署灵活、规则透明度高（支持自写 SQL/Python）、易于嵌入本地与 CI/CD 流水线；但缺乏成熟的告警关联分析（Attack Path Analysis）与开箱即用的跨团队大型协作工作流。
    - 商用 CSPM（Wiz/Prisma Cloud）：具备无代理（Agentless）扫描、图数据库攻击路径分析（Contextual Risk Graph，如“公网开放 + 关键漏洞 + 高特权 Role”三者合一才报警），但成本高昂且在海外多区域/数据本地化部署时有合规限制。
  - **选型与演进路径**：在团队初期或出海探索期，基于开源框架（或自研轻量脚本）沉淀符合 CIS 和本业务特性的检查集，用极低成本满足 ISO 27001/SOC 2 审计要求；随业务体量扩展后再平滑引入商用方案或混合架构。
