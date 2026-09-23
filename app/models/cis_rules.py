"""
CIS AWS Foundations Benchmark Rules Engine
- CIS-AWS-2.1.1: S3 Block Public Access
- CIS-AWS-5.2:   Security Group ingress 0.0.0.0/0 on risky ports
- CIS-AWS-2.2.1: EBS encryption at rest
- CIS-AWS-1.5:   IAM MFA for console users
"""
from typing import List, Dict, Any


def check_s3_public_access(bucket):
    b_name = bucket.get("Name", "unknown-bucket")
    pab = bucket.get("PublicAccessBlockConfiguration", {})
    is_blocked = all([
        pab.get("BlockPublicAcls") is True,
        pab.get("IgnorePublicAcls") is True,
        pab.get("BlockPublicPolicy") is True,
        pab.get("RestrictPublicBuckets") is True,
    ])
    status = "PASS" if is_blocked else "FAIL"
    details = ("Public access strictly blocked via BlockPublicAcls + IgnorePublicAcls + BlockPublicPolicy + RestrictPublicBuckets"
               if is_blocked else
               "S3 Bucket Public Access Block is missing or disabled — at risk of public read/write exposure")
    cli = (f"aws s3api put-public-access-block --bucket {b_name} "
           f"--public-access-block-configuration "
           f"'{{\"BlockPublicAcls\":true,\"IgnorePublicAcls\":true,\"BlockPublicPolicy\":true,\"RestrictPublicBuckets\":true}}'")
    boto3_snippet = (
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        f"s3.put_public_access_block(Bucket='{b_name}', PublicAccessBlockConfiguration={{\n"
        f"  'BlockPublicAcls': True, 'IgnorePublicAcls': True,\n"
        f"  'BlockPublicPolicy': True, 'RestrictPublicBuckets': True\n"
        f"}})"
    )
    tf = (
        f'resource "aws_s3_bucket_public_access_block" "{b_name}_pab" {{\n'
        f'  bucket = aws_s3_bucket.{b_name.replace("-", "_")}.id\n\n'
        f'  block_public_acls       = true\n'
        f'  ignore_public_acls      = true\n'
        f'  block_public_policy     = true\n'
        f'  restrict_public_buckets = true\n'
        f'}}'
    )
    return {
        "rule_id": "CIS-AWS-2.1.1",
        "rule_title": "S3 Bucket Public Access Block must be enabled",
        "resource_type": "AWS::S3::Bucket",
        "status": status,
        "severity": "CRITICAL",
        "framework_mapping": {
            "iso27001": "A.8.24 Use of cryptography",
            "soc2": "CC6.6 Logical boundaries",
            "pci_dss": "Requirement 1.3 / 2.2",
        },
        "finding_details": details,
        "remediation_aws_cli": cli,
        "remediation_boto3": boto3_snippet,
        "remediation_tf": tf,
    }


RISKY_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}


def check_security_group(sg):
    findings = []
    sg_id = sg.get("GroupId", "sg-unknown")
    sg_name = sg.get("GroupName", sg_id)
    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0) or 0
        to_port = rule.get("ToPort", 65535) or 65535
        ip_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
        if "0.0.0.0/0" not in ip_ranges:
            continue
        for port, svc in RISKY_PORTS.items():
            if from_port <= port <= to_port:
                findings.append({
                    "rule_id": "CIS-AWS-5.2",
                    "rule_title": f"No Security Group allows 0.0.0.0/0 ingress to {svc} (port {port})",
                    "resource_type": "AWS::EC2::SecurityGroup",
                    "status": "FAIL",
                    "severity": "CRITICAL" if port in (22, 3389) else "HIGH",
                    "framework_mapping": {
                        "iso27001": "A.8.20 Networks security",
                        "soc2": "CC6.6 Logical access controls",
                        "pci_dss": "Requirement 1.2 / 1.3",
                    },
                    "finding_details": (f"SG {sg_name} ({sg_id}) allows 0.0.0.0/0 ingress to port {port} ({svc}). "
                                        f"Restrict to known corporate CIDR or remove rule."),
                    "remediation_aws_cli": (f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                            f"--protocol tcp --port {port} --cidr 0.0.0.0/0"),
                    "remediation_boto3": (f"import boto3\nec2 = boto3.client('ec2')\n"
                                            f"ec2.revoke_security_group_ingress(\n"
                                            f"    GroupId='{sg_id}',\n"
                                            f"    IpPermissions=[{{'IpProtocol': 'tcp', 'FromPort': {port}, 'ToPort': {port}, 'IpRanges': [{{'CidrIp': '0.0.0.0/0'}}]}}]\n"
                                            f")"),
                    "remediation_tf": (f'resource "aws_security_group_rule" "remove_{sg_id}_{port}" {{\n'
                                        f'  type              = "ingress"\n'
                                        f'  from_port         = {port}\n'
                                        f'  to_port           = {port}\n'
                                        f'  protocol          = "tcp"\n'
                                        f'  cidr_blocks       = ["0.0.0.0/0"]\n'
                                        f'  security_group_id = aws_security_group.{sg_name}.id\n'
                                        f'}}  # TODO: replace with restricted CIDR'),
                })
    return findings


def check_ebs_encryption(volume):
    vol_id = volume.get("VolumeId", "vol-unknown")
    encrypted = volume.get("Encrypted", False)
    status = "PASS" if encrypted else "FAIL"
    details = (f"EBS volume {vol_id} encrypted at rest with KMS"
               if encrypted else
               f"EBS volume {vol_id} is NOT encrypted — violates PCI DSS / SOC 2 confidentiality")
    cli = f"aws ec2 modify-volume --volume-id {vol_id} --encrypted"
    boto3_snippet = (
        "import boto3\n"
        "ec2 = boto3.client('ec2')\n"
        f"ec2.modify_volume(VolumeId='{vol_id}', Encrypted=True)"
    )
    tf = (
        f'resource "aws_ebs_volume" "{vol_id}" {{\n'
        f'  availability_zone = "us-east-1a"\n'
        f'  size              = 100\n'
        f'  encrypted         = true\n'
        f'}}'
    )
    return {
        "rule_id": "CIS-AWS-2.2.1",
        "rule_title": "EBS volumes must be encrypted at rest",
        "resource_type": "AWS::EC2::Volume",
        "status": status,
        "severity": "HIGH",
        "framework_mapping": {
            "iso27001": "A.8.24 Use of cryptography",
            "soc2": "CC6.1 Logical access / Confidentiality",
            "pci_dss": "Requirement 3.4",
        },
        "finding_details": details,
        "remediation_aws_cli": cli,
        "remediation_boto3": boto3_snippet,
        "remediation_tf": tf,
    }


def check_iam_mfa(user):
    user_name = user.get("UserName", "user-unknown")
    mfa_active = len(user.get("MFADevices", [])) > 0
    status = "PASS" if mfa_active else "FAIL"
    details = (f"IAM user {user_name} has MFA configured ({len(user.get('MFADevices', []))} device(s))"
               if mfa_active else
               f"IAM user {user_name} has NO MFA — phishing/account-takeover risk")
    sev = "CRITICAL" if user.get("HasLoginProfile") and not mfa_active else "HIGH"
    cli = f"aws iam enable-mfa-device --user-name {user_name} --serial-number <arn> --authentication-code-1 <code1> --authentication-code-2 <code2>"
    boto3_snippet = (
        "import boto3\n"
        "iam = boto3.client('iam')\n"
        f"resp = iam.create_virtual_mfa_device(VirtualMFADeviceName='{user_name}-mfa')\n"
        f"iam.enable_mfa_device(\n"
        f"    UserName='{user_name}',\n"
        f"    SerialNumber=resp['VirtualMFADevice']['SerialNumber'],\n"
        f"    AuthenticationCode1='<c1>',\n"
        f"    AuthenticationCode2='<c2>'\n"
        f")"
    )
    tf = (
        f'resource "aws_iam_user_mfa_device" "{user_name}_mfa" {{\n'
        f'  user_name   = aws_iam_user.{user_name}.name\n'
        f'  serial_number = "arn:aws:iam::{{var.account_id}}:mfa/{user_name}-mfa"\n'
        f'  authentication_code_1 = "123456"\n'
        f'  authentication_code_2 = "789012"\n'
        f'}}'
    )
    return {
        "rule_id": "CIS-AWS-1.5",
        "rule_title": "IAM users with console access must have MFA",
        "resource_type": "AWS::IAM::User",
        "status": status,
        "severity": sev,
        "framework_mapping": {
            "iso27001": "A.8.5 Secure authentication",
            "soc2": "CC6.1 Logical access controls",
            "pci_dss": "Requirement 8.4",
        },
        "finding_details": details,
        "remediation_aws_cli": cli,
        "remediation_boto3": boto3_snippet,
        "remediation_tf": tf,
    }


RULE_DISPATCH = {
    "S3_BUCKET": check_s3_public_access,
    "EC2_SG": check_security_group,
    "EBS": check_ebs_encryption,
    "IAM_USER": check_iam_mfa,
}


def evaluate_asset(asset):
    rtype = asset.get("resource_type")
    fn = RULE_DISPATCH.get(rtype)
    if not fn:
        return []
    result = fn(asset.get("raw_config", asset))
    if isinstance(result, list):
        return result
    return [result]


SEVERITY_WEIGHTS = {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}


def compute_scorecard(findings):
    n_pass = sum(1 for f in findings if f["status"] == "PASS")
    n_fail = sum(1 for f in findings if f["status"] == "FAIL")
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_rule = {}
    weighted_risk = 0.0
    for f in findings:
        if f["status"] == "FAIL":
            sev = f["severity"]
            by_sev[sev] = by_sev.get(sev, 0) + 1
            weighted_risk += SEVERITY_WEIGHTS.get(sev, 1.0)
            rid = f["rule_id"]
            by_rule[rid] = by_rule.get(rid, 0) + 1
    total = n_pass + n_fail
    compliance_rate = (n_pass / total * 100) if total else 0.0
    return {
        "total_findings": total,
        "pass": n_pass,
        "fail": n_fail,
        "compliance_rate_pct": round(compliance_rate, 2),
        "weighted_risk_score": round(weighted_risk, 2),
        "by_severity": by_sev,
        "by_rule_failed": by_rule,
    }
