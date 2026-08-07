"""AWS configuration review checks.

Each check is pure logic over a normalized snapshot produced by the AWS
collector (or the demo data generator). Snapshot layout:

{
  "account_id": str, "principal": str,
  "iam": {"password_policy": {...}|None, "root": {"access_keys_active": bool,
           "mfa_enabled": bool}, "users": [{name, has_console_password, mfa_enabled,
           keys: [{id, age_days, active}]}], "admin_policies": [names]},
  "s3": [{name, public, public_acl, encryption, versioning, logging}],
  "ec2": {"security_groups": [{id, name, ingress: [{proto, ports, cidr}], open_ports: []}],
          "volumes": [{id, encrypted}], "instances": [{id, public_ip, security_groups}],
          "amis": [{id, public}]},
  "rds": [{id, publicly_accessible, storage_encrypted, backup_retention_days}],
  "sns": [{topic_arn, public}],
  "trail": {"exists": bool, "multi_region": bool, "log_file_validation": bool},
  "config": {"recorder": bool, "delivering": bool},
  "kms": [{key_id, rotation_enabled}],
  "ecr": [{repo_name, public}],
  "lambda": [{name, runtime}],
}
"""
from __future__ import annotations

from typing import Dict, List

from ..models import Check, Finding, Severity, Status

OPEN_PORTS = [22, 3389]
ALL_CIDR = {"0.0.0.0/0", "::/0"}
ADMIN_ACTIONS = {"*:*", "iam:*", "s3:*", "ec2:*"}  # representative full-admin markers


def _f(check: Check, snapshot: dict, resource: str, status: Status,
       detail: str = "", evidence: dict | None = None) -> Finding:
    return Finding(
        check_id=check.id, check_title=check.title, cloud=check.cloud,
        service=check.service, category=check.category, severity=check.severity,
        status=status, resource=resource, detail=detail,
        remediation=check.remediation, evidence=evidence or {}, cis=check.cis,
    )


def _sg_open_ports(ingress: List[dict]) -> List[int]:
    """Return list of open well-known ports exposed to 0.0.0.0/0 or ::/0."""
    open_ports: List[int] = []
    for rule in ingress:
        cidrs = set(rule.get("cidr", []))
        if not (cidrs & ALL_CIDR):
            continue
        proto = rule.get("proto", "").lower()
        if proto in ("icmp", "-1", "all"):
            continue
        ports = rule.get("ports")
        if ports is None:  # all ports
            return list(range(0, 65536))
        lo, hi = ports
        for p in (22, 3389, 3306, 5432, 6379, 9200):
            if lo <= p <= hi:
                open_ports.append(p)
    return open_ports


# --------------------------------------------------------------------------- #
# IAM
# --------------------------------------------------------------------------- #
def _aws_iam_checks() -> List[Check]:
    def root_keys(c, s, _):
        out = []
        if s["iam"]["root"].get("access_keys_active"):
            out.append(_f(c, s, "root-account", Status.FAIL,
                          "The AWS root account has active long-term access keys. "
                          "Root keys can never be rotated automatically and grant "
                          "full, unconditional access.",
                          {"active_keys": s["iam"]["root"].get("access_key_count", 1)}))
        else:
            out.append(_f(c, s, "root-account", Status.PASS, "No root access keys found."))
        return out

    def root_mfa(c, s, _):
        if s["iam"]["root"].get("mfa_enabled"):
            return [_f(c, s, "root-account", Status.PASS, "Root MFA enabled.")]
        return [_f(c, s, "root-account", Status.FAIL,
                   "Root account does not have MFA enforced.")]

    def user_key_age(c, s, _):
        out = []
        for u in s["iam"]["users"]:
            for k in u.get("keys", []):
                if k.get("active") and k.get("age_days", 0) > 90:
                    out.append(_f(c, s, f"user:{u['name']}/key:{k['id']}", Status.FAIL,
                                  f"Access key {k['id']} is {k['age_days']} days old (limit 90).",
                                  {"age_days": k["age_days"]}))
        if not out:
            out.append(_f(c, s, "iam-users", Status.PASS,
                          "No active access keys older than 90 days."))
        return out

    def user_mfa(c, s, _):
        out = []
        for u in s["iam"]["users"]:
            if u.get("has_console_password") and not u.get("mfa_enabled"):
                out.append(_f(c, s, f"user:{u['name']}", Status.FAIL,
                              "Console user does not have MFA enabled."))
        if not out:
            out.append(_f(c, s, "iam-users", Status.PASS,
                          "All console users have MFA enabled."))
        return out

    def admin_policies(c, s, _):
        out = []
        for name in s["iam"].get("admin_policies", []):
            out.append(_f(c, s, f"policy:{name}", Status.FAIL,
                          f"Policy '{name}' grants full administrative privileges "
                          "(*:*) which violates least privilege."))
        if not out:
            out.append(_f(c, s, "iam-policies", Status.PASS,
                          "No policies grant blanket administrative access."))
        return out

    def password_policy(c, s, _):
        pp = s["iam"].get("password_policy") or {}
        if not pp:
            return [_f(c, s, "account-password-policy", Status.FAIL,
                       "No IAM password policy is configured.")]
        issues = []
        if pp.get("minimum_password_length", 0) < 14:
            issues.append(f"min length {pp.get('minimum_password_length')} < 14")
        if not pp.get("require_symbols"):
            issues.append("no symbol requirement")
        if not pp.get("require_numbers"):
            issues.append("no number requirement")
        if not pp.get("require_uppercase_characters"):
            issues.append("no uppercase requirement")
        if not pp.get("require_lowercase_characters"):
            issues.append("no lowercase requirement")
        age = pp.get("max_password_age")
        if age in (None, 0):
            issues.append("password expiration disabled")
        elif age != 90:
            issues.append(f"max password age {age} != 90")
        if not issues:
            return [_f(c, s, "account-password-policy", Status.PASS,
                       "Password policy meets minimum hardening requirements.")]
        return [_f(c, s, "account-password-policy", Status.FAIL,
                   "Password policy is weak: " + "; ".join(issues))]

    return [
        Check("AWS-IAM-001", "aws", "IAM", "Identity & Access", Severity.CRITICAL,
              "Root account has active access keys",
              "The AWS root account should never have long-term access keys; all "
              "human and machine access must go through IAM users/roles.",
              "Delete the root access keys, enable SCPs/Organizations and use "
              "IAM roles with temporary credentials.",
              root_keys, cis="CIS AWS 1.3", guidance="CIS 1.3"),
        Check("AWS-IAM-002", "aws", "IAM", "Identity & Access", Severity.CRITICAL,
              "Root account does not have MFA enabled",
              "Root account MFA is the single most important control for the "
              "account; without it a compromised root password is fatal.",
              "Enable a hardware MFA device on the root account immediately.",
              root_mfa, cis="CIS AWS 1.4 / 1.5"),
        Check("AWS-IAM-003", "aws", "IAM", "Identity & Access", Severity.MEDIUM,
              "IAM user access keys older than 90 days",
              "Long-lived access keys increase the blast radius of a leaked "
              "credential. Rotate keys on a 90-day schedule.",
              "Rotate keys and prefer roles/SSO for humans and short-lived "
              "credentials for workloads.",
              user_key_age, cis="CIS AWS 1.13"),
        Check("AWS-IAM-004", "aws", "IAM", "Identity & Access", Severity.HIGH,
              "Console users without MFA",
              "Users with console passwords must use MFA to reduce risk of "
              "credential phishing and password re-use.",
              "Require MFA for all console users (e.g. via an IAM policy "
              "denying console access without MFA).",
              user_mfa, cis="CIS AWS 1.9"),
        Check("AWS-IAM-005", "aws", "IAM", "Identity & Access", Severity.CRITICAL,
              "IAM policies granting full administrative privileges",
              "Policies that grant *:* bypass all least-privilege controls and "
              "make a single compromised identity catastrophic.",
              "Replace full-admin policies with scoped, least-privilege "
              "policies; audit usage with IAM Access Analyzer.",
              admin_policies, cis="CIS AWS 1.15"),
        Check("AWS-IAM-006", "aws", "IAM", "Identity & Access", Severity.MEDIUM,
              "IAM password policy is weak or missing",
              "A strong password policy (length >= 14, all complexity classes) "
              "reduces brute-force and credential-stuffing risk.",
              "Configure a compliant password policy in IAM.",
              password_policy, cis="CIS AWS 1.7 / 1.8"),
    ]


# --------------------------------------------------------------------------- #
# S3
# --------------------------------------------------------------------------- #
def _aws_s3_checks() -> List[Check]:
    def public(c, s, _):
        out = []
        for b in s["s3"]:
            if b.get("public"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "Bucket is publicly readable (bucket policy or ACL "
                              "allows allUsers / authenticated users).",
                              {"public_acl": b.get("public_acl")}))
        if not out:
            out.append(_f(c, s, "s3-buckets", Status.PASS,
                          "No buckets found publicly accessible."))
        return out

    def encryption(c, s, _):
        out = []
        for b in s["s3"]:
            if not b.get("encryption"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "Default encryption (SSE) is not enabled."))
        if not out:
            out.append(_f(c, s, "s3-buckets", Status.PASS,
                          "All buckets have default encryption enabled."))
        return out

    def versioning(c, s, _):
        out = []
        for b in s["s3"]:
            if not b.get("versioning"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "Versioning is disabled; deleted/overwritten objects "
                              "cannot be recovered."))
        if not out:
            out.append(_f(c, s, "s3-buckets", Status.PASS,
                          "All buckets have versioning enabled."))
        return out

    def logging(c, s, _):
        out = []
        for b in s["s3"]:
            if not b.get("logging"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "Server access logging is disabled; no audit trail "
                              "of object-level access."))
        if not out:
            out.append(_f(c, s, "s3-buckets", Status.PASS,
                          "All buckets have access logging enabled."))
        return out

    return [
        Check("AWS-S3-001", "aws", "S3", "Storage & Data Protection", Severity.CRITICAL,
              "S3 bucket publicly accessible",
              "Publicly readable buckets expose sensitive data to the internet.",
              "Block public access at account level (BlockPublicAcl / "
              "BlockPublicPolicy) and keep ACLs off.",
              public, cis="CIS AWS 2.1.4", guidance="SOC2 CC6.1"),
        Check("AWS-S3-002", "aws", "S3", "Storage & Data Protection", Severity.HIGH,
              "S3 bucket default encryption disabled",
              "Unencrypted objects at rest violate data-protection requirements "
              "and CIS AWS 2.1.2.",
              "Enable SSE-S3 or SSE-KMS as the bucket default.",
              encryption, cis="CIS AWS 2.1.3"),
        Check("AWS-S3-003", "aws", "S3", "Storage & Data Protection", Severity.MEDIUM,
              "S3 bucket versioning disabled",
              "Without versioning, accidental deletes or ransomware overwrites "
              "cannot be rolled back.",
              "Enable versioning; pair with lifecycle rules for cost control.",
              versioning, cis="CIS AWS 2.1.2"),
        Check("AWS-S3-004", "aws", "S3", "Logging & Monitoring", Severity.LOW,
              "S3 server access logging disabled",
              "Object-level access logging provides forensic evidence for "
              "compromised credentials and data exfiltration.",
              "Enable server access logging to a dedicated logging bucket.",
              logging),
    ]


# --------------------------------------------------------------------------- #
# EC2 / network / compute
# --------------------------------------------------------------------------- #
def _aws_ec2_checks() -> List[Check]:
    def sg_open(c, s, _):
        out = []
        for sg in s["ec2"]["security_groups"]:
            ports = _sg_open_ports(sg.get("ingress", []))
            if ports:
                out.append(_f(c, s, f"sg:{sg['name']}", Status.FAIL,
                              "Security group exposes ports "
                              f"{sorted(set(ports))} to 0.0.0.0/0.",
                              {"open_ports": sorted(set(ports))}))
        if not out:
            out.append(_f(c, s, "security-groups", Status.PASS,
                          "No security groups expose common management ports "
                          "to the internet."))
        return out

    def ebs_encryption(c, s, _):
        out = []
        for v in s["ec2"]["volumes"]:
            if not v.get("encrypted"):
                out.append(_f(c, s, f"vol:{v['id']}", Status.FAIL,
                              "EBS volume is not encrypted at rest."))
        if not out:
            out.append(_f(c, s, "ebs-volumes", Status.PASS,
                          "All EBS volumes are encrypted."))
        return out

    def ami_public(c, s, _):
        out = []
        for a in s["ec2"]["amis"]:
            if a.get("public"):
                out.append(_f(c, s, f"ami:{a['id']}", Status.FAIL,
                              "AMI is public; any AWS account can launch instances "
                              "from it."))
        if not out:
            out.append(_f(c, s, "amis", Status.PASS, "No public AMIs found."))
        return out

    def instance_public_sg(c, s, _):
        out = []
        for i in s["ec2"]["instances"]:
            if not i.get("public_ip"):
                continue
            for sgid in i.get("security_groups", []):
                sg = next((x for x in s["ec2"]["security_groups"] if x["id"] == sgid), None)
                if sg and _sg_open_ports(sg.get("ingress", [])):
                    out.append(_f(c, s, f"i-{i['id']}", Status.FAIL,
                                  "Instance has a public IP and is attached to a "
                                  "security group exposing management ports."))
        if not out:
            out.append(_f(c, s, "ec2-instances", Status.PASS,
                          "No public instances attached to open security groups."))
        return out

    return [
        Check("AWS-EC2-001", "aws", "EC2/Network", "Network Security", Severity.CRITICAL,
              "Security group exposes management ports to the internet",
              "Ports 22/3389 (or DB/cache ports) open to 0.0.0.0/0 allow direct "
              "internet brute-force and compromise.",
              "Restrict ingress to known CIDRs/VPC endpoints; use AWS Systems "
              "Manager Session Manager instead of SSH.",
              sg_open, cis="CIS AWS 5.3"),
        Check("AWS-EC2-002", "aws", "EC2/Network", "Data Protection", Severity.HIGH,
              "EBS volume not encrypted at rest",
              "Unencrypted volumes expose data if the underlying storage is "
              "compromised or disposed of improperly.",
              "Enable EBS encryption by default at the account level.",
              ebs_encryption, cis="CIS AWS 5.1.1"),
        Check("AWS-EC2-003", "aws", "EC2/Network", "Compute", Severity.HIGH,
              "Public AMI shared with all AWS accounts",
              "Public AMIs can embed malicious software and are a supply-chain risk.",
              "Make AMIs private; share explicitly with trusted accounts.",
              ami_public),
        Check("AWS-EC2-004", "aws", "EC2/Network", "Network Security", Severity.HIGH,
              "Public instance attached to open security group",
              "Internet-exposed instances with permissive security groups are "
              "prime brute-force targets.",
              "Move instances into private subnets behind a bastion/ALB; scope "
              "security groups to the minimum required.",
              instance_public_sg),
    ]


# --------------------------------------------------------------------------- #
# RDS / SNS / CloudTrail / Config / KMS / ECR
# --------------------------------------------------------------------------- #
def _aws_misc_checks() -> List[Check]:
    def rds_public(c, s, _):
        out = []
        for r in s["rds"]:
            if r.get("publicly_accessible"):
                out.append(_f(c, s, f"rds:{r['id']}", Status.FAIL,
                              "RDS instance is publicly accessible.", {}))
        if not out:
            out.append(_f(c, s, "rds-instances", Status.PASS,
                          "No RDS instances are publicly accessible."))
        return out

    def rds_encryption(c, s, _):
        out = []
        for r in s["rds"]:
            if not r.get("storage_encrypted"):
                out.append(_f(c, s, f"rds:{r['id']}", Status.FAIL,
                              "RDS storage encryption is disabled."))
        if not out:
            out.append(_f(c, s, "rds-instances", Status.PASS,
                          "All RDS instances use encrypted storage."))
        return out

    def rds_backup(c, s, _):
        out = []
        for r in s["rds"]:
            if r.get("backup_retention_days", 0) < 7:
                out.append(_f(c, s, f"rds:{r['id']}", Status.FAIL,
                              f"Backup retention is {r.get('backup_retention_days', 0)} "
                              "days (recommended >= 7)."))
        if not out:
            out.append(_f(c, s, "rds-instances", Status.PASS,
                          "All RDS instances have adequate backup retention."))
        return out

    def sns_public(c, s, _):
        out = []
        for t in s["sns"]:
            if t.get("public"):
                out.append(_f(c, s, t["topic_arn"], Status.FAIL,
                              "SNS topic policy allows public subscription/publish."))
        if not out:
            out.append(_f(c, s, "sns-topics", Status.PASS,
                          "No SNS topics are publicly accessible."))
        return out

    def trail(c, s, _):
        t = s["trail"]
        if not t.get("exists"):
            return [_f(c, s, "cloudtrail", Status.FAIL,
                       "CloudTrail is not enabled in this account.")]
        issues = []
        if not t.get("multi_region"):
            issues.append("not multi-region")
        if not t.get("log_file_validation"):
            issues.append("log file integrity validation disabled")
        if issues:
            return [_f(c, s, "cloudtrail", Status.FAIL,
                       "CloudTrail is configured but: " + ", ".join(issues) + ".")]
        return [_f(c, s, "cloudtrail", Status.PASS,
                   "CloudTrail enabled, multi-region, with validation.")]

    def config(c, s, _):
        cfg = s["config"]
        if not cfg.get("recorder"):
            return [_f(c, s, "aws-config", Status.FAIL,
                       "AWS Config recorder is not running.")]
        if not cfg.get("delivering"):
            return [_f(c, s, "aws-config", Status.FAIL,
                       "Config recorder is not delivering to the delivery channel.")]
        return [_f(c, s, "aws-config", Status.PASS,
                   "Config recorder active and delivering.")]

    def kms_rotation(c, s, _):
        out = []
        for k in s["kms"]:
            if not k.get("rotation_enabled"):
                out.append(_f(c, s, f"kms:{k['key_id']}", Status.FAIL,
                              "KMS key rotation is disabled."))
        if not out:
            out.append(_f(c, s, "kms-keys", Status.PASS,
                          "All KMS keys have rotation enabled."))
        return out

    def ecr_public(c, s, _):
        out = []
        for r in s["ecr"]:
            if r.get("public"):
                out.append(_f(c, s, f"ecr:{r['repo_name']}", Status.FAIL,
                              "ECR repository policy allows public pulls."))
        if not out:
            out.append(_f(c, s, "ecr-repos", Status.PASS,
                          "No ECR repositories are public."))
        return out

    def lambda_legacy(c, s, _):
        legacy = {"python3.7", "python3.6", "nodejs12.x", "nodejs10.x", "nodejs8.10",
                  "dotnetcore2.1", "ruby2.5", "go1.x"}
        out = []
        for f in s["lambda"]:
            if f.get("runtime") in legacy:
                out.append(_f(c, s, f"lambda:{f['name']}", Status.FAIL,
                              f"Lambda uses end-of-life runtime {f['runtime']}."))
        if not out:
            out.append(_f(c, s, "lambda-functions", Status.PASS,
                          "No Lambda functions on deprecated runtimes."))
        return out

    return [
        Check("AWS-RDS-001", "aws", "RDS", "Database", Severity.CRITICAL,
              "RDS instance is publicly accessible",
              "Publicly reachable databases can be brute-forced or exploited "
              "directly from the internet.",
              "Disable public accessibility and place RDS in private subnets.",
              rds_public, cis="CIS AWS 2.2.3"),
        Check("AWS-RDS-002", "aws", "RDS", "Data Protection", Severity.HIGH,
              "RDS storage encryption disabled",
              "Unencrypted database storage violates at-rest encryption "
              "requirements.",
              "Enable RDS encryption (may require re-creation).",
              rds_encryption),
        Check("AWS-RDS-003", "aws", "RDS", "Backup & Recovery", Severity.MEDIUM,
              "RDS backup retention below 7 days",
              "Short retention limits point-in-time recovery capability.",
              "Set automated backup retention to at least 7 days.",
              rds_backup),
        Check("AWS-SNS-001", "aws", "SNS", "Network Security", Severity.MEDIUM,
              "SNS topic publicly accessible",
              "Public topic policies allow external actors to subscribe and "
              "receive sensitive notifications.",
              "Restrict topic policies to trusted principals and actions.",
              sns_public),
        Check("AWS-CT-001", "aws", "CloudTrail", "Logging & Monitoring", Severity.CRITICAL,
              "CloudTrail disabled or misconfigured",
              "Without CloudTrail there is no audit trail of API activity, "
              "breaking detection and forensics.",
              "Enable a multi-region trail with log file validation and an "
              "S3/KMS backed log store.",
              trail, cis="CIS AWS 3.1"),
        Check("AWS-CFG-001", "aws", "Config", "Logging & Monitoring", Severity.MEDIUM,
              "AWS Config recorder not running",
              "Config detects configuration drift that would otherwise go "
              "unnoticed.",
              "Enable the Config recorder and delivery channel.",
              config, cis="CIS AWS 3.3"),
        Check("AWS-KMS-001", "aws", "KMS", "Key Management", Severity.MEDIUM,
              "KMS key rotation disabled",
              "Without rotation, long-lived keys increase the impact of a leak.",
              "Enable automatic yearly rotation for symmetric customer keys.",
              kms_rotation, cis="CIS AWS 3.6"),
        Check("AWS-ECR-001", "aws", "ECR", "Container Security", Severity.HIGH,
              "ECR repository publicly accessible",
              "Public repositories expose container images that may contain "
              "secrets or proprietary code.",
              "Set repository policy to deny public access and enforce "
              "private-only pulls.",
              ecr_public),
        Check("AWS-LMB-001", "aws", "Lambda", "Compute", Severity.MEDIUM,
              "Lambda function on deprecated runtime",
              "End-of-life runtimes no longer receive security patches.",
              "Migrate to a supported runtime (e.g. python3.12, nodejs20.x).",
              lambda_legacy),
    ]


# --------------------------------------------------------------------------- #
# VPC / network hardening
# --------------------------------------------------------------------------- #
def _aws_network_checks() -> List[Check]:
    def default_vpc(c, s, _):
        out = []
        for v in s.get("vpcs", []):
            if v.get("is_default"):
                out.append(_f(c, s, f"vpc:{v['id']}", Status.FAIL,
                              "The default VPC exists and is in use; it ships with "
                              "permissive routing and no guard rails."))
        if not out:
            out.append(_f(c, s, "vpcs", Status.PASS, "No default VPC in use."))
        return out

    def flow_logs(c, s, _):
        out = []
        for v in s.get("vpcs", []):
            if not v.get("flow_logs"):
                out.append(_f(c, s, f"vpc:{v['id']}", Status.FAIL,
                              "VPC flow logging is not enabled; network traffic "
                              "cannot be audited or forensically reconstructed."))
        if not out:
            out.append(_f(c, s, "vpcs", Status.PASS, "All VPCs have flow logging enabled."))
        return out

    def nacl_open(c, s, _):
        out = []
        for n in s.get("nacls", []):
            if n.get("open_all"):
                out.append(_f(c, s, f"nacl:{n['id']}", Status.FAIL,
                              "NACL contains an inbound allow-all rule from "
                              "0.0.0.0/0, bypassing subnet-level filtering."))
        if not out:
            out.append(_f(c, s, "network-acls", Status.PASS,
                          "No NACLs allow all inbound traffic."))
        return out

    def default_sg_open(c, s, _):
        if s["ec2"].get("default_sg_open"):
            return [_f(c, s, "default-security-group", Status.FAIL,
                       "The default security group allows ingress from 0.0.0.0/0; "
                       "default groups should have no inbound rules.")]
        return [_f(c, s, "default-security-group", Status.PASS,
                   "Default security group has no open ingress rules.")]

    return [
        Check("AWS-VPC-001", "aws", "VPC", "Network Security", Severity.HIGH,
              "Default VPC in use",
              "The default VPC ships with permissive subnets, routing and an "
              "internet gateway - workloads there often bypass planned "
              "architecture and guard rails.",
              "Delete the default VPC (or stop using it) and deploy workloads "
              "in purpose-built VPCs.",
              default_vpc),
        Check("AWS-VPC-002", "aws", "VPC", "Logging & Monitoring", Severity.MEDIUM,
              "VPC flow logging not enabled",
              "Without flow logs, network traffic is invisible to detection and "
              "forensics.",
              "Enable flow logs on every VPC to a centralized log destination.",
              flow_logs, cis="CIS AWS 3.7"),
        Check("AWS-VPC-003", "aws", "VPC", "Network Security", Severity.MEDIUM,
              "NACL allows all inbound traffic",
              "Allow-all NACL entries negate subnet-level protection and mask "
              "the intent of security groups.",
              "Replace allow-all NACL entries with explicit allow rules for "
              "required traffic.",
              nacl_open),
        Check("AWS-VPC-004", "aws", "VPC", "Network Security", Severity.HIGH,
              "Default security group allows open ingress",
              "Open ingress on the default security group exposes every "
              "instance using it to the internet.",
              "Remove all inbound rules from default security groups.",
              default_sg_open, cis="CIS AWS 5.5"),
    ]


# --------------------------------------------------------------------------- #
# EC2 instance hardening
# --------------------------------------------------------------------------- #
def _aws_instance_checks() -> List[Check]:
    def ebs_default(c, s, _):
        if s["ec2"].get("ebs_default_encryption"):
            return [_f(c, s, "account-ebs", Status.PASS,
                       "EBS encryption by default is enabled at account level.")]
        return [_f(c, s, "account-ebs", Status.FAIL,
                   "EBS encryption by default is not enabled; new volumes are "
                   "created unencrypted unless specified.")]

    def _per_instance(c, s, field, good, label, how):
        out = []
        for i in s["ec2"]["instances"]:
            if i.get(field) != good:
                out.append(_f(c, s, f"i-{i['id']}", Status.FAIL, label.format(i=i)))
        if not out:
            out.append(_f(c, s, "ec2-instances", Status.PASS, how))
        return out

    def imdsv2(c, s, _):
        return _per_instance(c, s, "imdsv2", True,
                             "Instance does not require IMDSv2 (session-based "
                             "tokens); the SSRF risk profile is higher.",
                             "All instances require IMDSv2.")

    def term_protect(c, s, _):
        return _per_instance(c, s, "termination_protection", True,
                             "Instance termination protection is disabled; a "
                             "stray terminate API call destroys it.",
                             "All instances have termination protection enabled.")

    def monitoring(c, s, _):
        return _per_instance(c, s, "monitoring", True,
                             "Detailed CloudWatch monitoring is disabled on the "
                             "instance.",
                             "All instances have detailed monitoring enabled.")

    return [
        Check("AWS-EC2-005", "aws", "EC2", "Data Protection", Severity.MEDIUM,
              "EBS encryption by default disabled",
              "New EBS volumes are unencrypted by default unless the account "
              "setting is enabled.",
              "Enable EBS encryption by default and use a CMK where required.",
              ebs_default, cis="CIS AWS 5.1.1"),
        Check("AWS-EC2-006", "aws", "EC2", "Compute", Severity.MEDIUM,
              "EC2 instance does not require IMDSv2",
              "IMDSv1 allows token-less metadata access, enabling SSRF-based "
              "credential theft.",
              "Enforce IMDSv2 (HttpTokens=required) on instances and AMIs.",
              imdsv2),
        Check("AWS-EC2-007", "aws", "EC2", "Backup & Recovery", Severity.LOW,
              "EC2 termination protection disabled",
              "Without termination protection an accidental or malicious "
              "terminate call destroys the instance.",
              "Enable disableApiTermination on production instances.",
              term_protect),
        Check("AWS-EC2-008", "aws", "EC2", "Logging & Monitoring", Severity.LOW,
              "EC2 detailed monitoring disabled",
              "Basic monitoring misses short-lived CPU/network spikes needed "
              "for alerting.",
              "Enable detailed monitoring on critical instances.",
              monitoring),
    ]


# --------------------------------------------------------------------------- #
# CloudWatch alarms (CIS 4.1-4.10)
# --------------------------------------------------------------------------- #
def _aws_cw_checks() -> List[Check]:
    # Matching is substring-based against alarm names: an alarm is considered
    # present when its lowercased name contains every keyword below. Real-world
    # alarm names vary, so name your alarms to include these keywords (e.g.
    # "root-account-usage-alarm", "iam-policy-change-alarm").
    def _alarm_factory(needles, title, detail, rem, num, cis_ref):
        def run(c, s, _):
            names = [n.lower() for n in s["cw"].get("metric_alarms", [])]
            if any(all(nd in n for nd in needles) for n in names):
                return [_f(c, s, "cloudwatch-alarms", Status.PASS, title + " - alarm present.")]
            return [_f(c, s, "cloudwatch-alarms", Status.FAIL, detail)]
        return Check(f"AWS-CW-{int(num):03d}", "aws", "CloudWatch",
                     "Logging & Monitoring", Severity.MEDIUM, title, detail, rem,
                     run, cis=f"CIS AWS {cis_ref}")

    return [
        _alarm_factory(["root"], "No alarm for root account usage",
                       "No CloudWatch alarm fires when the root account is used - "
                       "root activity is the single most dangerous event to miss.",
                       "Create a metric filter + alarm for RootAccountUsageEvent.", "3", "4.3"),
        _alarm_factory(["iam", "policy"], "No alarm for IAM policy changes",
                       "IAM policy changes can silently grant privileges; without "
                       "an alarm they go unnoticed.",
                       "Create a metric filter + alarm for IAM PolicyEvent changes.", "4", "4.4"),
        _alarm_factory(["trail"], "No alarm for CloudTrail changes",
                       "Disabling or misconfiguring CloudTrail removes the audit "
                       "trail - changes must alert.",
                       "Create a metric filter + alarm for CloudTrail events.", "5", "4.5"),
        _alarm_factory(["signin", "mfa"], "No alarm for console sign-in without MFA",
                       "Sign-ins without MFA indicate a bypass or a compromised "
                       "password.",
                       "Create a metric filter + alarm for ConsoleLogin without MFA.", "6", "4.2"),
        _alarm_factory(["nacl"], "No alarm for NACL changes",
                       "NACL changes alter subnet traffic filtering; unexpected "
                       "changes must alert.",
                       "Create a metric filter + alarm for NetworkAcl events.", "7", "4.11"),
        _alarm_factory(["securitygroup", "sg"], "No alarm for security group changes",
                       "Security group changes can open ports to the internet.",
                       "Create a metric filter + alarm for SecurityGroup events.", "8", "4.10"),
        _alarm_factory(["s3", "bucket"], "No alarm for S3 bucket policy changes",
                       "Bucket policy changes can make data public.",
                       "Create a metric filter + alarm for PutBucketPolicy events.", "9", "4.8"),
        _alarm_factory(["kms"], "No alarm for KMS key changes",
                       "KMS key deletion/disabling destroys or locks data.",
                       "Create a metric filter + alarm for KMS key events.", "10", "4.7"),
        _alarm_factory(["unauthorized"], "No alarm for unauthorized API calls",
                       "Repeated denied API calls are a classic attack signal.",
                       "Create a metric filter + alarm for UnauthorizedOperation events.", "1", "4.1"),
        _alarm_factory(["failed", "signin"], "No alarm for failed console sign-ins",
                       "Brute-force and credential-stuffing attempts produce "
                       "failed sign-ins.",
                       "Create a metric filter + alarm for ConsoleLogin failures.", "2", "4.6"),
    ]


# --------------------------------------------------------------------------- #
# Detection / secrets / certs
# --------------------------------------------------------------------------- #
def _aws_detection_checks() -> List[Check]:
    def guardduty(c, s, _):
        if any(d.get("enabled") for d in s.get("guardduty", [])):
            return [_f(c, s, "guardduty", Status.PASS,
                       "GuardDuty is enabled with an active detector.")]
        return [_f(c, s, "guardduty", Status.FAIL,
                   "GuardDuty is not enabled in the scanned region; threat "
                   "detection is blind.")]

    def secret_rotation(c, s, _):
        out = []
        for x in s.get("secrets", []):
            if not x.get("rotation_enabled"):
                out.append(_f(c, s, f"secret:{x['name']}", Status.FAIL,
                              "Secret rotation is disabled; a leaked secret keeps "
                              "working indefinitely."))
        if not out:
            out.append(_f(c, s, "secrets-manager", Status.PASS,
                          "All secrets have rotation enabled."))
        return out

    def acm_expiry(c, s, _):
        out = []
        for cert in s.get("acm", []):
            d = cert.get("days_to_expiry", 9999)
            if cert.get("in_use") and d <= 30:
                label = "has expired" if d < 0 else f"expires in {d} day(s)"
                out.append(_f(c, s, f"cert:{cert['arn']}", Status.FAIL,
                              f"In-use certificate {label}; renew immediately to "
                              "avoid service outage.",
                              evidence={"days_to_expiry": d}))
        if not out:
            out.append(_f(c, s, "acm-certificates", Status.PASS,
                          "No in-use certificates are expired or close to expiry."))
        return out

    def trail_logging(c, s, _):
        t = s["trail"]
        if not t.get("exists"):
            return [_f(c, s, "cloudtrail", Status.FAIL,
                       "CloudTrail is not enabled (see AWS-CT-001).")]
        if not t.get("logging"):
            return [_f(c, s, "cloudtrail", Status.FAIL,
                       "The CloudTrail trail exists but is not actively logging.")]
        return [_f(c, s, "cloudtrail", Status.PASS, "CloudTrail is actively logging.")]

    return [
        Check("AWS-GD-001", "aws", "GuardDuty", "Security Posture", Severity.HIGH,
              "GuardDuty not enabled",
              "Without GuardDuty, credential compromise, crypto-mining and "
              "exfiltration behaviors go undetected.",
              "Enable GuardDuty with an active detector and integrate findings "
              "into your SIEM.",
              guardduty),  # GuardDuty has no CIS AWS v5.0 control - kept unmapped
        Check("AWS-SM-001", "aws", "Secrets Manager", "Key Management", Severity.MEDIUM,
              "Secret rotation disabled",
              "Non-rotating secrets become more valuable the longer they leak.",
              "Enable automatic rotation (every 30-90 days) for all secrets.",
              secret_rotation),
        Check("AWS-ACM-001", "aws", "ACM", "Network Security", Severity.HIGH,
              "In-use certificate expiring within 30 days",
              "Expired certificates break TLS for users and services; manual "
              "renewal often fails silently.",
              "Enable automatic renewal or monitor certificate expiry.",
              acm_expiry),
        Check("AWS-CT-005", "aws", "CloudTrail", "Logging & Monitoring", Severity.CRITICAL,
              "CloudTrail not actively logging",
              "A trail that exists but does not log provides no audit trail.",
              "Verify trail status shows IsLogging true and fix the delivery "
              "configuration.",
              trail_logging, cis="CIS AWS 3.1"),
    ]


# --------------------------------------------------------------------------- #
# Data-plane hardening (SQS / DynamoDB / Redshift / EFS / ElastiCache / RDS)
# --------------------------------------------------------------------------- #
def _aws_data_checks() -> List[Check]:
    def sqs_public(c, s, _):
        out = []
        for q in s.get("sqs", []):
            if q.get("public"):
                out.append(_f(c, s, q["url"], Status.FAIL,
                              "SQS queue policy allows anonymous SendMessage."))
        if not out:
            out.append(_f(c, s, "sqs-queues", Status.PASS,
                          "No SQS queues allow anonymous sends."))
        return out

    def sqs_enc(c, s, _):
        out = []
        for q in s.get("sqs", []):
            if not q.get("encrypted"):
                out.append(_f(c, s, q["url"], Status.FAIL,
                              "SQS queue does not use server-side encryption."))
        if not out:
            out.append(_f(c, s, "sqs-queues", Status.PASS,
                          "All SQS queues are SSE-encrypted."))
        return out

    def ddb_pitr(c, s, _):
        out = []
        for t in s.get("dynamodb", []):
            if not t.get("pitr"):
                out.append(_f(c, s, f"ddb:{t['name']}", Status.FAIL,
                              "Point-in-time recovery is disabled; data can only "
                              "be restored to the last backup."))
        if not out:
            out.append(_f(c, s, "dynamodb-tables", Status.PASS,
                          "All tables have PITR enabled."))
        return out

    def ddb_sse(c, s, _):
        out = []
        for t in s.get("dynamodb", []):
            if not t.get("sse"):
                out.append(_f(c, s, f"ddb:{t['name']}", Status.FAIL,
                              "Table is not encrypted with a KMS key."))
        if not out:
            out.append(_f(c, s, "dynamodb-tables", Status.PASS,
                          "All tables use KMS encryption."))
        return out

    def rs_public(c, s, _):
        out = []
        for c_ in s.get("redshift", []):
            if c_.get("public"):
                out.append(_f(c, s, f"redshift:{c_['id']}", Status.FAIL,
                              "Redshift cluster is publicly accessible."))
        if not out:
            out.append(_f(c, s, "redshift-clusters", Status.PASS,
                          "No Redshift clusters are publicly accessible."))
        return out

    def rs_enc(c, s, _):
        out = []
        for c_ in s.get("redshift", []):
            if not c_.get("encrypted"):
                out.append(_f(c, s, f"redshift:{c_['id']}", Status.FAIL,
                              "Redshift cluster encryption is disabled."))
        if not out:
            out.append(_f(c, s, "redshift-clusters", Status.PASS,
                          "All Redshift clusters are encrypted."))
        return out

    def rs_logging(c, s, _):
        out = []
        for c_ in s.get("redshift", []):
            if not c_.get("logging"):
                out.append(_f(c, s, f"redshift:{c_['id']}", Status.FAIL,
                              "Redshift audit logging is disabled."))
        if not out:
            out.append(_f(c, s, "redshift-clusters", Status.PASS,
                          "All Redshift clusters log to S3/CloudWatch."))
        return out

    def efs_enc(c, s, _):
        out = []
        for f in s.get("efs", []):
            if not f.get("encrypted"):
                out.append(_f(c, s, f"efs:{f['id']}", Status.FAIL,
                              "EFS file system is not encrypted at rest."))
        if not out:
            out.append(_f(c, s, "efs-file-systems", Status.PASS,
                          "All EFS file systems are encrypted."))
        return out

    def efs_backup(c, s, _):
        out = []
        for f in s.get("efs", []):
            if not f.get("backup"):
                out.append(_f(c, s, f"efs:{f['id']}", Status.FAIL,
                              "EFS file system has no automatic backup policy."))
        if not out:
            out.append(_f(c, s, "efs-file-systems", Status.PASS,
                          "All EFS file systems have backups."))
        return out

    def ec_at_rest(c, s, _):
        out = []
        for cc in s.get("elasticache", []):
            if not cc.get("at_rest"):
                out.append(_f(c, s, f"elasticache:{cc['id']}", Status.FAIL,
                              "ElastiCache cluster is not encrypted at rest."))
        if not out:
            out.append(_f(c, s, "elasticache-clusters", Status.PASS,
                          "All ElastiCache clusters are encrypted at rest."))
        return out

    def ec_transit(c, s, _):
        out = []
        for cc in s.get("elasticache", []):
            if not cc.get("transit"):
                out.append(_f(c, s, f"elasticache:{cc['id']}", Status.FAIL,
                              "ElastiCache cluster does not encrypt traffic in "
                              "transit."))
        if not out:
            out.append(_f(c, s, "elasticache-clusters", Status.PASS,
                          "All ElastiCache clusters encrypt in transit."))
        return out

    def rds_delprot(c, s, _):
        out = []
        for r in s["rds"]:
            if not r.get("deletion_protection"):
                out.append(_f(c, s, f"rds:{r['id']}", Status.FAIL,
                              "Deletion protection is disabled; the database can "
                              "be deleted accidentally or maliciously."))
        if not out:
            out.append(_f(c, s, "rds-instances", Status.PASS,
                          "All RDS instances have deletion protection."))
        return out

    def rds_multiaz(c, s, _):
        out = []
        for r in s["rds"]:
            if not r.get("multi_az"):
                out.append(_f(c, s, f"rds:{r['id']}", Status.FAIL,
                              "RDS instance is not Multi-AZ; failover on AZ loss "
                              "is unavailable."))
        if not out:
            out.append(_f(c, s, "rds-instances", Status.PASS,
                          "All RDS instances are Multi-AZ."))
        return out

    return [
        Check("AWS-SQS-001", "aws", "SQS", "Network Security", Severity.MEDIUM,
              "SQS queue publicly accessible",
              "Anonymous SendMessage policies let external actors inject "
              "messages into your queue.",
              "Restrict queue policies to trusted principals.",
              sqs_public),
        Check("AWS-SQS-002", "aws", "SQS", "Data Protection", Severity.MEDIUM,
              "SQS queue not encrypted",
              "Messages at rest are readable if queue storage is compromised.",
              "Enable SSE (SQS-managed or KMS) on all queues.",
              sqs_enc),
        Check("AWS-DDB-001", "aws", "DynamoDB", "Backup & Recovery", Severity.MEDIUM,
              "DynamoDB point-in-time recovery disabled",
              "Without PITR, accidental deletes/updates cannot be rolled back.",
              "Enable PITR on all production tables.",
              ddb_pitr),
        Check("AWS-DDB-002", "aws", "DynamoDB", "Data Protection", Severity.LOW,
              "DynamoDB table not KMS-encrypted",
              "Tables rely on default encryption or lack key-level control.",
              "Configure KMS customer-managed keys for tables.",
              ddb_sse),
        Check("AWS-RSH-001", "aws", "Redshift", "Database", Severity.CRITICAL,
              "Redshift cluster publicly accessible",
              "Public clusters expose large datasets to the internet; the "
              "security-group barrier is the only protection.",
              "Disable public accessibility and place clusters in private "
              "subnets.",
              rs_public),  # Redshift has no CIS AWS v5.0 control - kept unmapped
        Check("AWS-RSH-002", "aws", "Redshift", "Data Protection", Severity.HIGH,
              "Redshift encryption disabled",
              "Unencrypted clusters store data at rest in plaintext.",
              "Enable cluster encryption (may require re-creation).",
              rs_enc),
        Check("AWS-RSH-003", "aws", "Redshift", "Logging & Monitoring", Severity.MEDIUM,
              "Redshift audit logging disabled",
              "Without audit logging, who did what against the warehouse is "
              "unknowable.",
              "Enable audit logging to S3/CloudWatch.",
              rs_logging),
        Check("AWS-EFS-001", "aws", "EFS", "Data Protection", Severity.HIGH,
              "EFS file system not encrypted",
              "Unencrypted EFS stores file contents at rest in plaintext.",
              "Recreate the file system with encryption enabled.",
              efs_enc),
        Check("AWS-EFS-002", "aws", "EFS", "Backup & Recovery", Severity.LOW,
              "EFS backup policy missing",
              "Without an AWS Backup policy, file system data has no recovery "
              "path.",
              "Attach an AWS Backup policy to the file system.",
              efs_backup),
        Check("AWS-EC-001", "aws", "ElastiCache", "Data Protection", Severity.HIGH,
              "ElastiCache not encrypted at rest",
              "Cached data (sessions, tokens, PII) is readable at rest.",
              "Enable at-rest encryption on the cluster.",
              ec_at_rest),
        Check("AWS-EC-002", "aws", "ElastiCache", "Network Security", Severity.HIGH,
              "ElastiCache not encrypted in transit",
              "Traffic to the cache can be intercepted without transit "
              "encryption.",
              "Enable in-transit encryption (Redis AUTH).",
              ec_transit),
        Check("AWS-RDS-004", "aws", "RDS", "Backup & Recovery", Severity.MEDIUM,
              "RDS deletion protection disabled",
              "Accidental or malicious deletion destroys the database and its "
              "backups.",
              "Enable deletion protection on all production instances.",
              rds_delprot),
        Check("AWS-RDS-005", "aws", "RDS", "Backup & Recovery", Severity.LOW,
              "RDS instance not Multi-AZ",
              "Single-AZ instances fail on AZ loss and need manual failover.",
              "Enable Multi-AZ deployment.",
              rds_multiaz),
    ]


# --------------------------------------------------------------------------- #
# Web / edge / container hardening
# --------------------------------------------------------------------------- #
def _aws_web_checks() -> List[Check]:
    def elb_https(c, s, _):
        out = []
        for lb in s.get("elb", []):
            if not lb.get("https"):
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "Load balancer has no HTTPS/TLS listener; client "
                              "traffic is plaintext."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "All load balancers terminate TLS."))
        return out

    def elb_logs(c, s, _):
        out = []
        for lb in s.get("elb", []):
            if not lb.get("access_logs"):
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "Load balancer access logging is disabled."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "All load balancers log access."))
        return out

    def eks_public(c, s, _):
        out = []
        for cl in s.get("eks", []):
            if cl.get("public_endpoint"):
                out.append(_f(c, s, f"eks:{cl['name']}", Status.FAIL,
                              "EKS cluster API endpoint is publicly accessible."))
        if not out:
            out.append(_f(c, s, "eks-clusters", Status.PASS,
                          "All EKS clusters use private API endpoints."))
        return out

    def apigw_logging(c, s, _):
        out = []
        for api in s.get("apigw", []):
            if not api.get("logging"):
                out.append(_f(c, s, f"apigw:{api['name']}", Status.FAIL,
                              "API Gateway stage has no access logging or method "
                              "settings."))
        if not out:
            out.append(_f(c, s, "api-gateways", Status.PASS,
                          "All API Gateway stages log access."))
        return out

    def r53_dnssec(c, s, _):
        if s["r53"].get("dnssec"):
            return [_f(c, s, "route53", Status.PASS,
                       "DNSSEC signing is enabled on a hosted zone.")]
        return [_f(c, s, "route53", Status.FAIL,
                   "DNSSEC is not enabled on any hosted zone; DNS responses "
                   "can be spoofed.")]

    def s3_block_public(c, s, _):
        if s.get("s3_block_public"):
            return [_f(c, s, "s3-block-public", Status.PASS,
                       "Account-level S3 block public access is enabled.")]
        return [_f(c, s, "s3-block-public", Status.FAIL,
                   "Account-level S3 block public access is not fully enabled.")]

    return [
        Check("AWS-ELB-001", "aws", "ELB", "Network Security", Severity.HIGH,
              "Load balancer without HTTPS/TLS listener",
              "Plaintext listeners expose credentials and session data.",
              "Add HTTPS/TLS listeners and redirect HTTP to HTTPS.",
              elb_https),
        Check("AWS-ELB-002", "aws", "ELB", "Logging & Monitoring", Severity.MEDIUM,
              "Load balancer access logging disabled",
              "Without access logs, request-level forensic evidence is lost.",
              "Enable access logs to a centralized S3 bucket.",
              elb_logs),
        Check("AWS-EKS-001", "aws", "EKS", "Kubernetes", Severity.HIGH,
              "EKS cluster API endpoint publicly accessible",
              "A public API endpoint exposes the control plane to the internet; "
              "RBAC is the only barrier.",
              "Disable public endpoint access and use private endpoints with "
              "authorized CIDRs.",
              eks_public),
        Check("AWS-API-001", "aws", "API Gateway", "Logging & Monitoring", Severity.MEDIUM,
              "API Gateway access logging disabled",
              "Without access logs, abuse of your APIs is undetectable.",
              "Enable access logging and method settings on all stages.",
              apigw_logging),
        Check("AWS-R53-001", "aws", "Route 53", "Network Security", Severity.LOW,
              "DNSSEC not enabled",
              "Unsigned DNS allows response spoofing and cache poisoning.",
              "Enable DNSSEC signing on production hosted zones.",
              r53_dnssec),
        Check("AWS-S3-005", "aws", "S3", "Storage & Data Protection", Severity.CRITICAL,
              "Account-level S3 block public access disabled",
              "Without the account-level block, a single bad bucket policy or "
              "ACL makes data public.",
              "Enable all four block public access settings at account level.",
              s3_block_public, cis="CIS AWS 2.1.4"),
    ]


# --------------------------------------------------------------------------- #
# Tranche 2: CloudFront / ELB extras / log groups / Backup / snapshots / trust
# --------------------------------------------------------------------------- #
def _aws_tier2_checks() -> List[Check]:
    def cf_waf(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if not d.get("waf_attached"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "Distribution is not associated with an AWS WAF "
                              "web ACL; no L7 filtering."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions have WAF attached."))
        return out

    def cf_tls(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            mt = d.get("min_tls") or ""
            if mt not in ("TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.2_2018"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              f"Minimum TLS protocol is {mt or 'unset'} (require "
                              "TLSv1.2+)."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions require TLS 1.2+."))
        return out

    def cf_logging(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if not d.get("logging"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "Distribution access logging is disabled."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions log access."))
        return out

    def cf_default_cert(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if d.get("default_cert"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "Distribution uses the default cloudfront.net "
                              "certificate; serve content under your own domain "
                              "with an ACM cert."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions use custom ACM certificates."))
        return out

    def cf_origin_http(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if d.get("origin_http"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "Origin protocol policy is HTTP-only; edge-to-origin "
                              "traffic is plaintext."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All origins use HTTPS protocol policy."))
        return out

    def elb_ssl_policy(c, s, _):
        out = []
        for lb in s.get("elb", []):
            if lb.get("ssl_policy_secure") is False:
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "Listener uses a deprecated SSL policy (TLS 1.0/1.1 "
                              "or pre-2016 ciphers)."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "All listeners use modern SSL policies."))
        return out

    def elb_http_redirect(c, s, _):
        out = []
        for lb in s.get("elb", []):
            if lb.get("http_no_redirect"):
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "HTTP listener does not redirect to HTTPS."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "All HTTP listeners redirect to HTTPS."))
        return out

    def elb_waf(c, s, _):
        out = []
        for lb in s.get("elb", []):
            if lb.get("type") == "application" and not lb.get("waf_attached"):
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "Application load balancer is not associated with a "
                              "WAF web ACL."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "All application load balancers have WAF attached."))
        return out

    def rds_log_exports(c, s, _):
        out = []
        for r in s["rds"]:
            if not r.get("log_exports"):
                out.append(_f(c, s, f"rds:{r['id']}", Status.FAIL,
                              "RDS does not export logs (error/general/slow-query) "
                              "to CloudWatch."))
        if not out:
            out.append(_f(c, s, "rds-instances", Status.PASS,
                          "All RDS instances export logs to CloudWatch."))
        return out

    def eks_logging(c, s, _):
        out = []
        for cl in s.get("eks", []):
            if not cl.get("logging_enabled"):
                out.append(_f(c, s, f"eks:{cl['name']}", Status.FAIL,
                              "EKS control plane logging (audit/authenticator) is "
                              "not enabled."))
        if not out:
            out.append(_f(c, s, "eks-clusters", Status.PASS,
                          "All EKS clusters log the control plane."))
        return out

    def log_retention(c, s, _):
        out = []
        for lg in s.get("loggroups", []):
            r = lg.get("retention_days")
            if r is None or r < 365:
                out.append(_f(c, s, f"loggroup:{lg['name']}", Status.FAIL,
                              f"Log group retention is {r if r else 'never-expire-but-unset'}; "
                              "keep audit logs at least 365 days.",
                              evidence={"retention_days": r}))
        if not out:
            out.append(_f(c, s, "log-groups", Status.PASS,
                          "All log groups retain >= 365 days."))
        return out

    def log_encryption(c, s, _):
        out = []
        for lg in s.get("loggroups", []):
            if not lg.get("encrypted"):
                out.append(_f(c, s, f"loggroup:{lg['name']}", Status.FAIL,
                              "Log group is not encrypted with a KMS key."))
        if not out:
            out.append(_f(c, s, "log-groups", Status.PASS,
                          "All log groups are KMS-encrypted."))
        return out

    def backup_plan(c, s, _):
        if s.get("backup", {}).get("plans", 0) > 0:
            return [_f(c, s, "aws-backup", Status.PASS,
                       "AWS Backup plans exist for the account.")]
        return [_f(c, s, "aws-backup", Status.FAIL,
                   "No AWS Backup plans exist; resources rely on per-service "
                   "backups only.")]

    def secret_cmk(c, s, _):
        out = []
        for x in s.get("secrets", []):
            if not x.get("kms_cmk"):
                out.append(_f(c, s, f"secret:{x['name']}", Status.FAIL,
                              "Secret uses the default AWS-managed KMS key, not a "
                              "customer-managed key."))
        if not out:
            out.append(_f(c, s, "secrets-manager", Status.PASS,
                          "All secrets use CMKs."))
        return out

    def snapshot_public(c, s, _):
        out = []
        for snap in s.get("snapshots", []):
            if snap.get("public"):
                out.append(_f(c, s, f"snapshot:{snap['id']}", Status.FAIL,
                              "EBS snapshot is public; any AWS account can copy "
                              "it and read the data."))
        if not out:
            out.append(_f(c, s, "ebs-snapshots", Status.PASS,
                          "No EBS snapshots are public."))
        return out

    def cross_account(c, s, _):
        out = []
        for name in s["iam"].get("cross_account_roles", []):
            out.append(_f(c, s, f"role:{name}", Status.FAIL,
                          "Role trust policy allows principals from another "
                          "account; verify it is intended and limited."))
        if not out:
            out.append(_f(c, s, "iam-roles", Status.PASS,
                          "No cross-account trust roles found."))
        return out

    def s3_lifecycle(c, s, _):
        out = []
        for b in s["s3"]:
            if not b.get("lifecycle"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "Bucket has no lifecycle rules; stale objects "
                              "accumulate cost and risk."))
        if not out:
            out.append(_f(c, s, "s3-buckets", Status.PASS,
                          "All buckets define lifecycle rules."))
        return out

    def lambda_public(c, s, _):
        out = []
        for f in s["lambda"]:
            if f.get("public_policy"):
                out.append(_f(c, s, f"lambda:{f['name']}", Status.FAIL,
                              "Function resource policy allows anonymous invoke."))
        if not out:
            out.append(_f(c, s, "lambda-functions", Status.PASS,
                          "No functions allow anonymous invocation."))
        return out

    def ddb_public(c, s, _):
        out = []
        for t in s.get("dynamodb", []):
            if t.get("public"):
                out.append(_f(c, s, f"ddb:{t['name']}", Status.FAIL,
                              "Table policy allows anonymous access."))
        if not out:
            out.append(_f(c, s, "dynamodb-tables", Status.PASS,
                          "No tables have public policies."))
        return out

    return [
        Check("AWS-CF-001", "aws", "CloudFront", "Network Security", Severity.HIGH,
              "CloudFront distribution without WAF",
              "Distributions without WAF get no L7 filtering against SQLi/XSS "
              "and bot traffic.",
              "Associate an AWS WAF web ACL with every distribution.",
              cf_waf),
        Check("AWS-CF-002", "aws", "CloudFront", "Network Security", Severity.MEDIUM,
              "CloudFront minimum TLS below 1.2",
              "Legacy TLS versions weaken edge encryption.",
              "Set MinimumProtocolVersion to TLSv1.2_2021.",
              cf_tls),
        Check("AWS-CF-003", "aws", "CloudFront", "Logging & Monitoring", Severity.LOW,
              "CloudFront access logging disabled",
              "Without access logs, requests to your edge are invisible.",
              "Enable standard/real-time logging to S3.",
              cf_logging),
        Check("AWS-CF-004", "aws", "CloudFront", "Network Security", Severity.MEDIUM,
              "CloudFront uses default certificate",
              "Serving via the default cloudfront.net cert prevents custom "
              "domain control and SSL certificates.",
              "Attach an ACM certificate and serve under your domain.",
              cf_default_cert),
        Check("AWS-CF-005", "aws", "CloudFront", "Network Security", Severity.MEDIUM,
              "CloudFront origin uses HTTP",
              "Edge-to-origin HTTP transmits content in plaintext.",
              "Set origin protocol policy to HTTPS-only.",
              cf_origin_http),
        Check("AWS-ELB-003", "aws", "ELB", "Network Security", Severity.MEDIUM,
              "Load balancer uses deprecated SSL policy",
              "TLS 1.0/1.1 policies are vulnerable to known attacks.",
              "Use an ELBSecurityPolicy-TLS-1-2 policy on all listeners.",
              elb_ssl_policy),
        Check("AWS-ELB-004", "aws", "ELB", "Network Security", Severity.HIGH,
              "HTTP listener without HTTPS redirect",
              "Clients can reach the site over plaintext HTTP.",
              "Add a listener rule redirecting HTTP to HTTPS.",
              elb_http_redirect),
        Check("AWS-ELB-005", "aws", "ELB", "Network Security", Severity.HIGH,
              "Application load balancer without WAF",
              "ALBs without WAF lack L7 attack filtering.",
              "Associate a WAF web ACL with the ALB.",
              elb_waf),
        Check("AWS-RDS-006", "aws", "RDS", "Logging & Monitoring", Severity.MEDIUM,
              "RDS log export to CloudWatch disabled",
              "Database error/general/slow-query logs are not centralized for "
              "detection.",
              "Enable CloudWatch log exports on RDS instances.",
              rds_log_exports),
        Check("AWS-EKS-002", "aws", "EKS", "Logging & Monitoring", Severity.MEDIUM,
              "EKS control plane logging disabled",
              "Without audit logs, API activity on the control plane is "
              "invisible.",
              "Enable audit and authenticator log types.",
              eks_logging),
        Check("AWS-CWG-001", "aws", "CloudWatch Logs", "Logging & Monitoring", Severity.MEDIUM,
              "Log group retention below 365 days",
              "Short retention destroys audit evidence before compliance "
              "windows close.",
              "Set log group retention to >= 365 days (or never expire for "
              "compliance logs).",
              log_retention),
        Check("AWS-CWG-002", "aws", "CloudWatch Logs", "Data Protection", Severity.LOW,
              "Log group not KMS-encrypted",
              "Unencrypted log data can be read at rest.",
              "Encrypt log groups with a KMS CMK.",
              log_encryption),
        Check("AWS-BACK-001", "aws", "AWS Backup", "Backup & Recovery", Severity.MEDIUM,
              "No AWS Backup plans",
              "Without centralized Backup plans, resources depend on "
              "per-service backup settings.",
              "Create AWS Backup plans covering critical resources.",
              backup_plan),
        Check("AWS-SM-002", "aws", "Secrets Manager", "Data Protection", Severity.LOW,
              "Secret not encrypted with CMK",
              "Default AWS-managed keys give less key lifecycle control.",
              "Encrypt secrets with a customer-managed KMS key.",
              secret_cmk),
        Check("AWS-EC2-009", "aws", "EC2", "Storage & Data Protection", Severity.CRITICAL,
              "EBS snapshot publicly shared",
              "Public snapshots let any AWS account copy your volume data.",
              "Set snapshot createVolumePermission to private.",
              snapshot_public),
        Check("AWS-IAM-007", "aws", "IAM", "Identity & Access", Severity.MEDIUM,
              "Role trust allows cross-account or wildcard principals",
              "Cross-account trusts widen the attack surface; wildcard trusts "
              "let anyone assume the role.",
              "Restrict assume-role principals to known accounts/roles.",
              cross_account),
        Check("AWS-S3-006", "aws", "S3", "Security Posture", Severity.LOW,
              "S3 lifecycle rules missing",
              "Stale objects accumulate cost and expose old data.",
              "Define lifecycle rules to expire/transition stale objects.",
              s3_lifecycle),
        Check("AWS-LMB-002", "aws", "Lambda", "Network Security", Severity.HIGH,
              "Lambda function publicly invokable",
              "Anonymous invoke permissions let anyone run your function and "
              "incur cost or trigger logic.",
              "Remove public resource policies; use API Gateway/IAM auth.",
              lambda_public),
        Check("AWS-DDB-003", "aws", "DynamoDB", "Network Security", Severity.HIGH,
              "DynamoDB table policy public",
              "Public table policies expose the data plane anonymously.",
              "Remove anonymous principals from table policies.",
              ddb_public),
    ]


# --------------------------------------------------------------------------- #
# Tranche 3: CloudFront origin controls / CW dashboards / CloudTrail data /   #
#            snapshot & instance hardening / RDS & Lambda / S3-SNS-ECR-SQS /  #
#            classic ELB / ACM / Route53 / Backup vaults
# --------------------------------------------------------------------------- #
def _aws_tier3_checks() -> List[Check]:
    def cf_geo(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if not d.get("geo_restricted"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "No geo restriction (whitelist) is configured on the "
                              "distribution."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions enforce geo restriction."))
        return out

    def cf_fle(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if not d.get("field_level_encryption"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "Field-level encryption is not enabled; sensitive "
                              "fields are delivered to the origin in plaintext."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions use field-level encryption."))
        return out

    def cf_oac(c, s, _):
        out = []
        for d in s.get("cloudfront", []):
            if not d.get("oac_oai"):
                out.append(_f(c, s, f"cf:{d['id']}", Status.FAIL,
                              "S3 origin is not locked down with OAC/OAI; the "
                              "bucket may remain publicly readable."))
        if not out:
            out.append(_f(c, s, "cloudfront", Status.PASS,
                          "All distributions use origin access control."))
        return out

    def cw_dashboards(c, s, _):
        n = s["cw"].get("dashboards", 0)
        if n > 0:
            return [_f(c, s, "cloudwatch", Status.PASS,
                       f"{n} CloudWatch dashboard(s) exist.")]
        return [_f(c, s, "cloudwatch", Status.FAIL,
                   "No CloudWatch dashboards; operational/security metrics have "
                   "no centralized view.")]

    def ct_bucket_enc(c, s, _):
        t = s["trail"]
        if not t.get("exists"):
            return [_f(c, s, "cloudtrail", Status.FAIL, "No trail exists to evaluate.")]
        if t.get("s3_bucket_encrypted"):
            return [_f(c, s, "cloudtrail", Status.PASS, "The trail log bucket is encrypted.")]
        return [_f(c, s, "cloudtrail", Status.FAIL,
                   "The CloudTrail log bucket is not encrypted at rest.")]

    def ct_kms(c, s, _):
        t = s["trail"]
        if not t.get("exists"):
            return [_f(c, s, "cloudtrail", Status.FAIL, "No trail exists to evaluate.")]
        if t.get("kms_key_id"):
            return [_f(c, s, "cloudtrail", Status.PASS,
                       "The trail is encrypted with a KMS key.")]
        return [_f(c, s, "cloudtrail", Status.FAIL,
                   "CloudTrail is not configured with a KMS CMK for log encryption.")]

    def snap_enc(c, s, _):
        out = []
        for s2 in s.get("snapshots", []):
            if not s2.get("encrypted"):
                out.append(_f(c, s, f"snap:{s2['id']}", Status.FAIL,
                              "EBS snapshot is not encrypted at rest."))
        if not out:
            out.append(_f(c, s, "ebs-snapshots", Status.PASS,
                          "All EBS snapshots are encrypted."))
        return out

    def pub_no_sg(c, s, _):
        out = []
        for i in s["ec2"]["instances"]:
            if i.get("public_ip") and not i.get("security_groups"):
                out.append(_f(c, s, f"i-{i['id']}", Status.FAIL,
                              "Instance has a public IP but no security group is "
                              "attached."))
        if not out:
            out.append(_f(c, s, "ec2-instances", Status.PASS,
                          "No public instances lack security groups."))
        return out

    def unused_sg(c, s, _):
        used = set()
        for i in s["ec2"]["instances"]:
            used.update(i.get("security_groups", []))
        out = []
        for g in s["ec2"]["security_groups"]:
            if g["id"] not in used and g.get("name") != "default":
                out.append(_f(c, s, f"sg:{g['name']}", Status.FAIL,
                              "Security group is not referenced by any instance."))
        if not out:
            out.append(_f(c, s, "security-groups", Status.PASS,
                          "No unused security groups."))
        return out

    def rds_minor(c, s, _):
        out = []
        for db in s["rds"]:
            if not db.get("auto_minor_upgrade"):
                out.append(_f(c, s, f"rds:{db['id']}", Status.FAIL,
                              "Auto minor version upgrade is disabled; known engine "
                              "fixes are missed."))
        if not out:
            out.append(_f(c, s, "rds", Status.PASS,
                          "All RDS instances auto-upgrade minor versions."))
        return out

    def rds_public_snap(c, s, _):
        if s.get("rds_public_snapshots"):
            return [_f(c, s, "rds-snapshots", Status.FAIL,
                       "At least one RDS snapshot is publicly shareable.")]
        return [_f(c, s, "rds-snapshots", Status.PASS, "No public RDS snapshots.")]

    def lambda_vpc(c, s, _):
        out = []
        for f in s["lambda"]:
            if not f.get("in_vpc"):
                out.append(_f(c, s, f"lambda:{f['name']}", Status.FAIL,
                              "Lambda function is not attached to a VPC; it runs on "
                              "shared AWS-managed network infrastructure."))
        if not out:
            out.append(_f(c, s, "lambda", Status.PASS,
                          "All Lambda functions run inside a VPC."))
        return out

    def lambda_tracing(c, s, _):
        out = []
        for f in s["lambda"]:
            if not f.get("tracing"):
                out.append(_f(c, s, f"lambda:{f['name']}", Status.FAIL,
                              "X-Ray tracing is disabled; no end-to-end request "
                              "traces for the function."))
        if not out:
            out.append(_f(c, s, "lambda", Status.PASS,
                          "All Lambda functions have tracing enabled."))
        return out

    def s3_mfa(c, s, _):
        out = []
        for b in s["s3"]:
            if not b.get("mfa_delete"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "MFA delete is not enabled; destructive deletes bypass "
                              "multi-factor authentication."))
        if not out:
            out.append(_f(c, s, "s3", Status.PASS, "All buckets enforce MFA delete."))
        return out

    def sns_kms(c, s, _):
        out = []
        for t in s["sns"]:
            if not t.get("kms_encrypted"):
                out.append(_f(c, s, t["topic_arn"], Status.FAIL,
                              "SNS topic is not encrypted with a KMS key."))
        if not out:
            out.append(_f(c, s, "sns", Status.PASS, "All SNS topics are KMS-encrypted."))
        return out

    def ecr_scan(c, s, _):
        out = []
        for r in s["ecr"]:
            if not r.get("scan_on_push"):
                out.append(_f(c, s, f"ecr:{r['repo_name']}", Status.FAIL,
                              "Image scanning on push is disabled; vulnerabilities "
                              "are not detected before deploy."))
        if not out:
            out.append(_f(c, s, "ecr", Status.PASS, "All ECR repos scan on push."))
        return out

    def ecr_lifecycle(c, s, _):
        out = []
        for r in s["ecr"]:
            if not r.get("lifecycle_policy"):
                out.append(_f(c, s, f"ecr:{r['repo_name']}", Status.FAIL,
                              "No lifecycle policy; stale images accumulate and may "
                              "retain vulnerable code."))
        if not out:
            out.append(_f(c, s, "ecr", Status.PASS,
                          "All ECR repos have lifecycle policies."))
        return out

    def sqs_dlq(c, s, _):
        out = []
        for q in s["sqs"]:
            if not q.get("has_dlq"):
                out.append(_f(c, s, q["url"].rsplit("/", 1)[-1], Status.FAIL,
                              "Queue has no dead-letter queue; failed messages are "
                              "silently lost."))
        if not out:
            out.append(_f(c, s, "sqs", Status.PASS, "All SQS queues have a DLQ."))
        return out

    def elb_classic(c, s, _):
        out = []
        for lb in s.get("elb_classic", []):
            if not lb.get("https"):
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "Classic load balancer has no HTTPS/SSL listener."))
        if not out:
            out.append(_f(c, s, "elb", Status.PASS, "All classic ELBs terminate TLS."))
        return out

    def acm_expiry(c, s, _):
        out = []
        for cert in s.get("acm", []):
            if cert.get("days_to_expiry", 9999) < 30:
                out.append(_f(c, s, cert["arn"].rsplit("/", 1)[-1], Status.FAIL,
                              f"Certificate expires in {cert.get('days_to_expiry')} "
                              "days (< 30); renewal may not complete in time."))
        if not out:
            out.append(_f(c, s, "acm", Status.PASS,
                          "All certificates renew with > 30 days margin."))
        return out

    def r53_logging(c, s, _):
        z = s["r53"].get("zone_count", 0)
        if z == 0:
            return [_f(c, s, "route53", Status.NOT_APPLICABLE,
                       "No hosted zones to monitor.")]
        if s["r53"].get("query_logging"):
            return [_f(c, s, "route53", Status.PASS,
                       "DNS query logging is enabled.")]
        return [_f(c, s, "route53", Status.FAIL,
                   "DNS query logging is not enabled; resolver queries have no "
                   "audit trail.")]

    def backup_vault(c, s, _):
        if s["backup"].get("vaults", 0) > 0:
            return [_f(c, s, "backup", Status.PASS,
                       "Backup vaults exist as a durable recovery destination.")]
        return [_f(c, s, "backup", Status.FAIL,
                   "No AWS Backup vault; backup jobs have no durable destination.")]

    return [
        Check("AWS-CF-006", "aws", "CloudFront", "Network Security", Severity.MEDIUM,
              "CloudFront geo restriction not enabled",
              "Without geo whitelisting, content is served to any country, "
              "including sanctioned or attacker-origin regions.",
              "Configure a geo-restriction whitelist on the distribution.",
              cf_geo),
        Check("AWS-CF-007", "aws", "CloudFront", "Data Protection", Severity.MEDIUM,
              "CloudFront field-level encryption not enabled",
              "Sensitive fields are decrypted at the edge and sent to the "
              "origin in plaintext.",
              "Enable field-level encryption and configure encrypted fields.",
              cf_fle),
        Check("AWS-CF-008", "aws", "CloudFront", "Network Security", Severity.HIGH,
              "CloudFront S3 origin without OAC/OAI",
              "An S3 origin without origin access control can be read directly "
              "from the bucket, bypassing the CDN.",
              "Restrict the origin bucket to CloudFront via OAC/OAI.",
              cf_oac),
        Check("AWS-CW-011", "aws", "CloudWatch", "Logging & Monitoring", Severity.LOW,
              "No CloudWatch dashboards",
              "Without dashboards, operational and security metrics lack a "
              "central monitoring view.",
              "Create dashboards for key metrics (errors, throttles, cost).",
              cw_dashboards),
        Check("AWS-CT-006", "aws", "CloudTrail", "Data Protection", Severity.HIGH,
              "CloudTrail log bucket not encrypted",
              "Unencrypted trail logs can be read if the bucket is compromised.",
              "Enable SSE on the CloudTrail bucket (SSE-S3 or SSE-KMS).",
              ct_bucket_enc, cis="CIS AWS 3.5"),
        Check("AWS-CT-007", "aws", "CloudTrail", "Key Management", Severity.MEDIUM,
              "CloudTrail not using KMS key",
              "Without a KMS CMK, log encryption keys are not customer-managed.",
              "Configure CloudTrail with a KMS key for log encryption.",
              ct_kms, cis="CIS AWS 3.5"),
        Check("AWS-EC2-010", "aws", "EC2/Network", "Data Protection", Severity.HIGH,
              "EBS snapshot not encrypted",
              "Unencrypted snapshots expose volume data at rest.",
              "Copy snapshots with encryption enabled and delete the originals.",
              snap_enc),
        Check("AWS-EC2-011", "aws", "EC2/Network", "Network Security", Severity.HIGH,
              "Public instance without security group",
              "A public IP with no security group means no host-level ingress "
              "filtering at all.",
              "Attach a restrictive security group to every instance.",
              pub_no_sg),
        Check("AWS-EC2-012", "aws", "EC2/Network", "Security Posture", Severity.LOW,
              "Unused security group",
              "Orphaned security groups accumulate rules that can be re-used "
              "by mistake and indicate drift.",
              "Delete unused security groups or document their purpose.",
              unused_sg),
        Check("AWS-RDS-007", "aws", "RDS", "Security Posture", Severity.MEDIUM,
              "RDS auto minor version upgrade disabled",
              "Without auto-upgrades, known engine fixes are applied late or "
              "not at all.",
              "Enable auto minor version upgrade on RDS instances.",
              rds_minor),
        Check("AWS-RDS-008", "aws", "RDS", "Data Protection", Severity.CRITICAL,
              "Public RDS snapshot",
              "Publicly shared RDS snapshots expose database contents to any "
              "AWS account.",
              "Revoke public sharing on all RDS snapshots.",
              rds_public_snap),
        Check("AWS-LMB-003", "aws", "Lambda", "Network Security", Severity.MEDIUM,
              "Lambda function not in a VPC",
              "Functions outside a VPC run on shared infrastructure with no "
              "VPC-level network policy.",
              "Attach Lambda functions to a VPC when they access VPC resources.",
              lambda_vpc),
        Check("AWS-LMB-004", "aws", "Lambda", "Logging & Monitoring", Severity.LOW,
              "Lambda X-Ray tracing disabled",
              "Without tracing, request flows cannot be observed for debugging "
              "or security analysis.",
              "Enable active tracing on Lambda functions.",
              lambda_tracing),
        Check("AWS-S3-007", "aws", "S3", "Data Protection", Severity.MEDIUM,
              "S3 MFA delete not enabled",
              "Without MFA delete, a compromised credential can permanently "
              "delete objects even with versioning.",
              "Enable MFA delete on versioned buckets (requires a root MFA token).",
              s3_mfa),
        Check("AWS-SNS-002", "aws", "SNS", "Data Protection", Severity.MEDIUM,
              "SNS topic not KMS-encrypted",
              "Topic payloads are stored unencrypted without KMS.",
              "Associate a KMS key with the topic.",
              sns_kms),
        Check("AWS-ECR-002", "aws", "ECR", "Security Posture", Severity.MEDIUM,
              "ECR image scanning on push disabled",
              "Without scan-on-push, vulnerable images are deployed undetected.",
              "Enable enhanced scanning on ECR repositories.",
              ecr_scan),
        Check("AWS-ECR-003", "aws", "ECR", "Security Posture", Severity.LOW,
              "ECR lifecycle policy missing",
              "Stale images accumulate and can retain vulnerable code forever.",
              "Add a lifecycle policy to expire old/untagged images.",
              ecr_lifecycle),
        Check("AWS-SQS-003", "aws", "SQS", "Resilience", Severity.LOW,
              "SQS queue without dead-letter queue",
              "Messages that fail processing are silently lost.",
              "Configure a DLQ with a redrive policy.",
              sqs_dlq),
        Check("AWS-ELB-006", "aws", "ELB", "Network Security", Severity.HIGH,
              "Classic ELB without TLS listener",
              "Traffic to the load balancer is transmitted in plaintext.",
              "Terminate TLS on the listener or migrate to ALB/NLB with TLS.",
              elb_classic),
        Check("AWS-ACM-002", "aws", "ACM", "Security Posture", Severity.MEDIUM,
              "Certificate nearing expiry",
              "Expired certificates cause outages and break TLS validation.",
              "Automate renewal or rotate certificates with > 30 days margin.",
              acm_expiry),
        Check("AWS-R53-002", "aws", "Route 53", "Logging & Monitoring", Severity.MEDIUM,
              "DNS query logging not enabled",
              "Resolver queries have no audit trail for detection and forensics.",
              "Enable query logging to CloudWatch Logs.",
              r53_logging),
        Check("AWS-BACK-002", "aws", "Backup", "Backup & Recovery", Severity.HIGH,
              "No AWS Backup vault",
              "Backup plans without a vault cannot retain recoverable copies.",
              "Create backup vaults and point plans at them.",
              backup_vault),
    ]


# --------------------------------------------------------------------------- #
# Tranche 4: ECS / IoT / SES / ELB deletion protection / EFS lifecycle /      #
#            S3 object lock / DynamoDB protection / GuardDuty S3 / RDS monitor
# --------------------------------------------------------------------------- #
def _aws_tier4_checks() -> List[Check]:
    def ecs_insights(c, s, _):
        out = []
        for cl in s.get("ecs", {}).get("clusters", []):
            if not cl.get("container_insights"):
                out.append(_f(c, s, f"ecs:{cl['name']}", Status.FAIL,
                              "Container Insights is disabled; no per-task "
                              "metrics or logs are collected."))
        if not out:
            out.append(_f(c, s, "ecs", Status.PASS,
                          "All ECS clusters run Container Insights."))
        return out

    def ecs_hostnet(c, s, _):
        out = []
        for td in s.get("ecs", {}).get("task_definitions", []):
            if td.get("network_mode") == "host":
                out.append(_f(c, s, f"taskdef:{td['name']}", Status.FAIL,
                              "Task uses host network mode; containers share "
                              "the host network stack."))
        if not out:
            out.append(_f(c, s, "ecs", Status.PASS,
                          "No tasks run in host network mode."))
        return out

    def ecs_execrole(c, s, _):
        out = []
        for td in s.get("ecs", {}).get("task_definitions", []):
            if not td.get("execution_role"):
                out.append(_f(c, s, f"taskdef:{td['name']}", Status.FAIL,
                              "Task definition has no execution role; it cannot "
                              "fetch secrets or pull images securely."))
        if not out:
            out.append(_f(c, s, "ecs", Status.PASS,
                          "All task definitions have an execution role."))
        return out

    def iot_logging(c, s, _):
        lvl = s.get("iot", {}).get("logging_level")
        if lvl is None:
            return [_f(c, s, "iot", Status.NOT_APPLICABLE,
                       "IoT logging configuration could not be collected "
                       "(grant iot:GetV2LoggingOptions and re-run).")]
        if lvl == "ERROR":
            return [_f(c, s, "iot", Status.PASS,
                       "IoT logging is set to ERROR (audit trail present).")]
        return [_f(c, s, "iot", Status.FAIL,
                   f"IoT logging level is {lvl or 'not configured'}; no audit "
                   "trail of device activity.")]

    def iot_policy(c, s, _):
        out = []
        for p in s.get("iot", {}).get("public_policies", []):
            out.append(_f(c, s, f"iot-policy:{p}", Status.FAIL,
                          "IoT policy grants wildcard principals."))
        if not out:
            out.append(_f(c, s, "iot", Status.PASS,
                          "No IoT policies grant wildcard access."))
        return out

    def ses_dkim(c, s, _):
        out = []
        idents = s.get("ses", {}).get("identities", [])
        for ident in s.get("ses", {}).get("dkim_unverified", []):
            out.append(_f(c, s, f"ses:{ident}", Status.FAIL,
                          "DKIM is not verified for the identity; spoofing is "
                          "harder to detect."))
        if not out and not idents:
            out.append(_f(c, s, "ses", Status.NOT_APPLICABLE,
                          "No SES identities configured; nothing to verify."))
        elif not out:
            out.append(_f(c, s, "ses", Status.PASS,
                          "All SES identities have verified DKIM."))
        return out

    def elb_deletion(c, s, _):
        out = []
        for lb in s.get("elb", []):
            if lb.get("type") == "application" and not lb.get("deletion_protection"):
                out.append(_f(c, s, f"elb:{lb['name']}", Status.FAIL,
                              "Deletion protection is disabled; the load "
                              "balancer can be deleted accidentally."))
        if not out:
            out.append(_f(c, s, "elb", Status.PASS,
                          "All ALBs have deletion protection."))
        return out

    def efs_lifecycle(c, s, _):
        out = []
        for fs in s.get("efs", []):
            if not fs.get("lifecycle_policy"):
                out.append(_f(c, s, f"efs:{fs['id']}", Status.FAIL,
                              "No lifecycle policy; infrequently accessed files "
                              "never move to lower cost tiers."))
        if not out:
            out.append(_f(c, s, "efs", Status.PASS,
                          "All EFS file systems have lifecycle policies."))
        return out

    def s3_objectlock(c, s, _):
        out = []
        for b in s.get("s3", []):
            if not b.get("object_lock"):
                out.append(_f(c, s, f"s3://{b['name']}", Status.FAIL,
                              "Object Lock is disabled; objects can be "
                              "permanently overwritten or deleted."))
        if not out:
            out.append(_f(c, s, "s3", Status.PASS,
                          "All buckets enforce Object Lock."))
        return out

    def ddb_deletion(c, s, _):
        out = []
        for t in s.get("dynamodb", []):
            if not t.get("deletion_protection"):
                out.append(_f(c, s, f"ddb:{t['name']}", Status.FAIL,
                              "Deletion protection is disabled; the table can "
                              "be dropped accidentally."))
        if not out:
            out.append(_f(c, s, "dynamodb", Status.PASS,
                          "All DynamoDB tables have deletion protection."))
        return out

    def gd_s3(c, s, _):
        out = []
        dets = s.get("guardduty", [])
        uncollected = any(d.get("s3_protection") is None for d in dets)
        for d in dets:
            if d.get("s3_protection") is None:
                continue
            if not d.get("s3_protection"):
                out.append(_f(c, s, f"guardduty:{d['id']}", Status.FAIL,
                              "S3 protection is disabled; object-level data "
                              "exfiltration is not monitored."))
        if not out:
            if not dets or uncollected:
                out.append(_f(c, s, "guardduty", Status.NOT_APPLICABLE,
                              "GuardDuty S3 protection could not be verified "
                              "(no detector or status uncollected)."))
            else:
                out.append(_f(c, s, "guardduty", Status.PASS,
                              "GuardDuty monitors S3 data events."))
        return out

    def rds_monitor(c, s, _):
        out = []
        for db in s.get("rds", []):
            if not db.get("enhanced_monitoring"):
                out.append(_f(c, s, f"rds:{db['id']}", Status.FAIL,
                              "Enhanced monitoring is disabled; OS-level DB "
                              "metrics are not collected."))
        if not out:
            out.append(_f(c, s, "rds", Status.PASS,
                          "All RDS instances have enhanced monitoring."))
        return out

    return [
        Check("AWS-ECS-001", "aws", "ECS", "Logging & Monitoring", Severity.MEDIUM,
              "ECS Container Insights disabled",
              "Without Container Insights, per-task CPU/memory and log data "
              "are unavailable for troubleshooting and security.",
              "Enable Container Insights on ECS clusters.",
              ecs_insights),
        Check("AWS-ECS-002", "aws", "ECS", "Container Security", Severity.HIGH,
              "ECS task uses host network mode",
              "Host networking shares the host stack and bypasses ECS network "
              "isolation.",
              "Use awsvpc network mode for task isolation.",
              ecs_hostnet),
        Check("AWS-ECS-003", "aws", "ECS", "Identity & Access", Severity.MEDIUM,
              "ECS task definition without execution role",
              "Without an execution role, the task cannot fetch secrets or "
              "pull images securely.",
              "Attach an execution role to task definitions.",
              ecs_execrole),
        Check("AWS-IOT-001", "aws", "IoT", "Logging & Monitoring", Severity.MEDIUM,
              "IoT logging level not ERROR",
              "Without ERROR-level IoT logging, device lifecycle events have "
              "no audit trail.",
              "Set IoT logging to ERROR level (or higher verbosity).",
              iot_logging),
        Check("AWS-IOT-002", "aws", "IoT", "Identity & Access", Severity.HIGH,
              "IoT policy grants wildcard principals",
              "Wildcard IoT policies let any device/principal act with those "
              "permissions.",
              "Scope IoT policies to specific certificates/principals.",
              iot_policy),
        Check("AWS-SES-001", "aws", "SES", "Email Security", Severity.MEDIUM,
              "SES identity without verified DKIM",
              "Unverified DKIM increases spoofing and deliverability risk.",
              "Verify DKIM records for every SES identity.",
              ses_dkim),
        Check("AWS-ELB-007", "aws", "ELB", "Data Protection", Severity.MEDIUM,
              "ALB deletion protection disabled",
              "Without deletion protection, the load balancer can be removed "
              "accidentally, taking down traffic.",
              "Enable deletion protection on ALBs.",
              elb_deletion),
        Check("AWS-EFS-003", "aws", "EFS", "Security Posture", Severity.LOW,
              "EFS without lifecycle policy",
              "Stale files never transition to lower-cost tiers, inflating "
              "cost and attack surface.",
              "Add a lifecycle policy to transition IA files.",
              efs_lifecycle),
        Check("AWS-S3-008", "aws", "S3", "Data Protection", Severity.HIGH,
              "S3 Object Lock disabled",
              "Without Object Lock, ransomware or mistakes can permanently "
              "destroy objects.",
              "Enable Object Lock (with versioning + retention) on critical "
              "buckets.",
              s3_objectlock),
        Check("AWS-DDB-004", "aws", "DynamoDB", "Data Protection", Severity.MEDIUM,
              "DynamoDB deletion protection disabled",
              "Without deletion protection, the table can be dropped "
              "accidentally.",
              "Enable deletion protection on production tables.",
              ddb_deletion),
        Check("AWS-GD-002", "aws", "GuardDuty", "Security Posture", Severity.MEDIUM,
              "GuardDuty S3 protection disabled",
              "Without S3 data-event monitoring, data exfiltration from "
              "buckets goes undetected.",
              "Enable S3 protection in the GuardDuty detector.",
              gd_s3),
        Check("AWS-RDS-009", "aws", "RDS", "Logging & Monitoring", Severity.MEDIUM,
              "RDS enhanced monitoring disabled",
              "OS-level database metrics are not collected, hiding resource "
              "and anomaly signals.",
              "Enable enhanced monitoring with a 60s granularity.",
              rds_monitor),
    ]


# --------------------------------------------------------------------------- #
# SageMaker (ML) - unique coverage area: ML pipeline security
# --------------------------------------------------------------------------- #
def _aws_sagemaker_checks() -> List[Check]:
    def sm_notebook_internet(c, s, _):
        out = []
        for nb in s.get("sagemaker", {}).get("notebooks", []):
            if nb.get("direct_internet"):
                out.append(_f(c, s, f"sagemaker-notebook:{nb['name']}", Status.FAIL,
                              "Notebook instance has direct internet access; "
                              "code running in it (or its IAM role) can reach "
                              "the internet and exfiltrate data.",
                              {"direct_internet_access": "Enabled"}))
        if not out:
            out.append(_f(c, s, "sagemaker-notebooks", Status.PASS,
                          "All SageMaker notebook instances are VPC-only "
                          "(no direct internet access)."))
        return out

    def sm_notebook_kms(c, s, _):
        out = []
        for nb in s.get("sagemaker", {}).get("notebooks", []):
            if not nb.get("kms_key"):
                out.append(_f(c, s, f"sagemaker-notebook:{nb['name']}", Status.FAIL,
                              "Notebook instance root volume is not encrypted "
                              "with a customer-managed KMS key.",
                              {"kms_key_id": None}))
        if not out:
            out.append(_f(c, s, "sagemaker-notebooks", Status.PASS,
                          "All SageMaker notebook volumes are KMS-encrypted."))
        return out

    def sm_data_capture(c, s, _):
        out = []
        for ep in s.get("sagemaker", {}).get("endpoints", []):
            if not ep.get("data_capture"):
                out.append(_f(c, s, f"sagemaker-endpoint:{ep['name']}", Status.FAIL,
                              "Model endpoint has no data capture enabled; "
                              "request/response payloads are not recorded for "
                              "monitoring and audit.",
                              {"data_capture_config": "Disabled"}))
        if not out:
            out.append(_f(c, s, "sagemaker-endpoints", Status.PASS,
                          "All SageMaker endpoints capture data for monitoring."))
        return out

    return [
        Check("AWS-SGM-001", "aws", "SageMaker", "Security Posture", Severity.HIGH,
              "SageMaker notebook with direct internet access",
              "A notebook with DirectInternetAccess enabled is a data-exfil "
              "and lateral-movement vector: notebook code runs with the IAM "
              "role and can reach any internet host.",
              "Launch notebooks in a VPC-only mode (DirectInternetAccess=Disabled) "
              "and route egress through a NAT gateway or VPC endpoint.",
              sm_notebook_internet),
        Check("AWS-SGM-002", "aws", "SageMaker", "Data Protection", Severity.MEDIUM,
              "SageMaker notebook not KMS-encrypted",
              "The notebook root and EBS volumes are unencrypted or use the "
              "AWS-managed key, so notebooks and checkpoints at rest are not "
              "under your key control.",
              "Create the notebook with a customer-managed KMS key in "
              "KmsKeyId on the CreateNotebookInstance call.",
              sm_notebook_kms),
        Check("AWS-SGM-003", "aws", "SageMaker", "Logging & Monitoring", Severity.MEDIUM,
              "SageMaker endpoint data capture disabled",
              "Without data capture, model inputs/outputs are not recorded, "
              "so drift, bias and abuse on the model endpoint go undetected.",
              "Enable DataCaptureConfig on the endpoint configuration with a "
              "sampling percentage and an S3 destination.",
              sm_data_capture),
    ]


def get_checks() -> List[Check]:
    return (_aws_iam_checks() + _aws_s3_checks() + _aws_ec2_checks()
            + _aws_misc_checks() + _aws_network_checks() + _aws_instance_checks()
            + _aws_cw_checks() + _aws_detection_checks() + _aws_data_checks()
            + _aws_web_checks() + _aws_tier2_checks() + _aws_tier3_checks()
            + _aws_tier4_checks() + _aws_sagemaker_checks())
