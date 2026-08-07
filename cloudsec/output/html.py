"""Self-contained HTML dashboard generation (no external assets, offline-safe)."""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..compare import ComparisonRow
from ..frameworks import frameworks_for, lead_frameworks
from ..models import ScanResult
from ..registry import CLOUD_LABELS

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# Friendly names for CIS Benchmark sections (fallback: "Section N").
CIS_SECTION_NAMES = {
    "aws": {1: "Identity and Access Management", 2: "Storage", 3: "Logging",
            4: "Monitoring", 5: "Networking"},
    "azure": {1: "Identity and Access Management", 2: "Storage Accounts",
              3: "Database Services", 4: "Networking", 5: "Logging and Monitoring",
              6: "Security Center", 7: "Virtual Machines", 8: "Key Vault",
              9: "App Services"},
    "gcp": {1: "Identity and Access Management", 2: "Logging and Monitoring",
            3: "Networking", 4: "Virtual Machines", 5: "SQL Databases",
            6: "Kubernetes Engine"},
    "oci": {1: "Identity and Access Management", 2: "Networking",
            3: "Logging and Monitoring", 4: "Object Storage",
            5: "Asset Management"},
}


# Authoritative vendor docs per cloud+service (used for the "Reference / Fix
# article" links attached to every finding so remediation is actionable).
SERVICE_DOCS = {
    "aws": {
        "IAM": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "S3": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
        "EC2": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security.html",
        "EBS": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSCrypto.html",
        "RDS": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.Connect.html",
        "Redshift": "https://docs.aws.amazon.com/redshift/latest/mgmt/security.html",
        "DynamoDB": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/security.html",
        "VPC": "https://docs.aws.amazon.com/vpc/latest/userguide/security.html",
        "CloudTrail": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-security.html",
        "Config": "https://docs.aws.amazon.com/config/latest/developerguide/security.html",
        "CloudWatch": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/security.html",
        "GuardDuty": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-security.html",
        "KMS": "https://docs.aws.amazon.com/kms/latest/developerguide/security.html",
        "Secrets Manager": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/security.html",
        "ELB": "https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/security.html",
        "CloudFront": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/security.html",
        "WAF": "https://docs.aws.amazon.com/waf/latest/developerguide/security.html",
        "API Gateway": "https://docs.aws.amazon.com/apigateway/latest/developerguide/security.html",
        "Route 53": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/security.html",
        "ACM": "https://docs.aws.amazon.com/acm/latest/userguide/security.html",
        "ECR": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/security.html",
        "Lambda": "https://docs.aws.amazon.com/lambda/latest/dg/security.html",
        "EKS": "https://docs.aws.amazon.com/eks/latest/userguide/security.html",
        "ECS": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security.html",
        "EFS": "https://docs.aws.amazon.com/efs/latest/ug/security-considerations.html",
        "ElastiCache": "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/security.html",
        "SQS": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security.html",
        "SNS": "https://docs.aws.amazon.com/sns/latest/dg/sns-security.html",
        "IoT": "https://docs.aws.amazon.com/iot/latest/developerguide/security.html",
        "SES": "https://docs.aws.amazon.com/ses/latest/dg/security.html",
        "Backup": "https://docs.aws.amazon.com/aws-backup/latest/devguide/security.html",
        "Network": "https://docs.aws.amazon.com/vpc/latest/userguide/security.html",
        "SageMaker": "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
    },
    "azure": {
        "Identity & Access": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates",
        "Storage": "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security",
        "Key Vault": "https://learn.microsoft.com/en-us/azure/key-vault/general/security-features",
        "Networking": "https://learn.microsoft.com/en-us/azure/security/fundamentals/network-overview",
        "Database": "https://learn.microsoft.com/en-us/azure/azure-sql/database/security-overview",
        "Compute": "https://learn.microsoft.com/en-us/azure/virtual-machines/windows/security-policy",
        "Logging & Monitoring": "https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview",
        "Containers": "https://learn.microsoft.com/en-us/azure/aks/concepts-security",
        "App Services": "https://learn.microsoft.com/en-us/azure/app-service/security-recommendations",
        "Security Services": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-planning-and-operations-guide",
        "Policy & Governance": "https://learn.microsoft.com/en-us/azure/governance/policy/overview",
        "Messaging": "https://learn.microsoft.com/en-us/azure/event-hubs/network-security",
        # ---- exact service names used by the Azure check catalog ----
        "SQL": "https://learn.microsoft.com/en-us/azure/azure-sql/database/security-overview",
        "App Service": "https://learn.microsoft.com/en-us/azure/app-service/security-recommendations",
        "Network": "https://learn.microsoft.com/en-us/azure/security/fundamentals/network-overview",
        "AKS": "https://learn.microsoft.com/en-us/azure/aks/concepts-security",
        "IAM/Entra ID": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates",
        "IAM/RBAC": "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices",
        "Cosmos DB": "https://learn.microsoft.com/en-us/azure/cosmos-db/database-security",
        "Log Analytics": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-security",
        "API Management": "https://learn.microsoft.com/en-us/azure/api-management/security-baseline",
        "Monitoring": "https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview",
        "Container Registry": "https://learn.microsoft.com/en-us/azure/container-registry/container-registry-best-practices",
        "Redis Cache": "https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-best-practices",
        "Azure Policy": "https://learn.microsoft.com/en-us/azure/governance/policy/overview",
        "App Configuration": "https://learn.microsoft.com/en-us/azure/azure-app-configuration/overview",
        "Event Hubs": "https://learn.microsoft.com/en-us/azure/event-hubs/network-security",
        "Microsoft Sentinel": "https://learn.microsoft.com/en-us/azure/sentinel/overview",
        "Application Gateway": "https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview",
        "Microsoft Defender": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-planning-and-operations-guide",
        "Service Bus": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/network-security",
        "Front Door": "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-security-headers",
        "Functions": "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts",
    },
    "gcp": {
        "Identity & Access": "https://cloud.google.com/iam/docs/using-iam-securely",
        "Storage": "https://cloud.google.com/storage/docs/best-practices",
        "Networking": "https://cloud.google.com/vpc/docs/firewalls",
        "Compute": "https://cloud.google.com/architecture/security-foundations",
        "Database": "https://cloud.google.com/sql/docs/mysql/authorize-networks",
        "Key Management": "https://cloud.google.com/security-key-management",
        "Logging & Monitoring": "https://cloud.google.com/logging/docs/audit/best-practices",
        "Kubernetes": "https://cloud.google.com/kubernetes-engine/docs/concepts/security-overview",
        "Serverless": "https://cloud.google.com/run/docs",
        "Containers": "https://cloud.google.com/artifact-registry/docs/secure",
        "Cache": "https://cloud.google.com/memorystore/docs/redis/security-overview",
        "Organization Policies": "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints",
        "Workload Identity": "https://cloud.google.com/iam/docs/workload-identity-federation",
        "Vertex AI": "https://cloud.google.com/vertex-ai/docs/security/security-best-practices",
        "Pub/Sub": "https://cloud.google.com/pubsub/docs/security-best-practices",
    },
    "oci": {
        "Identity & Access": "https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/overview.htm",
        "Networking": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecurity.htm",
        "Compute": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm",
        "Database": "https://docs.oracle.com/en-us/iaas/Content/Database/Concepts/overview.htm",
        "Key Management": "https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm",
        "Storage": "https://docs.oracle.com/en-us/iaas/Content/Object/Concepts/objectsecurity.htm",
        "Logging & Monitoring": "https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm",
        "Security Posture": "https://docs.oracle.com/en-us/iaas/cloud-guard/using/index.htm",
        "API Gateway": "https://docs.oracle.com/en-us/iaas/Content/APIGateway/Concepts/apigatewayoverview.htm",
    },
}


# Category -> consequence sentence. Appended to findings whose check
# description is thin so every finding reads as a quality, self-contained
# paragraph (dashboard detail view + PDF/Excel/CSV exports).
_CATEGORY_IMPACT = {
    "Identity & Access": "Compromised or misconfigured identity controls are a leading entry point for account takeover and privilege escalation, and are routinely exploited in real-world breaches.",
    "Data Protection": "Weak data protection controls can expose sensitive or regulated data to unauthorized access, exfiltration, or accidental loss.",
    "Logging & Monitoring": "Insufficient logging and monitoring leaves security events undetected, delays incident response, and prevents forensic investigation after a breach.",
    "Network Security": "Network misconfigurations expand the attack surface and allow unauthorized inbound or lateral traffic, making the environment far easier to compromise.",
    "Storage & Data Protection": "Misconfigured storage can silently expose sensitive or regulated data to the internet or to unintended internal audiences.",
    "Key Management": "Weak key management undermines the confidentiality guarantees that encryption depends on, so protected data is at risk even where encryption is enabled.",
    "Kubernetes": "Kubernetes misconfigurations can be chained to escape pods, pivot across the cluster, and reach workloads that should be isolated.",
    "Compute": "Compute misconfigurations can be exploited to gain unauthorized access to workloads, host credentials, or the underlying hypervisor.",
    "Database": "Database misconfigurations risk exposure, theft, or destruction of sensitive data and frequently violate compliance obligations.",
    "Container Security": "Container misconfigurations can be leveraged to escape workloads, escalate privileges, or move laterally within the cluster.",
    "Backup & Recovery": "Inadequate backup and recovery controls mean data can be permanently lost to deletion, ransomware, or operator error.",
    "Security Posture": "A weak security posture leaves the environment without defense-in-depth, so a single misconfiguration can escalate into full compromise.",
    "Cost & Resilience": "Resilience gaps threaten availability and can turn a routine incident into extended downtime.",
    "Cost & Security Posture": "Combined cost and posture gaps indicate controls that are neither efficient nor effective at reducing risk.",
    "Email Security": "Email security gaps expose the organization to phishing, spoofing, and business-email-compromise attacks.",
    "Resilience": "Resilience gaps threaten availability and can turn a routine incident into extended downtime.",
}


def _quality_description(f: Dict[str, Any], ch) -> str:
    """Build a quality, multi-sentence description for a finding.

    Combines the check's description (what/why), the specific finding context
    (which resource is affected), and - for thin descriptions - a
    category-level consequence sentence. Guarantees every finding reads as a
    proper paragraph instead of a one-liner.
    """
    base = (ch.description or ch.title or "").strip().rstrip(".")
    if not base:
        return f.get("detail") or ch.title or ""
    sentences = [base + "."]
    detail = (f.get("detail") or "").strip()
    if detail and detail.lower() not in base.lower():
        sentences.append(detail.rstrip(".") + ".")
    if len(base) < 110:
        extra = _CATEGORY_IMPACT.get(f.get("category"))
        if extra:
            sentences.append(extra)
    return " ".join(sentences)


def reference_for(cloud: str, service: str, cis: Optional[str]) -> List[Dict[str, str]]:
    """Actionable reference links for a finding: the authoritative vendor
    hardening doc for the affected service. (Generic CIS benchmark landing
    pages were removed - they did not point at the specific control.)"""
    refs: List[Dict[str, str]] = []
    doc = SERVICE_DOCS.get(cloud, {}).get(service)
    if doc:
        refs.append({"label": f"{CLOUD_LABELS.get(cloud, cloud)} \u00b7 {service} docs", "url": doc})
    return refs


def cis_rollup(all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Group findings by CIS Benchmark section and control, per cloud.

    ``cis`` strings look like ``"CIS AWS 1.4 / 1.14"`` or ``"CIS Azure 3.6"``.
    Returns {cloud_id: {sections: [...], unmapped: n}} where each section has
    {section, label, fail, pass, controls: [{ref, fail, pass}]}.
    """
    rollup: Dict[str, Any] = {}
    for f in all_findings:
        cid = f.get("cloud") or (f.get("check_id", "").split("-")[0].lower())
        cis = (f.get("cis") or "").strip()
        status = f.get("status")
        is_fail = status in ("FAIL", "FAILED", "OPEN", "NON_COMPLIANT")
        is_pass = status in ("PASS", "OK")
        bucket = rollup.setdefault(cid, {"sections": {}, "unmapped": 0})
        # parse "CIS <cloud> <section>.x [/ <control>]"
        # Note: captures up to two control refs ("CIS AWS 1.4 / 1.14"),
        # ranges ("1.6-1.11") and suffixed refs ("2.1.1(DB)").
        m = re.match(r"^CIS\s+\w+\s+([0-9][0-9.]*(?:-[0-9.]+)?(?:\([A-Za-z0-9]+\))?)(?:\s*/\s*([0-9][0-9.]*(?:-[0-9.]+)?(?:\([A-Za-z0-9]+\))?))?", cis)
        if not m:
            # No CIS reference (e.g. OCI): keep the finding visible in the
            # unmapped bucket whether it failed or passed.
            if is_fail or is_pass:
                bucket["unmapped"] += 1
            continue
        sec_num = int(m.group(1).split(".")[0]) if m.group(1) else None
        refs = [r for r in (m.group(1), m.group(2)) if r]
        ref = " / ".join(refs)
        sec_key = sec_num or 0
        sec = bucket["sections"].setdefault(sec_key, {
            "section": sec_num or 0,
            "label": CIS_SECTION_NAMES.get(cid, {}).get(sec_num, f"Section {sec_num}"),
            "fail": 0, "pass": 0, "controls": {},
        })
        ctl = sec["controls"].setdefault(ref, {"ref": ref, "fail": 0, "pass": 0})
        if is_fail:
            sec["fail"] += 1
            ctl["fail"] += 1
        elif is_pass:
            sec["pass"] += 1
            ctl["pass"] += 1
    out = {}
    for cid, bucket in rollup.items():
        out[cid] = {
            "sections": [{
                "section": s["section"],
                "label": s["label"],
                "fail": s["fail"],
                "pass": s["pass"],
                "controls": sorted(s["controls"].values(), key=lambda c: c["ref"]),
            } for _, s in sorted(bucket["sections"].items())],
            "unmapped": bucket["unmapped"],
        }
    return out

# Official control list of the CIS AWS Foundations Benchmark v5.0 (63 controls,
# sections 1-5). Used to seed the benchmark so the dashboard score is computed
# against the full, current benchmark instead of only the checks we run.
CIS_AWS_V500 = {
    1: ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10",
        "1.11", "1.12", "1.13", "1.14", "1.15", "1.16", "1.17", "1.18", "1.19",
        "1.20", "1.21"],
    2: ["2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.2.1", "2.2.2", "2.2.3", "2.2.4",
        "2.3.1"],
    3: ["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9"],
    4: ["4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.10",
        "4.11", "4.12", "4.13", "4.14", "4.15", "4.16"],
    5: ["5.1.1", "5.1.2", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7"],
}

CIS_AWS_V500_TITLES = {
    "1.1": "Maintain current contact details",
    "1.2": "Ensure security contact information is registered",
    "1.3": "Ensure no 'root' user account access key exists",
    "1.4": "Ensure MFA is enabled for the 'root' user account",
    "1.5": "Ensure hardware MFA is enabled for the 'root' user account",
    "1.6": "Eliminate use of the 'root' user for administrative and daily tasks",
    "1.7": "Ensure IAM password policy requires minimum length of 14 or greater",
    "1.8": "Ensure IAM password policy prevents password reuse",
    "1.9": "Ensure MFA is enabled for all IAM users that have a console password",
    "1.10": "Do not create access keys during initial setup for IAM users with a console password",
    "1.11": "Ensure credentials unused for 45 days or more are disabled",
    "1.12": "Ensure there is only one active access key for any single IAM user",
    "1.13": "Ensure access keys are rotated every 90 days or less",
    "1.14": "Ensure IAM users receive permissions only through groups",
    "1.15": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
    "1.16": "Ensure a support role has been created to manage incidents with AWS Support",
    "1.17": "Ensure IAM instance roles are used for AWS resource access from instances",
    "1.18": "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed",
    "1.19": "Ensure that IAM External Access Analyzer is enabled for all regions",
    "1.20": "Ensure IAM users are managed centrally via identity federation or AWS Organizations",
    "1.21": "Ensure access to AWSCloudShellFullAccess is restricted",
    "2.1.1": "Ensure S3 Bucket Policy is set to deny HTTP requests",
    "2.1.2": "Ensure MFA Delete is enabled on S3 buckets",
    "2.1.3": "Ensure all data in Amazon S3 has been discovered, classified, and secured",
    "2.1.4": "Ensure that S3 is configured with 'Block Public Access' enabled",
    "2.2.1": "Ensure that encryption-at-rest is enabled for RDS instances",
    "2.2.2": "Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances",
    "2.2.3": "Ensure that RDS instances are not publicly accessible",
    "2.2.4": "Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
    "2.3.1": "Ensure that encryption is enabled for EFS file systems",
    "3.1": "Ensure CloudTrail is enabled in all regions",
    "3.2": "Ensure CloudTrail log file validation is enabled",
    "3.3": "Ensure AWS Config is enabled in all regions",
    "3.4": "Ensure that server access logging is enabled on the CloudTrail S3 bucket",
    "3.5": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
    "3.6": "Ensure rotation for customer-created symmetric CMKs is enabled",
    "3.7": "Ensure VPC flow logging is enabled in all VPCs",
    "3.8": "Ensure that object-level logging for write events is enabled for S3 buckets",
    "3.9": "Ensure that object-level logging for read events is enabled for S3 buckets",
    "4.1": "Ensure unauthorized API calls are monitored",
    "4.2": "Ensure management console sign-in without MFA is monitored",
    "4.3": "Ensure usage of the 'root' account is monitored",
    "4.4": "Ensure IAM policy changes are monitored",
    "4.5": "Ensure CloudTrail configuration changes are monitored",
    "4.6": "Ensure AWS Management Console authentication failures are monitored",
    "4.7": "Ensure disabling or scheduled deletion of customer-created CMKs is monitored",
    "4.8": "Ensure S3 bucket policy changes are monitored",
    "4.9": "Ensure AWS Config configuration changes are monitored",
    "4.10": "Ensure security group changes are monitored",
    "4.11": "Ensure Network Access Control List (NACL) changes are monitored",
    "4.12": "Ensure changes to network gateways are monitored",
    "4.13": "Ensure route table changes are monitored",
    "4.14": "Ensure VPC changes are monitored",
    "4.15": "Ensure AWS Organizations changes are monitored",
    "4.16": "Ensure AWS Security Hub is enabled",
    "5.1.1": "Ensure EBS volume encryption is enabled in all regions",
    "5.1.2": "Ensure CIFS access is restricted to trusted networks",
    "5.2": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to admin ports",
    "5.3": "Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports",
    "5.4": "Ensure no security groups allow ingress from ::/0 to admin ports",
    "5.5": "Ensure the default security group of every VPC restricts all traffic",
    "5.6": "Ensure routing tables for VPC peering are 'least access'",
    "5.7": "Ensure that the EC2 Metadata Service only allows IMDSv2",
}

CIS_BENCHMARK_VERSION = {
    "aws": "CIS AWS Foundations v5.0 (63 controls)",
    "azure": "CIS Microsoft Azure Foundations v6.0 (NIST checklist 1335; catalog refs may follow earlier editions)",
    "gcp": "catalog-mapped CIS controls",
    "oci": "catalog-mapped CIS controls",
}

CIS_BENCHMARK_SOURCES = {
    "aws": "https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html",
    "azure": "https://ncp.nist.gov/checklist/1335",
    "gcp": "https://www.cisecurity.org/benchmark/google_cloud_computing_platform/",
    "oci": "https://www.cisecurity.org/benchmark/oracle_cloud_infrastructure/",
}


def cis_benchmark(all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Broad per-cloud CIS Benchmark view driven by the catalog.

    Every check in the catalog that carries a ``cis`` mapping contributes a
    control row (even when the scan found nothing for it, shown as
    "not assessed"), so the panel reflects the full benchmark instead of only
    the sections that happened to fail.

    Returns {cloud: {sections: [{section, label, fail, pass, na, controls:[
    {ref, fail, pass, na, checks:[check_id]}], total_checks}], unmapped: n}}.
    """
    from ..registry import all_checks
    # index findings by (cloud, check_id)
    by_check: Dict[tuple, Dict[str, int]] = {}
    for f in all_findings:
        cid = f.get("cloud") or (f.get("check_id", "").split("-")[0].lower())
        key = (cid, f.get("check_id"))
        st = f.get("status")
        b = by_check.setdefault(key, {"fail": 0, "pass": 0, "na": 0})
        if st in ("FAIL", "FAILED", "OPEN", "NON_COMPLIANT"):
            b["fail"] += 1
        elif st in ("PASS", "OK"):
            b["pass"] += 1
        else:
            b["na"] += 1

    out: Dict[str, Any] = {}
    for cid, checks in all_checks().items():
        sections: Dict[int, dict] = {}
        unmapped = 0
        # Seed AWS with the full CIS AWS Foundations v5.0 control list so every
        # official control is represented (controls we do not cover stay
        # "not assessed" and do not affect the score).
        if cid == "aws":
            for sec_num, ids in CIS_AWS_V500.items():
                sec = sections.setdefault(sec_num, {
                    "section": sec_num, "label": CIS_SECTION_NAMES.get(cid, {}).get(sec_num, f"Section {sec_num}"),
                    "fail": 0, "pass": 0, "na": 0, "controls": {},
                })
                for cid_ref in ids:
                    sec["controls"].setdefault(cid_ref, {"ref": cid_ref, "label": CIS_AWS_V500_TITLES.get(cid_ref, ""), "fail": 0, "pass": 0, "na": 1, "checks": []})
        for ch in checks:
            cis = (ch.cis or "").strip()
            m = re.match(r"^CIS\s+\w+\s+([0-9][0-9.]*(?:-[0-9.]+)?(?:\([A-Za-z0-9]+\))?)(?:\s*/\s*([0-9][0-9.]*(?:-[0-9.]+)?(?:\([A-Za-z0-9]+\))?))?", cis)
            if not m:
                unmapped += 1
                continue
            refs = [r for r in (m.group(1), m.group(2)) if r]
            # split combined refs ("1.4 / 1.5") so every official control is
            # counted exactly once against the benchmark control list
            for ref in refs:
                sec_num = int(ref.split(".")[0]) if ref else 0
                sec = sections.setdefault(sec_num, {
                    "section": sec_num, "label": CIS_SECTION_NAMES.get(cid, {}).get(sec_num, f"Section {sec_num}"),
                    "fail": 0, "pass": 0, "na": 0, "controls": {},
                })
                ctl = sec["controls"].setdefault(ref, {"ref": ref, "label": CIS_AWS_V500_TITLES.get(ref, ""), "fail": 0, "pass": 0, "na": 0, "checks": []})
                ctl["checks"].append(ch.id)
                cnt = by_check.get((cid, ch.id), {"fail": 0, "pass": 0, "na": 1})
                ctl["fail"] += cnt["fail"]
                ctl["pass"] += cnt["pass"]
                if cnt["fail"] or cnt["pass"]:
                    ctl["na"] = 0
                else:
                    ctl["na"] += cnt["na"]
        out[cid] = {
            "sections": [{
                "section": s["section"], "label": s["label"],
                "fail": s["fail"], "pass": s["pass"], "na": s["na"],
                "controls": sorted(s["controls"].values(), key=lambda c: c["ref"]),
            } for _, s in sorted(sections.items())],
            "unmapped": unmapped,
            "version": CIS_BENCHMARK_VERSION.get(cid, ""),
            "source": CIS_BENCHMARK_SOURCES.get(cid, ""),
        }
    return out


def _load(name: str) -> str:
    with open(os.path.join(_TEMPLATE_DIR, name), encoding="utf-8") as fh:
        return fh.read()


def build_dashboard_html(results: Dict[str, ScanResult],
                         comparison_rows: Optional[List[ComparisonRow]] = None,
                         comparison_summary: Optional[Dict[str, Any]] = None,
                         coverage: Optional[Dict[str, dict]] = None,
                         policies: Optional[Dict[str, Any]] = None,
                         title: str = "Cloud Configuration Review",
                         review: bool = False) -> str:
    """Assemble the dashboard from scan results + optional comparison data."""
    from ..registry import coverage_report, all_checks
    from ..privilege import least_privilege_templates

    coverage = coverage or coverage_report()
    policies = policies or least_privilege_templates()
    checks_by_id = {ch.id: ch for lst in all_checks().values() for ch in lst}

    clouds = []
    for cid in ("aws", "azure", "gcp", "oci"):
        res = results.get(cid)
        if not res:
            continue
        d = res.to_dict()
        for f in d["findings"]:
            ch = checks_by_id.get(f.get("check_id", ""))
            f["impact"] = ch.description if ch else ""
            f["frameworks"] = frameworks_for(ch) if ch else frameworks_for(f.get("check_id", ""))
            # Lead framework(s) the check primarily serves - powers the
            # client-side Framework dropdown filter (mirrors --frameworks CLI).
            f["lead_frameworks"] = sorted(lead_frameworks(ch)) if ch else []
            # Quality description: check description + finding context +
            # category consequence, so every issue reads as a proper paragraph.
            f["description"] = _quality_description(f, ch) if ch else (f.get("detail") or "")
        clouds.append({
            "id": cid,
            "label": CLOUD_LABELS.get(cid, cid),
            "account_id": d["account_id"],
            "account_name": d.get("account_name", ""),
            "timestamp": d["timestamp"],
            "principal": d.get("principal", ""),
            "auth_mode": d.get("auth_mode", ""),
            "regions": d.get("regions", []),
            "risk_score": d["risk_score"],
            "checks_total": d["checks_total"],
            "checks_executed": d["checks_executed"],
            "errors": len(d.get("errors", [])),
            "privilege": res.extra.get("privilege_check", {"level": "unknown", "warnings": []}),
            "summary": d["summary"],
            "findings": d["findings"],
        })

    comparison = None
    if comparison_rows is not None:
        comparison = {
            "counts": comparison_summary.get("counts", {}) if comparison_summary else {},
            "fix_rate": comparison_summary.get("fix_rate", 0.0) if comparison_summary else 0.0,
            "rows": [r.to_dict() for r in comparison_rows],
        }

    # CIS Benchmark rollup: findings grouped by CIS section & control per cloud.
    all_findings = [f for c in clouds for f in c["findings"]]
    cis = cis_rollup(all_findings)
    # Broad catalog-driven benchmark (shows every mapped control incl. not-assessed)
    # plus actionable reference links on every finding.
    cis_broad = cis_benchmark(all_findings)
    for c in clouds:
        for f in c["findings"]:
            f["references"] = reference_for(c["id"], f.get("service", ""), f.get("cis"))

    # Compliance framework(s) this scan was explicitly filtered to
    # (--frameworks flag), as display names. The dashboard's Compliance
    # framework mapping panel and Framework dropdown stay hidden unless the
    # user opted into a compliance scan. CIS is excluded - it has its own
    # dedicated benchmark section.
    _FW_SLUG_TO_NAME = {"soc2": "SOC 2", "pci": "PCI DSS",
                        "nist": "NIST 800-53", "hipaa": "HIPAA"}
    frameworks_filter = sorted({
        _FW_SLUG_TO_NAME.get(s, s)
        for res in results.values() if res
        for s in (res.extra.get("frameworks") or []) if s != "cis"
    })

    data = {
        "clouds": clouds,
        "title": title,
        "frameworks_filter": frameworks_filter,
        "catalog_total": sum(len(v) for v in all_checks().values()),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "comparison": comparison,
        "review": review,
        "cis": cis,
        "cis_broad": cis_broad,
        "coverage": {cid: {
            "total_checks": c["total_checks"],
            "services": c["services"],
            "checks_by_service": c["checks_by_service"],
        } for cid, c in coverage.items()},
        "policies": policies,
    }

    head = _load("dashboard_head.html")
    js = _load("dashboard_js.html")
    js = js.replace("%%DATA%%", json.dumps(data).replace("</", "<\\/"))
    html = head.replace("%%TITLE%%", title)
    html = html.replace("%%GENERATED%%",
                        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    html = html.replace("/*%%JS%%*/", js)
    return html


def write_dashboard(path: str, html: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path
