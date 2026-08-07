"""Central registry of all checks and the coverage (areas/services) report."""
from __future__ import annotations

import math
import re
from typing import Dict, List, Optional

from .checks import aws as aws_checks
from .checks import azure as azure_checks
from .checks import gcp as gcp_checks
from .checks import oci as oci_checks
from .models import Check

CLOUDS = ("aws", "azure", "gcp", "oci")

CLOUD_LABELS = {
    "aws": "Amazon Web Services",
    "azure": "Microsoft Azure",
    "gcp": "Google Cloud Platform",
    "oci": "Oracle Cloud Infrastructure",
}

# Static documentation of the services/areas each cloud collector queries.
COVERAGE = {
    "aws": {
        "Identity & Access": ["IAM users/roles/policies", "Root account", "Password policy", "MFA"],
        "Storage": ["S3 buckets (ACL/policy, encryption, versioning, logging)",
                    "Account-level block public access"],
        "Compute": ["EC2 instances (IMDSv2, termination protection, monitoring)",
                    "EBS volumes + default encryption", "AMIs", "Security groups"],
        "Database": ["RDS (public access, encryption, backups, deletion protection, Multi-AZ)",
                     "Redshift", "DynamoDB (PITR, SSE)"],
        "Networking": ["VPCs (default VPC, flow logs)", "NACLs", "Security groups (unused/public-without-SG)",
                        "ELB/ALB + classic ELB (TLS, redirect, WAF, SSL policy)",
                        "CloudFront (WAF, TLS, logging, cert, geo restriction, field-level encryption, OAC/OAI)",
                        "API Gateway", "Route 53 DNSSEC + query logging", "ACM (expiry)"],
        "Logging & Monitoring": ["CloudTrail (enabled/multi-region/validation/logging/bucket-encryption/KMS)",
                                  "AWS Config", "CloudWatch metric alarms (CIS 4.1-4.10)",
                                  "CloudWatch log groups (retention, encryption)", "CloudWatch dashboards"],
        "Security Services": ["GuardDuty", "AWS WAF on edge/ALB"],
        "Key Management": ["KMS keys", "Secrets Manager rotation + CMK"],
        "Containers & Serverless": ["ECR (public, scan-on-push, lifecycle)", "Lambda (runtime, public invoke, VPC, tracing)",
                                    "EKS (endpoint, logging)", "ECS (Container Insights, network mode, execution role)",
                                    "IoT (logging, policies)", "SES (DKIM)"],
        "AI / Machine Learning": ["SageMaker notebooks (direct internet access, KMS encryption)",
                                   "SageMaker endpoints (data capture)"],
        "Data Storage": ["EFS (encryption, backups)", "ElastiCache (at-rest/in-transit)",
                          "SQS (public, encryption, DLQ)", "EBS snapshots (public, encryption)",
                          "RDS snapshots (public)", "DynamoDB (PITR, SSE, public)"],
        "Messaging": ["SNS topic policies + KMS", "SQS queues"],
        "Backup": ["AWS Backup plans + vaults", "S3 lifecycle + MFA delete + Object Lock",
                    "RDS deletion protection/Multi-AZ + enhanced monitoring",
                    "DynamoDB deletion protection", "EFS lifecycle", "ELB deletion protection",
                    "GuardDuty S3 protection"],
    },
    "azure": {
        "Identity & Access": ["RBAC role assignments (subscription scope)", "Custom roles",
                               "Guest users", "Entra ID user MFA registration",
                               "Conditional Access policies (MFA, legacy auth, risk)"],
        "Storage": ["Storage accounts (public access, TLS, HTTPS, network ACLs, CMK, blob soft delete)"],
        "Key Management": ["Key Vaults (soft delete, purge protection, network ACLs, private endpoints, key expiry, diagnostics)"],
        "Networking": ["NSGs (rules, associations, flow logs + retention)", "Bastion"],
        "Database": ["SQL servers (public access, auditing, TDE, min TLS, VA, AAD admin, LTR, firewall)",
                     "Cosmos DB (public, local auth, backup mode)", "Redis (non-SSL, private endpoint)"],
        "Compute": ["Managed disks (CMK)", "VMs (public IP + NSG, boot diagnostics, OS disk CMK, anti-malware, Monitor agent, encryption-at-host)"],
        "Logging & Monitoring": ["Activity log diagnostic settings + alert rules", "NSG flow logs",
                                  "Log Analytics workspaces (CMK, retention)", "Sentinel SIEM + analytics rules", "Network Watcher"],
        "Containers": ["Container Registry (admin account, network access)", "AKS (RBAC, private, network policy, AAD, pod identity, Azure Policy add-on, autoscaler)",
                        "API Management (managed identity, tier, VNet)", "Application Gateway (WAF, TLS)"],
        "App Services": ["HTTPS-only, min TLS, client certs, FTPS, managed identity, auth, HTTP logging, remote debugging"],
        "Edge & Serverless": ["Front Door (WAF policy, logging)", "Functions (HTTP trigger auth level, HTTPS-only)"],
        "Security Services": ["Microsoft Defender pricing plans", "DDoS protection"],
        "Policy & Governance": ["Azure Policy assignments + exemptions", "App Configuration (public access, private endpoints)"],
        "Messaging": ["Event Hubs (public, CMK)", "Service Bus (public access)"],
        "Identity & Access": ["RBAC (incl. service principal broad roles)", "Custom roles", "Guest users",
                               "Entra ID MFA + Conditional Access"],
    },
    "gcp": {
        "Identity & Access": ["Project IAM bindings", "External users", "Service account keys (count + age)",
                               "Primitive roles"],
        "Storage": ["GCS buckets (public, uniform ACL, versioning, CMEK, retention, lifecycle)",
                     "BigQuery datasets (public, CMEK)"],
        "Networking": ["VPC firewall rules + logging", "Default network", "Subnet flow logs", "Cloud DNS DNSSEC", "Cloud VPN (IKE version)"],
        "Compute": ["Compute disks (CMEK)", "Instances (Shielded VM, external IP, serial port, confidential, deletion protection)"],
        "Database": ["Cloud SQL (public IP, SSL, backups, PITR, CMEK, authorized networks)"],
        "Key Management": ["Cloud KMS key rotation", "Secret Manager rotation"],
        "Logging & Monitoring": ["Audit log config (admin + data access)", "Log sinks", "GCS access logging"],
        "Kubernetes": ["GKE clusters (private, network policy, ABAC, release channel, workload identity, shielded nodes, telemetry, node auto-upgrade/repair)"],
        "Serverless": ["Cloud Run (unauthenticated, ingress, CPU throttling, max instances, VPC connector)",
                        "Cloud Functions (public invoke, VPC connector)"],
        "Containers": ["Artifact Registry (public access, CMK)"],
        "Cache": ["Memorystore (transit encryption, AUTH, private IP, persistence)"],
        "Organization Policies": ["Domain-restricted sharing", "VM external IP constraint", "OS Login"],
        "Workload Identity": ["Workload identity pools (providers)"],
        "AI / Machine Learning": ["Vertex AI notebooks (public IP, CMEK)", "Pub/Sub topics (CMEK on messages)"],
        "Kubernetes": ["GKE Binary Authorization"],
    },
    "oci": {
        "Identity & Access": ["Users (MFA, API keys + age)", "IAM policies (broad grants, MFA policy, tenancy scope)"],
        "Networking": ["Security lists", "NSGs", "Subnet flow logs", "Internet gateways",
                        "Load balancers", "Route tables (public default route)", "NAT gateways"],
        "Compute": ["Block/Boot volumes (CMK, backups, replicas)", "OS Management Service (instances, patch-baseline groups)"],
        "Database": ["Autonomous Database (public endpoint, CMK, Data Guard, backup retention, auto-scaling)",
                      "DB systems (backups)", "NoSQL Database (throughput limits)", "DNS (DNSSEC)"],
        "Key Management": ["Vault keys"],
        "Storage": ["Object Storage (public, versioning, CMK, PARs + expiry, lifecycle)",
                    "File Storage (CMK, snapshots)"],
        "Logging & Monitoring": ["Audit configuration (retention period)"],
        "Security Posture": ["Cloud Guard (targets, detector recipes)", "Bastion"],
        "Edge & Serverless": ["API Gateway (WAF policy, TLS on public endpoints)"],
    },
}

_checks: Optional[Dict[str, List[Check]]] = None


def all_checks() -> Dict[str, List[Check]]:
    global _checks
    if _checks is None:
        _checks = {
            "aws": aws_checks.get_checks(),
            "azure": azure_checks.get_checks(),
            "gcp": gcp_checks.get_checks(),
            "oci": oci_checks.get_checks(),
        }
    return _checks


def get_checks(cloud: str) -> List[Check]:
    checks = all_checks().get(cloud)
    if checks is None:
        raise ValueError(f"Unknown cloud '{cloud}'. Choose from {', '.join(CLOUDS)}.")
    return checks


def get_check(cloud: str, check_id: str) -> Optional[Check]:
    for c in get_checks(cloud):
        if c.id == check_id:
            return c
    return None


def search_checks(cloud: str, query: str, limit: int = 10) -> List[dict]:
    """Fuzzy-match check catalog entries against a free-text query.

    ``cloud`` may be a single provider or ``"all"``. Each check is scored by
    how many query tokens appear in its title/service/category/CIS reference
    (exact-phrase matches in the title score highest). Returns the best
    matches as ``{"cloud", "check", "score"}`` dicts, best first.
    """
    q = (query or "").lower().strip()
    if not q:
        return []
    tokens = [t for t in re.split(r"[^a-z0-9]+", q) if len(t) >= 3]  # 1-2 char tokens are noise
    if not tokens:
        return []
    items = []
    hays = []
    for cid, checks in all_checks().items():
        if cloud != "all" and cid != cloud:
            continue
        for ch in checks:
            hay = " ".join([ch.title, ch.service, ch.category, ch.cis or "",
                             ch.guidance or ""]).lower()
            items.append((cid, ch, hay))
            hays.append(hay)
    # Inverse document frequency: rare tokens ("mfa") should outweigh common
    # ones ("disabled") so a flood of unrelated matches cannot drown results.
    total = max(1, len(hays))
    idf = {}
    for t in tokens:
        df = sum(1 for h in hays if t in h)
        idf[t] = 1.0 + math.log(total / (1.0 + df))
    scored = []
    for cid, ch, hay in items:
        score = 0.0
        if q in ch.title.lower():
            score += 10.0          # exact phrase in the title wins
        for t in tokens:
            if t in hay:
                score += 2.0 * idf[t]            # whole token match, weighted
            elif any(w.startswith(t) for w in re.split(r"[^a-z0-9]+", hay)):
                score += 1.0 * idf[t]            # prefix match (typo tolerance)
        if score > 0:
            scored.append({"cloud": cid, "check": ch, "score": round(score, 1)})
    scored.sort(key=lambda x: (-x["score"], x["check"].id))
    return scored[:limit]


def coverage_report(cloud: Optional[str] = None) -> Dict[str, dict]:
    """Per-cloud: services covered, check counts per service, totals."""
    report: Dict[str, dict] = {}
    for cloud_name, checks in all_checks().items():
        if cloud and cloud != cloud_name:
            continue
        by_service: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        sev: Dict[str, int] = {}
        for c in checks:
            by_service[c.service] = by_service.get(c.service, 0) + 1
            by_category[c.category] = by_category.get(c.category, 0) + 1
            sev[c.severity.value] = sev.get(c.severity.value, 0) + 1
        report[cloud_name] = {
            "total_checks": len(checks),
            "services": COVERAGE.get(cloud_name, {}),
            "checks_by_service": dict(sorted(by_service.items(), key=lambda x: -x[1])),
            "checks_by_category": dict(sorted(by_category.items(), key=lambda x: -x[1])),
            "checks_by_severity": sev,
        }
    return report
