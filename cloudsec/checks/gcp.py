"""GCP configuration review checks.

Snapshot layout:
{
  "project_id": str, "principal": str,
  "iam": [{member, role, type}],            # type: user|serviceAccount|group|allUsers|allAuthenticatedUsers
  "sa_keys": [{email, key_count}],
  "buckets": [{name, public, uniform, versioning, cmek}],
  "firewalls": [{name, network, allowed: [{proto, ports}], source_ranges,
                 open_ports, disabled}],
  "disks": [{name, cmek}],
  "instances": [{name, external_ip, shielded_vm}],
  "sql": [{name, private_ip, require_ssl, backup_enabled}],
  "kms": [{key, rotation_period_days}],
  "audit": {"admin_activity": bool, "log_sinks": int},
  "gke": [{name, private_cluster, network_policy, legacy_abac, release_channel}],
}
"""
from __future__ import annotations

from typing import Dict, List

from ..models import Check, Finding, Severity, Status

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
OPEN_PORTS = [22, 3389]


def _f(check: Check, snapshot: dict, resource: str, status: Status,
       detail: str = "", evidence: dict | None = None) -> Finding:
    if not isinstance(status, Status):
        status = Status.FAIL  # a Severity was passed by mistake
    return Finding(
        check_id=check.id, check_title=check.title, cloud=check.cloud,
        service=check.service, category=check.category, severity=check.severity,
        status=status, resource=resource, detail=detail,
        remediation=check.remediation, evidence=evidence or {}, cis=check.cis,
    )


def _fw_open_ports(fw: dict) -> List[int]:
    if fw.get("disabled"):
        return []
    srcs = set(fw.get("source_ranges", []))
    if not (srcs & {"0.0.0.0/0", "::/0"}):
        return []
    out: List[int] = []
    for a in fw.get("allowed", []):
        proto = a.get("proto", "").lower()
        if proto in ("icmp", "esp", "ah", "all"):
            continue
        ports = a.get("ports")
        if ports is None:
            out.extend([22, 3389, 3306, 5432, 6379, 9200])
            continue
        for pr in ports:
            if "-" in pr:
                lo, hi = pr.split("-")
                try:
                    lo, hi = int(lo), int(hi)
                except ValueError:
                    continue
                for p in OPEN_PORTS + [80, 443, 3306, 5432, 6379, 9200]:
                    if lo <= p <= hi and p not in out:
                        out.append(p)
            else:
                try:
                    p = int(pr)
                except ValueError:
                    continue
                if p in OPEN_PORTS + [80, 443, 3306, 5432, 6379, 9200] and p not in out:
                    out.append(p)
    return out


# --------------------------------------------------------------------------- #
# IAM
# --------------------------------------------------------------------------- #
def _gcp_iam_checks() -> List[Check]:
    def sa_keys(c, s, _):
        out = []
        for sa in s["sa_keys"]:
            if sa.get("key_count", 0) > 0:
                out.append(_f(c, s, f"sa:{sa['email']}", Status.FAIL,
                              f"Service account has {sa['key_count']} user-managed "
                              "JSON key(s) (long-lived credentials)."))
        if not out:
            out.append(_f(c, s, "service-accounts", Status.PASS,
                          "No service accounts use user-managed keys."))
        return out

    def primitive_on_users(c, s, _):
        out = []
        for b in s["iam"]:
            if b.get("role") in PRIMITIVE_ROLES and b.get("type") == "user":
                out.append(_f(c, s, f"{b['member']}", Status.FAIL,
                              f"Primitive role {b['role']} assigned to a human user."))
        if not out:
            out.append(_f(c, s, "project-iam", Status.PASS,
                          "No primitive roles on human users."))
        return out

    def public_bindings(c, s, _):
        out = []
        for b in s["iam"]:
            if b.get("type") in ("allUsers", "allAuthenticatedUsers"):
                out.append(_f(c, s, f"{b['member']}", Status.FAIL,
                              f"Binding {b['role']} is granted to {b['type']} "
                              "(anonymous/any authenticated)."))
        if not out:
            out.append(_f(c, s, "project-iam", Status.PASS,
                          "No bindings for allUsers / allAuthenticatedUsers."))
        return out

    return [
        Check("GCP-IAM-001", "gcp", "IAM", "Identity & Access", Severity.HIGH,
              "Service account uses user-managed keys",
              "Downloaded JSON keys never expire and are frequently leaked to "
              "source control.",
              "Delete user-managed keys and use workload identity / impersonation.",
              sa_keys, cis="CIS GCP 1.1"),
        Check("GCP-IAM-002", "gcp", "IAM", "Identity & Access", Severity.CRITICAL,
              "Primitive role assigned to a human user",
              "Owner/Editor on users grants near-total control and prevents "
              "fine-grained auditing.",
              "Replace primitive roles with least-privilege custom roles and "
              "groups.",
              primitive_on_users, cis="CIS GCP 1.4"),
        Check("GCP-IAM-003", "gcp", "IAM", "Identity & Access", Severity.CRITICAL,
              "Project IAM binding grants anonymous/all-authenticated access",
              "allUsers / allAuthenticatedUsers bindings expose resources to "
              "the entire internet or all Google identities.",
              "Remove public bindings; use signed URLs / IAP where sharing is "
              "required.",
              public_bindings, cis="CIS GCP 1.6"),
    ]


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def _gcp_storage_checks() -> List[Check]:
    def public(c, s, _):
        out = []
        for b in s["buckets"]:
            if b.get("public"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "Bucket is publicly readable (allUsers in IAM "
                              "policy or legacy ACL)."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "No buckets are publicly readable."))
        return out

    def uniform(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("uniform"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "Uniform bucket-level access is disabled (legacy "
                              "object ACLs in use)."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "All buckets use uniform bucket-level access."))
        return out

    def versioning(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("versioning"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "Object versioning is disabled."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "All buckets have versioning enabled."))
        return out

    def cmek(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("cmek"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "Bucket uses Google-managed encryption keys, not a "
                              "CMEK."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "All buckets use CMEK."))
        return out

    return [
        Check("GCP-ST-001", "gcp", "Cloud Storage", "Storage & Data Protection", Severity.CRITICAL,
              "Bucket publicly readable",
              "Public buckets are a leading cause of cloud data breaches.",
              "Remove allUsers/allAuthenticatedUsers bindings and enable public "
              "access prevention.",
              public, cis="CIS GCP 2.1"),
        Check("GCP-ST-002", "gcp", "Cloud Storage", "Storage & Data Protection", Severity.MEDIUM,
              "Uniform bucket-level access disabled",
              "Object-level ACLs are hard to audit and frequently over-permissive.",
              "Enable uniform bucket-level access on all buckets.",
              uniform, cis="CIS GCP 2.8"),
        Check("GCP-ST-003", "gcp", "Cloud Storage", "Backup & Recovery", Severity.MEDIUM,
              "Bucket versioning disabled",
              "Versioning protects against accidental deletion and ransomware.",
              "Enable versioning on buckets holding mutable data.",
              versioning, cis="CIS GCP 2.10"),
        Check("GCP-ST-004", "gcp", "Cloud Storage", "Data Protection", Severity.LOW,
              "Bucket not using customer-managed encryption key",
              "CMEK provides key lifecycle control for compliance regimes.",
              "Configure default KMS keys on buckets where required.",
              cmek),
    ]


# --------------------------------------------------------------------------- #
# Networking / Compute / SQL / KMS / Logging / GKE
# --------------------------------------------------------------------------- #
def _gcp_misc_checks() -> List[Check]:
    def fw_open(c, s, _):
        out = []
        for fw in s["firewalls"]:
            ports = _fw_open_ports(fw)
            if ports:
                out.append(_f(c, s, f"fw:{fw['name']}", Status.FAIL,
                              "Firewall rule exposes ports "
                              f"{sorted(set(ports))} to 0.0.0.0/0.",
                              {"open_ports": sorted(set(ports))}))
        if not out:
            out.append(_f(c, s, "firewall-rules", Status.PASS,
                          "No firewall rules expose management ports to the "
                          "internet."))
        return out

    def default_network(c, s, _):
        default_rules = [f for f in s["firewalls"] if f.get("network", "").endswith("default")]
        open_default = [f for f in default_rules if _fw_open_ports(f)]
        if open_default:
            names = ", ".join(f["name"] for f in open_default)
            return [_f(c, s, "default-vpc", Status.FAIL,
                       f"Default VPC contains open firewall rules: {names}.")]
        if default_rules:
            return [_f(c, s, "default-vpc", Status.PASS,
                       "Default VPC rules are not open to the internet.")]
        return [_f(c, s, "default-vpc", Status.PASS,
                   "No default network in use.")]

    def disk_cmek(c, s, _):
        out = []
        for d in s["disks"]:
            if not d.get("cmek"):
                out.append(_f(c, s, f"disk:{d['name']}", Status.FAIL,
                              "Disk uses Google-managed key, not CMEK."))
        if not out:
            out.append(_f(c, s, "compute-disks", Status.PASS,
                          "All disks use CMEK."))
        return out

    def shielded_vm(c, s, _):
        out = []
        for i in s["instances"]:
            if not i.get("shielded_vm"):
                out.append(_f(c, s, f"instance:{i['name']}", Status.FAIL,
                              "Shielded VM (secure boot / vTPM / integrity "
                              "monitoring) is disabled."))
        if not out:
            out.append(_f(c, s, "compute-instances", Status.PASS,
                          "All instances use Shielded VM."))
        return out

    def sql_public(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("private_ip"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Cloud SQL instance only has a public IP address."))
        if not out:
            out.append(_f(c, s, "cloud-sql", Status.PASS,
                          "All Cloud SQL instances use private IPs."))
        return out

    def sql_ssl(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("require_ssl"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Cloud SQL does not require SSL/TLS connections."))
        if not out:
            out.append(_f(c, s, "cloud-sql", Status.PASS,
                          "All Cloud SQL instances require SSL."))
        return out

    def sql_backup(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("backup_enabled"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Automated backups are disabled."))
        if not out:
            out.append(_f(c, s, "cloud-sql", Status.PASS,
                          "All Cloud SQL instances have automated backups."))
        return out

    def kms_rotation(c, s, _):
        out = []
        for k in s["kms"]:
            period = k.get("rotation_period_days") or 0
            if not period:
                out.append(_f(c, s, f"kms:{k['key']}", Status.FAIL,
                              "KMS key rotation is not configured (or period > 90 "
                              "days)."))
        if not out:
            out.append(_f(c, s, "kms-keys", Status.PASS,
                          "All KMS keys rotate within 90 days."))
        return out

    def audit_admin(c, s, _):
        if s["audit"].get("admin_activity"):
            return [_f(c, s, "project-audit-config", Status.PASS,
                       "Admin activity audit logs are enabled.")]
        return [_f(c, s, "project-audit-config", Status.FAIL,
                   "Admin activity audit logging is not enabled for the project.")]

    def log_sinks(c, s, _):
        n = s["audit"].get("log_sinks", 0)
        if n == 0:
            return [_f(c, s, "log-sinks", Status.FAIL,
                       "No log sinks export logs to an external SIEM/storage "
                       "for retention and correlation.")]
        return [_f(c, s, "log-sinks", Status.PASS,
                   f"{n} log sink(s) export project logs.")]

    def gke_private(c, s, _):
        out = []
        for cl in s["gke"]:
            if not cl.get("private_cluster"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "GKE cluster nodes have public IPs (not a private "
                              "cluster)."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "All GKE clusters are private."))
        return out

    def gke_network_policy(c, s, _):
        out = []
        for cl in s["gke"]:
            if not cl.get("network_policy"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Network policy is not enabled on the cluster."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "All GKE clusters enforce network policy."))
        return out

    def gke_legacy(c, s, _):
        # One finding per cluster (aggregates sub-issues) so the
        # (check_id, resource) comparison key stays unambiguous.
        out = []
        for cl in s["gke"]:
            issues = []
            if cl.get("legacy_abac"):
                issues.append("Legacy ABAC authorization is enabled (cluster-wide "
                              "permissions)")
            if not cl.get("release_channel"):
                issues.append("cluster is not enrolled in a release channel "
                              "(misses managed security upgrades)")
            if issues:
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "; ".join(issues) + "."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "No legacy ABAC clusters; all enrolled in release "
                          "channels."))
        return out

    return [
        Check("GCP-FW-001", "gcp", "VPC/Firewall", "Network Security", Severity.CRITICAL,
              "Firewall rule exposes management ports to the internet",
              "0.0.0.0/0 rules for 22/3389 (and data ports) allow direct "
              "internet access to workloads.",
              "Restrict source ranges; use IAP tunnel for SSH and remove "
              "broad rules.",
              fw_open, cis="CIS GCP 3.6"),
        Check("GCP-FW-002", "gcp", "VPC/Firewall", "Network Security", Severity.HIGH,
              "Default VPC contains open firewall rules",
              "The default network ships with permissive rules and should not "
              "host production workloads.",
              "Disable the default network; create hardened VPCs with "
              "deny-by-default rules.",
              default_network, cis="CIS GCP 3.1"),
        Check("GCP-CMP-001", "gcp", "Compute", "Data Protection", Severity.LOW,
              "Disk not using customer-managed encryption key",
              "CMEK on disks enables key rotation and separation of duties.",
              "Use CMEK for disks where compliance requires key control.",
              disk_cmek),
        Check("GCP-CMP-002", "gcp", "Compute", "Compute", Severity.MEDIUM,
              "Shielded VM disabled",
              "Shielded VMs protect against boot-level malware and rootkit "
              "persistence.",
              "Enable secure boot, vTPM and integrity monitoring on instances.",
              shielded_vm, cis="CIS GCP 4.3"),
        Check("GCP-SQL-001", "gcp", "Cloud SQL", "Database", Severity.HIGH,
              "Cloud SQL instance only has public IP",
              "Public IPs expose databases to the internet; firewall rules are "
              "the only barrier.",
              "Assign a private IP and disable public IP on Cloud SQL "
              "instances.",
              sql_public, cis="CIS GCP 6.1"),
        Check("GCP-SQL-002", "gcp", "Cloud SQL", "Network Security", Severity.MEDIUM,
              "Cloud SQL does not require SSL",
              "Connections without SSL can be intercepted in transit.",
              "Set require_ssl=true (and enforce TLS 1.2+).",
              sql_ssl, cis="CIS GCP 6.2"),
        Check("GCP-SQL-003", "gcp", "Cloud SQL", "Backup & Recovery", Severity.MEDIUM,
              "Cloud SQL automated backups disabled",
              "Without backups, data loss cannot be recovered.",
              "Enable automated backups with a suitable retention window.",
              sql_backup, cis="CIS GCP 6.6"),
        Check("GCP-KMS-001", "gcp", "Cloud KMS", "Key Management", Severity.MEDIUM,
              "KMS key rotation not configured",
              "Keys that never rotate increase the impact of a leak.",
              "Configure rotation period <= 90 days for symmetric keys.",
              kms_rotation, cis="CIS GCP 1.9"),
        Check("GCP-LOG-001", "gcp", "Cloud Logging", "Logging & Monitoring", Severity.HIGH,
              "Admin activity audit logging disabled",
              "Without audit logs, privilege misuse and configuration changes "
              "are invisible.",
              "Enable admin activity (and optionally data access) audit logs "
              "for all services.",
              audit_admin, cis="CIS GCP 2.12"),
        Check("GCP-LOG-002", "gcp", "Cloud Logging", "Logging & Monitoring", Severity.MEDIUM,
              "No log sinks for external log export",
              "Logs without an export sink are at risk of loss and cannot be "
              "fed to a SIEM.",
              "Create log sinks to BigQuery/PubSub/Storage with a retention "
              "policy.",
              log_sinks, cis="CIS GCP 2.13"),
        Check("GCP-GKE-001", "gcp", "GKE", "Kubernetes", Severity.HIGH,
              "GKE cluster is not private",
              "Public node IPs expose the Kubernetes data plane to the "
              "internet.",
              "Create private clusters with authorized networks and no public "
              "endpoint.",
              gke_private, cis="CIS GKE 1.3.1"),
        Check("GCP-GKE-002", "gcp", "GKE", "Kubernetes", Severity.MEDIUM,
              "GKE network policy disabled",
              "Without network policy, pods can communicate unrestricted "
              "laterally.",
              "Enable NetworkPolicy enforcement on the cluster.",
              gke_network_policy, cis="CIS GKE 1.2.5"),
        Check("GCP-GKE-003", "gcp", "GKE", "Kubernetes", Severity.CRITICAL,
              "GKE uses legacy ABAC / no release channel",
              "ABAC grants cluster-wide permissions; clusters outside a release "
              "channel miss managed security upgrades.",
              "Disable ABAC and enroll the cluster in a release channel.",
              gke_legacy, cis="CIS GKE 1.1.1"),
    ]


# --------------------------------------------------------------------------- #
# Hardening: IAM extras / storage / network / SQL / GKE / BQ / secrets / org
# --------------------------------------------------------------------------- #
def _gcp_hardening_checks() -> List[Check]:
    def external_users(c, s, _):
        out = []
        for b in s["iam"]:
            if b.get("external"):
                out.append(_f(c, s, b["member"], Status.FAIL,
                              f"External identity {b['member']} holds {b['role']}; "
                              "verify it is required and governed."))
        if not out:
            out.append(_f(c, s, "project-iam", Status.PASS,
                          "No external users in project IAM."))
        return out

    def sa_key_age(c, s, _):
        out = []
        for sa in s["sa_keys"]:
            age = sa.get("oldest_key_age_days", 0)
            if age > 90:
                out.append(_f(c, s, f"sa:{sa['email']}", Status.FAIL,
                              f"Service account key is {age} days old (rotate "
                              "within 90 days)."))
        if not out:
            out.append(_f(c, s, "service-accounts", Status.PASS,
                          "No service account keys exceed 90 days."))
        return out

    def retention(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("retention"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "Bucket has no retention policy; deleted objects "
                              "cannot be recovered."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "All buckets have retention policies."))
        return out

    def lifecycle(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("lifecycle"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "No lifecycle rules; stale or redundant objects "
                              "accumulate cost and risk."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "All buckets define lifecycle rules."))
        return out

    def instance_external(c, s, _):
        out = []
        for i in s["instances"]:
            if i.get("external_ip"):
                out.append(_f(c, s, f"instance:{i['name']}", Status.FAIL,
                              "Instance has an external IP; prefer IAP or "
                              "Cloud NAT for egress."))
        if not out:
            out.append(_f(c, s, "compute-instances", Status.PASS,
                          "No instances have external IPs."))
        return out

    def flow_logs(c, s, _):
        out = []
        for sn in s.get("subnets", []):
            if not sn.get("enable_flow_logs"):
                out.append(_f(c, s, f"subnet:{sn['name']}", Status.FAIL,
                              "VPC flow logs are not enabled on this subnet."))
        if not out:
            out.append(_f(c, s, "subnets", Status.PASS,
                          "All subnets have flow logs enabled."))
        return out

    def dnssec(c, s, _):
        d = s["dns"]
        if d.get("total_zones", 0) == 0:
            return [_f(c, s, "cloud-dns", Status.PASS, "No managed zones to sign.")]
        if d.get("dnssec_zones") == d.get("total_zones"):
            return [_f(c, s, "cloud-dns", Status.PASS,
                       "All managed zones have DNSSEC enabled.")]
        return [_f(c, s, "cloud-dns", Status.FAIL,
                   f"DNSSEC enabled on {d.get('dnssec_zones')}/{d.get('total_zones')} "
                   "managed zones.")]

    def sql_cmek(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("cmek"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Cloud SQL not encrypted with CMEK."))
        if not out:
            out.append(_f(c, s, "cloud-sql", Status.PASS,
                          "All Cloud SQL instances use CMEK."))
        return out

    def sql_broad_nets(c, s, _):
        out = []
        for db in s["sql"]:
            if db.get("broad_authorized_networks"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Authorized networks include 0.0.0.0/0 (open to "
                              "the internet)."))
        if not out:
            out.append(_f(c, s, "cloud-sql", Status.PASS,
                          "No Cloud SQL instances allow 0.0.0.0/0."))
        return out

    def gke_wi(c, s, _):
        out = []
        for cl in s["gke"]:
            if not cl.get("workload_identity"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Workload Identity is not enabled; pods must use "
                              "long-lived keys or node IAM."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "All clusters use Workload Identity."))
        return out

    def gke_shielded(c, s, _):
        out = []
        for cl in s["gke"]:
            if not cl.get("shielded_nodes"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Shielded nodes are disabled; nodes lack secure "
                              "boot and integrity monitoring."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "All clusters use shielded nodes."))
        return out

    def gke_endpoint(c, s, _):
        out = []
        for cl in s["gke"]:
            if not cl.get("private_endpoint"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Cluster master endpoint is publicly accessible "
                              "(private endpoint access disabled)."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "All clusters use private endpoints."))
        return out

    def gke_telemetry(c, s, _):
        out = []
        for cl in s["gke"]:
            if not cl.get("logging_service") or not cl.get("monitoring_service"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Cluster logging/monitoring is disabled; activity "
                              "is invisible."))
        if not out:
            out.append(_f(c, s, "gke-clusters", Status.PASS,
                          "All clusters send logs and metrics."))
        return out

    def bq_public(c, s, _):
        out = []
        for ds in s.get("bigquery", []):
            if ds.get("public"):
                out.append(_f(c, s, f"bq:{ds['dataset_id']}", Status.FAIL,
                              "BigQuery dataset is publicly readable (allUsers "
                              "binding)."))
        if not out:
            out.append(_f(c, s, "bigquery-datasets", Status.PASS,
                          "No BigQuery datasets are public."))
        return out

    def bq_cmek(c, s, _):
        out = []
        for ds in s.get("bigquery", []):
            if not ds.get("cmek"):
                out.append(_f(c, s, f"bq:{ds['dataset_id']}", Status.FAIL,
                              "Dataset uses Google-managed keys, not CMEK."))
        if not out:
            out.append(_f(c, s, "bigquery-datasets", Status.PASS,
                          "All datasets use CMEK."))
        return out

    def secret_rotation(c, s, _):
        out = []
        for sec in s.get("secrets", []):
            if not sec.get("rotation"):
                out.append(_f(c, s, f"secret:{sec['name']}", Status.FAIL,
                              "Secret rotation policy is not configured."))
        if not out:
            out.append(_f(c, s, "secrets", Status.PASS,
                          "All secrets have rotation configured."))
        return out

    def _org(c, s, key, title, detail, rem):
        op = s.get("org_policies", {})
        val = op.get(key)
        if not op.get("collected") or val is None:
            return [_f(c, s, "org-policies", Status.NOT_APPLICABLE,
                       "This organization policy could not be verified with the "
                       "current permissions; grant Organization Policy Viewer at "
                       "the organization level to assess.")]
        if val:
            return [_f(c, s, "org-policies", Status.PASS, title + " - enforced.")]
        return [_f(c, s, "org-policies", Status.FAIL, detail)]

    def org_domains(c, s, _):
        return _org(c, s, "domain_restricted_sharing",
                    "Domain-restricted sharing",
                    "The iam.allowedPolicyMemberDomains constraint is not "
                    "enforced; external principals can be added to IAM.",
                    "Enforce domain-restricted sharing at the organization.")

    def org_vm_ext(c, s, _):
        return _org(c, s, "vm_external_ip",
                    "VM external IP constraint",
                    "compute.vmExternalIpAccess is not restricted; VMs can be "
                    "created with public IPs.",
                    "Restrict external IP creation via organization policy.")

    def data_access(c, s, _):
        if s["audit"].get("data_access"):
            return [_f(c, s, "project-audit-config", Status.PASS,
                       "Data access audit logs are enabled.")]
        return [_f(c, s, "project-audit-config", Status.FAIL,
                   "Data access audit logging is not enabled (only admin "
                   "activity is captured).")]

    return [
        Check("GCP-IAM-004", "gcp", "IAM", "Identity & Access", Severity.MEDIUM,
              "External user in project IAM",
              "External identities cannot be governed by your identity provider "
              "and often retain access after offboarding.",
              "Remove external users or manage them through identity federation "
              "and access reviews.",
              external_users),
        Check("GCP-IAM-005", "gcp", "IAM", "Identity & Access", Severity.MEDIUM,
              "Service account key older than 90 days",
              "Long-lived keys never expire and are frequently leaked to source "
              "control.",
              "Rotate keys and move workloads to workload identity.",
              sa_key_age),
        Check("GCP-ST-005", "gcp", "Cloud Storage", "Backup & Recovery", Severity.LOW,
              "Bucket retention policy missing",
              "Without retention, deleted objects are gone permanently.",
              "Configure retention policies on buckets holding regulated data.",
              retention),
        Check("GCP-ST-006", "gcp", "Cloud Storage", "Security Posture", Severity.LOW,
              "Bucket lifecycle rules missing",
              "Without lifecycle rules, stale objects accumulate cost and risk.",
              "Define lifecycle rules to transition and delete stale objects.",
              lifecycle),
        Check("GCP-CMP-003", "gcp", "Compute", "Network Security", Severity.MEDIUM,
              "Instance has an external IP",
              "Public IPs expose instances directly to the internet; egress can "
              "go through Cloud NAT.",
              "Remove external IPs and use IAP/Cloud NAT.",
              instance_external),
        Check("GCP-NET-001", "gcp", "VPC", "Logging & Monitoring", Severity.MEDIUM,
              "Subnet VPC flow logs disabled",
              "Flow logs give network visibility for detection and forensics.",
              "Enable VPC flow logs on subnets (sampled 50%).",
              flow_logs),
        Check("GCP-NET-002", "gcp", "Cloud DNS", "Network Security", Severity.LOW,
              "DNSSEC not enabled on all zones",
              "Unsigned DNS is vulnerable to response spoofing.",
              "Enable DNSSEC on production managed zones.",
              dnssec),
        Check("GCP-SQL-004", "gcp", "Cloud SQL", "Data Protection", Severity.LOW,
              "Cloud SQL not encrypted with CMEK",
              "Google-managed keys give less lifecycle control.",
              "Encrypt instances with CMEK where required.",
              sql_cmek),
        Check("GCP-SQL-005", "gcp", "Cloud SQL", "Network Security", Severity.HIGH,
              "Cloud SQL authorized networks include 0.0.0.0/0",
              "Open authorized networks expose the database to the internet.",
              "Remove 0.0.0.0/0 and restrict to trusted CIDRs / private IP.",
              sql_broad_nets),
        Check("GCP-GKE-004", "gcp", "GKE", "Identity & Access", Severity.MEDIUM,
              "GKE Workload Identity disabled",
              "Pods without Workload Identity use node credentials or keys.",
              "Enable Workload Identity on the cluster and namespaces.",
              gke_wi),
        Check("GCP-GKE-005", "gcp", "GKE", "Compute", Severity.MEDIUM,
              "GKE shielded nodes disabled",
              "Shielded nodes protect against boot-level compromise.",
              "Enable shielded nodes (secure boot + integrity monitoring).",
              gke_shielded),
        Check("GCP-GKE-006", "gcp", "GKE", "Network Security", Severity.MEDIUM,
              "GKE master endpoint publicly accessible",
              "Public endpoints expose the control plane; authorized networks "
              "are the only barrier.",
              "Enable private endpoint access and disable public access.",
              gke_endpoint),
        Check("GCP-GKE-007", "gcp", "GKE", "Logging & Monitoring", Severity.MEDIUM,
              "GKE logging or monitoring disabled",
              "Clusters without telemetry are invisible to detection.",
              "Enable Cloud Logging and Cloud Monitoring for the cluster.",
              gke_telemetry),
        Check("GCP-BQ-001", "gcp", "BigQuery", "Storage & Data Protection", Severity.CRITICAL,
              "BigQuery dataset publicly readable",
              "Public datasets expose query results and tables to the internet.",
              "Remove allUsers/allAuthenticatedUsers bindings.",
              bq_public),
        Check("GCP-BQ-002", "gcp", "BigQuery", "Data Protection", Severity.LOW,
              "BigQuery dataset not using CMEK",
              "Google-managed keys give less key control for regulated data.",
              "Set a default CMEK on datasets where required.",
              bq_cmek),
        Check("GCP-SM-001", "gcp", "Secret Manager", "Key Management", Severity.MEDIUM,
              "Secret rotation not configured",
              "Non-rotating secrets become more valuable the longer they leak.",
              "Configure rotation periods on all secrets.",
              secret_rotation),
        Check("GCP-ORG-001", "gcp", "Org Policies", "Identity & Access", Severity.MEDIUM,
              "Domain-restricted sharing not enforced",
              "Without allowedPolicyMemberDomains, external principals can be "
              "added to IAM.",
              "Enforce domain-restricted sharing at the organization.",
              org_domains),
        Check("GCP-ORG-002", "gcp", "Org Policies", "Network Security", Severity.MEDIUM,
              "VM external IP constraint not enforced",
              "VMs can be created with public IPs without policy restriction.",
              "Restrict compute.vmExternalIpAccess at the organization.",
              org_vm_ext),
        Check("GCP-LOG-003", "gcp", "Cloud Logging", "Logging & Monitoring", Severity.MEDIUM,
              "Data access audit logs disabled",
              "Data-plane reads/writes are not audited; sensitive data access "
              "is invisible.",
              "Enable DATA_READ/DATA_WRITE audit logs for sensitive services.",
              data_access),
    ]


# --------------------------------------------------------------------------- #
# Tranche 2: Cloud Run / Memorystore / instance extras / bucket logging
# --------------------------------------------------------------------------- #
def _gcp_tier2_checks() -> List[Check]:
    def cr_unauth(c, s, _):
        out = []
        for svc in s.get("cloudrun", []):
            if svc.get("unauthenticated"):
                out.append(_f(c, s, f"run:{svc['name']}", Status.FAIL,
                              "Cloud Run service allows unauthenticated invocation "
                              "(allUsers/allAuthenticatedUsers)."))
        if not out:
            out.append(_f(c, s, "cloud-run", Status.PASS,
                          "No Cloud Run services allow unauthenticated calls."))
        return out

    def cr_ingress(c, s, _):
        out = []
        for svc in s.get("cloudrun", []):
            if svc.get("ingress_all"):
                out.append(_f(c, s, f"run:{svc['name']}", Status.FAIL,
                              "Cloud Run service accepts traffic from the internet "
                              "(ingress all)."))
        if not out:
            out.append(_f(c, s, "cloud-run", Status.PASS,
                          "Cloud Run services restrict ingress."))
        return out

    def mem_transit(c, s, _):
        out = []
        for m in s.get("memorystore", []):
            if not m.get("transit_encryption"):
                out.append(_f(c, s, f"memorystore:{m['name']}", Status.FAIL,
                              "Memorystore transit encryption (TLS) is disabled."))
        if not out:
            out.append(_f(c, s, "memorystore", Status.PASS,
                          "All Memorystore instances encrypt in transit."))
        return out

    def mem_auth(c, s, _):
        out = []
        for m in s.get("memorystore", []):
            if not m.get("auth_enabled"):
                out.append(_f(c, s, f"memorystore:{m['name']}", Status.FAIL,
                              "Memorystore AUTH is disabled; anyone who can reach "
                              "the instance can read/write data."))
        if not out:
            out.append(_f(c, s, "memorystore", Status.PASS,
                          "All Memorystore instances require AUTH."))
        return out

    def mem_private(c, s, _):
        out = []
        for m in s.get("memorystore", []):
            if not m.get("private_ip"):
                out.append(_f(c, s, f"memorystore:{m['name']}", Status.FAIL,
                              "Memorystore instance has a public IP; no private "
                              "service connect."))
        if not out:
            out.append(_f(c, s, "memorystore", Status.PASS,
                          "All Memorystore instances use private IPs."))
        return out

    def serial_port(c, s, _):
        out = []
        for i in s["instances"]:
            if i.get("serial_port"):
                out.append(_f(c, s, f"instance:{i['name']}", Status.FAIL,
                              "Serial port access is enabled; interactive console "
                              "access bypasses SSH controls."))
        if not out:
            out.append(_f(c, s, "compute-instances", Status.PASS,
                          "No instances expose the serial port."))
        return out

    def confidential(c, s, _):
        out = []
        for i in s["instances"]:
            if not i.get("confidential"):
                out.append(_f(c, s, f"instance:{i['name']}", Status.FAIL,
                              "Confidential computing is not enabled on the "
                              "instance."))
        if not out:
            out.append(_f(c, s, "compute-instances", Status.PASS,
                          "All instances use confidential computing."))
        return out

    def bucket_logging(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("logging"):
                out.append(_f(c, s, f"gs://{b['name']}", Status.FAIL,
                              "Access logging is not enabled on the bucket."))
        if not out:
            out.append(_f(c, s, "buckets", Status.PASS,
                          "All buckets log access."))
        return out

    def primitive_sa(c, s, _):
        out = []
        for b in s["iam"]:
            if b.get("role") in PRIMITIVE_ROLES and b.get("type") == "serviceAccount":
                out.append(_f(c, s, b["member"], Status.FAIL,
                              f"Primitive role {b['role']} assigned to a service "
                              "account; use least-privilege roles."))
        if not out:
            out.append(_f(c, s, "project-iam", Status.PASS,
                          "No primitive roles on service accounts."))
        return out

    return [
        Check("GCP-CR-001", "gcp", "Cloud Run", "Network Security", Severity.HIGH,
              "Cloud Run allows unauthenticated invocation",
              "Anonymous callers can invoke the service and consume resources "
              "or trigger logic.",
              "Remove allUsers/allAuthenticatedUsers from the service IAM "
              "policy; require authentication.",
              cr_unauth),
        Check("GCP-CR-002", "gcp", "Cloud Run", "Network Security", Severity.MEDIUM,
              "Cloud Run accepts all internet traffic",
              "Ingress-all allows requests from the whole internet.",
              "Restrict ingress to internal/LB traffic.",
              cr_ingress),
        Check("GCP-MEM-001", "gcp", "Memorystore", "Network Security", Severity.HIGH,
              "Memorystore transit encryption disabled",
              "Traffic to the cache is plaintext without TLS.",
              "Enable transit encryption (SERVER_AUTHENTICATION).",
              mem_transit),
        Check("GCP-MEM-002", "gcp", "Memorystore", "Identity & Access", Severity.MEDIUM,
              "Memorystore AUTH disabled",
              "Without AUTH, reachable clients can read/write cache data.",
              "Enable AUTH with a strong password or IAM auth.",
              mem_auth),
        Check("GCP-MEM-003", "gcp", "Memorystore", "Network Security", Severity.MEDIUM,
              "Memorystore instance has public IP",
              "Public IPs expose the cache beyond the VPC.",
              "Use Private Service Connect / VPC peering with private IPs.",
              mem_private),
        Check("GCP-CMP-004", "gcp", "Compute", "Compute", Severity.MEDIUM,
              "Serial port access enabled",
              "The interactive serial console bypasses OS-level auth and is a "
              "common takeover vector.",
              "Disable serial-port-enable metadata on instances.",
              serial_port),
        Check("GCP-CMP-005", "gcp", "Compute", "Data Protection", Severity.LOW,
              "Confidential computing not enabled",
              "Memory of the instance is not encrypted in use.",
              "Enable confidential computing on sensitive workloads.",
              confidential),
        Check("GCP-ST-007", "gcp", "Cloud Storage", "Logging & Monitoring", Severity.MEDIUM,
              "Bucket access logging disabled",
              "Without access logs, object-level activity cannot be audited.",
              "Enable access logging to a dedicated log bucket.",
              bucket_logging),
        Check("GCP-IAM-006", "gcp", "IAM", "Identity & Access", Severity.HIGH,
              "Primitive role assigned to a service account",
              "Owner/Editor on service accounts grants broad control with "
              "machine-speed credentials.",
              "Replace primitive roles with least-privilege roles.",
              primitive_sa),
    ]


# --------------------------------------------------------------------------- #
# Tranche 3: Cloud Run CPU/max-instances / Artifact Registry / GKE node ops / #
#            instance deletion protection / OS Login / SQL PITR / Memorystore
# --------------------------------------------------------------------------- #
def _gcp_tier3_checks() -> List[Check]:
    def cr_cpu(c, s, _):
        out = []
        for svc in s.get("cloudrun", []):
            if svc.get("cpu_always_allocated"):
                out.append(_f(c, s, f"run:{svc['name']}", Status.FAIL,
                              "CPU is always allocated (throttling disabled); "
                              "billing and attack surface increase."))
        if not out:
            out.append(_f(c, s, "cloud-run", Status.PASS,
                          "All Cloud Run services throttle CPU when idle."))
        return out

    def cr_maxinst(c, s, _):
        out = []
        for svc in s.get("cloudrun", []):
            if svc.get("max_instances", 0) == 0:
                out.append(_f(c, s, f"run:{svc['name']}", Status.FAIL,
                              "Maximum instances is unlimited; a traffic spike "
                              "can scale without bound."))
        if not out:
            out.append(_f(c, s, "cloud-run", Status.PASS,
                          "All Cloud Run services cap max instances."))
        return out

    def ar_public(c, s, _):
        out = []
        for r in s.get("artifact_repos", []):
            if r.get("public"):
                out.append(_f(c, s, f"artifact:{r['name']}", Status.FAIL,
                              "Artifact Registry repository is publicly "
                              "readable."))
        if not out:
            out.append(_f(c, s, "artifact-registry", Status.PASS,
                          "No Artifact Registry repositories are public."))
        return out

    def ar_cmk(c, s, _):
        out = []
        for r in s.get("artifact_repos", []):
            if not r.get("cmk"):
                out.append(_f(c, s, f"artifact:{r['name']}", Status.FAIL,
                              "Repository is not encrypted with a customer-"
                              "managed key."))
        if not out:
            out.append(_f(c, s, "artifact-registry", Status.PASS,
                          "All repositories use CMK encryption."))
        return out

    def gke_upgrade(c, s, _):
        out = []
        for cl in s.get("gke", []):
            if not cl.get("node_auto_upgrade"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Node auto-upgrade is disabled; node OS and "
                              "kubelet fixes are applied late."))
        if not out:
            out.append(_f(c, s, "gke", Status.PASS,
                          "All GKE node pools auto-upgrade."))
        return out

    def gke_repair(c, s, _):
        out = []
        for cl in s.get("gke", []):
            if not cl.get("node_auto_repair"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Node auto-repair is disabled; unhealthy nodes "
                              "are not replaced automatically."))
        if not out:
            out.append(_f(c, s, "gke", Status.PASS,
                          "All GKE node pools auto-repair."))
        return out

    def cmp_deletion(c, s, _):
        out = []
        for i in s.get("instances", []):
            if not i.get("deletion_protection"):
                out.append(_f(c, s, f"vm:{i['name']}", Status.FAIL,
                              "Instance deletion protection is disabled; an "
                              "accidental delete destroys the VM."))
        if not out:
            out.append(_f(c, s, "compute-instances", Status.PASS,
                          "All instances have deletion protection."))
        return out

    def org_oslogin(c, s, _):
        os_login = s.get("org_policies", {}).get("os_login")
        if os_login is None:
            return [_f(c, s, "org-policy", Status.NOT_APPLICABLE,
                       "OS Login constraint could not be verified with the "
                       "current permissions.")]
        if os_login:
            return [_f(c, s, "org-policy", Status.PASS,
                       "OS Login is enforced on instances.")]
        return [_f(c, s, "org-policy", Status.FAIL,
                   "OS Login is not enforced; instances rely on SSH keys "
                   "that are hard to revoke.")]

    def sql_pitr(c, s, _):
        out = []
        for db in s.get("sql", []):
            if not db.get("pitr"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Point-in-time recovery is disabled; data can "
                              "only be restored to the last backup."))
        if not out:
            out.append(_f(c, s, "cloud-sql", Status.PASS,
                          "All Cloud SQL instances enable PITR."))
        return out

    def mem_persistence(c, s, _):
        out = []
        for m in s.get("memorystore", []):
            if not m.get("persistence"):
                out.append(_f(c, s, f"redis:{m['name']}", Status.FAIL,
                              "Persistence is disabled; cached data is lost on "
                              "failover or maintenance."))
        if not out:
            out.append(_f(c, s, "memorystore", Status.PASS,
                          "All Memorystore instances persist data."))
        return out

    return [
        Check("GCP-CR-003", "gcp", "Cloud Run", "Cost & Security Posture", Severity.LOW,
              "Cloud Run CPU throttling disabled",
              "Always-allocated CPU bills continuously and keeps cold-start "
              "surface warm longer.",
              "Re-enable CPU throttling for request-driven services.",
              cr_cpu),
        Check("GCP-CR-004", "gcp", "Cloud Run", "Resilience", Severity.MEDIUM,
              "Cloud Run unlimited max instances",
              "Unlimited scaling can exhaust quota and inflate cost during "
              "traffic spikes.",
              "Set a maximum instance count per service.",
              cr_maxinst),
        Check("GCP-AR-001", "gcp", "Artifact Registry", "Network Security", Severity.HIGH,
              "Artifact Registry repository public",
              "Public repositories expose container images and packages to "
              "anyone.",
              "Remove allUsers/allAuthenticatedUsers from repository IAM.",
              ar_public),
        Check("GCP-AR-002", "gcp", "Artifact Registry", "Data Protection", Severity.LOW,
              "Artifact Registry without CMK",
              "Platform-managed keys give less key control for artifacts.",
              "Configure a customer-managed encryption key.",
              ar_cmk),
        Check("GCP-GKE-008", "gcp", "GKE", "Kubernetes", Severity.MEDIUM,
              "GKE node auto-upgrade disabled",
              "Without auto-upgrade, nodes miss OS and kubelet security "
              "fixes.",
              "Enable node auto-upgrade on all node pools.",
              gke_upgrade),
        Check("GCP-GKE-009", "gcp", "GKE", "Kubernetes", Severity.MEDIUM,
              "GKE node auto-repair disabled",
              "Unhealthy nodes are not replaced automatically, prolonging "
              "outages.",
              "Enable node auto-repair on all node pools.",
              gke_repair),
        Check("GCP-CMP-006", "gcp", "Compute", "Data Protection", Severity.MEDIUM,
              "Instance deletion protection disabled",
              "Without deletion protection, an accidental delete destroys the "
              "instance and its disks.",
              "Enable deletion protection on production instances.",
              cmp_deletion),
        Check("GCP-ORG-003", "gcp", "Organization Policies", "Identity & Access", Severity.HIGH,
              "OS Login not enforced",
              "SSH key-based access cannot be centrally revoked when staff "
              "leave.",
              "Enforce the compute.requireOsLogin organization constraint.",
              org_oslogin, cis="CIS GCP 4.7"),
        Check("GCP-SQL-006", "gcp", "Cloud SQL", "Backup & Recovery", Severity.MEDIUM,
              "Cloud SQL point-in-time recovery disabled",
              "Without PITR, restoration is limited to the latest backup.",
              "Enable point-in-time recovery in backup configuration.",
              sql_pitr),
        Check("GCP-MEM-004", "gcp", "Memorystore", "Backup & Recovery", Severity.LOW,
              "Memorystore persistence disabled",
              "Non-persistent instances lose cached data on failover.",
              "Enable RDB/AOF persistence on production caches.",
              mem_persistence),
    ]


# --------------------------------------------------------------------------- #
# Tranche 4: Cloud Functions / Cloud VPN / Workload Identity pools /          #
#            firewall logging / GKE binary auth / Cloud Run VPC
# --------------------------------------------------------------------------- #
def _gcp_tier4_checks() -> List[Check]:
    def func_unauth(c, s, _):
        out = []
        for fn in s.get("functions", []):
            if fn.get("unauthenticated"):
                out.append(_f(c, s, f"fn:{fn['name']}", Status.FAIL,
                              "Cloud Function is publicly invokable by any "
                              "caller."))
        if not out:
            out.append(_f(c, s, "cloud-functions", Status.PASS,
                          "No Cloud Functions allow unauthenticated invoke."))
        return out

    def func_vpc(c, s, _):
        out = []
        for fn in s.get("functions", []):
            if not fn.get("vpc_connector"):
                out.append(_f(c, s, f"fn:{fn['name']}", Status.FAIL,
                              "Cloud Function has no VPC connector; it cannot "
                              "reach private resources securely."))
        if not out:
            out.append(_f(c, s, "cloud-functions", Status.PASS,
                          "All Cloud Functions use a VPC connector."))
        return out

    def vpn_ike(c, s, _):
        out = []
        for t in s.get("vpn_tunnels", []):
            if t.get("ike_version") == 1:
                out.append(_f(c, s, f"vpn:{t['name']}", Status.FAIL,
                              "Tunnel uses IKEv1; the deprecated protocol is "
                              "weaker and unsupported for new use."))
        if not out:
            out.append(_f(c, s, "cloud-vpn", Status.PASS,
                          "All VPN tunnels use IKEv2."))
        return out

    def wi_pool(c, s, _):
        out = []
        for p in s.get("wipools", []):
            if p.get("providers", 0) == 0:
                out.append(_f(c, s, f"wipool:{p['name']}", Status.FAIL,
                              "Workload identity pool has no OIDC/JWT provider; "
                              "external federation cannot be trusted."))
        if not out:
            out.append(_f(c, s, "workload-identity", Status.PASS,
                          "All workload identity pools have providers."))
        return out

    def fw_logging(c, s, _):
        out = []
        for f in s.get("firewalls", []):
            if not f.get("disabled") and not f.get("logging"):
                out.append(_f(c, s, f"fw:{f['name']}", Status.FAIL,
                              "Firewall rule logging is disabled; denied/allowed "
                              "traffic is not recorded."))
        if not out:
            out.append(_f(c, s, "firewalls", Status.PASS,
                          "All active firewall rules log traffic."))
        return out

    def gke_binauth(c, s, _):
        out = []
        for cl in s.get("gke", []):
            if not cl.get("binary_authorization"):
                out.append(_f(c, s, f"gke:{cl['name']}", Status.FAIL,
                              "Binary Authorization is disabled; unsigned or "
                              "malicious images can be deployed."))
        if not out:
            out.append(_f(c, s, "gke", Status.PASS,
                          "All GKE clusters enforce Binary Authorization."))
        return out

    def cr_vpc(c, s, _):
        out = []
        for svc in s.get("cloudrun", []):
            if not svc.get("vpc_connector"):
                out.append(_f(c, s, f"run:{svc['name']}", Status.FAIL,
                              "Cloud Run service has no VPC connector; it cannot "
                              "reach private resources securely."))
        if not out:
            out.append(_f(c, s, "cloud-run", Status.PASS,
                          "All Cloud Run services use a VPC connector."))
        return out

    return [
        Check("GCP-FUNC-001", "gcp", "Cloud Functions", "Network Security", Severity.HIGH,
              "Cloud Function publicly invokable",
              "Anonymous callers can invoke the function, incurring cost and "
              "exposing logic.",
              "Require authentication on the function trigger.",
              func_unauth),
        Check("GCP-FUNC-002", "gcp", "Cloud Functions", "Network Security", Severity.MEDIUM,
              "Cloud Function without VPC connector",
              "Functions without a connector cannot reach private resources "
              "without exposing them.",
              "Attach a VPC connector for private resource access.",
              func_vpc),
        Check("GCP-VPN-001", "gcp", "Cloud VPN", "Network Security", Severity.MEDIUM,
              "VPN tunnel using IKEv1",
              "IKEv1 is deprecated and weaker than IKEv2 for tunnel security.",
              "Recreate tunnels with IKEv2.",
              vpn_ike),
        Check("GCP-WI-001", "gcp", "Workload Identity", "Identity & Access", Severity.MEDIUM,
              "Workload identity pool without provider",
              "A pool with no provider cannot establish trust for external "
              "workloads, indicating a broken or half-configured federation.",
              "Add an OIDC/JWT provider to the pool or remove it.",
              wi_pool),
        Check("GCP-NET-003", "gcp", "VPC Network", "Logging & Monitoring", Severity.MEDIUM,
              "VPC firewall logging disabled",
              "Without firewall logs, rejected/allowed traffic cannot be "
              "audited.",
              "Enable firewall rule logging for production rules.",
              fw_logging),
        Check("GCP-GKE-010", "gcp", "GKE", "Kubernetes", Severity.MEDIUM,
              "GKE Binary Authorization disabled",
              "Without Binary Authorization, images are not verified before "
              "deploy.",
              "Enable Binary Authorization (GKE default deny) on clusters.",
              gke_binauth),
        Check("GCP-CR-005", "gcp", "Cloud Run", "Network Security", Severity.MEDIUM,
              "Cloud Run without VPC connector",
              "Services cannot reach private resources without a connector.",
              "Attach a VPC connector to the service.",
              cr_vpc),
    ]


# --------------------------------------------------------------------------- #
# Vertex AI + Pub/Sub (unique coverage: ML platform security + message security)
# --------------------------------------------------------------------------- #
def _gcp_edge_checks() -> List[Check]:
    def va_public(c, s, _):
        out = []
        for nb in s.get("vertex_ai", {}).get("notebooks", []):
            if nb.get("external_ip"):
                out.append(_f(c, s, f"vertex-notebook:{nb['name']}", Status.FAIL,
                              "Vertex AI notebook has a public external IP; "
                              "Jupyter access and the instance are reachable "
                              "from the internet."))
        if not out:
            out.append(_f(c, s, "vertex-notebooks", Status.PASS,
                          "All Vertex AI notebooks are VPC-only (no external IP)."))
        return out

    def va_cmek(c, s, _):
        out = []
        for nb in s.get("vertex_ai", {}).get("notebooks", []):
            if not nb.get("cmek"):
                out.append(_f(c, s, f"vertex-notebook:{nb['name']}", Status.FAIL,
                              "Vertex AI notebook disks are not encrypted with "
                              "a customer-managed key (CMEK)."))
        if not out:
            out.append(_f(c, s, "vertex-notebooks", Status.PASS,
                          "All Vertex AI notebooks use CMEK encryption."))
        return out

    def ps_cmek(c, s, _):
        out = []
        for topic in s.get("pubsub", []):
            if not topic.get("cmek"):
                out.append(_f(c, s, f"pubsub:{topic['name']}", Status.FAIL,
                              "Pub/Sub topic is not encrypted with a "
                              "customer-managed key (CMEK); message data is "
                              "protected only by Google-managed keys."))
        if not out:
            out.append(_f(c, s, "pubsub-topics", Status.PASS,
                          "All Pub/Sub topics are CMEK-encrypted."))
        return out

    return [
        Check("GCP-VA-001", "gcp", "Vertex AI", "Network Security", Severity.HIGH,
              "Vertex AI notebook with public external IP",
              "A notebook with a public IP exposes JupyterLab and the VM to "
              "the internet; a stolen notebook credential becomes remote code "
              "execution on your ML estate.",
              "Create notebooks in a VPC with no external IP; access via IAP "
              "or a bastion host.",
              va_public),
        Check("GCP-VA-002", "gcp", "Vertex AI", "Data Protection", Severity.MEDIUM,
              "Vertex AI notebook without CMEK",
              "Notebook and model artifacts at rest are encrypted with "
              "Google-managed keys only, outside your key control.",
              "Attach a customer-managed encryption key (CMEK) when creating "
              "the notebook instance.",
              va_cmek),
        Check("GCP-PS-001", "gcp", "Pub/Sub", "Data Protection", Severity.MEDIUM,
              "Pub/Sub topic not CMEK-encrypted",
              "Messages at rest are encrypted with Google-managed keys only; "
              "for regulated data you need your own key.",
              "Enable customer-managed encryption (CMEK) on the topic at "
              "creation time.",
              ps_cmek),
    ]


def get_checks() -> List[Check]:
    return (_gcp_iam_checks() + _gcp_storage_checks() + _gcp_misc_checks()
            + _gcp_hardening_checks() + _gcp_tier2_checks() + _gcp_tier3_checks()
            + _gcp_tier4_checks() + _gcp_edge_checks())
