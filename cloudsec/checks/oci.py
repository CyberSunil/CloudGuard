"""OCI configuration review checks.

Snapshot layout:
{
  "tenancy": str, "principal": str,
  "users": [{name, mfa_enabled, has_console_password, api_keys}],
  "policies": [{name, statements, broad_manage}],
  "buckets": [{name, public_type, versioning, cmk}],
  "sec_lists": [{id, name, ingress: [{proto, src, ports}], open_ports}],
  "nsgs": [{id, name, open_ingress, referenced}],
  "volumes": [{id, name, type, cmk}],
  "adbs": [{name, public_endpoint, cmk}],
  "keys": [{key, rotation_enabled}],
  "cloud_guard": {"enabled": bool},
  "subnets": [{name, flow_log_enabled}],
}
"""
from __future__ import annotations

from typing import Dict, List

from ..models import Check, Finding, Severity, Status

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


def _sl_open_ports(rules: List[dict]) -> List[int]:
    out: List[int] = []
    for r in rules:
        if r.get("src") not in ("0.0.0.0/0", "::/0"):
            continue
        proto = r.get("proto", "").lower()
        if proto in ("icmp",):
            continue
        ports = r.get("ports")  # None => all protocols/ports
        if ports is None:
            out.extend(OPEN_PORTS)
            continue
        lo, hi = ports
        for p in OPEN_PORTS + [80, 443, 3306, 5432, 6379, 9200]:
            if lo <= p <= hi and p not in out:
                out.append(p)
    return out


# --------------------------------------------------------------------------- #
# IAM / policies
# --------------------------------------------------------------------------- #
def _oci_iam_checks() -> List[Check]:
    def user_mfa(c, s, _):
        out = []
        for u in s["users"]:
            if u.get("has_console_password") and not u.get("mfa_enabled"):
                out.append(_f(c, s, f"user:{u['name']}", Status.FAIL,
                              "Console user does not have MFA enrolled."))
        if not out:
            out.append(_f(c, s, "iam-users", Status.PASS,
                          "All console users have MFA enrolled."))
        return out

    def user_api_keys(c, s, _):
        out = []
        for u in s["users"]:
            n = u.get("api_keys", 0)
            if n > 0:
                out.append(_f(c, s, f"user:{u['name']}", Status.FAIL,
                              f"User has {n} long-lived API signing key(s).",
                              evidence={"api_keys": n}))
        if not out:
            out.append(_f(c, s, "iam-users", Status.PASS,
                          "No users hold API signing keys."))
        return out

    def broad_policies(c, s, _):
        out = []
        for p in s["policies"]:
            if p.get("broad_manage"):
                out.append(_f(c, s, f"policy:{p['name']}", Status.FAIL,
                              "Policy contains statements granting manage "
                              "all-resources (tenancy/root compartment)."))
        if not out:
            out.append(_f(c, s, "iam-policies", Status.PASS,
                          "No broad manage-all-resources policies found."))
        return out

    return [
        Check("OCI-IAM-001", "oci", "IAM", "Identity & Access", Severity.HIGH,
              "OCI user without MFA",
              "Console users without MFA are vulnerable to credential phishing "
              "and password reuse.",
              "Enforce MFA for all console users via the Identity policy "
              "'mfa-totp' and group policy.",
              user_mfa, cis="CIS OCI 1.7"),
        Check("OCI-IAM-002", "oci", "IAM", "Identity & Access", Severity.LOW,
              "User holds long-lived API signing keys",
              "API keys never expire; a leaked key grants access until revoked.",
              "Use instance principals / resource principals and rotate keys "
              "regularly.",
              user_api_keys, cis="CIS OCI 1.8"),
        Check("OCI-IAM-003", "oci", "IAM", "Identity & Access", Severity.CRITICAL,
              "IAM policy grants broad manage all-resources",
              "Statements like 'Allow group X to manage all-resources in "
              "tenancy' grant total control and violate least privilege.",
              "Scope policies to compartments and specific resource-types; "
              "audit with Policy Analyzer.",
              broad_policies, cis="CIS OCI 1.2"),
    ]


# --------------------------------------------------------------------------- #
# Object Storage
# --------------------------------------------------------------------------- #
def _oci_storage_checks() -> List[Check]:
    def public(c, s, _):
        out = []
        for b in s["buckets"]:
            pt = b.get("public_type")
            if pt in ("ObjectRead", "ObjectReadWithoutList"):
                out.append(_f(c, s, f"oci://{b['name']}", Status.FAIL,
                              f"Bucket is publicly readable (public access type: "
                              f"{pt})."))
        if not out:
            out.append(_f(c, s, "object-storage", Status.PASS,
                          "No buckets are publicly readable."))
        return out

    def versioning(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("versioning"):
                out.append(_f(c, s, f"oci://{b['name']}", Status.FAIL,
                              "Bucket versioning is disabled."))
        if not out:
            out.append(_f(c, s, "object-storage", Status.PASS,
                          "All buckets have versioning enabled."))
        return out

    def cmk(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("cmk"):
                out.append(_f(c, s, f"oci://{b['name']}", Status.FAIL,
                              "Bucket uses Oracle-managed keys, not a Vault "
                              "customer key."))
        if not out:
            out.append(_f(c, s, "object-storage", Status.PASS,
                          "All buckets use customer-managed Vault keys."))
        return out

    return [
        Check("OCI-OS-001", "oci", "Object Storage", "Storage & Data Protection", Severity.CRITICAL,
              "Bucket publicly readable",
              "Public object storage exposes data to anonymous users.",
              "Set public access type to NoPublicAccess and review bucket "
              "policies.",
              public, cis="CIS OCI 4.1"),
        Check("OCI-OS-002", "oci", "Object Storage", "Backup & Recovery", Severity.MEDIUM,
              "Bucket versioning disabled",
              "Versioning protects object data from accidental deletion and "
              "overwrites.",
              "Enable versioning on buckets holding mutable data.",
              versioning),
        Check("OCI-OS-003", "oci", "Object Storage", "Data Protection", Severity.LOW,
              "Bucket not using customer-managed encryption key",
              "Vault customer keys provide key lifecycle control.",
              "Encrypt buckets with a Vault-managed key where required.",
              cmk),
    ]


# --------------------------------------------------------------------------- #
# Network / storage volumes / databases / KMS / security services
# --------------------------------------------------------------------------- #
def _oci_misc_checks() -> List[Check]:
    def sl_open(c, s, _):
        out = []
        for sl in s["sec_lists"]:
            ports = _sl_open_ports(sl.get("ingress", []))
            if ports:
                out.append(_f(c, s, f"seclist:{sl['name']}", Status.FAIL,
                              "Security list exposes ports "
                              f"{sorted(set(ports))} to 0.0.0.0/0.",
                              {"open_ports": sorted(set(ports))}))
        if not out:
            out.append(_f(c, s, "security-lists", Status.PASS,
                          "No security lists expose management ports to the "
                          "internet."))
        return out

    def nsg_open(c, s, _):
        out = []
        for n in s["nsgs"]:
            if n.get("open_ingress"):
                out.append(_f(c, s, f"nsg:{n['name']}", Status.FAIL,
                              "NSG contains an ingress rule open to 0.0.0.0/0 on "
                              "management ports."))
        if not out:
            out.append(_f(c, s, "network-security-groups", Status.PASS,
                          "No NSGs expose management ports to the internet."))
        return out

    def volume_cmk(c, s, _):
        out = []
        for v in s["volumes"]:
            if not v.get("cmk"):
                out.append(_f(c, s, f"volume:{v['name']}", Status.FAIL,
                              f"{v['type'].title()} volume uses Oracle-managed "
                              "encryption keys, not a customer-managed Vault key."))
        if not out:
            out.append(_f(c, s, "block-storage", Status.PASS,
                          "All volumes use customer-managed Vault keys."))
        return out

    def adb_public(c, s, _):
        out = []
        for a in s["adbs"]:
            if a.get("public_endpoint"):
                out.append(_f(c, s, f"adb:{a['name']}", Status.FAIL,
                              "Autonomous Database uses a public endpoint."))
        if not out:
            out.append(_f(c, s, "autonomous-db", Status.PASS,
                          "No Autonomous Databases use public endpoints."))
        return out

    def adb_cmk(c, s, _):
        out = []
        for a in s["adbs"]:
            if not a.get("cmk"):
                out.append(_f(c, s, f"adb:{a['name']}", Status.FAIL,
                              "ADB uses Oracle-managed keys (not customer-managed "
                              "Vault keys)."))
        if not out:
            out.append(_f(c, s, "autonomous-db", Status.PASS,
                          "All ADBs use customer-managed keys."))
        return out

    def key_rotation(c, s, _):
        out = []
        for k in s["keys"]:
            if not k.get("rotation_enabled"):
                out.append(_f(c, s, f"key:{k['key']}", Status.FAIL,
                              "Vault key rotation is disabled (or no rotation "
                              "schedule)."))
        if not out:
            out.append(_f(c, s, "vault-keys", Status.PASS,
                          "All Vault keys have rotation enabled."))
        return out

    def cloud_guard(c, s, _):
        if s["cloud_guard"].get("enabled"):
            return [_f(c, s, "cloud-guard", Status.PASS,
                       "Cloud Guard is enabled with a target in the tenancy.")]
        return [_f(c, s, "cloud-guard", Status.FAIL,
                   "Cloud Guard is not enabled (or has no target).")]

    def flow_logs(c, s, _):
        out = []
        for sub in s["subnets"]:
            if not sub.get("flow_log_enabled"):
                out.append(_f(c, s, f"subnet:{sub['name']}", Status.FAIL,
                              "VCN flow logging is not enabled on this subnet."))
        if not out:
            out.append(_f(c, s, "subnets", Status.PASS,
                          "All subnets have VCN flow logging enabled."))
        return out

    return [
        Check("OCI-NET-001", "oci", "VCN/Security Lists", "Network Security", Severity.CRITICAL,
              "Security list exposes management ports to the internet",
              "0.0.0.0/0 ingress on 22/3389 exposes compute instances to "
              "internet brute force.",
              "Restrict security list ingress to trusted CIDRs; use OCI Bastion "
              "service for SSH.",
              sl_open, cis="CIS OCI 2.1 / 2.2"),
        Check("OCI-NET-002", "oci", "VCN/NSG", "Network Security", Severity.HIGH,
              "NSG allows open ingress to management ports",
              "NSG rules open to the internet bypass the intent of network "
              "segmentation.",
              "Scope NSG ingress rules to specific source CIDRs and ports.",
              nsg_open, cis="CIS OCI 2.3 / 2.4"),
        Check("OCI-BV-001", "oci", "Block Storage", "Data Protection", Severity.LOW,
              "Volume not encrypted with customer-managed key",
              "Customer-managed Vault keys give control over key lifecycle.",
              "Encrypt volumes with a Vault customer key where compliance "
              "requires it.",
              volume_cmk),
        Check("OCI-DB-001", "oci", "Autonomous Database", "Database", Severity.HIGH,
              "Autonomous Database uses a public endpoint",
              "Public endpoints expose databases to the internet; access "
              "control relies on network security lists alone.",
              "Disable public access and use private endpoints / private DNS.",
              adb_public),
        Check("OCI-DB-002", "oci", "Autonomous Database", "Data Protection", Severity.LOW,
              "ADB not using customer-managed encryption key",
              "Customer-managed keys satisfy stricter key-control compliance.",
              "Associate a Vault master key with the database.",
              adb_cmk),
        Check("OCI-KMS-001", "oci", "Vault", "Key Management", Severity.MEDIUM,
              "Vault key rotation disabled",
              "Keys that never rotate increase the impact of compromise.",
              "Enable key rotation (min 90 days, or use versioned keys).",
              key_rotation, cis="CIS OCI 3.16"),
        Check("OCI-CG-001", "oci", "Cloud Guard", "Security Posture", Severity.HIGH,
              "Cloud Guard not enabled",
              "OCI's native CSPM service detects misconfigurations and threats; "
              "leaving it off removes continuous visibility.",
              "Enable Cloud Guard with a tenancy-level target and responder "
              "rules.",
              cloud_guard, cis="CIS OCI 3.15"),
        Check("OCI-NET-003", "oci", "VCN/Subnets", "Logging & Monitoring", Severity.MEDIUM,
              "VCN flow logging disabled",
              "Flow logs provide network traffic visibility for detection and "
              "forensics.",
              "Enable flow logs on all subnets and ship to a log group.",
              flow_logs, cis="CIS OCI 3.14"),
    ]


# --------------------------------------------------------------------------- #
# Hardening: MFA policy / PARs / IGW / LB / backups / Bastion / data guard
# --------------------------------------------------------------------------- #
def _oci_hardening_checks() -> List[Check]:
    def mfa_policy(c, s, _):
        stmts = " ".join(st.lower() for p in s["policies"] for st in p["statements"])
        if "mfa" in stmts:
            return [_f(c, s, "iam-policies", Status.PASS,
                       "An IAM policy enforces MFA (mfa-totp) for access.")]
        return [_f(c, s, "iam-policies", Status.FAIL,
                   "No IAM policy enforces MFA; console and API access can "
                   "proceed without it.")]

    def tenancy_scope(c, s, _):
        out = []
        for p in s["policies"]:
            if any(" tenancy" in st.lower() for st in p["statements"]):
                out.append(_f(c, s, f"policy:{p['name']}", Status.FAIL,
                              "Policy statement is scoped to the tenancy root "
                              "compartment - applies to every compartment."))
        if not out:
            out.append(_f(c, s, "iam-policies", Status.PASS,
                          "No policies grant access at tenancy root scope."))
        return out

    def nsg_unreferenced(c, s, _):
        out = []
        for n in s["nsgs"]:
            if not n.get("referenced", True):
                out.append(_f(c, s, f"nsg:{n['name']}", Status.FAIL,
                              "NSG is not referenced by any resource; it provides "
                              "no protection."))
        if not out:
            out.append(_f(c, s, "network-security-groups", Status.PASS,
                          "All NSGs are referenced by resources."))
        return out

    def par(c, s, _):
        out = []
        for b in s["buckets"]:
            n = b.get("par_count", 0)
            if n > 0:
                out.append(_f(c, s, f"oci://{b['name']}", Status.FAIL,
                              f"Bucket has {n} active pre-authenticated request(s) "
                              "- time-bound URLs that bypass IAM.",
                              evidence={"par_count": n}))
        if not out:
            out.append(_f(c, s, "object-storage", Status.PASS,
                          "No buckets have active PARs."))
        return out

    def igw(c, s, _):
        out = []
        for g in s.get("igws", []):
            if g.get("enabled"):
                out.append(_f(c, s, f"igw:{g['name']}", Status.FAIL,
                              "Enabled internet gateway provides direct public "
                              "routing for the VCN."))
        if not out:
            out.append(_f(c, s, "internet-gateways", Status.PASS,
                          "No enabled internet gateways found."))
        return out

    def lb_ssl(c, s, _):
        out = []
        for lb in s.get("lbs", []):
            if not lb.get("ssl_listener"):
                out.append(_f(c, s, f"lb:{lb['name']}", Status.FAIL,
                              "Load balancer has no listener with SSL/TLS; "
                              "traffic is plaintext."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "All load balancers terminate TLS."))
        return out

    def lb_public(c, s, _):
        out = []
        for lb in s.get("lbs", []):
            if lb.get("public"):
                out.append(_f(c, s, f"lb:{lb['name']}", Status.FAIL,
                              "Load balancer has a public IP; consider private "
                              "LB behind a WAF/bastion."))
        if not out:
            out.append(_f(c, s, "load-balancers", Status.PASS,
                          "No public load balancers."))
        return out

    def volume_backups(c, s, _):
        out = []
        for v in s["volumes"]:
            if v.get("backup_count", 0) == 0:
                out.append(_f(c, s, f"volume:{v['name']}", Status.FAIL,
                              "Volume has no backups configured; data loss "
                              "cannot be recovered."))
        if not out:
            out.append(_f(c, s, "block-storage", Status.PASS,
                          "All volumes have backups."))
        return out

    def bastion(c, s, _):
        if s["bastion"].get("exists"):
            return [_f(c, s, "bastion", Status.PASS,
                       "A Bastion service is deployed.")]
        return [_f(c, s, "bastion", Status.FAIL,
                   "No Bastion service; SSH/RDP to compute is likely exposed "
                   "via public ingress.")]

    def data_guard(c, s, _):
        out = []
        for a in s["adbs"]:
            if not a.get("data_guard"):
                out.append(_f(c, s, f"adb:{a['name']}", Status.FAIL,
                              "Autonomous Data Guard is not enabled; no "
                              "cross-region failover for the database."))
        if not out:
            out.append(_f(c, s, "autonomous-db", Status.PASS,
                          "All ADBs use Autonomous Data Guard."))
        return out

    def cloud_guard_detectors(c, s, _):
        n = s["cloud_guard"].get("detectors_enabled", 0)
        if n > 0:
            return [_f(c, s, "cloud-guard", Status.PASS,
                       f"Cloud Guard has {n} detector recipe(s) active.")]
        return [_f(c, s, "cloud-guard", Status.FAIL,
                   "Cloud Guard has no detector recipes active; misconfigurations "
                   "and threats are not detected.")]

    return [
        Check("OCI-IAM-004", "oci", "IAM", "Identity & Access", Severity.HIGH,
              "No MFA enforcement policy",
              "Without an mfa-totp policy, console and API access relies on "
              "passwords and API keys alone.",
              "Add an identity policy enforcing MFA for all users/groups.",
              mfa_policy, cis="CIS OCI 1.7"),
        Check("OCI-IAM-005", "oci", "IAM", "Identity & Access", Severity.MEDIUM,
              "IAM policy scoped to tenancy root",
              "Tenancy-scoped grants apply to every compartment; a single "
              "compromise has full blast radius.",
              "Scope policies to compartments and specific resource-types.",
              tenancy_scope, cis="CIS OCI 1.2"),
        Check("OCI-NET-007", "oci", "VCN/NSG", "Network Security", Severity.LOW,
              "NSG not referenced by any resource",
              "Unreferenced NSGs give a false sense of segmentation.",
              "Attach the NSG to the intended resources or delete it.",
              nsg_unreferenced),
        Check("OCI-OS-004", "oci", "Object Storage", "Network Security", Severity.HIGH,
              "Bucket has active pre-authenticated requests",
              "PARs create time-bound URLs that bypass IAM; forgotten PARs "
              "silently expose objects.",
              "List and revoke unused PARs; prefer signed URLs issued on demand.",
              par),
        Check("OCI-NET-004", "oci", "VCN", "Network Security", Severity.LOW,
              "Internet gateway enabled",
              "Internet gateways provide direct public routing; verify every "
              "one is intended.",
              "Disable internet gateways not required and route egress through "
              "NAT.",
              igw),
        Check("OCI-NET-005", "oci", "Load Balancer", "Network Security", Severity.HIGH,
              "Load balancer without SSL listener",
              "Plaintext listeners expose credentials and traffic.",
              "Terminate TLS on all listeners and redirect HTTP to HTTPS.",
              lb_ssl),
        Check("OCI-NET-006", "oci", "Load Balancer", "Network Security", Severity.MEDIUM,
              "Load balancer is public",
              "Public load balancers expose the data plane to the internet.",
              "Use private load balancers behind WAF where possible.",
              lb_public),
        Check("OCI-BV-002", "oci", "Block Storage", "Backup & Recovery", Severity.MEDIUM,
              "Volume has no backups",
              "Without backups, volume data is unrecoverable after loss or "
              "ransomware.",
              "Configure automatic or policy-based backups for all volumes.",
              volume_backups),
        Check("OCI-BST-001", "oci", "Bastion", "Network Security", Severity.MEDIUM,
              "No Bastion service deployed",
              "Without OCI Bastion, management access typically uses public "
              "SSH/RDP ingress.",
              "Deploy the Bastion service and remove public management ingress.",
              bastion),
        Check("OCI-DB-003", "oci", "Autonomous Database", "Backup & Recovery", Severity.LOW,
              "Autonomous Data Guard disabled",
              "Without Data Guard there is no cross-region failover for the "
              "database.",
              "Enable Autonomous Data Guard for production databases.",
              data_guard),
        Check("OCI-CG-002", "oci", "Cloud Guard", "Security Posture", Severity.MEDIUM,
              "No Cloud Guard detector recipes active",
              "Detector recipes power Cloud Guard's misconfiguration and "
              "threat detections.",
              "Enable managed detector recipes and attach them to targets.",
              cloud_guard_detectors, cis="CIS OCI 3.15"),
    ]


# --------------------------------------------------------------------------- #
# Tranche 2: File Storage / OSMS / lifecycle / replicas / route tables / NAT
# --------------------------------------------------------------------------- #
def _oci_tier2_checks() -> List[Check]:
    def fs_cmk(c, s, _):
        out = []
        for f in s.get("filesystems", []):
            if not f.get("cmk"):
                out.append(_f(c, s, f"fs:{f['name']}", Status.FAIL,
                              "File system uses Oracle-managed keys, not a Vault "
                              "customer key."))
        if not out:
            out.append(_f(c, s, "file-storage", Status.PASS,
                          "All file systems use customer-managed keys."))
        return out

    def fs_snapshots(c, s, _):
        out = []
        for f in s.get("filesystems", []):
            if f.get("snapshots", 0) == 0:
                out.append(_f(c, s, f"fs:{f['name']}", Status.FAIL,
                              "File system has no snapshots; data cannot be "
                              "rolled back."))
        if not out:
            out.append(_f(c, s, "file-storage", Status.PASS,
                          "All file systems have snapshots."))
        return out

    def osms(c, s, _):
        n = s.get("osms", {}).get("managed_instances", 0)
        if n > 0:
            return [_f(c, s, "osms", Status.PASS,
                       f"OS Management Service manages {n} instance(s).")]
        return [_f(c, s, "osms", Status.FAIL,
                   "No instances are managed by OS Management Service; patch "
                   "and vulnerability compliance is not tracked.")]

    def lifecycle(c, s, _):
        out = []
        for b in s["buckets"]:
            if not b.get("lifecycle_policy"):
                out.append(_f(c, s, f"oci://{b['name']}", Status.FAIL,
                              "Bucket has no lifecycle policy; stale objects "
                              "accumulate."))
        if not out:
            out.append(_f(c, s, "object-storage", Status.PASS,
                          "All buckets have lifecycle policies."))
        return out

    def volume_replica(c, s, _):
        out = []
        for v in s["volumes"]:
            if not v.get("has_replica"):
                out.append(_f(c, s, f"volume:{v['name']}", Status.FAIL,
                              "Volume has no cross-region replica; data is lost "
                              "if the region fails."))
        if not out:
            out.append(_f(c, s, "block-storage", Status.PASS,
                          "All volumes have cross-region replicas."))
        return out

    def public_route(c, s, _):
        out = []
        for rt in s.get("route_tables", []):
            if rt.get("public_default_route"):
                out.append(_f(c, s, f"routetable:{rt['name']}", Status.FAIL,
                              "Route table sends 0.0.0.0/0 to an internet gateway; "
                              "workloads get direct public egress."))
        if not out:
            out.append(_f(c, s, "route-tables", Status.PASS,
                          "No route tables default to an internet gateway."))
        return out

    def nat(c, s, _):
        if s.get("nat_gateways", 0) > 0:
            return [_f(c, s, "nat-gateway", Status.PASS,
                       "A NAT gateway provides controlled egress.")]
        return [_f(c, s, "nat-gateway", Status.FAIL,
                   "No NAT gateway; egress either uses public route tables or "
                   "is unavailable.")]

    return [
        Check("OCI-FS-001", "oci", "File Storage", "Data Protection", Severity.LOW,
              "File system not encrypted with customer-managed key",
              "Oracle-managed keys give less key lifecycle control.",
              "Associate a Vault master key with the file system.",
              fs_cmk),
        Check("OCI-FS-002", "oci", "File Storage", "Backup & Recovery", Severity.MEDIUM,
              "File system has no snapshots",
              "Without snapshots, accidental deletion or ransomware cannot be "
              "rolled back.",
              "Enable automatic snapshots on file systems.",
              fs_snapshots),
        Check("OCI-OSMS-001", "oci", "OS Management", "Security Posture", Severity.MEDIUM,
              "OS Management Service not managing instances",
              "Without OSMS, patch and vulnerability compliance across compute "
              "is not tracked.",
              "Onboard instances to OS Management Service.",
              osms),
        Check("OCI-OS-005", "oci", "Object Storage", "Security Posture", Severity.LOW,
              "Bucket lifecycle policy missing",
              "Stale objects accumulate cost and risk without lifecycle rules.",
              "Define a lifecycle policy to expire/archive objects.",
              lifecycle),
        Check("OCI-BV-003", "oci", "Block Storage", "Backup & Recovery", Severity.LOW,
              "Volume has no cross-region replica",
              "Without replicas, volumes are lost on regional failure.",
              "Create cross-region volume replicas for critical volumes.",
              volume_replica),
        Check("OCI-NET-010", "oci", "VCN/Route Tables", "Network Security", Severity.MEDIUM,
              "Default route targets internet gateway",
              "0.0.0.0/0 to an internet gateway gives direct public egress; "
              "use NAT for controlled egress.",
              "Route default traffic via NAT gateway and restrict IGW routes.",
              public_route),
        Check("OCI-NET-011", "oci", "VCN/NAT", "Network Security", Severity.MEDIUM,
              "No NAT gateway",
              "Without NAT, private workloads either lack egress or must use "
              "public routing.",
              "Deploy a NAT gateway and route egress through it.",
              nat),
    ]


# --------------------------------------------------------------------------- #
# Tranche 3: OSMS patch baselines (instance groups) / audit retention / ADB  #
#            backup retention / PAR expiry / API key age
# --------------------------------------------------------------------------- #
def _oci_tier3_checks() -> List[Check]:
    def osms_groups(c, s, _):
        n = s.get("osms", {}).get("managed_instance_groups", 0)
        if n > 0:
            return [_f(c, s, "osms", Status.PASS,
                       f"{n} OSMS managed instance group(s) provide patch "
                       "baselines.")]
        return [_f(c, s, "osms", Status.FAIL,
                   "No OSMS managed instance groups; instances have no "
                   "scheduled patch baseline.")]

    def audit_retention(c, s, _):
        days = s.get("audit", {}).get("retention_days")
        if days is None:
            return [_f(c, s, "audit", Status.NOT_APPLICABLE,
                       "Audit configuration could not be read with the current "
                       "permissions.")]
        if days >= 90:
            return [_f(c, s, "audit", Status.PASS,
                       f"Audit logs are retained for {days} days.")]
        return [_f(c, s, "audit", Status.FAIL,
                   f"Audit log retention is {days} days (< 90); forensic "
                   "history is lost too early.")]

    def adb_backup(c, s, _):
        out = []
        for db in s.get("adbs", []):
            days = db.get("backup_retention_days", 0)
            if days < 7:
                out.append(_f(c, s, f"adb:{db['name']}", Status.FAIL,
                              f"Backup retention is {days} days (< 7); recovery "
                              "options are limited."))
        if not out:
            out.append(_f(c, s, "autonomous-db", Status.PASS,
                          "All ADBs retain backups >= 7 days."))
        return out

    def par_expiry(c, s, _):
        out = []
        for b in s.get("buckets", []):
            n = b.get("par_no_expiry", 0)
            if n > 0:
                out.append(_f(c, s, f"bucket:{b['name']}", Status.FAIL,
                              f"{n} pre-authenticated request(s) have no "
                              "expiration; temporary access never expires."))
        if not out:
            out.append(_f(c, s, "object-storage", Status.PASS,
                          "All PARs have an expiration."))
        return out

    def api_key_age(c, s, _):
        out = []
        for u in s.get("users", []):
            age = u.get("max_api_key_age", 0)
            if age > 90:
                out.append(_f(c, s, f"user:{u['name']}", Status.FAIL,
                              f"API key is {age} days old (> 90); rotate to "
                              "limit leaked-key blast radius."))
        if not out:
            out.append(_f(c, s, "iam-users", Status.PASS,
                          "All API keys are younger than 90 days."))
        return out

    return [
        Check("OCI-OSMS-002", "oci", "OS Management", "Security Posture", Severity.MEDIUM,
              "No OSMS managed instance groups",
              "Without instance groups, patch baselines cannot be scheduled "
              "and compliance cannot be tracked.",
              "Create OSMS managed instance groups and attach patch baselines.",
              osms_groups),
        Check("OCI-AUDIT-001", "oci", "Audit", "Logging & Monitoring", Severity.MEDIUM,
              "Audit log retention below 90 days",
              "Short audit retention erases the evidence needed for forensic "
              "investigations.",
              "Raise audit retention period to >= 90 days.",
              audit_retention, cis="CIS OCI 3.1"),
        Check("OCI-DB-004", "oci", "Autonomous Database", "Backup & Recovery", Severity.MEDIUM,
              "ADB backup retention below 7 days",
              "Short backup retention limits point-in-time recovery.",
              "Set backup retention to at least 7 days.",
              adb_backup),
        Check("OCI-OS-006", "oci", "Object Storage", "Network Security", Severity.HIGH,
              "Pre-authenticated request without expiration",
              "PARs without expiry leave temporary access open indefinitely.",
              "Set an expiration on every pre-authenticated request.",
              par_expiry),
        Check("OCI-IAM-006", "oci", "IAM", "Identity & Access", Severity.MEDIUM,
              "OCI API key older than 90 days",
              "Long-lived API keys increase the blast radius of leaked "
              "credentials.",
              "Rotate user API keys every 90 days.",
              api_key_age, cis="CIS OCI 1.8"),
    ]


# --------------------------------------------------------------------------- #
# Tranche 4: NoSQL throughput limits / DNS DNSSEC / DB backups / ADB scaling
# --------------------------------------------------------------------------- #
def _oci_tier4_checks() -> List[Check]:
    def nosql_limits(c, s, _):
        out = []
        for t in s.get("nosql_tables", []):
            if not t.get("has_limits"):
                out.append(_f(c, s, f"nosql:{t['name']}", Status.FAIL,
                              "Table has no throughput limits; a traffic spike "
                              "can drive unbounded cost."))
        if not out:
            out.append(_f(c, s, "nosql", Status.PASS,
                          "All NoSQL tables define throughput limits."))
        return out

    def dns_dnssec(c, s, _):
        z = s.get("dns_zones", {})
        if z.get("total", 0) == 0:
            return [_f(c, s, "dns", Status.NOT_APPLICABLE,
                       "No DNS zones to evaluate.")]
        off = z.get("dnssec_off", [])
        if off:
            return [_f(c, s, "dns", Status.FAIL,
                       f"{len(off)}/{z['total']} zone(s) lack DNSSEC: "
                       f"{', '.join(off)}.")]
        return [_f(c, s, "dns", Status.PASS,
                   "All DNS zones have DNSSEC enabled.")]

    def db_backup(c, s, _):
        d = s.get("db_backups", {})
        if d.get("db_systems", 0) == 0:
            return [_f(c, s, "database", Status.NOT_APPLICABLE,
                       "No DB systems to back up.")]
        if d.get("count", 0) > 0:
            return [_f(c, s, "database", Status.PASS,
                       "Database backups are configured.")]
        return [_f(c, s, "database", Status.FAIL,
                   "DB systems exist but no backups are configured; data is "
                   "unprotected against loss.")]

    def adb_scaling(c, s, _):
        out = []
        for db in s.get("adbs", []):
            if not db.get("auto_scaling"):
                out.append(_f(c, s, f"adb:{db['name']}", Status.FAIL,
                              "Auto-scaling is disabled; the database cannot "
                              "grow under load."))
        if not out:
            out.append(_f(c, s, "autonomous-db", Status.PASS,
                          "All ADBs have auto-scaling enabled."))
        return out

    return [
        Check("OCI-NOSQL-001", "oci", "NoSQL Database", "Cost & Resilience", Severity.MEDIUM,
              "NoSQL table without throughput limits",
              "Tables without limits can consume unbounded OCPUs/GB under "
              "load, spiking cost.",
              "Define max read/write throughput on every NoSQL table.",
              nosql_limits),
        Check("OCI-DNS-001", "oci", "DNS", "Network Security", Severity.HIGH,
              "DNS zone without DNSSEC",
              "Zones without DNSSEC are vulnerable to cache poisoning and "
              "DNS hijacking.",
              "Enable DNSSEC on all public DNS zones.",
              dns_dnssec),
        Check("OCI-DB-005", "oci", "Database", "Backup & Recovery", Severity.CRITICAL,
              "DB system without backups",
              "Database backups protect against data loss; none are configured.",
              "Configure automated backups for all DB systems.",
              db_backup),
        Check("OCI-DB-006", "oci", "Autonomous Database", "Resilience", Severity.LOW,
              "ADB auto-scaling disabled",
              "Without auto-scaling the database cannot handle load spikes.",
              "Enable auto-scaling on production ADBs.",
              adb_scaling),
    ]


# --------------------------------------------------------------------------- #
# API Gateway (unique coverage: edge API security for OCI)
# --------------------------------------------------------------------------- #
def _oci_edge_checks() -> List[Check]:
    def agw_waf(c, s, _):
        out = []
        for gw in s.get("api_gateways", []):
            if not gw.get("waf"):
                out.append(_f(c, s, f"apigateway:{gw['name']}", Status.FAIL,
                              "API Gateway has no OCI WAF policy attached; "
                              "API traffic is not filtered for common "
                              "web attacks."))
        if not out:
            out.append(_f(c, s, "api-gateways", Status.PASS,
                          "All API gateways have a WAF policy attached."))
        return out

    def agw_tls(c, s, _):
        out = []
        for gw in s.get("api_gateways", []):
            if gw.get("public") and not gw.get("tls"):
                out.append(_f(c, s, f"apigateway:{gw['name']}", Status.FAIL,
                              "Public API Gateway endpoint does not enforce a "
                              "TLS/HTTPS certificate; clients can fall back to "
                              "plaintext."))
        if not out:
            out.append(_f(c, s, "api-gateways", Status.PASS,
                          "All public API gateways enforce TLS."))
        return out

    return [
        Check("OCI-AG-001", "oci", "API Gateway", "Security Posture", Severity.MEDIUM,
              "API Gateway without WAF policy",
              "OCI API Gateway is the internet-facing entry for your APIs; "
              "without a Web Application Firewall policy, injection and bot "
              "traffic reach backends unfiltered.",
              "Attach an OCI WAF policy (managed protection rules) to the API "
              "Gateway.",
              agw_waf),
        Check("OCI-AG-002", "oci", "API Gateway", "Network Security", Severity.MEDIUM,
              "Public API Gateway without enforced TLS",
              "A public gateway without a TLS certificate permits plaintext "
              "API calls; credentials and payloads can be intercepted.",
              "Attach a TLS certificate to the gateway's public endpoint and "
              "redirect HTTP to HTTPS.",
              agw_tls),
    ]


def get_checks() -> List[Check]:
    return (_oci_iam_checks() + _oci_storage_checks() + _oci_misc_checks()
            + _oci_hardening_checks() + _oci_tier2_checks() + _oci_tier3_checks()
            + _oci_tier4_checks() + _oci_edge_checks())
