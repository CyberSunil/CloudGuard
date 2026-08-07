"""Azure configuration review checks (native azure-mgmt based; designed to be
far more accurate than ScoutSuite's Azure module).

Snapshot layout:
{
  "subscription_id": str, "principal": str,
  "assignments": [{principal, principal_type, role, scope}],
  "storage": [{name, allow_blob_public_access, min_tls, https_only,
               default_action, cmk}],
  "keyvaults": [{name, soft_delete, purge_protection, default_action}],
  "nsgs": [{name, rules: [{proto, ports, source, direction}], open_ports, associated}],
  "sql": [{name, public_network_access, auditing, tde}],
  "disks": [{name, encryption_type, cmk}],
  "vms": [{name, public_ip, nic_has_nsg}],
  "activity_log": {"diagnostic_count": int},
  "acr": [{name, admin_enabled, public_network_access}],
  "appservices": [{name, https_only}],
  "cosmos": [{name, public_network_access}],
  "aad": {"collected": bool,   # False -> Entra ID checks report NOT_APPLICABLE
          "users": [{upn, mfa_registered, privileged, account_enabled}],
          "ca_policies": [{name, state, require_mfa, block_legacy_auth,
                            include_all_users, risk_based}]},
}
"""
from __future__ import annotations

from typing import Dict, List

from ..models import Check, Finding, Severity, Status

OPEN_PORTS = [22, 3389]


def _f(check: Check, snapshot: dict, resource: str, status: Status,
       detail: str = "", evidence: dict | None = None) -> Finding:
    if not isinstance(status, Status):
        # a Severity was passed by mistake -> treat as a failed finding
        status = Status.FAIL
    return Finding(
        check_id=check.id, check_title=check.title, cloud=check.cloud,
        service=check.service, category=check.category, severity=check.severity,
        status=status, resource=resource, detail=detail,
        remediation=check.remediation, evidence=evidence or {}, cis=check.cis,
    )


def _tls_ok(min_tls) -> bool:
    """True when the storage account requires TLS >= 1.2."""
    if min_tls is None:
        return False
    s = str(min_tls).upper().replace("TLS", "").replace("_", ".")
    try:
        major, minor = s.split(".")[:2]
        return (int(major), int(minor)) >= (1, 2)
    except ValueError:
        return False


def _nsg_open_ports(rules: List[dict]) -> List[int]:
    """Inbound ports exposed to '*' or any public source on common ports."""
    found: List[int] = []
    for r in rules:
        if r.get("direction", "Inbound").lower() != "inbound":
            continue
        source = r.get("source", "")
        if not (source in ("*", "Any", "Internet", "0.0.0.0/0", "::/0")):
            continue
        pr = r.get("ports", "")
        if pr in ("*", "0-65535", "Any"):
            found.extend(OPEN_PORTS)
            continue
        for chunk in str(pr).split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                lo, hi = chunk.split("-")
                try:
                    lo, hi = int(lo), int(hi)
                except ValueError:
                    continue
                for p in OPEN_PORTS + [80, 443, 3306, 5432, 6379, 9200]:
                    if lo <= p <= hi:
                        found.append(p)
            else:
                try:
                    found.append(int(chunk))
                except ValueError:
                    continue
    return found


# --------------------------------------------------------------------------- #
# Identity: Entra ID (Azure AD) MFA + Conditional Access
# --------------------------------------------------------------------------- #
def _az_identity_checks() -> List[Check]:
    def _ctx(s):
        return s.get("aad") or {}

    def _not_collected(c, s):
        return [_f(c, s, "entra-id", Status.NOT_APPLICABLE,
                   "Entra ID (AAD) identity data was not collected. Grant the "
                   "review identity Microsoft Graph scopes - User.Read.All, "
                   "UserAuthenticationMethod.Read.All (or Reports.Read.All), "
                   "RoleManagement.Read.Directory and Policy.Read.All - then "
                   "re-run.")]

    def mfa_all(c, s, _):
        aad = _ctx(s)
        if not aad.get("collected"):
            return _not_collected(c, s)
        out = []
        for u in aad.get("users", []):
            if u.get("account_enabled", True) and not u.get("mfa_registered"):
                out.append(_f(c, s, f"user:{u['upn']}", Status.FAIL,
                              f"User {u['upn']} has no MFA-capable authentication "
                              "method registered; a phished password is enough "
                              "to sign in as them.",
                              evidence={"privileged": bool(u.get("privileged"))}))
        if not out:
            out.append(_f(c, s, "entra-id-users", Status.PASS,
                          "All enabled users have an MFA-capable method registered."))
        return out

    def mfa_privileged(c, s, _):
        aad = _ctx(s)
        if not aad.get("collected"):
            return _not_collected(c, s)
        out = []
        for u in aad.get("users", []):
            if u.get("privileged") and not u.get("mfa_registered"):
                out.append(_f(c, s, f"user:{u['upn']}", Status.FAIL,
                              f"Privileged user {u['upn']} does not have MFA "
                              "enforced - a single credential compromise grants "
                              "elevated access."))
        if not out:
            out.append(_f(c, s, "entra-id-privileged", Status.PASS,
                          "All privileged users have MFA enforced."))
        return out

    def ca_mfa(c, s, _):
        aad = _ctx(s)
        if not aad.get("collected"):
            return _not_collected(c, s)
        active = [p for p in aad.get("ca_policies", []) if p.get("state") == "enabled"]
        enforcing = [p for p in active
                     if p.get("include_all_users") and p.get("require_mfa")]
        if not enforcing:
            return [_f(c, s, "conditional-access", Status.FAIL,
                       f"No enabled Conditional Access policy requires MFA for all "
                       f"users ({len(active)} enabled policy/policies found; "
                       "none targets all users with an MFA grant).")]
        return [_f(c, s, "conditional-access", Status.PASS,
                   "An enabled Conditional Access policy requires MFA for all users.")]

    def ca_legacy(c, s, _):
        aad = _ctx(s)
        if not aad.get("collected"):
            return _not_collected(c, s)
        active = [p for p in aad.get("ca_policies", []) if p.get("state") == "enabled"]
        blocking = [p for p in active if p.get("block_legacy_auth")]
        if not blocking:
            return [_f(c, s, "conditional-access", Status.FAIL,
                       "No enabled Conditional Access policy blocks legacy "
                       "authentication (basic-auth clients bypass MFA entirely).")]
        return [_f(c, s, "conditional-access", Status.PASS,
                   "Legacy authentication is blocked by a Conditional Access policy.")]

    def ca_risk(c, s, _):
        aad = _ctx(s)
        if not aad.get("collected"):
            return _not_collected(c, s)
        active = [p for p in aad.get("ca_policies", []) if p.get("state") == "enabled"]
        risky = [p for p in active if p.get("risk_based")]
        if not risky:
            return [_f(c, s, "conditional-access", Status.FAIL,
                       "No enabled Conditional Access policy reacts to sign-in or "
                       "user risk (e.g. require MFA / block on medium+ risk).")]
        return [_f(c, s, "conditional-access", Status.PASS,
                   "A risk-based Conditional Access policy is enabled.")]

    return [
        Check("AZ-IAM-001", "azure", "IAM/Entra ID", "Identity & Access", Severity.HIGH,
              "MFA not enforced for all users",
              "Users without MFA rely on passwords alone; credential phishing "
              "or reuse leads directly to account takeover.",
              "Register an MFA-capable method for every user and enforce MFA via "
              "a Conditional Access policy targeting all users (or security "
              "defaults if no CA policies exist).",
              mfa_all, cis="CIS Azure 1.2.1"),
        Check("AZ-IAM-002", "azure", "IAM/Entra ID", "Identity & Access", Severity.CRITICAL,
              "MFA not enforced for privileged users",
              "Privileged identities (Global Admin, Owner, etc.) without MFA are "
              "the fastest path to full tenant compromise.",
              "Enforce MFA on all privileged accounts and require strong "
              "authentication for every elevation (PIM + CA MFA grant).",
              mfa_privileged, cis="CIS Azure 1.2.2"),
        Check("AZ-IAM-003", "azure", "IAM/Entra ID", "Identity & Access", Severity.HIGH,
              "No Conditional Access policy enforcing MFA",
              "Without a Conditional Access policy, MFA enforcement depends on "
              "per-user settings that users can weaken or administrators forget.",
              "Create an enabled CA policy requiring MFA for all users (and "
              "exclude only break-glass accounts).",
              ca_mfa, cis="CIS Azure 1.1.6"),
        Check("AZ-IAM-004", "azure", "IAM/Entra ID", "Identity & Access", Severity.HIGH,
              "Legacy authentication not blocked",
              "Legacy (basic-auth) clients such as old Exchange/IMAP do not "
              "honor MFA, so passwords alone grant access.",
              "Create an enabled CA policy blocking legacy authentication for "
              "all users and migrate to modern auth.",
              ca_legacy, cis="CIS Azure 1.1.7"),
        Check("AZ-IAM-005", "azure", "IAM/Entra ID", "Identity & Access", Severity.MEDIUM,
              "No risk-based Conditional Access policy",
              "Without risk policies, compromised-but-not-yet-detected sessions "
              "can keep operating until manual review.",
              "Enable CA risk policies (sign-in and user risk) requiring MFA or "
              "blocking access on medium/high risk.",
              ca_risk, guidance="Microsoft CA risk-based recommendations"),
    ]


# --------------------------------------------------------------------------- #
# Storage accounts
# --------------------------------------------------------------------------- #
def _az_storage_checks() -> List[Check]:
    def blob_public(c, s, _):
        out = []
        for a in s["storage"]:
            if a.get("allow_blob_public_access"):
                out.append(_f(c, s, f"storage:{a['name']}", Status.FAIL,
                              "Blob public access is enabled (anonymous read "
                              "possible)."))
        if not out:
            out.append(_f(c, s, "storage-accounts", Status.PASS,
                          "No storage accounts allow blob public access."))
        return out

    def min_tls(c, s, _):
        out = []
        for a in s["storage"]:
            mt = a.get("min_tls")
            if not _tls_ok(mt):
                out.append(_f(c, s, f"storage:{a['name']}", Status.FAIL,
                              f"Minimum TLS version is {mt or 'unset'} (require TLS1_2)."))
        if not out:
            out.append(_f(c, s, "storage-accounts", Status.PASS,
                          "All storage accounts require TLS 1.2+."))
        return out

    def https_only(c, s, _):
        out = []
        for a in s["storage"]:
            if not a.get("https_only"):
                out.append(_f(c, s, f"storage:{a['name']}", Status.FAIL,
                              "Secure transfer (HTTPS-only) is disabled."))
        if not out:
            out.append(_f(c, s, "storage-accounts", Status.PASS,
                          "All storage accounts enforce HTTPS."))
        return out

    def network_rules(c, s, _):
        out = []
        for a in s["storage"]:
            if a.get("default_action", "").lower() == "allow":
                out.append(_f(c, s, f"storage:{a['name']}", Status.FAIL,
                              "Network rules default to Allow (public access from "
                              "any network)."))
        if not out:
            out.append(_f(c, s, "storage-accounts", Status.PASS,
                          "All storage accounts deny public network access by default."))
        return out

    def cmk(c, s, _):
        out = []
        for a in s["storage"]:
            if not a.get("cmk"):
                out.append(_f(c, s, f"storage:{a['name']}", Status.FAIL,
                              "Storage encryption does not use a customer-managed "
                              "key (CMK).",
                              evidence={"encryption_type": a.get("encryption_type", "MicrosoftManaged")}))
        if not out:
            out.append(_f(c, s, "storage-accounts", Status.PASS,
                          "All storage accounts use CMK encryption."))
        return out

    return [
        Check("AZ-STR-001", "azure", "Storage", "Storage & Data Protection", Severity.HIGH,
              "Storage account allows Blob public access",
              "Anonymous blob access can expose data without authentication. "
              "ScoutSuite frequently misses this because it requires the "
              "Storage Blob Data Reader permission to verify.",
              "Set allowBlobPublicAccess=false (default deny) and audit "
              "containers with the anonymous access property.",
              blob_public, cis="CIS Azure 3.6"),
        Check("AZ-STR-002", "azure", "Storage", "Network Security", Severity.HIGH,
              "Storage account minimum TLS below 1.2",
              "TLS 1.0/1.1 are deprecated and vulnerable to known attacks.",
              "Require TLS 1.2 minimum on all storage accounts.",
              min_tls, cis="CIS Azure 3.1"),
        Check("AZ-STR-003", "azure", "Storage", "Network Security", Severity.HIGH,
              "Secure transfer (HTTPS-only) disabled",
              "HTTP traffic to storage is transmitted in clear text.",
              "Enable the require-secure-transfer flag.",
              https_only, cis="CIS Azure 3.2"),
        Check("AZ-STR-004", "azure", "Storage", "Network Security", Severity.HIGH,
              "Storage account network rules default to Allow",
              "With default action Allow, all networks can reach the account "
              "unless explicit denies exist.",
              "Set network default action to Deny and whitelist trusted "
              "networks/service endpoints.",
              network_rules, cis="CIS Azure 3.7"),
        Check("AZ-STR-005", "azure", "Storage", "Data Protection", Severity.LOW,
              "Storage encryption uses Microsoft-managed key",
              "Customer-managed keys give control over key lifecycle and "
              "rotation, required by some compliance regimes.",
              "Optionally configure CMK with a Key Vault-managed key.",
              cmk),
    ]


# --------------------------------------------------------------------------- #
# Key Vault
# --------------------------------------------------------------------------- #
def _az_keyvault_checks() -> List[Check]:
    def soft_delete(c, s, _):
        out = []
        for kv in s["keyvaults"]:
            if not kv.get("soft_delete"):
                out.append(_f(c, s, f"vault:{kv['name']}", Status.FAIL,
                              "Soft delete is disabled; deleted secrets/keys are "
                              "permanently destroyed."))
        if not out:
            out.append(_f(c, s, "key-vaults", Status.PASS,
                          "All Key Vaults have soft delete enabled."))
        return out

    def purge_protection(c, s, _):
        out = []
        for kv in s["keyvaults"]:
            if not kv.get("purge_protection"):
                out.append(_f(c, s, f"vault:{kv['name']}", Status.FAIL,
                              "Purge protection is disabled; vault contents can "
                              "be purged, defeating soft-delete recovery."))
        if not out:
            out.append(_f(c, s, "key-vaults", Status.PASS,
                          "All Key Vaults have purge protection."))
        return out

    def network_rules(c, s, _):
        out = []
        for kv in s["keyvaults"]:
            if kv.get("default_action", "").lower() == "allow":
                out.append(_f(c, s, f"vault:{kv['name']}", Status.FAIL,
                              "Key Vault network ACLs default to Allow (public)."))
        if not out:
            out.append(_f(c, s, "key-vaults", Status.PASS,
                          "All Key Vaults deny public network access by default."))
        return out

    return [
        Check("AZ-KV-001", "azure", "Key Vault", "Key Management", Severity.HIGH,
              "Key Vault soft delete disabled",
              "Without soft delete, accidental or malicious deletion destroys "
              "keys and secrets permanently.",
              "Enable soft delete (retention >= 90 days) on all vaults.",
              soft_delete, cis="CIS Azure 8.2"),
        Check("AZ-KV-002", "azure", "Key Vault", "Key Management", Severity.MEDIUM,
              "Key Vault purge protection disabled",
              "Purge protection prevents permanent purge and is the safety net "
              "for soft delete.",
              "Enable purge protection on vaults holding production secrets.",
              purge_protection, cis="CIS Azure 8.3"),
        Check("AZ-KV-003", "azure", "Key Vault", "Network Security", Severity.HIGH,
              "Key Vault publicly reachable",
              "Vaults with default-Allow network ACLs are reachable from any "
              "network, expanding attack surface for key material.",
              "Restrict network ACLs to deny by default and allow only trusted "
              "networks/private endpoints.",
              network_rules, cis="CIS Azure 8.4"),
    ]


# --------------------------------------------------------------------------- #
# Networking / NSG
# --------------------------------------------------------------------------- #
def _az_network_checks() -> List[Check]:
    def nsg_open(c, s, _):
        out = []
        for n in s["nsgs"]:
            ports = _nsg_open_ports(n.get("rules", []))
            if ports:
                out.append(_f(c, s, f"nsg:{n['name']}", Status.FAIL,
                              "NSG inbound rules expose ports "
                              f"{sorted(set(ports))} to any source.",
                              {"open_ports": sorted(set(ports))}))
        if not out:
            out.append(_f(c, s, "network-security-groups", Status.PASS,
                          "No NSGs expose management ports to any source."))
        return out

    def nsg_unattached(c, s, _):
        out = []
        for n in s["nsgs"]:
            if not n.get("associated"):
                out.append(_f(c, s, f"nsg:{n['name']}", Status.FAIL,
                              "NSG is not associated with any subnet or NIC; it "
                              "provides no protection."))
        if not out:
            out.append(_f(c, s, "network-security-groups", Status.PASS,
                          "All NSGs are associated with resources."))
        return out

    return [
        Check("AZ-NSG-001", "azure", "Network", "Network Security", Severity.CRITICAL,
              "NSG exposes management ports to any source",
              "Rules allowing 22/3389 (or database/cache ports) from '*' expose "
              "workloads to internet brute force.",
              "Restrict inbound rules to specific source IPs; use Azure Bastion "
              "for RDP/SSH.",
              nsg_open, cis="CIS Azure 6.1", guidance="SOC2 CC6.6"),
        Check("AZ-NSG-002", "azure", "Network", "Network Security", Severity.LOW,
              "NSG not attached to any resource",
              "Unattached NSGs give a false sense of security and indicate "
              "misconfigured subnets.",
              "Attach the NSG to the intended subnets/NICs or delete it.",
              nsg_unattached),
    ]


# --------------------------------------------------------------------------- #
# SQL
# --------------------------------------------------------------------------- #
def _az_sql_checks() -> List[Check]:
    def public(c, s, _):
        out = []
        for db in s["sql"]:
            if db.get("public_network_access"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "SQL server allows public network access."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "No SQL servers allow public network access."))
        return out

    def auditing(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("auditing"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "SQL auditing is disabled (or not writing to a log "
                              "analytics workspace / storage)."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "All SQL servers have auditing enabled."))
        return out

    def tde(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("tde"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Transparent Data Encryption is disabled."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "All SQL servers have TDE enabled."))
        return out

    return [
        Check("AZ-SQL-001", "azure", "SQL", "Database", Severity.HIGH,
              "SQL server allows public network access",
              "Public SQL endpoints are a primary target for brute-force and "
              "exploitation.",
              "Disable public network access; use private endpoints / service "
              "endpoints and enforce NSG rules.",
              public, cis="CIS Azure 4.1.1"),
        Check("AZ-SQL-002", "azure", "SQL", "Logging & Monitoring", Severity.HIGH,
              "SQL server auditing disabled",
              "Without auditing, database access events cannot be investigated.",
              "Enable auditing to a Log Analytics workspace and storage account.",
              auditing, cis="CIS Azure 4.1.2"),
        Check("AZ-SQL-003", "azure", "SQL", "Data Protection", Severity.HIGH,
              "SQL transparent data encryption disabled",
              "TDE protects database files at rest; disabling it violates "
              "at-rest encryption requirements.",
              "Enable TDE on the server (default in new deployments).",
              tde, cis="CIS Azure 4.1.3"),
    ]


# --------------------------------------------------------------------------- #
# Compute / disks / RBAC / monitoring / ACR / App Service / Cosmos
# --------------------------------------------------------------------------- #
def _az_misc_checks() -> List[Check]:
    def disk_encryption(c, s, _):
        out = []
        for d in s["disks"]:
            if not d.get("cmk"):
                out.append(_f(c, s, f"disk:{d['name']}", Status.FAIL,
                              "Managed disk does not use a customer-managed key "
                              "(platform-managed key only).",
                              evidence={"encryption_type": d.get("encryption_type")}))
        if not out:
            out.append(_f(c, s, "managed-disks", Status.PASS,
                          "All managed disks use CMK encryption."))
        return out

    def vm_public(c, s, _):
        out = []
        for v in s["vms"]:
            if v.get("public_ip") and not v.get("nic_has_nsg"):
                out.append(_f(c, s, f"vm:{v['name']}", Status.FAIL,
                              "VM has a public IP but its NIC/subnet has no "
                              "network security group."))
        if not out:
            out.append(_f(c, s, "virtual-machines", Status.PASS,
                          "No public VMs lack NSG protection."))
        return out

    def rbac_owner(c, s, _):
        out = []
        owners = [a for a in s["assignments"]
                  if a.get("role", "").lower() in ("owner", "contributor")]
        for a in owners:
            out.append(_f(c, s, f"{a['principal']}", Status.FAIL,
                          f"'{a['role']}' role assigned at scope "
                          f"{a.get('scope', 'subscription')}. Verify the principal "
                          "requires this privilege and has MFA enforced.",
                          evidence={"principal_type": a.get("principal_type")}))
        if not out:
            out.append(_f(c, s, "rbac-assignments", Status.PASS,
                          "No Owner/Contributor assignments at subscription scope."))
        return out

    def activity_log(c, s, _):
        n = s["activity_log"].get("diagnostic_count", 0)
        if n == 0:
            return [_f(c, s, "subscription-activity-log", Status.FAIL,
                       "No diagnostic settings export the subscription activity "
                       "log to a workspace/storage.")]
        return [_f(c, s, "subscription-activity-log", Status.PASS,
                   f"{n} diagnostic setting(s) export the activity log.")]

    def acr_admin(c, s, _):
        out = []
        for r in s["acr"]:
            if r.get("admin_enabled"):
                out.append(_f(c, s, f"acr:{r['name']}", Status.FAIL,
                              "ACR admin account is enabled (shared static "
                              "credentials)."))
        if not out:
            out.append(_f(c, s, "container-registries", Status.PASS,
                          "No ACR admin accounts enabled."))
        return out

    def acr_public(c, s, _):
        out = []
        for r in s["acr"]:
            if r.get("public_network_access"):
                out.append(_f(c, s, f"acr:{r['name']}", Status.FAIL,
                              "ACR is reachable from the public internet."))
        if not out:
            out.append(_f(c, s, "container-registries", Status.PASS,
                          "All ACRs restrict public network access."))
        return out

    def app_https(c, s, _):
        out = []
        for a in s["appservices"]:
            if not a.get("https_only"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "App Service allows plain HTTP (HTTPS-only disabled)."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "All App Services enforce HTTPS."))
        return out

    def cosmos_public(c, s, _):
        out = []
        for cdb in s["cosmos"]:
            if cdb.get("public_network_access"):
                out.append(_f(c, s, f"cosmos:{cdb['name']}", Status.FAIL,
                              "Cosmos DB account allows public network access."))
        if not out:
            out.append(_f(c, s, "cosmos-accounts", Status.PASS,
                          "All Cosmos DB accounts restrict public access."))
        return out

    return [
        Check("AZ-VM-001", "azure", "Compute", "Data Protection", Severity.LOW,
              "Managed disk uses platform-managed key",
              "Customer-managed keys on disks provide key control required by "
              "some compliance frameworks.",
              "Optionally enable disk encryption sets with CMK.",
              disk_encryption),
        Check("AZ-VM-002", "azure", "Compute", "Network Security", Severity.HIGH,
              "VM with public IP has no NSG",
              "Internet-reachable VMs without NSG filtering are directly "
              "exposed to scanning and exploitation.",
              "Associate an NSG (with deny-by-default rules) to the NIC or "
              "subnet, or move the VM behind a load balancer.",
              vm_public, cis="CIS Azure 6.1"),
        Check("AZ-RBAC-001", "azure", "IAM/RBAC", "Identity & Access", Severity.MEDIUM,
              "Owner/Contributor assignments at subscription scope",
              "Broad privileged roles on the subscription mean one compromised "
              "identity can take over the environment.",
              "Reduce to least privilege; use PIM for just-in-time elevation "
              "and enforce MFA/conditional access.",
              rbac_owner, cis="CIS Azure 1.23"),
        Check("AZ-MON-001", "azure", "Monitoring", "Logging & Monitoring", Severity.HIGH,
              "Activity log not exported",
              "Without diagnostic settings, control-plane activity is not "
              "available for detection and compliance.",
              "Create diagnostic settings sending activity logs to a Log "
              "Analytics workspace and storage.",
              activity_log, cis="CIS Azure 5.1.1"),
        Check("AZ-ACR-001", "azure", "Container Registry", "Container Security", Severity.HIGH,
              "ACR admin account enabled",
              "The admin account uses shared static credentials and bypasses "
              "Azure AD identity.",
              "Disable the admin account and use managed identities/AAD auth.",
              acr_admin, cis="CIS Azure 2.6"),
        Check("AZ-ACR-002", "azure", "Container Registry", "Network Security", Severity.MEDIUM,
              "ACR allows public network access",
              "Public registry endpoints widen the attack surface for image "
              "exfiltration and supply-chain tampering.",
              "Disable public network access; use private endpoints.",
              acr_public),
        Check("AZ-APP-001", "azure", "App Service", "Network Security", Severity.HIGH,
              "App Service HTTPS-only disabled",
              "Allowing HTTP transmits credentials and session data in clear "
              "text.",
              "Enable HTTPS-only and set minimum TLS to 1.2.",
              app_https, cis="CIS Azure 9.2"),
        Check("AZ-COS-001", "azure", "Cosmos DB", "Network Security", Severity.MEDIUM,
              "Cosmos DB allows public network access",
              "Public access to Cosmos DB accounts exposes the data plane to "
              "the internet.",
              "Restrict network access to selected networks or private "
              "endpoints.",
              cosmos_public),
    ]


# --------------------------------------------------------------------------- #
# Hardening: App Service / AKS / SQL / Redis / VM / NSG / Defender / RBAC
# --------------------------------------------------------------------------- #
def _az_hardening_checks() -> List[Check]:
    def app_min_tls(c, s, _):
        out = []
        for a in s["appservices"]:
            mt = a.get("min_tls")
            if mt not in ("1.2", "1.3"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              f"App Service minimum TLS is {mt or 'unset'} (require 1.2+)."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "All App Services require TLS 1.2+."))
        return out

    def app_client_cert(c, s, _):
        out = []
        for a in s["appservices"]:
            if not a.get("client_cert"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "Incoming client certificates are not required."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "All App Services require client certificates."))
        return out

    def app_identity(c, s, _):
        out = []
        for a in s["appservices"]:
            if not a.get("managed_identity"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "Managed identity is not enabled; the app likely "
                              "uses secrets in configuration."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "All App Services use a managed identity."))
        return out

    def app_ftps(c, s, _):
        out = []
        for a in s["appservices"]:
            if (a.get("ftps_state") or "").lower() not in ("ftpsonly", "disabled"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "FTPS is not restricted (state: "
                              f"{a.get('ftps_state') or 'unset'})."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "FTPS is restricted on all App Services."))
        return out

    def app_auth(c, s, _):
        out = []
        for a in s["appservices"]:
            if not a.get("auth_enabled"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "App Service authentication (Easy Auth) is not "
                              "enabled."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "All App Services have authentication enabled."))
        return out

    def aks_rbac(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("rbac_enabled"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "Kubernetes RBAC is disabled on the cluster."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters enforce RBAC."))
        return out

    def aks_private(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("private_cluster"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "AKS API server is publicly reachable (not a "
                              "private cluster)."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters are private."))
        return out

    def aks_netpol(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("network_policy"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "Network policy is not enforced (pod-to-pod "
                              "lateral movement unrestricted)."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters enforce network policy."))
        return out

    def aks_aad(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("azure_ad_auth"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "Azure AD integration is not enabled for cluster "
                              "authentication."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters use Azure AD auth."))
        return out

    def aks_podid(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("pod_identity"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "Pod managed identities are not enabled; pods "
                              "cannot get scoped Azure credentials safely."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters use pod managed identity."))
        return out

    def sql_min_tls(c, s, _):
        out = []
        for db in s["sql"]:
            mt = db.get("min_tls") or ""
            if mt not in ("1.2", "1.3"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              f"SQL minimum TLS is {mt or 'unset'} (require 1.2+)."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "All SQL servers require TLS 1.2+."))
        return out

    def sql_va(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("va_enabled"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "SQL vulnerability assessment is not enabled."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "All SQL servers have VA enabled."))
        return out

    def sql_ad_admin(c, s, _):
        out = []
        for db in s["sql"]:
            if not db.get("ad_admin"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "No Azure AD admin is configured; SQL relies on "
                              "SQL-authenticated identities."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "All SQL servers have an Azure AD admin."))
        return out

    def redis_ssl(c, s, _):
        out = []
        for r in s.get("redis", []):
            if r.get("non_ssl_enabled"):
                out.append(_f(c, s, f"redis:{r['name']}", Status.FAIL,
                              "Non-SSL port (6379) is enabled; clients can "
                              "connect in plaintext."))
        if not out:
            out.append(_f(c, s, "redis-caches", Status.PASS,
                          "All Redis caches disable the non-SSL port."))
        return out

    def vm_bootdiag(c, s, _):
        out = []
        for v in s["vms"]:
            if not v.get("boot_diagnostics"):
                out.append(_f(c, s, f"vm:{v['name']}", Status.FAIL,
                              "Boot diagnostics are disabled; boot-time issues "
                              "cannot be debugged or audited."))
        if not out:
            out.append(_f(c, s, "virtual-machines", Status.PASS,
                          "All VMs have boot diagnostics enabled."))
        return out

    def vm_os_cmk(c, s, _):
        out = []
        for v in s["vms"]:
            if not v.get("os_disk_cmk"):
                out.append(_f(c, s, f"vm:{v['name']}", Status.FAIL,
                              "OS disk does not use a customer-managed key."))
        if not out:
            out.append(_f(c, s, "virtual-machines", Status.PASS,
                          "All VM OS disks use CMK."))
        return out

    def nsg_flow(c, s, _):
        out = []
        for n in s["nsgs"]:
            if not n.get("flow_logs"):
                out.append(_f(c, s, f"nsg:{n['name']}", Status.FAIL,
                              "NSG flow logs are not enabled; denied/allowed "
                              "traffic is not recorded."))
        if not out:
            out.append(_f(c, s, "network-security-groups", Status.PASS,
                          "All NSGs have flow logs enabled."))
        return out

    def bastion(c, s, _):
        if s["bastion"].get("exists"):
            return [_f(c, s, "bastion", Status.PASS,
                       "A Bastion host is deployed for RDP/SSH access.")]
        return [_f(c, s, "bastion", Status.FAIL,
                   "No Bastion host; RDP/SSH management traffic likely goes "
                   "directly over the internet.")]

    def defender(c, s, _):
        d = s.get("defender", {})
        if not d.get("collected"):
            return [_f(c, s, "microsoft-defender", Status.NOT_APPLICABLE,
                       "Defender pricing status could not be determined with "
                       "the current permissions.")]
        plans = d.get("plans", {})
        if not plans:
            return [_f(c, s, "microsoft-defender", Status.FAIL,
                       "No Defender pricing plans found; server and database "
                       "protection is not enabled.")]
        free = [k for k, v in plans.items() if v == "Free"]
        if free:
            return [_f(c, s, "microsoft-defender", Status.FAIL,
                       f"Defender plans on Free tier: {', '.join(sorted(free))}.")]
        return [_f(c, s, "microsoft-defender", Status.PASS,
                   "All Defender plans are on Standard tier.")]

    def kv_private(c, s, _):
        out = []
        for kv in s["keyvaults"]:
            if not kv.get("private_endpoint"):
                out.append(_f(c, s, f"vault:{kv['name']}", Status.FAIL,
                              "Key Vault has no private endpoint; traffic to "
                              "the vault traverses the public network."))
        if not out:
            out.append(_f(c, s, "key-vaults", Status.PASS,
                          "All Key Vaults use private endpoints."))
        return out

    def cosmos_firewall(c, s, _):
        out = []
        for cdb in s["cosmos"]:
            if not cdb.get("ip_rules"):
                out.append(_f(c, s, f"cosmos:{cdb['name']}", Status.FAIL,
                              "Cosmos DB has no IP firewall rules; access is "
                              "open to all networks."))
        if not out:
            out.append(_f(c, s, "cosmos-accounts", Status.PASS,
                          "All Cosmos DB accounts have firewall rules."))
        return out

    def rbac_custom(c, s, _):
        out = []
        for r in s.get("custom_roles", []):
            if r.get("broad"):
                out.append(_f(c, s, f"role:{r['name']}", Status.FAIL,
                              "Custom role contains wildcard actions, effectively "
                              "bypassing least privilege."))
        if not out:
            out.append(_f(c, s, "custom-roles", Status.PASS,
                          "No custom roles use wildcard permissions."))
        return out

    def guest_users(c, s, _):
        n = s.get("aad", {}).get("guest_users", 0)
        if n == 0:
            return [_f(c, s, "entra-id-guests", Status.PASS,
                       "No guest users in the directory.")]
        return [_f(c, s, "entra-id-guests", Status.FAIL,
                   f"{n} guest user(s) in the directory; review their access "
                   "and lifecycle.")]

    return [
        Check("AZ-APP-002", "azure", "App Service", "Network Security", Severity.HIGH,
              "App Service minimum TLS below 1.2",
              "TLS 1.0/1.1 are deprecated and vulnerable.",
              "Set minimum TLS version to 1.2 on all App Services.",
              app_min_tls, cis="CIS Azure 9.3"),
        Check("AZ-APP-003", "azure", "App Service", "Network Security", Severity.MEDIUM,
              "Client certificates not required",
              "Mutual TLS prevents clients without a trusted cert from "
              "connecting.",
              "Enable client certificate authentication (incoming client "
              "certificates).",
              app_client_cert),
        Check("AZ-APP-004", "azure", "App Service", "Identity & Access", Severity.LOW,
              "App Service managed identity not enabled",
              "Without a managed identity the app must hold credentials in "
              "configuration.",
              "Enable a system-assigned managed identity and use Key Vault "
              "references.",
              app_identity),
        Check("AZ-APP-005", "azure", "App Service", "Network Security", Severity.LOW,
              "FTPS not restricted",
              "Unrestricted FTP transmits credentials and files insecurely.",
              "Set FTPS state to FtpsOnly or Disabled.",
              app_ftps),
        Check("AZ-APP-006", "azure", "App Service", "Identity & Access", Severity.MEDIUM,
              "App Service authentication disabled",
              "Without Easy Auth, anonymous users reach the app and identity "
              "logic is hand-rolled.",
              "Enable App Service authentication backed by Azure AD.",
              app_auth),
        Check("AZ-AKS-001", "azure", "AKS", "Kubernetes", Severity.CRITICAL,
              "AKS RBAC disabled",
              "Without RBAC, every authenticated user can act as cluster admin.",
              "Enable Kubernetes RBAC on the cluster.",
              aks_rbac),
        Check("AZ-AKS-002", "azure", "AKS", "Kubernetes", Severity.HIGH,
              "AKS cluster not private",
              "A public API server exposes the Kubernetes control plane.",
              "Create a private cluster with private API server access.",
              aks_private),
        Check("AZ-AKS-003", "azure", "AKS", "Kubernetes", Severity.MEDIUM,
              "AKS network policy not enforced",
              "Pods can communicate laterally without policy constraints.",
              "Enable Azure network policy or Calico.",
              aks_netpol),
        Check("AZ-AKS-004", "azure", "AKS", "Identity & Access", Severity.MEDIUM,
              "AKS Azure AD integration disabled",
              "Clusters without Azure AD auth rely on shared/local identities.",
              "Integrate the cluster with Azure AD for authentication.",
              aks_aad),
        Check("AZ-AKS-005", "azure", "AKS", "Identity & Access", Severity.LOW,
              "AKS pod managed identity disabled",
              "Pods without managed identity must store cloud credentials.",
              "Enable pod managed identity (AAD pod identity / workload "
              "identity).",
              aks_podid),
        Check("AZ-SQL-004", "azure", "SQL", "Network Security", Severity.HIGH,
              "SQL minimum TLS below 1.2",
              "Legacy TLS versions weaken connection security.",
              "Set minimal TLS version to 1.2 on SQL servers.",
              sql_min_tls, cis="CIS Azure 4.1.4"),
        Check("AZ-SQL-005", "azure", "SQL", "Security Posture", Severity.MEDIUM,
              "SQL vulnerability assessment disabled",
              "VA finds database misconfigurations and missing patches.",
              "Enable SQL vulnerability assessment with a scan schedule.",
              sql_va, cis="CIS Azure 4.1.5"),
        Check("AZ-SQL-006", "azure", "SQL", "Identity & Access", Severity.MEDIUM,
              "No Azure AD admin on SQL server",
              "SQL-authenticated identities cannot be centrally governed or "
              "MFA-protected.",
              "Configure an Azure AD administrator and use AAD auth.",
              sql_ad_admin),
        Check("AZ-RED-001", "azure", "Redis Cache", "Network Security", Severity.HIGH,
              "Redis non-SSL port enabled",
              "Plaintext connections expose cached data and credentials.",
              "Disable the non-SSL port (enableNonSslPort=false).",
              redis_ssl, cis="CIS Azure 4.3.1"),
        Check("AZ-VM-003", "azure", "Compute", "Logging & Monitoring", Severity.MEDIUM,
              "VM boot diagnostics disabled",
              "Without boot diagnostics, boot failures cannot be diagnosed or "
              "audited.",
              "Enable boot diagnostics with managed storage.",
              vm_bootdiag, cis="CIS Azure 7.3"),
        Check("AZ-VM-004", "azure", "Compute", "Data Protection", Severity.LOW,
              "VM OS disk not using CMK",
              "Platform-managed keys give less key lifecycle control.",
              "Use disk encryption sets with customer-managed keys.",
              vm_os_cmk),
        Check("AZ-NSG-003", "azure", "Network", "Logging & Monitoring", Severity.MEDIUM,
              "NSG flow logs disabled",
              "Flow logs provide the network evidence needed for detection and "
              "forensics.",
              "Enable NSG flow logs to a Log Analytics workspace and storage.",
              nsg_flow, cis="CIS Azure 5.1.4"),
        Check("AZ-NET-001", "azure", "Network", "Network Security", Severity.MEDIUM,
              "No Bastion host deployed",
              "Without Bastion, RDP/SSH access is typically exposed via public "
              "IPs.",
              "Deploy Azure Bastion and remove public RDP/SSH exposure.",
              bastion),
        Check("AZ-DEF-001", "azure", "Microsoft Defender", "Security Posture", Severity.MEDIUM,
              "Microsoft Defender plans not on Standard",
              "Defender for Cloud plans detect attacks and misconfigurations; "
              "Free tier disables most detections.",
              "Enable Standard pricing for VMs, storage, SQL, app services and "
              "DNS.",
              defender, cis="CIS Azure 2.1.1"),
        Check("AZ-KV-004", "azure", "Key Vault", "Network Security", Severity.LOW,
              "Key Vault without private endpoint",
              "Public vault endpoints route key material over the internet.",
              "Connect vaults via private endpoints.",
              kv_private),
        Check("AZ-COS-002", "azure", "Cosmos DB", "Network Security", Severity.MEDIUM,
              "Cosmos DB firewall not configured",
              "Accounts without IP rules are reachable from any network.",
              "Add IP firewall rules or restrict to private endpoints.",
              cosmos_firewall, cis="CIS Azure 3.5"),
        Check("AZ-RBAC-002", "azure", "IAM/RBAC", "Identity & Access", Severity.MEDIUM,
              "Custom role with wildcard permissions",
              "Wildcard custom roles defeat Azure's built-in least-privilege "
              "model.",
              "Replace wildcards with explicit action lists.",
              rbac_custom),
        Check("AZ-RBAC-003", "azure", "IAM/Entra ID", "Identity & Access", Severity.LOW,
              "Guest users in the directory",
              "Guest accounts are a common vector when not governed by an "
              "identity lifecycle.",
              "Review guest access and enforce an access-review process.",
              guest_users),
    ]


# --------------------------------------------------------------------------- #
# Tranche 2: Policy / App Config / DDoS / Watcher / KV diag / SQL fw / VM av /
#            app logs / Cosmos auth / Event Hubs / Service Bus / Sentinel
# --------------------------------------------------------------------------- #
def _az_tier2_checks() -> List[Check]:
    def policy_assignments(c, s, _):
        n = s.get("policy_assignments")
        if n is None:
            return [_f(c, s, "azure-policy", Status.NOT_APPLICABLE,
                       "Azure Policy status could not be determined with the "
                       "current permissions.")]
        if n > 0:
            return [_f(c, s, "azure-policy", Status.PASS,
                       f"{n} policy assignment(s) enforce guardrails.")]
        return [_f(c, s, "azure-policy", Status.FAIL,
                   "No Azure Policy assignments; the environment has no "
                   "automated guardrails.")]

    def appcfg_public(c, s, _):
        out = []
        for st in s.get("appconfig", []):
            if st.get("public_network_access"):
                out.append(_f(c, s, f"appcfg:{st['name']}", Status.FAIL,
                              "App Configuration store is reachable from the "
                              "public internet."))
        if not out:
            out.append(_f(c, s, "app-config", Status.PASS,
                          "All App Configuration stores restrict public access."))
        return out

    def appcfg_pe(c, s, _):
        out = []
        for st in s.get("appconfig", []):
            if not st.get("private_endpoint"):
                out.append(_f(c, s, f"appcfg:{st['name']}", Status.FAIL,
                              "App Configuration store has no private endpoint."))
        if not out:
            out.append(_f(c, s, "app-config", Status.PASS,
                          "All App Configuration stores use private endpoints."))
        return out

    def ddos(c, s, _):
        n = s.get("ddos_plans")
        if n is None:
            return [_f(c, s, "ddos-protection", Status.NOT_APPLICABLE,
                       "DDoS plan status could not be determined with the "
                       "current permissions.")]
        if n > 0:
            return [_f(c, s, "ddos-protection", Status.PASS,
                       "A DDoS protection plan is enabled.")]
        return [_f(c, s, "ddos-protection", Status.FAIL,
                   "No DDoS protection plan; public endpoints lack DDoS "
                   "mitigation.")]

    def watcher(c, s, _):
        ex = s["network_watcher"].get("exists")
        if ex is None:
            return [_f(c, s, "network-watcher", Status.NOT_APPLICABLE,
                       "Network Watcher status could not be determined with the "
                       "current permissions.")]
        if ex:
            return [_f(c, s, "network-watcher", Status.PASS,
                       "Network Watcher is enabled in a region.")]
        return [_f(c, s, "network-watcher", Status.FAIL,
                   "Network Watcher is not enabled; NSG flow logs and "
                   "connection diagnostics are unavailable.")]

    def kv_diag(c, s, _):
        out = []
        for kv in s["keyvaults"]:
            if not kv.get("diagnostics"):
                out.append(_f(c, s, f"vault:{kv['name']}", Status.FAIL,
                              "Key Vault audit events are not exported via "
                              "diagnostic settings."))
        if not out:
            out.append(_f(c, s, "key-vaults", Status.PASS,
                          "All Key Vaults export diagnostics."))
        return out

    def sql_firewall(c, s, _):
        out = []
        for db in s["sql"]:
            if db.get("firewall_open"):
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "SQL firewall allows 0.0.0.0-255.255.255.255 (all "
                              "Azure + internet IPs)."))
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "No SQL firewalls allow all IPs."))
        return out

    def vm_av(c, s, _):
        out = []
        for v in s["vms"]:
            if not v.get("antimalware"):
                out.append(_f(c, s, f"vm:{v['name']}", Status.FAIL,
                              "No anti-malware/security extension installed on "
                              "the VM."))
        if not out:
            out.append(_f(c, s, "virtual-machines", Status.PASS,
                          "All VMs have anti-malware protection."))
        return out

    def app_logging(c, s, _):
        out = []
        for a in s["appservices"]:
            if not a.get("http_logging"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "HTTP logging is disabled on the App Service."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "All App Services log HTTP traffic."))
        return out

    def cosmos_localauth(c, s, _):
        out = []
        for cdb in s["cosmos"]:
            if cdb.get("local_auth"):
                out.append(_f(c, s, f"cosmos:{cdb['name']}", Status.FAIL,
                              "Local authentication (primary/secondary keys) is "
                              "enabled; use Entra ID only."))
        if not out:
            out.append(_f(c, s, "cosmos-accounts", Status.PASS,
                          "All Cosmos DB accounts disable local auth."))
        return out

    def evh_public(c, s, _):
        out = []
        for n in s.get("eventhubs", []):
            if n.get("public_network_access"):
                out.append(_f(c, s, f"eventhubs:{n['name']}", Status.FAIL,
                              "Event Hubs namespace allows public network access."))
        if not out:
            out.append(_f(c, s, "event-hubs", Status.PASS,
                          "All Event Hubs namespaces restrict public access."))
        return out

    def evh_cmk(c, s, _):
        out = []
        for n in s.get("eventhubs", []):
            if not n.get("cmk"):
                out.append(_f(c, s, f"eventhubs:{n['name']}", Status.FAIL,
                              "Event Hubs namespace not encrypted with CMK."))
        if not out:
            out.append(_f(c, s, "event-hubs", Status.PASS,
                          "All Event Hubs namespaces use CMK."))
        return out

    def sb_public(c, s, _):
        out = []
        for n in s.get("servicebus", []):
            if n.get("public_network_access"):
                out.append(_f(c, s, f"servicebus:{n['name']}", Status.FAIL,
                              "Service Bus namespace allows public network access."))
        if not out:
            out.append(_f(c, s, "service-bus", Status.PASS,
                          "All Service Bus namespaces restrict public access."))
        return out

    def log_analytics(c, s, _):
        n = s.get("log_analytics", {}).get("workspaces")
        if n is None:
            return [_f(c, s, "log-analytics", Status.NOT_APPLICABLE,
                       "Log Analytics status could not be determined with the "
                       "current permissions.")]
        if n > 0:
            return [_f(c, s, "log-analytics", Status.PASS,
                       f"{n} Log Analytics workspace(s) collect logs.")]
        return [_f(c, s, "log-analytics", Status.FAIL,
                   "No Log Analytics workspace; security logs have no "
                   "central destination.")]

    def sentinel(c, s, _):
        n = s.get("sentinel", {}).get("workspaces")
        if n is None:
            return [_f(c, s, "sentinel", Status.NOT_APPLICABLE,
                       "Sentinel workspace status could not be determined with "
                       "the current permissions.")]
        if n > 0:
            return [_f(c, s, "sentinel", Status.PASS,
                       f"{n} Sentinel workspace(s) provide SIEM detection.")]
        return [_f(c, s, "sentinel", Status.FAIL,
                   "No Microsoft Sentinel workspace; there is no SIEM layer "
                   "correlating security events.")]

    return [
        Check("AZ-POL-001", "azure", "Azure Policy", "Security Posture", Severity.MEDIUM,
              "No Azure Policy assignments",
              "Without policy, misconfigurations are not prevented or flagged "
              "automatically.",
              "Assign built-in security policy initiatives (e.g. Azure Security "
              "Benchmark) at subscription scope.",
              policy_assignments),
        Check("AZ-APPC-001", "azure", "App Configuration", "Network Security", Severity.MEDIUM,
              "App Configuration publicly accessible",
              "Public stores expose configuration and secrets-bearing data.",
              "Disable public network access and use private endpoints.",
              appcfg_public),
        Check("AZ-APPC-002", "azure", "App Configuration", "Network Security", Severity.LOW,
              "App Configuration without private endpoint",
              "Traffic to the store traverses the public network.",
              "Connect stores via private endpoints.",
              appcfg_pe),
        Check("AZ-NET-002", "azure", "Network", "Network Security", Severity.MEDIUM,
              "No DDoS protection plan",
              "Public IPs without DDoS protection are exposed to volumetric "
              "attacks.",
              "Enable DDoS Network Protection on production VNets.",
              ddos),
        Check("AZ-NET-004", "azure", "Network", "Logging & Monitoring", Severity.MEDIUM,
              "Network Watcher not enabled",
              "Without Network Watcher, NSG flow logs and connection "
              "diagnostics are unavailable.",
              "Enable Network Watcher in all regions.",
              watcher),
        Check("AZ-KV-005", "azure", "Key Vault", "Logging & Monitoring", Severity.MEDIUM,
              "Key Vault diagnostics not enabled",
              "Vault access events are not exported for detection/compliance.",
              "Enable diagnostic settings sending vault logs to a workspace.",
              kv_diag),
        Check("AZ-SQL-007", "azure", "SQL", "Network Security", Severity.HIGH,
              "SQL firewall allows all IPs",
              "0.0.0.0-255.255.255.255 firewall rules allow any IP to attempt "
              "connections.",
              "Remove allow-all firewall rules and scope to trusted IPs/VNets.",
              sql_firewall),
        Check("AZ-VM-006", "azure", "Compute", "Security Posture", Severity.MEDIUM,
              "VM without anti-malware protection",
              "VMs without antimalware/Defender extensions have no host-level "
              "threat detection.",
              "Install the antimalware or Microsoft Defender extension.",
              vm_av),
        Check("AZ-APP-007", "azure", "App Service", "Logging & Monitoring", Severity.LOW,
              "App Service HTTP logging disabled",
              "Request-level logs are needed to investigate attacks and errors.",
              "Enable web server logging on the App Service.",
              app_logging),
        Check("AZ-COS-003", "azure", "Cosmos DB", "Identity & Access", Severity.MEDIUM,
              "Cosmos DB local authentication enabled",
              "Primary/secondary keys bypass Entra ID and MFA; a leaked key "
              "grants full data access.",
              "Disable local auth and use Azure AD/RBAC only.",
              cosmos_localauth),
        Check("AZ-EVH-001", "azure", "Event Hubs", "Network Security", Severity.MEDIUM,
              "Event Hubs publicly accessible",
              "Public namespaces widen the attack surface for event data.",
              "Disable public network access; use private endpoints.",
              evh_public),
        Check("AZ-EVH-002", "azure", "Event Hubs", "Data Protection", Severity.LOW,
              "Event Hubs not encrypted with CMK",
              "Default Microsoft-managed keys give less key control.",
              "Encrypt namespaces with customer-managed keys.",
              evh_cmk),
        Check("AZ-SB-001", "azure", "Service Bus", "Network Security", Severity.MEDIUM,
              "Service Bus publicly accessible",
              "Public namespaces expose the messaging plane to the internet.",
              "Disable public network access; use private endpoints.",
              sb_public),
        Check("AZ-LOG-001", "azure", "Log Analytics", "Logging & Monitoring", Severity.HIGH,
              "No Log Analytics workspace",
              "Without a central workspace, security logs cannot be collected "
              "or correlated.",
              "Create a Log Analytics workspace and route diagnostics to it.",
              log_analytics),
        Check("AZ-SEN-001", "azure", "Microsoft Sentinel", "Security Posture", Severity.MEDIUM,
              "No Microsoft Sentinel workspace",
              "Without Sentinel there is no SIEM correlation, alerting or "
              "automated response.",
              "Enable Microsoft Sentinel on a Log Analytics workspace.",
              sentinel),
    ]


# --------------------------------------------------------------------------- #
# Tranche 3: Sentinel analytics rules / Policy exemptions / KV key expiry /   #
#            SQL LTR / AKS policy addon / Log Analytics / RBAC / Cosmos /     #
#            Redis / App Service / VM Monitor agent / NSG flow retention
# --------------------------------------------------------------------------- #
def _az_tier3_checks() -> List[Check]:
    def sen_rules(c, s, _):
        n = s.get("sentinel", {}).get("analytics_rules")
        if n is None:
            return [_f(c, s, "sentinel", Status.NOT_APPLICABLE,
                       "Sentinel analytics-rule status could not be determined "
                       "with the current permissions.")]
        if n > 0:
            return [_f(c, s, "sentinel", Status.PASS,
                       f"{n} Sentinel analytics rule(s) generate detections.")]
        return [_f(c, s, "sentinel", Status.FAIL,
                   "No Sentinel analytics rules; the SIEM collects logs but "
                   "detects nothing.")]

    def pol_exempt(c, s, _):
        n = s.get("policy_exemptions_no_expiry")
        if n is None:
            return [_f(c, s, "azure-policy", Status.NOT_APPLICABLE,
                       "Policy exemption status could not be determined with "
                       "the current permissions.")]
        if n > 0:
            return [_f(c, s, "azure-policy", Status.FAIL,
                       f"{n} policy exemption(s) have no expiration date; "
                       "exemptions can silently become permanent.")]
        return [_f(c, s, "azure-policy", Status.PASS,
                   "No policy exemptions lack an expiration.")]

    def kv_key_expiry(c, s, _):
        out = []
        verified = 0
        for kv in s["keyvaults"]:
            n = kv.get("keys_without_expiry")
            if n is None:
                continue  # data-plane perms missing for this vault
            verified += 1
            if n > 0:
                out.append(_f(c, s, f"vault:{kv['name']}", Status.FAIL,
                              f"{n} key(s) have no expiry date set."))
        if verified == 0:
            return [_f(c, s, "key-vaults", Status.NOT_APPLICABLE,
                       "Key expiry could not be verified: grant the review "
                       "identity Key.Get on the vaults (data plane) and re-run.")]
        if not out:
            out.append(_f(c, s, "key-vaults", Status.PASS,
                          "All verified vault keys have an expiry date."))
        return out

    def sql_ltr(c, s, _):
        out = []
        verified = 0
        for db in s["sql"]:
            v = db.get("lt_retention")
            if v is None:
                continue  # could not be verified with current permissions
            verified += 1
            if not v:
                out.append(_f(c, s, f"sql:{db['name']}", Status.FAIL,
                              "Long-term backup retention is not configured; "
                              "recovery is limited to the automated window."))
        if verified == 0:
            return [_f(c, s, "sql-servers", Status.NOT_APPLICABLE,
                       "Long-term retention could not be verified with the "
                       "current permissions.")]
        if not out:
            out.append(_f(c, s, "sql-servers", Status.PASS,
                          "All verified SQL servers have long-term backup "
                          "retention."))
        return out

    def aks_policy(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("azure_policy_addon"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "The Azure Policy add-on is disabled on the "
                              "cluster; policy violations inside pods are not "
                              "enforced."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters run the Azure Policy add-on."))
        return out

    def la_cmk(c, s, _):
        n = s.get("log_analytics", {}).get("workspaces")
        if n is None:
            return [_f(c, s, "log-analytics", Status.NOT_APPLICABLE,
                       "Log Analytics status could not be determined with the "
                       "current permissions.")]
        if s.get("log_analytics", {}).get("cmk"):
            return [_f(c, s, "log-analytics", Status.PASS,
                       "Workspaces are encrypted with customer-managed keys.")]
        return [_f(c, s, "log-analytics", Status.FAIL,
                   "Log Analytics workspaces are not encrypted with a CMK.")]

    def la_retention(c, s, _):
        n = s.get("log_analytics", {}).get("workspaces")
        if n is None:
            return [_f(c, s, "log-analytics", Status.NOT_APPLICABLE,
                       "Log Analytics status could not be determined with the "
                       "current permissions.")]
        short = s.get("log_analytics", {}).get("short_retention", [])
        if short:
            return [_f(c, s, "log-analytics", Status.FAIL,
                       f"Workspace(s) {', '.join(short)} retain logs for less "
                       "than 30 days.")]
        return [_f(c, s, "log-analytics", Status.PASS,
                   "All workspaces retain logs >= 30 days.")]

    def sp_owner(c, s, _):
        out = []
        for a in s["assignments"]:
            if (a.get("principal_type", "").lower() == "serviceprincipal"
                    and a.get("role", "").lower() in ("owner", "contributor")):
                out.append(_f(c, s, f"sp:{a['principal']}", Status.FAIL,
                              f"Service principal holds '{a['role']}' at "
                              f"{a.get('scope', 'subscription')}; machine "
                              "credentials with broad roles are high-risk."))
        if not out:
            out.append(_f(c, s, "rbac-assignments", Status.PASS,
                          "No service principals hold Owner/Contributor."))
        return out

    def cosmos_backup(c, s, _):
        out = []
        for cdb in s["cosmos"]:
            if not cdb.get("backup_continuous"):
                out.append(_f(c, s, f"cosmos:{cdb['name']}", Status.FAIL,
                              "Backup is not continuous; point-in-time "
                              "restoration is unavailable."))
        if not out:
            out.append(_f(c, s, "cosmos-accounts", Status.PASS,
                          "All Cosmos DB accounts use continuous backup."))
        return out

    def redis_pe(c, s, _):
        out = []
        for r in s.get("redis", []):
            if not r.get("private_endpoint"):
                out.append(_f(c, s, f"redis:{r['name']}", Status.FAIL,
                              "Redis cache has no private endpoint; traffic "
                              "traverses the public network."))
        if not out:
            out.append(_f(c, s, "redis-caches", Status.PASS,
                          "All Redis caches use private endpoints."))
        return out

    def app_remotedebug(c, s, _):
        out = []
        for a in s["appservices"]:
            if a.get("remote_debugging"):
                out.append(_f(c, s, f"app:{a['name']}", Status.FAIL,
                              "Remote debugging is enabled; anyone who can reach "
                              "the app can attach a debugger."))
        if not out:
            out.append(_f(c, s, "app-services", Status.PASS,
                          "Remote debugging is disabled on all App Services."))
        return out

    def vm_monitor(c, s, _):
        out = []
        for v in s["vms"]:
            if not v.get("monitor_agent"):
                out.append(_f(c, s, f"vm:{v['name']}", Status.FAIL,
                              "The Azure Monitor agent is not installed; guest "
                              "OS telemetry is not collected."))
        if not out:
            out.append(_f(c, s, "virtual-machines", Status.PASS,
                          "All VMs run the Azure Monitor agent."))
        return out

    def nsg_flow_retention(c, s, _):
        out = []
        for n in s["nsgs"]:
            days = n.get("flow_retention_days", 0)
            if n.get("flow_logs") and days < 90:
                out.append(_f(c, s, f"nsg:{n['name']}", Status.FAIL,
                              f"Flow log retention is {days} days (< 90); "
                              "forensic history expires too soon."))
        if not out:
            out.append(_f(c, s, "network-security-groups", Status.PASS,
                          "All flow logs are retained >= 90 days."))
        return out

    return [
        Check("AZ-SEN-002", "azure", "Microsoft Sentinel", "Security Posture", Severity.MEDIUM,
              "Sentinel workspace without analytics rules",
              "A Sentinel workspace with no analytics rules ingests logs but "
              "never raises alerts.",
              "Create analytics rule templates for identity, data and network "
              "detections.",
              sen_rules),
        Check("AZ-POL-002", "azure", "Azure Policy", "Security Posture", Severity.MEDIUM,
              "Policy exemption without expiration",
              "Exemptions without expiry silently become permanent waivers.",
              "Set an expiration date on every policy exemption.",
              pol_exempt),
        Check("AZ-KV-006", "azure", "Key Vault", "Key Management", Severity.MEDIUM,
              "Key Vault keys without expiry",
              "Keys with no expiry never rotate automatically and are not "
              "removed when their use ends.",
              "Set an expiration date on all vault keys.",
              kv_key_expiry),
        Check("AZ-SQL-008", "azure", "SQL", "Backup & Recovery", Severity.LOW,
              "SQL long-term backup retention disabled",
              "Recovery is limited to the short automated window without LTR.",
              "Configure long-term retention policies for compliance archives.",
              sql_ltr),
        Check("AZ-AKS-006", "azure", "AKS", "Kubernetes", Severity.MEDIUM,
              "AKS Azure Policy add-on disabled",
              "Without the add-on, policy violations inside pods are not "
              "enforced or audited.",
              "Enable the Azure Policy add-on on the cluster.",
              aks_policy),
        Check("AZ-LOG-002", "azure", "Log Analytics", "Data Protection", Severity.LOW,
              "Log Analytics not encrypted with CMK",
              "Platform-managed keys give less key lifecycle control over logs.",
              "Configure customer-managed keys on workspaces.",
              la_cmk),
        Check("AZ-LOG-003", "azure", "Log Analytics", "Logging & Monitoring", Severity.MEDIUM,
              "Log Analytics retention below 30 days",
              "Short retention destroys forensic history before investigations "
              "complete.",
              "Raise workspace retention to >= 30 days (90+ for security).",
              la_retention),
        Check("AZ-RBAC-004", "azure", "IAM/RBAC", "Identity & Access", Severity.HIGH,
              "Service principal with Owner/Contributor",
              "Machine credentials with broad roles are a high-risk takeover "
              "target with no human MFA.",
              "Grant service principals only scoped roles; use managed "
              "identity and break-glass roles.",
              sp_owner),
        Check("AZ-COS-004", "azure", "Cosmos DB", "Backup & Recovery", Severity.MEDIUM,
              "Cosmos DB backup not continuous",
              "Periodic backups lose data since the last snapshot and have no "
              "point-in-time restore.",
              "Enable continuous backup mode with PITR.",
              cosmos_backup),
        Check("AZ-RED-002", "azure", "Redis Cache", "Network Security", Severity.LOW,
              "Redis cache without private endpoint",
              "Cache traffic traverses the public network.",
              "Connect caches via private endpoints.",
              redis_pe),
        Check("AZ-APP-008", "azure", "App Service", "Security Posture", Severity.MEDIUM,
              "App Service remote debugging enabled",
              "Remote debugging exposes the app to debugger attachment, a "
              "common post-exploitation vector.",
              "Disable remote debugging in production.",
              app_remotedebug),
        Check("AZ-VM-007", "azure", "Compute", "Logging & Monitoring", Severity.MEDIUM,
              "VM without Azure Monitor agent",
              "Without the guest agent, OS-level telemetry and security "
              "signals are not collected.",
              "Install the Azure Monitor agent on all VMs.",
              vm_monitor),
        Check("AZ-NSG-004", "azure", "Network", "Logging & Monitoring", Severity.MEDIUM,
              "NSG flow log retention below 90 days",
              "Short flow-log retention erases the evidence needed for "
              "forensics.",
              "Set flow log retention to >= 90 days.",
              nsg_flow_retention),
    ]


# --------------------------------------------------------------------------- #
# Tranche 4: API Management / App Gateway / VM encryption-at-host /           #
#            activity log alerts / AKS autoscaler / storage blob soft delete
# --------------------------------------------------------------------------- #
def _az_tier4_checks() -> List[Check]:
    def apim_identity(c, s, _):
        out = []
        for a in s.get("apim", []):
            if not a.get("identity"):
                out.append(_f(c, s, f"apim:{a['name']}", Status.FAIL,
                              "API Management has no managed identity; it must "
                              "hold secrets to reach backends."))
        if not out:
            out.append(_f(c, s, "api-management", Status.PASS,
                          "All API Management services use a managed identity."))
        return out

    def apim_sku(c, s, _):
        out = []
        for a in s.get("apim", []):
            if (a.get("sku") or "").lower() == "developer":
                out.append(_f(c, s, f"apim:{a['name']}", Status.FAIL,
                              "API Management is on the Developer tier (no SLA, "
                              "limited features, no VNet isolation)."))
        if not out:
            out.append(_f(c, s, "api-management", Status.PASS,
                          "All API Management services run a production tier."))
        return out

    def apim_vnet(c, s, _):
        out = []
        for a in s.get("apim", []):
            if not a.get("vnet"):
                out.append(_f(c, s, f"apim:{a['name']}", Status.FAIL,
                              "API Management is not injected into a VNet; the "
                              "gateway is publicly reachable."))
        if not out:
            out.append(_f(c, s, "api-management", Status.PASS,
                          "All API Management services are VNet-injected."))
        return out

    def agw_waf(c, s, _):
        out = []
        for g in s.get("appgateways", []):
            if not g.get("waf"):
                out.append(_f(c, s, f"agw:{g['name']}", Status.FAIL,
                              "Application Gateway has no WAF policy; L7 attacks "
                              "are not filtered."))
        if not out:
            out.append(_f(c, s, "app-gateway", Status.PASS,
                          "All App Gateways run WAF."))
        return out

    def agw_ssl(c, s, _):
        out = []
        for g in s.get("appgateways", []):
            if not g.get("ssl_policy"):
                out.append(_f(c, s, f"agw:{g['name']}", Status.FAIL,
                              "Application Gateway has no TLS policy; TLS "
                              "settings are not hardened."))
        if not out:
            out.append(_f(c, s, "app-gateway", Status.PASS,
                          "All App Gateways enforce a TLS policy."))
        return out

    def vm_encathost(c, s, _):
        out = []
        for v in s["vms"]:
            if not v.get("encryption_at_host"):
                out.append(_f(c, s, f"vm:{v['name']}", Status.FAIL,
                              "Encryption at host is disabled; temporary disks "
                              "and cache are not encrypted."))
        if not out:
            out.append(_f(c, s, "virtual-machines", Status.PASS,
                          "All VMs use encryption at host."))
        return out

    def mon_alerts(c, s, _):
        n = s.get("activity_log_alerts")
        if n is None:
            return [_f(c, s, "monitoring", Status.NOT_APPLICABLE,
                       "Activity log alert status could not be determined with "
                       "the current permissions.")]
        if n > 0:
            return [_f(c, s, "monitoring", Status.PASS,
                       f"{n} activity log alert rule(s) notify on control-plane "
                       "events.")]
        return [_f(c, s, "monitoring", Status.FAIL,
                   "No activity log alert rules; admin operations (role "
                   "changes, security settings) generate no alerts.")]

    def aks_autoscaler(c, s, _):
        out = []
        for cl in s.get("aks", []):
            if not cl.get("autoscaler"):
                out.append(_f(c, s, f"aks:{cl['name']}", Status.FAIL,
                              "Cluster autoscaler is not configured; node pools "
                              "cannot scale with demand."))
        if not out:
            out.append(_f(c, s, "aks-clusters", Status.PASS,
                          "All AKS clusters run the cluster autoscaler."))
        return out

    def str_softdel(c, s, _):
        out = []
        for a in s["storage"]:
            if not a.get("blob_soft_delete"):
                out.append(_f(c, s, f"storage:{a['name']}", Status.FAIL,
                              "Blob soft delete is disabled; deleted blobs are "
                              "permanently destroyed."))
        if not out:
            out.append(_f(c, s, "storage-accounts", Status.PASS,
                          "All storage accounts enable blob soft delete."))
        return out

    return [
        Check("AZ-APIM-001", "azure", "API Management", "Identity & Access", Severity.MEDIUM,
              "API Management without managed identity",
              "Without a managed identity the gateway cannot securely reach "
              "Key Vault and backend credentials.",
              "Enable a system-assigned managed identity on the service.",
              apim_identity),
        Check("AZ-APIM-002", "azure", "API Management", "Security Posture", Severity.MEDIUM,
              "API Management on Developer tier",
              "The Developer tier has no SLA, limited features and no VNet "
              "isolation.",
              "Upgrade to Standard/Premium for production APIs.",
              apim_sku),
        Check("AZ-APIM-003", "azure", "API Management", "Network Security", Severity.HIGH,
              "API Management not VNet-injected",
              "A public gateway exposes the API surface directly to the "
              "internet.",
              "Inject API Management into a VNet (external or internal mode).",
              apim_vnet),
        Check("AZ-AGW-001", "azure", "Application Gateway", "Network Security", Severity.HIGH,
              "App Gateway without WAF",
              "Without WAF, SQLi/XSS and other L7 attacks reach backends "
              "unfiltered.",
              "Attach a WAF policy (OWASP ruleset) to the gateway.",
              agw_waf),
        Check("AZ-AGW-002", "azure", "Application Gateway", "Network Security", Severity.MEDIUM,
              "App Gateway without TLS policy",
              "Default TLS settings may allow weak protocol versions.",
              "Configure an explicit TLS policy on the gateway.",
              agw_ssl),
        Check("AZ-VM-005", "azure", "Compute", "Data Protection", Severity.MEDIUM,
              "VM encryption at host disabled",
              "Temporary disks and VM cache are not encrypted without "
              "encryption-at-host.",
              "Enable encryption at host for sensitive workloads.",
              vm_encathost),
        Check("AZ-MON-002", "azure", "Monitoring", "Logging & Monitoring", Severity.MEDIUM,
              "No activity log alert rules",
              "Admin operations such as role changes or security-settings "
              "edits go unnoticed.",
              "Create activity log alerts for critical control-plane events.",
              mon_alerts, cis="CIS Azure 5.2.1"),
        Check("AZ-AKS-007", "azure", "AKS", "Kubernetes", Severity.MEDIUM,
              "AKS cluster autoscaler disabled",
              "Node pools cannot scale to demand, causing availability and "
              "scheduling issues.",
              "Enable the cluster autoscaler on node pools.",
              aks_autoscaler),
        Check("AZ-STR-006", "azure", "Storage", "Data Protection", Severity.MEDIUM,
              "Storage blob soft delete disabled",
              "Accidental or malicious blob deletes are unrecoverable.",
              "Enable blob soft delete with a retention policy.",
              str_softdel),
    ]


# --------------------------------------------------------------------------- #
# Front Door + Functions (unique coverage: edge WAF posture + serverless auth)
# --------------------------------------------------------------------------- #
def _az_edge_checks() -> List[Check]:
    def fd_waf(c, s, _):
        out = []
        for fd in s.get("frontdoors", []):
            if not fd.get("waf"):
                out.append(_f(c, s, f"frontdoor:{fd['name']}", Status.FAIL,
                              "Front Door profile has no WAF policy attached "
                              "to its endpoints; edge traffic is unfiltered."))
        if not out:
            out.append(_f(c, s, "frontdoors", Status.PASS,
                          "All Front Door profiles have a WAF policy attached."))
        return out

    def fd_logging(c, s, _):
        out = []
        for fd in s.get("frontdoors", []):
            if not fd.get("logging"):
                out.append(_f(c, s, f"frontdoor:{fd['name']}", Status.FAIL,
                              "Front Door diagnostics/logging is disabled; "
                              "access and WAF logs are not retained."))
        if not out:
            out.append(_f(c, s, "frontdoors", Status.PASS,
                          "All Front Door profiles emit access/WAF logs."))
        return out

    def fn_https(c, s, _):
        out = []
        for fn in s.get("functions", []):
            if not fn.get("https_only"):
                out.append(_f(c, s, f"functionapp:{fn['name']}", Status.FAIL,
                              "Function app accepts plaintext HTTP traffic."))
        if not out:
            out.append(_f(c, s, "function-apps", Status.PASS,
                          "All function apps enforce HTTPS-only."))
        return out

    def fn_anon(c, s, _):
        out = []
        for fn in s.get("functions", []):
            if fn.get("auth_level") == "anonymous":
                out.append(_f(c, s, f"functionapp:{fn['name']}", Status.FAIL,
                              "Function app exposes HTTP triggers with "
                              "anonymous (unauthenticated) authorization."))
        if not out:
            out.append(_f(c, s, "function-apps", Status.PASS,
                          "All function apps require authentication for HTTP "
                          "triggers."))
        return out

    return [
        Check("AZ-FD-001", "azure", "Front Door", "Security Posture", Severity.HIGH,
              "Front Door profile without WAF policy",
              "Azure Front Door is the internet-facing edge; without a WAF "
              "policy, SQLi/XSS/bot traffic reaches origins unfiltered.",
              "Attach a WAF policy (managed rule sets) to each Front Door "
              "endpoint/frontend host.",
              fd_waf),
        Check("AZ-FD-002", "azure", "Front Door", "Logging & Monitoring", Severity.MEDIUM,
              "Front Door logging disabled",
              "Without diagnostics, access and WAF logs are not retained, "
              "hiding attacks and usage anomalies.",
              "Enable diagnostic settings for Front Door access and WAF logs "
              "to a Log Analytics workspace.",
              fd_logging),
        Check("AZ-FN-001", "azure", "Functions", "Security Posture", Severity.HIGH,
              "Function app allows anonymous HTTP triggers",
              "HTTP-triggered functions with anonymous auth level can be "
              "invoked by anyone on the internet.",
              "Require function/app-level auth (Function key, Entra ID or "
              "App Service auth) instead of anonymous.",
              fn_anon),
        Check("AZ-FN-002", "azure", "Functions", "Data Protection", Severity.MEDIUM,
              "Function app not HTTPS-only",
              "Plaintext HTTP traffic to the function endpoint can be "
              "intercepted or tampered with.",
              "Set HTTPS Only (https_only) and a minimum TLS version on the "
              "function app.",
              fn_https),
    ]


def get_checks() -> List[Check]:
    return (_az_identity_checks() + _az_storage_checks() + _az_keyvault_checks()
            + _az_network_checks() + _az_sql_checks() + _az_misc_checks()
            + _az_hardening_checks() + _az_tier2_checks() + _az_tier3_checks()
            + _az_tier4_checks() + _az_edge_checks())
