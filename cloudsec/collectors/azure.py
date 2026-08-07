"""Azure collector (azure-mgmt + azure-identity).

Auth options (``auth`` dict):
  tenant_id / client_id / client_secret : service principal (recommended, Reader role)
  subscription_id                        : optional; defaults to the first available
  Or rely on DefaultAzureCredential (az login / managed identity) when the
  SP fields are absent.
"""
from __future__ import annotations

import json as _json
from typing import Any, Dict, List
from urllib.request import Request, urlopen


GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Authentication-method types that can satisfy MFA (anything that is not a
# password or email-only method).
_MFA_EXEMPT_TYPES = (
    "#microsoft.graph.passwordAuthenticationMethod",
    "#microsoft.graph.emailAuthenticationMethod",
)


def _graph_json(token: str, url: str, timeout: int = 30) -> Dict[str, Any]:
    """GET a Microsoft Graph endpoint and return the decoded JSON body."""
    req = Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    with urlopen(req, timeout=timeout) as resp:
        return _json.loads(resp.read().decode("utf-8"))


def _graph_all(token: str, url: str, timeout: int = 30) -> List[Dict[str, Any]]:
    """Follow @odata.nextLink pagination and return every page's value rows."""
    rows: List[Dict[str, Any]] = []
    while url:
        data = _graph_json(token, url, timeout=timeout)
        rows.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return rows


# Directory roles treated as privileged for the MFA-enforcement check.
# Fail-closed: if the role name can't be resolved the principal is kept
# privileged rather than silently downgraded.
_ADMIN_ROLES = frozenset(
    role.lower() for role in (
        "Global Administrator", "Privileged Role Administrator",
        "Privileged Authentication Administrator", "Authentication Administrator",
        "Security Administrator", "Security Operator", "Security Reader",
        "Application Administrator", "Cloud Application Administrator",
        "Hybrid Identity Administrator", "Exchange Administrator",
        "SharePoint Administrator", "User Administrator",
        "Billing Administrator", "Intune Administrator",
    )
)


def collect_azure(auth: Dict[str, Any]) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential  # lazy
    from azure.mgmt.resource import SubscriptionClient  # lazy

    errors: List[Dict[str, Any]] = []

    def note(service: str, err: Exception, ctx: str = "") -> None:
        errors.append({"service": service, "error": str(err)[:300], "context": ctx})

    tenant = auth.get("tenant_id")
    cid = auth.get("client_id")
    secret = auth.get("client_secret")
    if tenant and cid and secret:
        cred = ClientSecretCredential(tenant_id=tenant, client_id=cid, client_secret=secret)
    else:
        cred = DefaultAzureCredential()

    sub_client = SubscriptionClient(cred)
    subs = list(sub_client.subscriptions.list())
    if not subs:
        raise RuntimeError("No Azure subscriptions accessible with the current credentials.")
    sub = next((s for s in subs if s.subscription_id == auth.get("subscription_id")),
               subs[0])
    sub_id = sub.subscription_id
    scope = f"/subscriptions/{sub_id}"

    snapshot: Dict[str, Any] = {
        "subscription_id": sub_id,
        "account_name": sub.display_name or sub_id,
        "principal": auth.get("principal") or cid or "unknown",
        "assignments": [], "storage": [], "keyvaults": [], "nsgs": [], "sql": [],
        "disks": [], "vms": [], "activity_log": {"diagnostic_count": 0},
        "acr": [], "appservices": [], "cosmos": [],
        "aks": [], "redis": [], "bastion": {"exists": False},
        "defender": {"plans": {}, "collected": False}, "custom_roles": [],
        "aad": {"collected": False, "users": [], "ca_policies": [], "guest_users": 0},
        # None = not collected (SDK/permissions missing) -> checks report
        # NOT_APPLICABLE instead of a misleading FAIL; 0 = collected, empty.
        "policy_assignments": None, "policy_exemptions_no_expiry": None,
        "appconfig": [], "ddos_plans": None,
        "network_watcher": {"exists": None},
        "eventhubs": [], "servicebus": [],
        # None = not collected (SDK/permissions missing) -> checks report
        # NOT_APPLICABLE instead of a misleading FAIL; 0 = collected, empty.
        "log_analytics": {"workspaces": None, "cmk": None,
                          "short_retention": [], "workspace_ids": []},
        "sentinel": {"workspaces": None, "analytics_rules": None},
        "apim": [], "appgateways": [], "activity_log_alerts": None,
    }

    # ---- RBAC assignments at subscription scope ---------------------------------
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
        authz = AuthorizationManagementClient(cred, sub_id)
        role_defs = {}
        for rd in authz.role_definitions.list(scope=scope):
            role_defs[rd.name] = rd.role_name or rd.name
        for ra in authz.role_assignments.list_for_scope(scope=scope):
            snapshot["assignments"].append({
                "principal": ra.principal_id or "",
                "principal_type": ra.principal_type or "",
                "role": role_defs.get(ra.role_definition_id.split("/")[-1], ra.role_definition_id),
                "scope": ra.scope or scope,
            })
    except Exception as e:
        note("authorization", e, "role_assignments")

    # ---- Storage accounts --------------------------------------------------------
    try:
        from azure.mgmt.storage import StorageManagementClient
        st = StorageManagementClient(cred, sub_id)
        for a in st.storage_accounts.list():
            snapshot["storage"].append({
                "name": a.name,
                "allow_blob_public_access": bool(a.allow_blob_public_access),
                "min_tls": getattr(a, "minimum_tls_version", None),
                "https_only": bool(a.enable_https_traffic_only),
                "default_action": (a.network_rule_set.default_action if a.network_rule_set else "Allow"),
                "cmk": (a.encryption.key_source == "Microsoft.Keyvault") if a.encryption else False,
                "encryption_type": getattr(a.encryption, "key_source", None),
            })
    except Exception as e:
        note("storage", e, "list")

    # ---- Storage blob soft delete -------------------------------------------------------------
    try:
        from azure.mgmt.storage import StorageManagementClient
        st2 = StorageManagementClient(cred, sub_id)
        for a in st2.storage_accounts.list():
            entry = next((x for x in snapshot["storage"] if x["name"] == a.name), None)
            if entry is None:
                continue
            try:
                props = st2.blob_services.get_service_properties(
                    resource_group_name=a.id.split("/")[4], account_name=a.name)
                drp = props.delete_retention_policy
                entry["blob_soft_delete"] = bool(drp and drp.enabled)
            except Exception:
                entry["blob_soft_delete"] = False
    except Exception as e:
        note("storage", e, "blob soft delete")

    # ---- Key Vaults ----------------------------------------------------------------
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        kv = KeyVaultManagementClient(cred, sub_id)
        for v in kv.vaults.list():
            props = v.properties
            snapshot["keyvaults"].append({
                "name": v.name,
                "soft_delete": bool(getattr(props, "enable_soft_delete", False)),
                "purge_protection": bool(getattr(props, "enable_purge_protection", False)),
                "default_action": (props.network_acls.default_action
                                   if props.network_acls else "Allow"),
                "private_endpoint": bool(getattr(props, "private_endpoint_connections", None)),
                "diagnostics": False,
                "keys_without_expiry": None,
            })
    except Exception as e:
        note("keyvault", e, "list")

    # ---- NSGs ----------------------------------------------------------------------
    try:
        from azure.mgmt.network import NetworkManagementClient
        net = NetworkManagementClient(cred, sub_id)
        for n in net.network_security_groups.list_all():
            rules = []
            for r in n.security_rules or []:
                rules.append({
                    "proto": (r.protocol or "").title(),
                    "ports": r.destination_port_range or "*",
                    "source": r.source_address_prefix or (r.source_address_prefixes[0]
                                                          if r.source_address_prefixes else "*"),
                    "direction": (r.direction or "Inbound").title(),
                    "access": (r.access or "").title(),
                })
            associated = bool(n.subnets) or bool(n.network_interfaces)
            snapshot["nsgs"].append({"name": n.name, "rules": rules, "associated": associated,
                                     "flow_retention_days": 0})
    except Exception as e:
        note("network", e, "nsgs")

    # ---- SQL firewall + Key Vault diagnostics ---------------------------------------
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        mon2 = MonitorManagementClient(cred, sub_id)
        vault_ids = {}
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            kv2 = KeyVaultManagementClient(cred, sub_id)
            for v in kv2.vaults.list():
                vault_ids[v.name] = v.id
        except Exception:
            pass
        for kv_entry in snapshot["keyvaults"]:
            vid = vault_ids.get(kv_entry["name"])
            if not vid:
                continue
            try:
                diags = list(mon2.diagnostic_settings.list(resource_uri=vid))
                kv_entry["diagnostics"] = bool(diags)
            except Exception:
                pass
    except Exception as e:
        note("monitor", e, "kv diagnostics")

    # ---- Key Vault key expiry (data plane; needs the 'Key Vault Reader' role or a
    #      legacy vault access policy with 'list' on keys - metadata only) ---------------
    try:
        from azure.keyvault.keys import KeyClient
        for kv in snapshot["keyvaults"]:
            kv["keys_without_expiry"] = 0
            try:
                kc = KeyClient(vault_url=f"https://{kv['name']}.vault.azure.net",
                               credential=cred)
                for prop in kc.list_properties_of_keys():
                    if prop.expires_on is None:
                        kv["keys_without_expiry"] += 1
            except Exception:
                kv["keys_without_expiry"] = None  # data-plane perms missing
    except Exception as e:
        note("keyvault", e, "key expiry (data plane)")

    # ---- SQL ------------------------------------------------------------------------
    try:
        from azure.mgmt.sql import SqlManagementClient
        sql = SqlManagementClient(cred, sub_id)
        for srv in sql.servers.list():
            auditing = False
            try:
                policies = list(sql.server_blob_auditing_policies.list_by_server(
                    resource_group_name=srv.id.split("/")[4], server_name=srv.name))
                auditing = any(p.state == "Enabled" for p in policies)
            except Exception:
                pass
            tde = False
            try:
                dbs = list(sql.databases.list_by_server(
                    resource_group_name=srv.id.split("/")[4], server_name=srv.name))
                tde = True
                for db in dbs:
                    t = sql.transparent_data_encryptions.get(
                        resource_group_name=srv.id.split("/")[4], server_name=srv.name,
                        database_name=db.name, tde_name="current")
                    tde = tde and t.status == "Enabled"
            except Exception:
                pass
            firewall_open = False
            try:
                for fr in sql.firewall_rules.list_by_server(
                        resource_group_name=srv.id.split("/")[4], server_name=srv.name):
                    if fr.start_ip_address in ("0.0.0.0", "::") and fr.end_ip_address in ("0.0.0.0", "::", "255.255.255.255"):
                        firewall_open = True
            except Exception:
                pass
            snapshot["sql"].append({
                "name": srv.name,
                "public_network_access": bool(getattr(srv, "public_network_access", "Enabled") == "Enabled"),
                "auditing": auditing,
                "tde": tde,
                "firewall_open": firewall_open,
                # None until verified; the LTR API signature varies across
                # SDK versions, so an exception must not masquerade as "no LTR".
                "lt_retention": None,
            })
    except Exception as e:
        note("sql", e, "servers")

    # ---- Compute: disks + VMs --------------------------------------------------------
    try:
        from azure.mgmt.compute import ComputeManagementClient
        comp = ComputeManagementClient(cred, sub_id)
        for d in comp.disks.list():
            enc_type = getattr(d.encryption, "type", "") if d.encryption else ""
            snapshot["disks"].append({
                "name": d.name,
                "encryption_type": enc_type,
                "cmk": "CustomerKey" in enc_type,
            })
        nics = {}
        try:
            from azure.mgmt.network import NetworkManagementClient
            net = NetworkManagementClient(cred, sub_id)
            for nic in net.network_interfaces.list_all():
                nsg = bool(nic.network_security_group)
                if nic.ip_configurations:
                    cfg = nic.ip_configurations[0]
                    subnet_nsg = None
                    if cfg.subnet:
                        sn = net.subnets.get(cfg.subnet.id.split("/")[4],
                                             cfg.subnet.name,
                                             cfg.subnet.id.split("/")[8])
                        subnet_nsg = bool(sn.network_security_group)
                    public_ip = False
                    if cfg.public_ip_address:
                        public_ip = True
                    nics[nic.name] = {"public_ip": public_ip, "has_nsg": nsg or subnet_nsg}
        except Exception as e:
            note("network", e, "nic_map")
        for vm in comp.virtual_machines.list_all():
            has_nsg, pub = True, False
            if vm.network_profile and vm.network_profile.network_interfaces:
                for nic_ref in vm.network_profile.network_interfaces:
                    nic = nics.get(nic_ref.id.split("/")[-1], {})
                    has_nsg = has_nsg and nic.get("has_nsg", True)
                    pub = pub or nic.get("public_ip", False)
            antimalware = False
            ama = False
            try:
                rg = vm.id.split("/")[4]
                for ext in comp.virtual_machine_extensions.list(rg, vm.name):
                    en = ext.name.lower()
                    if any(k in en for k in ("antimalware", "security", "mde")):
                        antimalware = True
                    if any(k in en for k in ("azuremonitorlinuxagent",
                                             "azuremonitorwindowsagent",
                                             "azuremonitormacagent")):
                        ama = True
            except Exception:
                pass
            snapshot["vms"].append({"name": vm.name, "public_ip": pub, "nic_has_nsg": has_nsg,
                                    "antimalware": antimalware, "monitor_agent": ama})
    except Exception as e:
        note("compute", e, "disks/vms")

    # ---- Activity log diagnostics -----------------------------------------------------
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        mon = MonitorManagementClient(cred, sub_id)
        count = 0
        try:
            count = len(list(mon.diagnostic_settings.list(resource_uri=scope)))
        except Exception:
            pass
        snapshot["activity_log"] = {"diagnostic_count": count}
    except Exception as e:
        note("monitor", e, "diagnostic_settings")

    # ---- Container Registry --------------------------------------------------------------
    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        acr = ContainerRegistryManagementClient(cred, sub_id)
        for r in acr.registries.list():
            snapshot["acr"].append({
                "name": r.name,
                "admin_enabled": bool(r.admin_user_enabled),
                "public_network_access": bool(getattr(r, "public_network_access", "Enabled") == "Enabled"),
            })
    except Exception as e:
        note("containerregistry", e, "registries")

    # ---- App Services (extended) -----------------------------------------------------------
    try:
        from azure.mgmt.web import WebSiteManagementClient
        web = WebSiteManagementClient(cred, sub_id)
        for site in web.web_apps.list():
            rg = site.id.split("/")[4]
            cfg = None
            auth_enabled = False
            try:
                cfg = web.web_apps.get_configuration(resource_group_name=rg, name=site.name)
            except Exception:
                pass
            try:
                auth_enabled = bool(web.web_apps.get_auth_settings(
                    resource_group_name=rg, name=site.name).enabled)
            except Exception:
                pass
            snapshot["appservices"].append({
                "name": site.name,
                "https_only": bool(site.https_only),
                "min_tls": (cfg.min_tls_version if cfg else None),
                "client_cert": bool(getattr(cfg, "client_cert_enabled", False)) if cfg else False,
                "ftps_state": (getattr(cfg, "ftps_state", None) if cfg else None),
                "managed_identity": site.identity is not None,
                "auth_enabled": auth_enabled,
                "http_logging": bool(getattr(cfg, "http_logging_enabled", False)) if cfg else False,
                "remote_debugging": bool(getattr(cfg, "remote_debugging_enabled", False)) if cfg else False,
            })
    except Exception as e:
        note("web", e, "web_apps")

    # ---- Cosmos DB ----------------------------------------------------------------------------
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        cdb = CosmosDBManagementClient(cred, sub_id)
        for acc in cdb.database_accounts.list():
            snapshot["cosmos"].append({
                "name": acc.name,
                "public_network_access": bool(getattr(acc, "public_network_access", "Enabled") == "Enabled"),
                "local_auth": bool(getattr(acc, "disable_local_auth", False) is False),
                "backup_continuous": bool(getattr(acc, "backup_policy", None)
                                           and getattr(acc.backup_policy, "type", "").lower().startswith("continuous")),
            })
    except Exception as e:
        note("cosmosdb", e, "database_accounts")

    # ---- API Management / App Gateway --------------------------------------------------------------
    try:
        from azure.mgmt.apimanagement import ApiManagementClient
        apim = ApiManagementClient(cred, sub_id)
        for s in apim.api_management_service.list():
            snapshot["apim"].append({
                "name": s.name,
                "identity": s.identity is not None,
                "sku": (s.sku.name if s.sku else ""),
                "vnet": bool(s.virtual_network_type and s.virtual_network_type != "None"),
            })
    except Exception as e:
        note("apimanagement", e, "services")
    try:
        from azure.mgmt.network import NetworkManagementClient
        net4 = NetworkManagementClient(cred, sub_id)
        for gw in net4.application_gateways.list_all():
            waf = bool(gw.web_application_firewall_configuration or gw.waf_policy)
            snapshot["appgateways"].append({"name": gw.name, "waf": waf,
                                             "ssl_policy": bool(gw.ssl_policy)})
    except Exception as e:
        note("network", e, "application gateways")
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        mon3 = MonitorManagementClient(cred, sub_id)
        snapshot["activity_log_alerts"] = len(
            list(mon3.activity_log_alerts.list_by_subscription_id()))
    except Exception as e:
        note("monitor", e, "activity log alerts")  # stays None -> NOT_APPLICABLE

    # ---- Azure Policy / App Config / DDoS / Network Watcher / Log Analytics / Sentinel -------------
    try:
        from azure.mgmt.resource.policy import PolicyClient
        pol = PolicyClient(cred, sub_id, subscription_id=sub_id)
        snapshot["policy_assignments"] = len(list(pol.policy_assignments.list()))
        no_expiry = 0
        try:
            for ex in pol.policy_exemptions.list():
                if getattr(ex, "expires_on", None) is None:
                    no_expiry += 1
        except Exception:
            pass
        snapshot["policy_exemptions_no_expiry"] = no_expiry
    except Exception as e:
        note("policy", e, "policy_assignments")  # stays None -> NOT_APPLICABLE
    try:
        from azure.mgmt.appconfiguration import AppConfigurationManagementClient
        ac = AppConfigurationManagementClient(cred, sub_id)
        for store in ac.configuration_stores.list():
            snapshot["appconfig"].append({
                "name": store.name,
                "public_network_access": bool(getattr(store, "public_network_access", "Enabled") == "Enabled"),
                "private_endpoint": bool(getattr(store, "private_endpoint_connections", None)),
            })
    except Exception as e:
        note("appconfiguration", e, "configuration_stores")
    try:
        from azure.mgmt.network import NetworkManagementClient
        net3 = NetworkManagementClient(cred, sub_id)
        snapshot["ddos_plans"] = len(list(net3.ddos_protection_plans.list()))
        snapshot["network_watcher"]["exists"] = len(list(net3.network_watchers.list_all())) > 0
    except Exception as e:
        note("network", e, "ddos / watchers")  # stays None -> NOT_APPLICABLE
    try:
        from azure.mgmt.loganalytics import LogAnalyticsManagementClient
        la = LogAnalyticsManagementClient(cred, sub_id)
        workspaces = list(la.workspaces.list())
        snapshot["log_analytics"]["workspaces"] = len(workspaces)
        snapshot["log_analytics"]["cmk"] = False
        snapshot["log_analytics"]["short_retention"] = []
        snapshot["log_analytics"]["workspace_ids"] = []
        for w in workspaces:
            if getattr(w, "key_vault_properties", None) or getattr(w, "encryption", None):
                snapshot["log_analytics"]["cmk"] = True
            rt = getattr(w, "retention_in_days", None)
            if rt is not None and rt < 30:
                snapshot["log_analytics"]["short_retention"].append(w.name)
            if getattr(w, "id", None):
                snapshot["log_analytics"]["workspace_ids"].append((w.id, w.name))
    except Exception as e:
        note("loganalytics", e, "workspaces")  # stays None -> NOT_APPLICABLE
    try:
        from azure.mgmt.securityinsight import SecurityInsights
        si = SecurityInsights(cred, sub_id)
        count = 0
        try:
            from azure.mgmt.resource import ResourceManagementClient
            rm = ResourceManagementClient(cred, sub_id)
            for rg in rm.resource_groups.list():
                try:
                    count += len(list(si.operations.list_by_resource_group(
                        resource_group_name=rg.name)))
                except Exception:
                    continue
        except Exception:
            pass
        snapshot["sentinel"]["workspaces"] = count
        rules = 0
        try:
            for wid, wname in snapshot["log_analytics"].get("workspace_ids", []):
                try:
                    rules += len(list(si.alert_rules.list(
                        resource_group_name=wid.split("/")[4], workspace_name=wname)))
                except Exception:
                    continue
        except Exception:
            pass
        snapshot["sentinel"]["analytics_rules"] = rules
    except Exception as e:
        note("securityinsight", e, "sentinel workspaces")  # stays None -> NOT_APPLICABLE

    # ---- Event Hubs / Service Bus -------------------------------------------------------------------
    try:
        from azure.mgmt.eventhub import EventHubManagementClient
        evh = EventHubManagementClient(cred, sub_id)
        for ns in evh.namespaces.list():
            snapshot["eventhubs"].append({
                "name": ns.name,
                "public_network_access": bool(getattr(ns, "public_network_access", "Enabled") == "Enabled"),
                "cmk": ns.encryption is not None,
            })
    except Exception as e:
        note("eventhub", e, "namespaces")
    try:
        from azure.mgmt.servicebus import ServiceBusManagementClient
        sb = ServiceBusManagementClient(cred, sub_id)
        for ns in sb.namespaces.list():
            snapshot["servicebus"].append({
                "name": ns.name,
                "public_network_access": bool(getattr(ns, "public_network_access", "Enabled") == "Enabled"),
            })
    except Exception as e:
        note("servicebus", e, "namespaces")

    # ---- AKS / Redis / SQL extras / VM extras / flow logs / Bastion / Defender / custom roles ---
    try:
        from azure.mgmt.containerservice import ContainerServiceClient
        aks = ContainerServiceClient(cred, sub_id)
        for c in aks.managed_clusters.list():
            private = bool(c.api_server_access_profile
                           and c.api_server_access_profile.enable_private_cluster)
            if not private and getattr(c, "private_fqdn", None):
                private = True
            snapshot["aks"].append({
                "name": c.name,
                "rbac_enabled": bool(getattr(c, "enable_rbac", False)),
                "private_cluster": private,
                "network_policy": bool(c.network_profile
                                       and c.network_profile.network_policy),
                "azure_ad_auth": c.aad_profile is not None,
                "pod_identity": bool(c.pod_identity_profile
                                      and c.pod_identity_profile.enabled),
                "azure_policy_addon": bool(getattr(c, "azure_policy_profile", None)
                                            and c.azure_policy_profile.enabled),
                "autoscaler": (True if any(
                    getattr(p, "enable_auto_scaling", False)
                    for p in (getattr(c, "agent_pool_profiles", None) or [])
                ) else bool(getattr(c, "agent_pool_profiles", None) is None
                            and getattr(c, "autoscaler_profile", None) is not None)),
            })
    except Exception as e:
        note("containerservice", e, "managed_clusters")
    try:
        from azure.mgmt.redis import RedisManagementClient
        redis_mgmt = RedisManagementClient(cred, sub_id)
        for r in redis_mgmt.redis.list():
            snapshot["redis"].append({"name": r.name,
                                       "non_ssl_enabled": bool(r.enable_non_ssl_port),
                                       "private_endpoint": bool(getattr(r, "private_endpoint_connections", None))})
    except Exception as e:
        note("redis", e, "list")
    try:
        # SQL hardening extras: min TLS, VA, Azure AD admin (reuse sql client if present)
        try:
            sql_client
        except NameError:
            sql_client = None
        if sql_client is not None:
            server_ids = {}
            try:
                for s in sql_client.servers.list():
                    server_ids[s.name] = s.id
            except Exception:
                pass
            for srv in snapshot["sql"]:
                rid = server_ids.get(srv["name"])
                if not rid:
                    continue
                rg = rid.split("/")[4]
                try:
                    srv["min_tls"] = (sql_client.servers.get(
                        resource_group_name=rg, server_name=srv["name"])
                        .minimal_tls_version or "")
                except Exception:
                    srv["min_tls"] = ""
                srv["ad_admin"] = False
                try:
                    admins = list(sql_client.server_azure_ad_administrators.list_by_server(
                        resource_group_name=rg, server_name=srv["name"]))
                    srv["ad_admin"] = bool(admins)
                except Exception:
                    pass
                srv["va_enabled"] = False
                try:
                    va_setting = sql_client.server_vulnerability_assessments.get(
                        resource_group_name=rg, server_name=srv["name"],
                        vulnerability_assessment_name="default")
                    srv["va_enabled"] = bool(va_setting and va_setting.state == "Enabled")
                except Exception:
                    pass
                srv["lt_retention"] = False
                try:
                    for db in sql_client.databases.list_by_server(
                            resource_group_name=rg, server_name=srv["name"]):
                        try:
                            pol2 = sql_client.backup_long_term_retention_policies.get(
                                resource_group_name=rg, server_name=srv["name"],
                                database_name=db.name, policy_name="default")
                            if getattr(pol2, "weekly_retention", None):
                                srv["lt_retention"] = True
                        except Exception:
                            srv["lt_retention"] = None
                            break
                except Exception:
                    srv["lt_retention"] = None  # unverified -> NOT_APPLICABLE
    except Exception as e:
        note("sql", e, "hardening extras")
    try:
        from azure.mgmt.compute import ComputeManagementClient
        comp2 = ComputeManagementClient(cred, sub_id)
        for vm in comp2.virtual_machines.list_all():
            entry = next((x for x in snapshot["vms"] if x["name"] == vm.name), None)
            if entry is None:
                entry = {"name": vm.name, "public_ip": False, "nic_has_nsg": True,
                         "monitor_agent": False}
                snapshot["vms"].append(entry)
            bd = bool(vm.diagnostics_profile and vm.diagnostics_profile.boot_diagnostics
                      and vm.diagnostics_profile.boot_diagnostics.enabled)
            os_cmk = False
            if vm.storage_profile and vm.storage_profile.os_disk:
                md = vm.storage_profile.os_disk.managed_disk
                os_cmk = bool(md and md.disk_encryption_set_id)
            entry["boot_diagnostics"] = bd
            entry["os_disk_cmk"] = os_cmk
            sp = vm.security_profile
            entry["encryption_at_host"] = bool(sp and getattr(sp, "encryption_at_host", False))
    except Exception as e:
        note("compute", e, "vm hardening")
    try:
        # NSG flow logs (child of network watchers) + Bastion presence
        from azure.mgmt.network import NetworkManagementClient
        net2 = NetworkManagementClient(cred, sub_id)
        flow_targets = set()
        flow_retention = {}
        try:
            for w in net2.network_watchers.list_all():
                for fl in w.flow_logs or []:
                    tid = (fl.target_resource_id or "").lower()
                    flow_targets.add(tid)
                    days = 0
                    try:
                        days = int(fl.retention_policy.days) if fl.retention_policy else 0
                    except Exception:
                        pass
                    flow_retention[tid] = days
        except Exception:
            pass
        for n in snapshot["nsgs"]:
            n["flow_logs"] = any(t.endswith(("/" + n["name"]).lower()) for t in flow_targets)
            n["flow_retention_days"] = min(
                (d for t, d in flow_retention.items()
                 if t.endswith(("/" + n["name"]).lower())), default=0)
        bastions = list(net2.bastion_hosts.list())
        snapshot["bastion"] = {"exists": bool(bastions)}
    except Exception as e:
        note("network", e, "flow logs / bastion")
    try:
        from azure.mgmt.security import SecurityCenter
        sec = SecurityCenter(cred, sub_id, asc_location="centralus")
        plans = {}
        try:
            for p in sec.pricings.list():
                plans[p.name] = getattr(p, "pricing_tier", "") or ""
        except Exception:
            pass
        snapshot["defender"] = {"plans": plans, "collected": True}
    except Exception as e:
        note("security", e, "pricings")  # stays collected=False -> NOT_APPLICABLE
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
        authz2 = AuthorizationManagementClient(cred, sub_id)
        for rd in authz2.role_definitions.list(scope=scope):
            if getattr(rd, "role_type", "") != "CustomRole":
                continue
            broad = any(("*" in (p.actions or [])) or ("*" in (p.not_actions or []))
                        for p in rd.permissions or [])
            snapshot["custom_roles"].append({"name": rd.role_name or rd.name, "broad": broad})
    except Exception as e:
        note("authorization", e, "custom roles")

    # ---- Front Door (edge WAF posture) ----------------------------------------------------------
    try:
        from azure.mgmt.frontdoor import FrontDoorManagementClient
        fd = FrontDoorManagementClient(cred, sub_id)
        frontdoors = []
        try:
            for f in fd.front_doors.list():
                fe = f.frontend_endpoints or []
                frontdoors.append({
                    "name": f.name,
                    "waf": any(getattr(x, "web_application_firewall_policy_link", None)
                                for x in fe),
                    "logging": False,
                })
        except Exception:
            pass
        snapshot["frontdoors"] = frontdoors
        # Diagnostics on Front Door (activity/access logs)
        try:
            from azure.mgmt.monitor import MonitorManagementClient
            mon_fd = MonitorManagementClient(cred, sub_id)
            for entry in snapshot["frontdoors"]:
                try:
                    rm = __import__("azure.mgmt.resource", fromlist=["ResourceManagementClient"])
                    rmc = rm.ResourceManagementClient(cred, sub_id)
                    resources = list(rmc.resources.list(
                        filter=f"resourceType eq 'Microsoft.Network/frontDoors'"))
                    for r in resources:
                        if r.name == entry["name"]:
                            diags = list(mon_fd.diagnostic_settings.list(resource_uri=r.id))
                            entry["logging"] = bool(diags)
                            break
                except Exception:
                    pass
        except Exception as e:
            note("frontdoor", e, "diagnostics")
    except Exception as e:
        note("frontdoor", e, "client")  # SDK/permissions missing -> [] (NOT_APPLICABLE-ish)

    # ---- Functions (serverless auth + HTTPS) -----------------------------------------------------
    try:
        fns = []
        for site in web.web_apps.list():
            if "functionapp" not in (site.kind or "").lower():
                continue
            rg = site.id.split("/")[4]
            auth = False
            try:
                auth = bool(web.web_apps.get_auth_settings(
                    resource_group_name=rg, name=site.name).enabled)
            except Exception:
                pass
            # App-level auth off + HTTP triggers = effectively anonymous.
            fns.append({"name": site.name, "https_only": bool(site.https_only),
                        "auth_level": "anonymous" if not auth else "function"})
        snapshot["functions"] = fns
    except Exception as e:
        note("web", e, "functions")

    # ---- Entra ID (Azure AD): MFA registration + Conditional Access ---------------------------
    # Identity data lives in Microsoft Graph, not azure-mgmt. The review
    # identity needs graph scopes: User.Read.All, UserAuthenticationMethod.Read.All
    # (or Reports.Read.All), RoleManagement.Read.Directory, Policy.Read.All.
    aad = snapshot["aad"]
    try:
        token = cred.get_token(GRAPH_SCOPE).token

        # MFA-capable methods already registered per user (bulk report, beta).
        # The report is notoriously slow on large tenants -> generous timeout.
        report_state: Dict[str, bool] = {}
        try:
            for row in _graph_all(token, "https://graph.microsoft.com/beta/reports/"
                                        "authenticationMethodsUserRegistration?$top=999",
                                  timeout=120):
                report_state[(row.get("userPrincipalName") or "").lower()] = \
                    bool(row.get("isMfaRegistered"))
        except Exception as e:
            note("aad", e, "authenticationMethodsUserRegistration report")

        # Full user list.
        users_by_id = {}
        guest_count = 0
        for u in _graph_all(token, "https://graph.microsoft.com/v1.0/users?"
                                   "$select=id,userPrincipalName,accountEnabled,userType"):
            users_by_id[u.get("id")] = u
            if (u.get("userType") or "").lower() == "guest":
                guest_count += 1
        aad["guest_users"] = guest_count

        # Principals holding privileged directory roles (beta, best-effort). Only
        # high-privilege admin roles mark a user privileged - not any role.
        privileged_ids = set()
        try:
            for ra in _graph_all(token, "https://graph.microsoft.com/beta/roleManagement/"
                                        "directory/roleAssignments?$select=id,principalId,"
                                        "roleDefinitionId&$expand=roleDefinition($select=displayName)"):
                display = (ra.get("roleDefinition") or {}).get("displayName") or ""
                if display.lower() in _ADMIN_ROLES or not display:
                    privileged_ids.add(ra.get("principalId"))
        except Exception as e:
            note("aad", e, "directory role assignments")

        # MFA registration per user. ``mfa_known`` counts users whose state was
        # actually determined; if nothing could be verified the snapshot stays
        # collected=False so the checks report NOT_APPLICABLE instead of a
        # misleading wall of FAILs.
        mfa_known = 0
        for uid, u in users_by_id.items():
            upn = (u.get("userPrincipalName") or uid).lower()
            if upn in report_state:
                registered = report_state[upn]
                mfa_known += 1
            else:
                registered = False
                try:
                    methods = _graph_all(token, f"https://graph.microsoft.com/v1.0/users/"
                                                f"{uid}/authenticationMethods")
                    registered = any(
                        m.get("@odata.type", "") not in _MFA_EXEMPT_TYPES
                        for m in methods)
                    mfa_known += 1
                except Exception:
                    pass  # scope/perms missing -> state unknown, fail-closed
            aad["users"].append({
                "upn": u.get("userPrincipalName") or uid,
                "mfa_registered": registered,
                "privileged": uid in privileged_ids,
                "account_enabled": bool(u.get("accountEnabled", True)),
            })

        # Conditional Access policies (v1.0).
        for p in _graph_all(token, "https://graph.microsoft.com/v1.0/identity/"
                                   "conditionalAccess/policies"):
            cond = p.get("conditions", {})
            grants = p.get("grantControls", {})
            aad["ca_policies"].append({
                "name": p.get("displayName") or p.get("id"),
                "state": p.get("state", ""),
                "require_mfa": "mfa" in (grants.get("builtInControls") or []),
                "block_legacy_auth": (
                    "other" in (cond.get("clientAppTypes") or [])
                    and (grants.get("operator") or "").upper() == "BLOCK"
                ),
                "include_all_users": "All" in (cond.get("users", {}).get("includeUsers") or []),
                "risk_based": bool(cond.get("signInRiskLevels") or cond.get("userRiskLevels")),
            })
        aad["collected"] = mfa_known > 0
    except Exception as e:
        note("aad", e, "graph token")

    return snapshot, errors
