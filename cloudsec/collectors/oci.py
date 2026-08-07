"""OCI collector (oci SDK).

Auth options (``auth`` dict):
  config_file : str  - path to OCI config (default ~/.oci/config)
  profile     : str  - config profile (default DEFAULT)
  compartment : str  - compartment OCID (default: tenancy root)
"""
from __future__ import annotations

from typing import Any, Dict, List


def collect_oci(auth: Dict[str, Any]) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    import oci  # lazy
    from oci.config import from_file

    errors: List[Dict[str, Any]] = []

    def note(service: str, err: Exception, ctx: str = "") -> None:
        errors.append({"service": service, "error": str(err)[:300], "context": ctx})

    config = from_file(auth.get("config_file"),
                        auth.get("oci_profile") or auth.get("profile")) if auth.get("config_file") \
        else from_file()
    tenancy = config["tenancy"]
    identity = oci.identity.IdentityClient(config)
    user = identity.get_user(config["user"]).data
    compartment = auth.get("compartment") or tenancy

    snapshot: Dict[str, Any] = {
        "tenancy": tenancy,
        "account_name": tenancy,
        "principal": config["user"],
        "users": [], "policies": [], "buckets": [], "sec_lists": [],
        "nsgs": [], "volumes": [], "adbs": [], "keys": [],
        "cloud_guard": {"enabled": False, "detectors_enabled": 0},
        "subnets": [], "igws": [], "lbs": [],
        "bastion": {"exists": False},
        "filesystems": [], "route_tables": [], "nat_gateways": 0,
        "osms": {"managed_instances": 0, "managed_instance_groups": 0},
        "audit": {"retention_days": None},
        "nosql_tables": [], "dns_zones": {"total": 0, "dnssec_off": []},
        "db_backups": {"count": 0, "db_systems": 0},
    }

    # ---- IAM users / MFA / API keys -------------------------------------------------
    try:
        for u in identity.list_users(compartment_id=tenancy).data:
            mfa = False
            try:
                mfa_devices = identity.list_mfa_totp_devices(
                    user_id=u.id).data
                mfa = any(d.is_activated for d in mfa_devices)
            except Exception:
                pass
            api_keys = 0
            max_key_age = 0
            try:
                from datetime import datetime, timezone
                for k in identity.list_api_keys(user_id=u.id).data:
                    api_keys += 1
                    created = getattr(k, "time_created", None)
                    if created:
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                        age = max(0, (datetime.now(timezone.utc) - created).days)
                        max_key_age = max(max_key_age, age)
            except Exception:
                pass
            snapshot["users"].append({
                "name": u.name, "mfa_enabled": mfa,
                "has_console_password": True,  # OCI users have console by default
                "api_keys": api_keys, "max_api_key_age": max_key_age,
            })
    except Exception as e:
        note("identity", e, "list_users")

    # ---- IAM policies -------------------------------------------------------------------
    try:
        for p in identity.list_policies(compartment_id=tenancy).data:
            broad = any("manage all-resources" in s.lower() and "tenancy" in s.lower()
                        for s in p.statements)
            snapshot["policies"].append({"name": p.name, "statements": p.statements,
                                         "broad_manage": broad})
    except Exception as e:
        note("identity", e, "list_policies")

    # ---- Object storage --------------------------------------------------------------------
    try:
        os_client = oci.object_storage.ObjectStorageClient(config)
        ns = os_client.get_namespace().data
        for b in os_client.list_buckets(compartment_id=compartment, namespace_name=ns).data:
            bucket = os_client.get_bucket(namespace_name=ns, bucket_name=b.name).data
            par_count = 0
            par_no_expiry = 0
            try:
                for p in os_client.list_preauthenticated_requests(
                        namespace_name=ns, bucket_name=bucket.name).data:
                    par_count += 1
                    if getattr(p, "time_expires", None) is None:
                        par_no_expiry += 1
            except Exception:
                pass
            snapshot["buckets"].append({
                "name": bucket.name,
                "public_type": bucket.public_access_type,
                "versioning": bool(bucket.versioning == "Enabled"),
                "cmk": bucket.kms_key_id is not None,
                "par_count": par_count,
                "par_no_expiry": par_no_expiry,
            })
    except Exception as e:
        note("object-storage", e, "buckets")

    # ---- VCN: security lists, NSGs, subnets -----------------------------------------------
    try:
        core = oci.core.VirtualNetworkClient(config)
        for sl in core.list_security_lists(compartment_id=compartment).data:
            ingress = []
            for rule in sl.ingress_security_rules:
                ports = None
                if rule.tcp_options:
                    ports = (rule.tcp_options.destination_port_range.min,
                             rule.tcp_options.destination_port_range.max)
                elif rule.udp_options:
                    ports = (rule.udp_options.destination_port_range.min,
                             rule.udp_options.destination_port_range.max)
                ingress.append({"proto": rule.protocol, "src": rule.source,
                                "ports": ports})
            snapshot["sec_lists"].append({"id": sl.id, "name": sl.display_name,
                                          "ingress": ingress})
        for nsg in core.list_network_security_groups(compartment_id=compartment).data:
            open_ingress = False
            try:
                for rule in core.list_network_security_group_security_rules(
                        network_security_group_id=nsg.id).data:
                    if rule.direction == "INGRESS" and rule.source == "0.0.0.0/0":
                        ports = None
                        if rule.tcp_options:
                            ports = (rule.tcp_options.destination_port_range.min,
                                     rule.tcp_options.destination_port_range.max)
                        if ports is None or ports[0] in (22, 3389) or ports[0] <= 22 <= ports[1]:
                            open_ingress = True
            except Exception:
                pass
            referenced = True  # fail-closed default
            try:
                referenced = len(core.list_network_security_group_vnics(
                    network_security_group_id=nsg.id).data) > 0
            except Exception:
                pass
            snapshot["nsgs"].append({"id": nsg.id, "name": nsg.display_name,
                                     "open_ingress": open_ingress, "referenced": referenced})
        for sub in core.list_subnets(compartment_id=compartment).data:
            snapshot["subnets"].append({"name": sub.display_name,
                                        "flow_log_enabled": bool(getattr(sub, "enable_flow_logs", False))})
        for igw in core.list_internet_gateways(compartment_id=compartment).data:
            snapshot["igws"].append({"id": igw.id, "name": igw.display_name,
                                     "enabled": igw.is_enabled})
    except Exception as e:
        note("vcn", e, "security lists / nsgs / igws")

    # ---- Load balancers ------------------------------------------------------------------
    try:
        lb_client = oci.load_balancer.LoadBalancerClient(config)
        for lb in lb_client.list_load_balancers(compartment_id=compartment).data:
            public = not lb.is_private
            ssl = False
            try:
                detail = lb_client.get_load_balancer(lb.id).data
                for ls in detail.listeners.values():
                    if ls.ssl_configuration:
                        ssl = True
            except Exception:
                pass
            snapshot["lbs"].append({"name": lb.display_name, "public": public,
                                    "ssl_listener": ssl})
    except Exception as e:
        note("load-balancer", e, "list")

    # ---- Block storage --------------------------------------------------------------------------
    try:
        bv = oci.core.BlockstorageClient(config)
        for vol in bv.list_volumes(compartment_id=compartment).data:
            backup_count = 0
            try:
                backup_count = len(bv.list_volume_backups(compartment_id=compartment,
                                                          volume_id=vol.id).data)
            except Exception:
                pass
            snapshot["volumes"].append({"id": vol.id, "name": vol.display_name,
                                        "type": "block", "cmk": vol.kms_key_id is not None,
                                        "backup_count": backup_count})
        try:
            for av in bv.list_availability_domains(compartment_id=compartment).data:
                for boot in bv.list_boot_volumes(compartment_id=compartment,
                                                 availability_domain=av.name).data:
                    backup_count = 0
                    try:
                        backup_count = len(bv.list_boot_volume_backups(
                            compartment_id=compartment, boot_volume_id=boot.id).data)
                    except Exception:
                        pass
                    snapshot["volumes"].append({"id": boot.id, "name": boot.display_name,
                                                "type": "boot", "cmk": boot.kms_key_id is not None,
                                                "backup_count": backup_count})
        except Exception:
            pass
    except Exception as e:
        note("blockstorage", e, "volumes")

    # ---- Autonomous Database ---------------------------------------------------------------------
    try:
        db = oci.database.DatabaseClient(config)
        for adb in db.list_autonomous_databases(compartment_id=compartment).data:
            snapshot["adbs"].append({
                "name": adb.db_name,
                "public_endpoint": adb.subnet_id is None,  # private endpoint => subnet set
                "cmk": adb.kms_key_id is not None,
                "data_guard": bool(getattr(adb, "is_data_guard_enabled", False)),
                "backup_retention_days": int(getattr(adb, "backup_retention_period_in_days", 0) or 0),
                "auto_scaling": bool(getattr(adb, "is_auto_scaling_enabled", False)),
            })
    except Exception as e:
        note("database", e, "autonomous")

    # ---- Vault keys ---------------------------------------------------------------------------------
    try:
        kms_mgmt = oci.key_management.KmsManagementClient(config)
        vaults = oci.key_management.KmsVaultClient(config).list_vaults(
            compartment_id=compartment).data
        for vault in vaults:
            kms_mgmt.base_client.host = vault.management_endpoint
            try:
                for key in kms_mgmt.list_keys(compartment_id=compartment).data:
                    rotation = False
                    if key.is_auto_rotation_enabled:
                        rotation = True
                    snapshot["keys"].append({"key": key.display_name,
                                             "rotation_enabled": rotation})
            except Exception:
                continue
    except Exception as e:
        note("kms", e, "vault keys")

    # ---- Cloud Guard -----------------------------------------------------------------------------------
    try:
        cg = oci.cloud_guard.CloudGuardClient(config)
        targets = cg.list_targets(compartment_id=compartment).data
        snapshot["cloud_guard"]["enabled"] = len(targets) > 0
        det_enabled = 0
        try:
            for d in cg.list_detector_recipes(compartment_id=compartment).data:
                det_enabled += 1
        except Exception:
            pass
        snapshot["cloud_guard"]["detectors_enabled"] = det_enabled
    except Exception as e:
        note("cloud-guard", e, "list_targets")

    # ---- Bastion ------------------------------------------------------------------------------------------
    try:
        bas = oci.bastion.BastionClient(config)
        snapshot["bastion"]["exists"] = len(bas.list_bastions(compartment_id=compartment).data) > 0
    except Exception as e:
        note("bastion", e, "list_bastions")

    # ---- Route tables / NAT gateways ------------------------------------------------------------------------
    try:
        core2 = oci.core.VirtualNetworkClient(config)
        for rt in core2.list_route_tables(compartment_id=compartment).data:
            public_default = any(
                r.destination in ("0.0.0.0/0", "::/0")
                and getattr(r, "network_entity_type", "") == "InternetGateway"
                for r in rt.route_rules)
            snapshot["route_tables"].append({"name": rt.display_name,
                                             "public_default_route": public_default})
        snapshot["nat_gateways"] = len(core2.list_nat_gateways(compartment_id=compartment).data)
    except Exception as e:
        note("vcn", e, "route tables / nat")

    # ---- File Storage ----------------------------------------------------------------------------------------
    try:
        fs = oci.file_storage.FileStorageClient(config)
        for f in fs.list_file_systems(compartment_id=compartment).data:
            snap_count = 0
            try:
                snap_count = len(fs.list_snapshots(
                    file_system_id=f.id).data)
            except Exception:
                pass
            snapshot["filesystems"].append({
                "name": f.display_name,
                "cmk": f.kms_key_id is not None,
                "snapshots": snap_count,
            })
    except Exception as e:
        note("file-storage", e, "file systems")

    # ---- OS Management Service (patch compliance) -------------------------------------------------------------
    try:
        osm = oci.os_management.OsManagementClient(config)
        snapshot["osms"]["managed_instances"] = len(
            osm.list_managed_instances(compartment_id=compartment).data)
        snapshot["osms"]["managed_instance_groups"] = len(
            osm.list_managed_instance_groups(compartment_id=compartment).data)
    except Exception as e:
        note("os-management", e, "managed instances")  # stays 0 -> FAIL if collectable

    # ---- NoSQL tables / DNS DNSSEC / DB backups ------------------------------------------------
    try:
        nosql = oci.nosql.NosqlClient(config)
        snapshot["nosql_tables"] = []
        for t in nosql.list_tables(compartment_id=compartment).data:
            has_limits = False
            try:
                detail = nosql.get_table(table_name_or_id=t.name_or_id).data
                has_limits = detail.table_limits is not None
            except Exception:
                pass
            snapshot["nosql_tables"].append({"name": t.name_or_id, "has_limits": has_limits})
    except Exception as e:
        note("nosql", e, "tables")
    try:
        dns = oci.dns.DnsClient(config)
        zones = dns.list_zones(compartment_id=compartment).data
        dnssec_off = [z.name for z in zones
                      if getattr(z, "dnssec_state", "") != "ENABLED"]
        snapshot["dns_zones"] = {"total": len(zones), "dnssec_off": dnssec_off}
    except Exception as e:
        note("dns", e, "zones")
    try:
        db2 = oci.database.DatabaseClient(config)
        backups = len(db2.list_db_backups(compartment_id=compartment).data)
        db_systems = len(db2.list_db_systems(compartment_id=compartment).data)
        snapshot["db_backups"] = {"count": backups, "db_systems": db_systems}
    except Exception as e:
        note("database", e, "db backups")

    # ---- Audit configuration (retention period) ------------------------------------------------
    try:
        audit = oci.audit.AuditClient(config)
        cfg = audit.get_configuration(compartment_id=compartment).data
        snapshot["audit"]["retention_days"] = int(
            getattr(cfg, "retention_period_days", 0) or 0)
    except Exception as e:
        note("audit", e, "configuration")  # stays None -> NOT_APPLICABLE

    # ---- Object storage lifecycle policy + volume replicas -----------------------------------------------------
    try:
        os_client2 = oci.object_storage.ObjectStorageClient(config)
        ns2 = os_client2.get_namespace().data
        for b in snapshot["buckets"]:
            try:
                os_client2.get_lifecycle_policy(bucket_name=b["name"], namespace_name=ns2)
                b["lifecycle_policy"] = True
            except Exception:
                b["lifecycle_policy"] = False
    except Exception as e:
        note("object-storage", e, "lifecycle")
    try:
        bv2 = oci.core.BlockstorageClient(config)
        replica_vols = set()
        try:
            for r in bv2.list_volume_replicas(compartment_id=compartment).data:
                replica_vols.add(r.volume_id)
        except Exception:
            pass
        for v in snapshot["volumes"]:
            v["has_replica"] = v.get("id") in replica_vols
    except Exception as e:
        note("blockstorage", e, "replicas")

    # ---- API Gateway (edge API security) -----------------------------------------------------------
    try:
        from oci.apigateway import ApiGatewayClient
        agw = ApiGatewayClient(config)
        gateways = []
        try:
            for g in agw.list_gateways(compartment_id=compartment).data:
                gateways.append({
                    "name": g.display_name,
                    "public": (g.endpoint_type or "").upper() == "PUBLIC",
                    "waf": False,   # WAF association is best-effort; verified below
                    "tls": bool(getattr(g, "certificate_id", None)
                                or getattr(g, "ca_bundles", None)),
                })
        except Exception as e:
            note("apigateway", e, "gateways")
        # WAF policies: check for any WebAppFirewall policy in the compartment
        try:
            from oci.waf import WafClient
            waf_c = WafClient(config)
            waf_attached = False
            try:
                waf_attached = any(waf_c.list_web_app_firewall_policies(
                    compartment_id=compartment).data)
            except Exception:
                pass
            for g in gateways:
                g["waf"] = waf_attached
        except Exception:
            pass
        snapshot["api_gateways"] = gateways
    except Exception as e:
        note("apigateway", e, "client")

    return snapshot, errors
