"""GCP collector (google-cloud-* + googleapiclient for Cloud SQL Admin).

Auth options (``auth`` dict):
  project_id : str          - GCP project to scan
  service_account_file: str - path to a service account key (recommended) or
                              rely on Application Default Credentials.
"""
from __future__ import annotations

from typing import Any, Dict, List


def collect_gcp(auth: Dict[str, Any]) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    from google.cloud import storage as gcs  # lazy
    from google.cloud import compute_v1  # lazy
    from google.cloud import kms as kms_lib  # lazy
    from google.cloud import logging as logging_lib  # lazy
    from google.cloud import container_v1  # lazy
    from google.cloud import resource_manager_v3  # lazy

    errors: List[Dict[str, Any]] = []

    def note(service: str, err: Exception, ctx: str = "") -> None:
        errors.append({"service": service, "error": str(err)[:300], "context": ctx})

    project = auth["project_id"]
    creds_kwargs = {}
    if auth.get("service_account_file"):
        creds_kwargs["credentials"] = (
            __import__("google.oauth2.service_account", fromlist=["Credentials"])
            .Credentials.from_service_account_file(auth["service_account_file"]))

    snapshot: Dict[str, Any] = {
        "project_id": project,
        "account_name": project,
        "principal": auth.get("principal") or "unknown",
        "iam": [], "sa_keys": [], "buckets": [], "firewalls": [],
        "disks": [], "instances": [], "sql": [], "kms": [],
        "audit": {"admin_activity": False, "data_access": False, "log_sinks": 0},
        "gke": [], "subnets": [], "bigquery": [], "secrets": [],
        "dns": {"dnssec_zones": 0, "total_zones": 0},
        "org_policies": {"collected": False,
                          "domain_restricted_sharing": False,
                          "vm_external_ip": False,
                          "os_login": None},
        "cloudrun": [], "memorystore": [], "artifact_repos": [],
        "functions": [], "vpn_tunnels": [], "wipools": [],
    }

    # ---- Project IAM bindings + audit config ----------------------------------------
    try:
        rmp = resource_manager_v3.ProjectsClient(**creds_kwargs)
        project_name = f"projects/{project}"
        policy = rmp.get_iam_policy(request={"resource": project_name})
        project_domain = None
        for binding in policy.bindings:
            role = binding.role
            for member in binding.members:
                mtype = "serviceAccount"
                if member == "allUsers":
                    mtype = "allUsers"
                elif member == "allAuthenticatedUsers":
                    mtype = "allAuthenticatedUsers"
                elif member.startswith("user:"):
                    mtype = "user"
                    domain = member.split(":", 1)[1].split("@", 1)[-1] if "@" in member else ""
                    if project_domain is None:
                        project_domain = domain
                    external = bool(domain and domain not in (project_domain, "gmail.com",
                                                              "googlemail.com"))
                elif member.startswith("group:"):
                    mtype = "group"
                elif member.startswith("domain:"):
                    mtype = "domain"
                snapshot["iam"].append({"member": member, "role": role, "type": mtype,
                                         "external": mtype == "user" and external})
        for ac in policy.audit_configs:
            log_types = [s.log_type for s in ac.audit_log_configs]
            if "ADMIN_READ" in log_types:
                snapshot["audit"]["admin_activity"] = True
            if "DATA_READ" in log_types or "DATA_WRITE" in log_types:
                snapshot["audit"]["data_access"] = True
    except Exception as e:
        note("resource-manager", e, "get_iam_policy")

    # ---- Service account keys ----------------------------------------------------------
    try:
        from googleapiclient.discovery import build
        from google.oauth2 import service_account
        import google.auth
        if auth.get("service_account_file"):
            sa_creds = service_account.Credentials.from_service_account_file(
                auth["service_account_file"],
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        else:
            sa_creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        iam_svc = build("iam", "v1", credentials=sa_creds, cache_discovery=False)
        accounts = iam_svc.projects().serviceAccounts().list(
            name=f"projects/{project}", pageSize=300).execute().get("accounts", [])
        from datetime import datetime, timezone
        for acc in accounts:
            keys = iam_svc.projects().serviceAccounts().keys().list(
                name=acc["name"],
                keyTypes="USER_MANAGED").execute().get("keys", [])
            oldest = 0
            for k in keys:
                try:
                    created = datetime.fromisoformat(
                        k["validAfterTime"].replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - created).days
                    oldest = max(oldest, age)
                except Exception:
                    continue
            snapshot["sa_keys"].append({"email": acc["email"], "key_count": len(keys),
                                         "oldest_key_age_days": oldest})
    except Exception as e:
        note("iam", e, "service_account_keys")

    # ---- GCS buckets ---------------------------------------------------------------------
    try:
        client = gcs.Client(project=project, **creds_kwargs)
        for b in client.list_buckets():
            public = False
            try:
                pol = b.get_iam_policy()
                for binding in pol.bindings:
                    if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                        public = True
            except Exception:
                pass
            uniform = bool(b.iam_configuration.uniform_bucket_level_access_enabled)
            versioning = bool(b.versioning_enabled)
            cmek = b.default_kms_key_name is not None
            snapshot["buckets"].append({
                "name": b.name, "public": public, "uniform": uniform,
                "versioning": versioning, "cmek": cmek,
                "retention": b.retention_policy is not None,
                "lifecycle": bool(b.lifecycle_rules),
                "logging": bool(getattr(b, "logging", None)),
            })
    except Exception as e:
        note("storage", e, "buckets")

    # ---- Compute: firewalls, disks, instances ----------------------------------------------
    try:
        fw = compute_v1.FirewallsClient(**creds_kwargs)
        for rule in fw.list(project=project):
            allowed = [{"proto": a.IProtocol, "ports": list(a.ports)}
                       for a in rule.allowed]
            snapshot["firewalls"].append({
                "name": rule.name,
                "network": rule.network.rsplit("/", 1)[-1],
                "allowed": allowed,
                "source_ranges": list(rule.source_ranges),
                "disabled": rule.disabled,
                "logging": bool(rule.log_config and rule.log_config.enable),
            })
    except Exception as e:
        note("compute", e, "firewalls")
    try:
        disks_client = compute_v1.DisksClient(**creds_kwargs)
        zones = []
        try:
            zones = [z.name for z in compute_v1.ZonesClient(**creds_kwargs).list(project=project)]
        except Exception:
            zones = ["us-central1-a", "us-central1-b", "us-central1-c", "us-east1-b",
                     "us-east1-c", "us-west1-a", "europe-west1-b"]
        seen = set()
        for zone in zones:
            for d in disks_client.list(project=project, zone=zone):
                if d.name in seen:
                    continue
                seen.add(d.name)
                snapshot["disks"].append({"name": d.name,
                                          "cmek": d.disk_encryption_key is not None})
    except Exception as e:
        note("compute", e, "disks")
    try:
        inst = compute_v1.InstancesClient(**creds_kwargs)
        for zone in zones:
            for i in inst.list(project=project, zone=zone):
                external = any(nic.access_configs for nic in i.network_interfaces)
                shielded = False
                if i.shielded_instance_config is not None:
                    shielded = (i.shielded_instance_config.enable_secure_boot
                                and i.shielded_instance_config.enable_vtpm)
                serial_port = False
            for item in (i.metadata.items if i.metadata else []) or []:
                if item.key == "serial-port-enable" and (item.value or "").lower() == "true":
                    serial_port = True
            confidential = bool(i.confidential_instance_config
                                and i.confidential_instance_config.enable_confidential_compute)
            snapshot["instances"].append({
                    "name": i.name, "external_ip": external, "shielded_vm": shielded,
                    "serial_port": serial_port, "confidential": confidential,
                    "deletion_protection": bool(i.deletion_protection)})
    except Exception as e:
        note("compute", e, "instances")

    # ---- Cloud SQL --------------------------------------------------------------------------
    try:
        from googleapiclient.discovery import build
        import google.auth
        from google.oauth2 import service_account
        if auth.get("service_account_file"):
            sa_creds = service_account.Credentials.from_service_account_file(
                auth["service_account_file"],
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        else:
            sa_creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        sql_svc = build("sqladmin", "v1beta4", credentials=sa_creds, cache_discovery=False)
        for inst in sql_svc.instances().list(project=project).execute().get("items", []):
            has_private = False
            for ip in inst.get("ipAddresses", []):
                if ip.get("type") == "PRIVATE":
                    has_private = True
            settings = inst.get("settings", {})
            ip_cfg = settings.get("ipConfiguration", {})
            require_ssl = bool(ip_cfg.get("requireSsl"))
            backup = settings.get("backupConfiguration", {}).get("enabled", False)
            ip_cfg = settings.get("ipConfiguration", {})
            auth_nets = ip_cfg.get("authorizedNetworks", [])
            broad_nets = any(n.get("value") in ("0.0.0.0/0", "::/0") for n in auth_nets)
            cmek = bool(settings.get("diskEncryptionConfiguration", {}).get("kmsKeyName"))
            snapshot["sql"].append({
                "name": inst["name"], "private_ip": has_private,
                "require_ssl": require_ssl, "backup_enabled": backup,
                "cmek": cmek, "broad_authorized_networks": broad_nets,
                "pitr": bool(settings.get("backupConfiguration", {})
                              .get("pointInTimeRecoveryEnabled", False)),
            })
    except Exception as e:
        note("sqladmin", e, "instances")

    # ---- KMS ------------------------------------------------------------------------------------
    try:
        kms_client = kms_lib.KeyManagementServiceClient(**creds_kwargs)
        locations = ["global", "us-central1", "us-east1", "europe-west1", "asia-southeast1"]
        for loc in locations:
            parent = f"projects/{project}/locations/{loc}"
            try:
                for ring in kms_client.list_key_rings(parent=parent):
                    for key in kms_client.list_crypto_keys(parent=ring.name):
                        period = 0
                        if key.rotation_period:
                            period = key.rotation_period.seconds // 86400
                        snapshot["kms"].append({"key": key.name,
                                                "rotation_period_days": period})
            except Exception:
                continue
    except Exception as e:
        note("kms", e, "list_keys")

    # ---- Logging sinks ------------------------------------------------------------------------------
    try:
        log_client = logging_lib.Client(project=project, **creds_kwargs)
        sinks = list(log_client.list_sinks())
        snapshot["audit"]["log_sinks"] = len(sinks)
    except Exception as e:
        note("logging", e, "list_sinks")

    # ---- GKE ------------------------------------------------------------------------------------------
    try:
        gke = container_v1.ClusterManagerClient(**creds_kwargs)
        for cluster in gke.list_clusters(parent=f"projects/{project}/locations/-").clusters:
            private = False
            if cluster.private_cluster_config is not None:
                private = bool(cluster.private_cluster_config.enable_private_nodes)
            net_policy = bool(cluster.network_policy.enabled) if cluster.network_policy else False
            channel = cluster.release_channel.channel.name if cluster.release_channel else ""
            pcc = cluster.private_cluster_config
            auto_upgrade = False
            auto_repair = False
            for np in (cluster.node_pools or []):
                if np.management and np.management.auto_upgrade:
                    auto_upgrade = True
                if np.management and np.management.auto_repair:
                    auto_repair = True
            snapshot["gke"].append({
                "name": cluster.name,
                "private_cluster": private,
                "network_policy": net_policy,
                "legacy_abac": bool(cluster.legacy_abac),
                "release_channel": channel or None,
                "workload_identity": cluster.workload_identity_config is not None,
                "shielded_nodes": bool(cluster.shielded_nodes and cluster.shielded_nodes.enabled),
                "private_endpoint": bool(pcc and pcc.enable_private_endpoint),
                "logging_service": bool(cluster.logging_service and "none" not in cluster.logging_service.lower()),
                "monitoring_service": bool(cluster.monitoring_service and "none" not in cluster.monitoring_service.lower()),
                "node_auto_upgrade": auto_upgrade,
                "node_auto_repair": auto_repair,
                "binary_authorization": bool(
                    cluster.binary_authorization
                    and cluster.binary_authorization.evaluation_mode
                    and cluster.binary_authorization.evaluation_mode.name != "DISABLED"),
            })
    except Exception as e:
        note("container", e, "clusters")

    # ---- VPC subnets flow logs -------------------------------------------------------------------
    try:
        sub_client = compute_v1.SubnetworksClient(**creds_kwargs)
        regions_list = ["us-central1", "us-east1", "us-west1", "europe-west1", "asia-southeast1"]
        try:
            regions_list = [r.name for r in compute_v1.RegionsClient(**creds_kwargs).list(project=project)]
        except Exception:
            pass
        for region in regions_list:
            try:
                for sn in sub_client.list(project=project, region=region):
                    snapshot["subnets"].append({"name": sn.name, "region": region,
                                                 "enable_flow_logs": bool(getattr(sn, "enable_flow_logs", False))})
            except Exception:
                continue
    except Exception as e:
        note("compute", e, "subnets")

    # ---- BigQuery datasets ---------------------------------------------------------------------------
    try:
        from google.cloud import bigquery
        bq = bigquery.Client(project=project, **creds_kwargs)
        for ds in bq.list_datasets():
            d = bq.get_dataset(ds.dataset_id)
            public = False
            try:
                pol = d.get_iam_policy()
                for b_ in pol.bindings:
                    if "allUsers" in b_["members"] or "allAuthenticatedUsers" in b_["members"]:
                        public = True
            except Exception:
                pass
            snapshot["bigquery"].append({
                "dataset_id": d.dataset_id,
                "public": public,
                "cmek": d.default_encryption_configuration is not None,
            })
    except Exception as e:
        note("bigquery", e, "datasets")

    # ---- Secret Manager ---------------------------------------------------------------------------------
    try:
        from google.cloud import secretmanager
        sm = secretmanager.SecretManagerServiceClient(**creds_kwargs)
        for s in sm.list_secrets(request={"parent": f"projects/{project}"}):
            snapshot["secrets"].append({
                "name": s.name.rsplit("/", 1)[-1],
                "rotation": s.rotation is not None,
            })
    except Exception as e:
        note("secretmanager", e, "list_secrets")

    # ---- Cloud DNS DNSSEC ----------------------------------------------------------------------------------
    try:
        from google.cloud import dns
        dns_client = dns.Client(project=project, **creds_kwargs)
        zones = list(dns_client.list_zones())
        dnssec = sum(1 for z in zones
                     if getattr(z.dnssec_config, "state", "") == "on")
        snapshot["dns"] = {"dnssec_zones": dnssec, "total_zones": len(zones)}
    except Exception as e:
        note("dns", e, "zones")

    # ---- Organization policies (best-effort; NOT_APPLICABLE if not collectable) ---------------------------
    try:
        from google.cloud import resource_manager_v3
        org_client = resource_manager_v3.OrgPolicyClient(**creds_kwargs)
        parent = f"projects/{project}"
        # Each constraint is tracked independently: None means it could not be
        # verified (so its check reports NOT_APPLICABLE rather than a false
        # FAIL), False means verified-but-not-enforced, True means enforced.
        domains_set: Any = None
        vm_ext_denied: Any = None
        os_login: Any = None
        try:
            ep = org_client.get_effective_policy(
                name=f"{parent}/constraints/iam.allowedPolicyMemberDomains")
            found = False
            for r in ep.rules:
                if r.condition is None and getattr(r, "values", None):
                    domains_set = set(r.values.values)
                    found = True
            if not found:
                domains_set = set()  # verified: policy exists but no allow-list
        except Exception:
            pass
        try:
            ep = org_client.get_effective_policy(
                name=f"{parent}/constraints/compute.vmExternalIpAccess")
            allowed = []
            for r in ep.rules:
                if r.condition is None and getattr(r, "values", None):
                    allowed = list(r.values.values)
            vm_ext_denied = not allowed  # verified: no allow-list => denied
        except Exception:
            pass
        try:
            ep = org_client.get_effective_policy(
                name=f"{parent}/constraints/compute.requireOsLogin")
            os_login = False
            for r in ep.rules:
                if r.condition is None and getattr(r, "values", None) and r.values.values:
                    os_login = True
        except Exception:
            pass
        if domains_set is not None or vm_ext_denied is not None or os_login is not None:
            snapshot["org_policies"]["collected"] = True
            snapshot["org_policies"]["domain_restricted_sharing"] = bool(domains_set) \
                if domains_set is not None else None
            snapshot["org_policies"]["vm_external_ip"] = vm_ext_denied
            snapshot["org_policies"]["os_login"] = os_login
    except Exception as e:
        note("resource-manager", e, "org policies")

    # ---- Cloud Run -----------------------------------------------------------------------------------
    try:
        from google.cloud import run_v2
        from google.iam.v1 import iam_policy_pb2
        run_client = run_v2.ServicesClient(**creds_kwargs)
        for svc in run_client.list_services(parent=f"projects/{project}/locations/-"):
            unauth = False
            try:
                policy = run_client.get_iam_policy(
                    request=iam_policy_pb2.GetIamPolicyRequest(resource=svc.name))
                for b_ in policy.bindings:
                    if "allUsers" in b_.members or "allAuthenticatedUsers" in b_.members:
                        unauth = True
            except Exception:
                pass
            ingress_all = bool(svc.ingress and svc.ingress.name == "INGRESS_TRAFFIC_ALL")
            ann = dict(getattr(svc.template, "annotations", None) or {})
            cpu_always = ann.get("run.googleapis.com/cpu-throttling", "true").lower() == "false"
            try:
                max_inst = int(ann.get("autoscaling.knative.dev/maxScale", "0") or 0)
            except Exception:
                max_inst = 0
            snapshot["cloudrun"].append({
                "name": svc.name.rsplit("/", 1)[-1],
                "unauthenticated": unauth,
                "ingress_all": ingress_all,
                "cpu_always_allocated": cpu_always,
                "max_instances": max_inst,
                "vpc_connector": bool(svc.template and svc.template.vpc_access
                                       and svc.template.vpc_access.connector),
            })
    except Exception as e:
        note("run", e, "services")

    # ---- Cloud Functions ---------------------------------------------------------------------------------
    try:
        from google.cloud import functions_v2
        from google.iam.v1 import iam_policy_pb2
        func_client = functions_v2.FunctionServiceClient(**creds_kwargs)
        for fn in func_client.list_functions(
                parent=f"projects/{project}/locations/-"):
            unauth = False
            try:
                pol = func_client.get_iam_policy(
                    request=iam_policy_pb2.GetIamPolicyRequest(resource=fn.name))
                for b in pol.bindings:
                    if "allUsers" in b.members or "allAuthenticatedUsers" in b.members:
                        unauth = True
            except Exception:
                pass
            vpc = bool(fn.service_config and fn.service_config.vpc_connector)
            snapshot["functions"].append({
                "name": fn.name.rsplit("/", 1)[-1],
                "unauthenticated": unauth,
                "vpc_connector": vpc,
            })
    except Exception as e:
        note("functions", e, "functions")

    # ---- Cloud VPN tunnels -------------------------------------------------------------------------------
    try:
        from google.cloud import compute_v1
        vpn = compute_v1.VpnTunnelsClient(**creds_kwargs)
        for region in regions_list:
            try:
                for t in vpn.list(project=project, region=region):
                    snapshot["vpn_tunnels"].append({
                        "name": t.name,
                        "ike_version": int(getattr(t, "ike_version", 2) or 2),
                    })
            except Exception:
                continue
    except Exception as e:
        note("compute", e, "vpn tunnels")

    # ---- Workload Identity pools --------------------------------------------------------------------------
    try:
        from googleapiclient.discovery import build
        import google.auth
        from google.oauth2 import service_account
        if auth.get("service_account_file"):
            sa_creds = service_account.Credentials.from_service_account_file(
                auth["service_account_file"],
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        else:
            sa_creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"])
        iam_svc = build("iam", "v1", credentials=sa_creds, cache_discovery=False)
        pools = (iam_svc.projects().locations().workloadIdentityPools().list(
            parent=f"projects/{project}/locations/global",
            pageSize=100).execute().get("workloadIdentityPools", []))
        for p in pools:
            providers = (iam_svc.projects().locations().workloadIdentityPools()
                         .providers().list(
                             parent=p["name"], pageSize=100).execute()
                         .get("workloadIdentityPoolsProviders", []))
            snapshot["wipools"].append({
                "name": p.get("name", "").rsplit("/", 1)[-1],
                "providers": len(providers),
            })
    except Exception as e:
        note("iam", e, "workload identity pools")

    # ---- Artifact Registry ------------------------------------------------------------------------------
    try:
        from google.cloud import artifactregistry_v1
        ar = artifactregistry_v1.ArtifactRegistryClient(**creds_kwargs)
        seen_ar = set()
        for loc in ("us-central1", "us-east1", "europe-west1", "asia-southeast1", "global"):
            try:
                for repo in ar.list_repositories(
                        parent=f"projects/{project}/locations/{loc}"):
                    if repo.name in seen_ar:
                        continue
                    seen_ar.add(repo.name)
                    public = False
                    try:
                        pol = ar.get_iam_policy(request={"resource": repo.name})
                        for b in pol.bindings:
                            if "allUsers" in b.members or "allAuthenticatedUsers" in b.members:
                                public = True
                    except Exception:
                        pass
                    snapshot["artifact_repos"].append({
                        "name": repo.name.rsplit("/", 1)[-1],
                        "public": public,
                        "cmk": bool(getattr(repo, "kms_key_name", None)
                                    or getattr(repo, "kms_key", None)),
                    })
            except Exception:
                continue
    except Exception as e:
        note("artifactregistry", e, "repositories")

    # ---- Memorystore (Redis) --------------------------------------------------------------------------
    try:
        from google.cloud import redis_v1
        redis_client = redis_v1.CloudRedisClient(**creds_kwargs)
        try:
            for inst in redis_client.list_instances(
                    parent=f"projects/{project}/locations/-").instances:
                transit = bool(inst.transit_encryption_mode
                               and inst.transit_encryption_mode.name == "SERVER_AUTHENTICATION")
                auth = bool(inst.auth_enabled)
                private = bool(inst.private_service_connect or inst.host
                               and inst.host.startswith("10."))
                pc = getattr(inst, "persistence_config", None)
                persistence = bool(pc and getattr(pc, "persistence_mode", None)
                                   and pc.persistence_mode.name in ("RDB", "AOF", "RDB_AOF"))
                snapshot["memorystore"].append({
                    "name": inst.name.rsplit("/", 1)[-1],
                    "transit_encryption": transit,
                    "auth_enabled": auth,
                    "private_ip": private,
                    "persistence": persistence,
                })
        except Exception:
            # older API shape: iterate locations
            for loc in ("global", "us-central1", "us-east1", "europe-west1"):
                try:
                    for inst in redis_client.list_instances(
                            parent=f"projects/{project}/locations/{loc}").instances:
                        pc = getattr(inst, "persistence_config", None)
                        snapshot["memorystore"].append({
                            "name": inst.name.rsplit("/", 1)[-1],
                            "transit_encryption": bool(inst.transit_encryption_mode
                                                       and inst.transit_encryption_mode.name == "SERVER_AUTHENTICATION"),
                            "auth_enabled": bool(inst.auth_enabled),
                            "private_ip": bool(inst.host and inst.host.startswith("10.")),
                            "persistence": bool(pc and getattr(pc, "persistence_mode", None)
                                                 and pc.persistence_mode.name in ("RDB", "AOF", "RDB_AOF")),
                        })
                except Exception:
                    continue
    except Exception as e:
        note("redis", e, "instances")

    # ---- Vertex AI notebooks (ML platform security) ----------------------------------------------
    try:
        from google.cloud import notebooks_v1
        nbc = notebooks_v1.NotebookServiceClient(**creds_kwargs)
        notebooks = []
        try:
            parent = f"projects/{project}/locations/-"
            for inst in nbc.list_instances(parent=parent):
                notebooks.append({
                    "name": inst.name.split("/")[-1],
                    "external_ip": bool(getattr(inst, "no_proxy_access", False)),
                    "cmek": bool(getattr(inst, "kms_key", "")),
                })
        except Exception as e:
            note("vertex-ai", e, "notebooks")
        snapshot["vertex_ai"] = {"notebooks": notebooks}
    except Exception as e:
        note("vertex-ai", e, "client")  # SDK/permissions missing -> []

    # ---- Pub/Sub topics (CMEK on messages at rest) ------------------------------------------------
    try:
        from google.cloud import pubsub_v1
        pub = pubsub_v1.PublisherClient(**creds_kwargs)
        topics = []
        try:
            for t in pub.list_topics(request={"project": project}):
                topics.append({"name": t.name.split("/")[-1],
                               "cmek": bool(t.kms_key_name)})
        except Exception as e:
            note("pubsub", e, "topics")
        snapshot["pubsub"] = topics
    except Exception as e:
        note("pubsub", e, "client")

    return snapshot, errors
