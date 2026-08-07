"""Demo data: realistic normalized snapshots for all four clouds.

The demo environment mimics a mid-size production landing zone with a mix of
hardened and misconfigured resources so the dashboard, comparison and coverage
features are fully exercisable without any cloud credentials.
"""
from __future__ import annotations

from typing import Dict, Any


def aws_snapshot() -> Dict[str, Any]:
    return {
        "account_id": "111122223333",
        "account_name": "demo-prod-aws",
        "principal": "arn:aws:iam::111122223333:user/security-reviewer",
        "iam": {
            "password_policy": {
                "minimum_password_length": 16,
                "require_symbols": True,
                "require_numbers": True,
                "require_uppercase_characters": True,
                "require_lowercase_characters": True,
                "max_password_age": 90,
            },
            "root": {"access_keys_active": False, "mfa_enabled": True, "access_key_count": 0},
            "users": [
                {"name": "alice", "has_console_password": True, "mfa_enabled": True, "keys": []},
                {"name": "bob", "has_console_password": True, "mfa_enabled": False, "keys": []},
                {"name": "ci-bot", "has_console_password": False, "mfa_enabled": False,
                 "keys": [
                     {"id": "AKIAEXAMPLE12345", "age_days": 45, "active": True},
                     {"id": "AKIASTALE98765", "age_days": 210, "active": True},
                 ]},
            ],
            "admin_policies": [],
            "cross_account_roles": ["delegated-role"],
        },
        "s3": [
            {"name": "prod-data", "public": False, "public_acl": None,
             "encryption": True, "versioning": True, "logging": True, "lifecycle": True,
             "mfa_delete": True, "object_lock": True},
            {"name": "legacy-public", "public": False, "public_acl": None,
             "encryption": True, "versioning": True, "logging": False, "lifecycle": False,
             "mfa_delete": False, "object_lock": False},
            {"name": "backups", "public": False, "public_acl": None,
             "encryption": False, "versioning": True, "logging": True, "lifecycle": True,
             "mfa_delete": False, "object_lock": False},
            {"name": "archive", "public": False, "public_acl": None,
             "encryption": True, "versioning": False, "logging": True, "lifecycle": False,
             "mfa_delete": False, "object_lock": False},
        ],
        "ec2": {
            "security_groups": [
                {"id": "sg-01", "name": "sg-web",
                 "ingress": [
                     {"proto": "tcp", "ports": (443, 443), "cidr": ["0.0.0.0/0"]},
                     {"proto": "tcp", "ports": (22, 22), "cidr": ["0.0.0.0/0"]},
                 ]},
                {"id": "sg-02", "name": "sg-app",
                 "ingress": [{"proto": "tcp", "ports": (443, 443), "cidr": ["10.0.0.0/8"]}]},
                {"id": "sg-03", "name": "sg-db",
                 "ingress": [{"proto": "tcp", "ports": (3306, 3306), "cidr": ["0.0.0.0/0"]}]},
            ],
            "volumes": [
                {"id": "01", "encrypted": True},
                {"id": "02", "encrypted": False},
            ],
            "instances": [
                {"id": "01", "public_ip": "54.1.2.3", "security_groups": ["sg-01"],
                 "imdsv2": False, "termination_protection": False, "monitoring": False},
                {"id": "02", "public_ip": None, "security_groups": ["sg-02"],
                 "imdsv2": True, "termination_protection": True, "monitoring": True},
                {"id": "03", "public_ip": "54.7.8.9", "security_groups": [],
                 "imdsv2": False, "termination_protection": False, "monitoring": False},
            ],
            "amis": [
                {"id": "01", "public": False},
                {"id": "02", "public": True},
            ],
            "ebs_default_encryption": False,
            "default_sg_open": True,
        },
        "rds": [
            {"id": "prod-db", "publicly_accessible": True, "storage_encrypted": True,
             "backup_retention_days": 14, "deletion_protection": True, "multi_az": True,
             "minor_version": "15.7", "log_exports": True, "auto_minor_upgrade": True,
             "enhanced_monitoring": True},
            {"id": "stage-db", "publicly_accessible": False, "storage_encrypted": False,
             "backup_retention_days": 3, "deletion_protection": False, "multi_az": False,
             "minor_version": "14.2", "log_exports": False, "auto_minor_upgrade": False,
             "enhanced_monitoring": False},
        ],
        "sns": [{"topic_arn": "arn:aws:sns:us-east-1:111122223333:alerts", "public": True,
                  "kms_encrypted": False}],
        "trail": {"exists": True, "multi_region": True, "log_file_validation": False,
                   "logging": True, "s3_bucket_encrypted": False, "kms_key_id": False},
        "config": {"recorder": False, "delivering": False},
        "kms": [
            {"key_id": "prod", "rotation_enabled": True},
            {"key_id": "legacy", "rotation_enabled": False},
        ],
        "ecr": [
            {"repo_name": "prod-images", "public": False, "scan_on_push": True,
             "lifecycle_policy": True},
            {"repo_name": "legacy", "public": True, "scan_on_push": False,
             "lifecycle_policy": False},
        ],
        "lambda": [
            {"name": "ingest", "runtime": "python3.12", "public_policy": False,
             "in_vpc": True, "tracing": True},
            {"name": "old-etl", "runtime": "python3.7", "public_policy": True,
             "in_vpc": False, "tracing": False},
        ],
        "vpcs": [
            {"id": "vpc-prod", "is_default": False, "flow_logs": True, "has_igw": True},
            {"id": "vpc-default", "is_default": True, "flow_logs": False, "has_igw": True},
        ],
        "nacls": [
            {"id": "acl-prod", "open_all": False},
            {"id": "acl-legacy", "open_all": True},
        ],
        "guardduty": [{"id": "detector-main", "enabled": True, "s3_protection": False}],
        "secrets": [
            {"name": "prod-db-password", "rotation_enabled": True, "kms_cmk": True},
            {"name": "legacy-api-key", "rotation_enabled": False, "kms_cmk": False},
        ],
        "sqs": [
            {"url": "https://sqs.us-east-1.amazonaws.com/111122223333/alerts",
             "public": True, "encrypted": False, "has_dlq": False},
            {"url": "https://sqs.us-east-1.amazonaws.com/111122223333/jobs",
             "public": False, "encrypted": True, "has_dlq": True},
        ],
        "dynamodb": [
            {"name": "orders", "pitr": True, "sse": True, "public": False,
             "deletion_protection": True},
            {"name": "legacy-log", "pitr": False, "sse": False, "public": False,
             "deletion_protection": False},
        ],
        "redshift": [
            {"id": "analytics", "public": True, "encrypted": True, "logging": False},
            {"id": "warehouse", "public": False, "encrypted": True, "logging": True},
        ],
        "efs": [
            {"id": "fs-prod", "encrypted": True, "backup": True, "lifecycle_policy": True},
            {"id": "fs-legacy", "encrypted": False, "backup": False, "lifecycle_policy": False},
        ],
        "elasticache": [
            {"id": "cache-prod", "engine": "redis", "at_rest": True, "transit": True},
            {"id": "cache-legacy", "engine": "redis", "at_rest": False, "transit": False},
        ],
        "elb": [
            {"name": "web-alb", "type": "application", "https": True, "access_logs": True,
             "ssl_policy_secure": True, "http_no_redirect": False, "waf_attached": True,
             "deletion_protection": True},
            {"name": "legacy-elb", "type": "classic", "https": False, "access_logs": False,
             "ssl_policy_secure": False, "http_no_redirect": True, "waf_attached": False,
             "deletion_protection": False},
            {"name": "stage-alb", "type": "application", "https": True, "access_logs": False,
             "ssl_policy_secure": True, "http_no_redirect": False, "waf_attached": True,
             "deletion_protection": False},
        ],
        "acm": [
            {"arn": "arn:aws:acm:us-east-1:111122223333:cert/prod", "in_use": True,
             "days_to_expiry": 300},
            {"arn": "arn:aws:acm:us-east-1:111122223333:cert/expiring", "in_use": True,
             "days_to_expiry": 12},
        ],
        "eks": [
            {"name": "prod-eks", "public_endpoint": False, "logging_enabled": True},
            {"name": "legacy-eks", "public_endpoint": True, "logging_enabled": False},
        ],
        "apigw": [
            {"name": "payments-api", "public": True, "logging": True},
            {"name": "internal-api", "public": True, "logging": False},
        ],
        "r53": {"dnssec": False, "query_logging": False, "zone_count": 2},
        "cw": {"metric_alarms": ["root-account-usage-alarm", "iam-policy-change-alarm"],
                "dashboards": 0},
        "cloudfront": [
            {"id": "E1PROD", "waf_attached": True, "min_tls": "TLSv1.2_2021",
             "logging": True, "default_cert": False, "origin_http": False,
             "geo_restricted": True, "field_level_encryption": True, "oac_oai": True},
            {"id": "E2LEGACY", "waf_attached": False, "min_tls": "TLSv1",
             "logging": False, "default_cert": True, "origin_http": True,
             "geo_restricted": False, "field_level_encryption": False, "oac_oai": False},
        ],
        "loggroups": [
            {"name": "/aws/lambda/ingest", "retention_days": 400, "encrypted": True},
            {"name": "/aws/lambda/old-etl", "retention_days": 30, "encrypted": False},
            {"name": "/aws/rds/prod-db", "retention_days": None, "encrypted": False},
        ],
        "snapshots": [
            {"id": "snap-prod", "public": False, "encrypted": True},
            {"id": "snap-leaked", "public": True, "encrypted": False},
        ],
        "backup": {"plans": 0, "vaults": 0},
        "rds_public_snapshots": True,
        "elb_classic": [{"name": "legacy-elb", "https": False}],
        "s3_block_public": False,
        "ecs": {
            "clusters": [
                {"name": "prod-ecs", "container_insights": True},
                {"name": "legacy-ecs", "container_insights": False},
            ],
            "task_definitions": [
                {"name": "app-task", "network_mode": "awsvpc", "execution_role": True},
                {"name": "legacy-task", "network_mode": "host", "execution_role": False},
            ],
        },
        "iot": {"logging_level": "INFO", "public_policies": ["legacy-iot-policy"]},
        "ses": {"identities": ["prod@example.com", "legacy@example.com"],
                 "dkim_unverified": ["legacy@example.com"]},
        "sagemaker": {
            "notebooks": [
                {"name": "ml-lab", "direct_internet": False, "kms_key": "arn:aws:kms:us-east-1:111122223333:key/ml"},
                {"name": "ml-lab-legacy", "direct_internet": True, "kms_key": None},
            ],
            "endpoints": [
                {"name": "fraud-model", "data_capture": True},
                {"name": "legacy-model", "data_capture": False},
            ],
        },
    }


def azure_snapshot() -> Dict[str, Any]:
    return {
        "subscription_id": "aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4eeee4",
        "account_name": "demo-prod-azure",
        "principal": "demo-security-reviewer@contoso.onmicrosoft.com",
        "assignments": [
            {"principal": "infra-admins@contoso.com", "principal_type": "Group",
             "role": "Contributor", "scope": "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4eeee4"},
            {"principal": "app-sre@contoso.com", "principal_type": "Group",
             "role": "Reader", "scope": "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4eeee4"},
            {"principal": "deploy-svc", "principal_type": "ServicePrincipal",
             "role": "Owner", "scope": "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4eeee4"},
        ],
        "storage": [
            {"name": "prodstore", "allow_blob_public_access": False, "min_tls": "TLS1_2",
             "https_only": True, "default_action": "Deny", "cmk": True,
             "encryption_type": "CustomerManaged", "blob_soft_delete": True},
            {"name": "legacystore", "allow_blob_public_access": True, "min_tls": "TLS1_0",
             "https_only": False, "default_action": "Allow", "cmk": False,
             "encryption_type": "MicrosoftManaged", "blob_soft_delete": False},
            {"name": "logstore", "allow_blob_public_access": False, "min_tls": "TLS1_2",
             "https_only": True, "default_action": "Deny", "cmk": False,
             "encryption_type": "MicrosoftManaged", "blob_soft_delete": True},
        ],
        "keyvaults": [
            {"name": "prod-kv", "soft_delete": True, "purge_protection": True,
             "default_action": "Deny", "private_endpoint": True, "diagnostics": True,
             "keys_without_expiry": 0},
            {"name": "legacy-kv", "soft_delete": False, "purge_protection": False,
             "default_action": "Allow", "private_endpoint": False, "diagnostics": False,
             "keys_without_expiry": 3},
        ],
        "nsgs": [
            {"name": "nsg-web", "associated": True, "flow_logs": True,
             "flow_retention_days": 120,
             "rules": [
                 {"proto": "Tcp", "ports": "443", "source": "Internet", "direction": "Inbound"},
                 {"proto": "Tcp", "ports": "22", "source": "*", "direction": "Inbound"},
             ]},
            {"name": "nsg-dangling", "associated": False, "flow_logs": True,
             "flow_retention_days": 14,
             "rules": [{"proto": "Tcp", "ports": "80", "source": "10.0.0.0/8", "direction": "Inbound"}]},
        ],
        "sql": [
            {"name": "prodsql", "public_network_access": False, "auditing": True, "tde": True,
             "min_tls": "1.2", "va_enabled": True, "ad_admin": True, "firewall_open": False,
             "lt_retention": True},
            {"name": "legacysql", "public_network_access": True, "auditing": False, "tde": True,
             "min_tls": "1.0", "va_enabled": False, "ad_admin": False, "firewall_open": True,
             "lt_retention": False},
        ],
        "disks": [
            {"name": "vm01_osdisk", "encryption_type": "EncryptionAtRestWithCustomerKey", "cmk": True},
            {"name": "vm02_osdisk", "encryption_type": "EncryptionAtRestWithPlatformKey", "cmk": False},
        ],
        "vms": [
            {"name": "vm-web", "public_ip": True, "nic_has_nsg": True,
             "boot_diagnostics": True, "os_disk_cmk": True, "antimalware": True,
             "monitor_agent": True, "encryption_at_host": True},
            {"name": "vm-legacy", "public_ip": True, "nic_has_nsg": False,
             "boot_diagnostics": False, "os_disk_cmk": False, "antimalware": False,
             "monitor_agent": False, "encryption_at_host": False},
        ],
        "activity_log": {"diagnostic_count": 0},
        "acr": [
            {"name": "prodacr", "admin_enabled": False, "public_network_access": False},
            {"name": "legacyacr", "admin_enabled": True, "public_network_access": True},
        ],
        "appservices": [
            {"name": "portal-app", "https_only": True, "min_tls": "1.2",
             "client_cert": True, "ftps_state": "FtpsOnly", "managed_identity": True,
             "auth_enabled": True, "http_logging": True, "remote_debugging": False},
            {"name": "legacy-app", "https_only": False, "min_tls": "1.0",
             "client_cert": False, "ftps_state": "AllAllowed", "managed_identity": False,
             "auth_enabled": False, "http_logging": False, "remote_debugging": True},
        ],
        "cosmos": [
            {"name": "prod-cosmos", "public_network_access": False, "ip_rules": 2,
             "local_auth": False, "backup_continuous": True},
            {"name": "legacy-cosmos", "public_network_access": True, "ip_rules": 0,
             "local_auth": True, "backup_continuous": False},
        ],
        "aks": [
            {"name": "prod-aks", "rbac_enabled": True, "private_cluster": True,
             "network_policy": "azure", "azure_ad_auth": True, "pod_identity": True,
             "azure_policy_addon": True, "autoscaler": True},
            {"name": "legacy-aks", "rbac_enabled": False, "private_cluster": False,
             "network_policy": None, "azure_ad_auth": False, "pod_identity": False,
             "azure_policy_addon": False, "autoscaler": False},
        ],
        "redis": [
            {"name": "cache-prod", "non_ssl_enabled": False, "private_endpoint": True},
            {"name": "cache-legacy", "non_ssl_enabled": True, "private_endpoint": False},
        ],
        "bastion": {"exists": False},
        "defender": {"plans": {
            "virtualmachines": "Standard", "storageaccounts": "Standard",
            "sqlservers": "Free", "appservices": "Free", "dns": "Free"},
            "collected": True},
        "custom_roles": [
            {"name": "broad-ops", "broad": True},
            {"name": "scoped-reader", "broad": False},
        ],
        "policy_assignments": 0,
        "policy_exemptions_no_expiry": 2,
        "appconfig": [
            {"name": "prod-appcfg", "public_network_access": False, "private_endpoint": True},
            {"name": "legacy-appcfg", "public_network_access": True, "private_endpoint": False},
        ],
        "ddos_plans": 0,
        "network_watcher": {"exists": False},
        "eventhubs": [
            {"name": "events-prod", "public_network_access": False, "cmk": True},
            {"name": "events-legacy", "public_network_access": True, "cmk": False},
        ],
        "servicebus": [
            {"name": "bus-prod", "public_network_access": False},
            {"name": "bus-legacy", "public_network_access": True},
        ],
        "log_analytics": {"workspaces": 0, "cmk": False, "short_retention": ["legacy-workspace"],
                          "workspace_ids": []},
        "sentinel": {"workspaces": 0, "analytics_rules": 0},
        "apim": [
            {"name": "prod-apim", "identity": True, "sku": "Premium", "vnet": True},
            {"name": "legacy-apim", "identity": False, "sku": "Developer", "vnet": False},
        ],
        "appgateways": [
            {"name": "gw-prod", "waf": True, "ssl_policy": True},
            {"name": "gw-legacy", "waf": False, "ssl_policy": False},
        ],
        "activity_log_alerts": 0,
        "aad": {
            "collected": True,
            "users": [
                {"upn": "alice@contoso.com", "mfa_registered": True,
                 "privileged": False, "account_enabled": True},
                {"upn": "bob@contoso.com", "mfa_registered": False,
                 "privileged": False, "account_enabled": True},
                {"upn": "infra-admin@contoso.com", "mfa_registered": False,
                 "privileged": True, "account_enabled": True},
                {"upn": "break-glass@contoso.com", "mfa_registered": True,
                 "privileged": True, "account_enabled": True},
            ],
            "ca_policies": [
                {"name": "Require MFA for admins", "state": "enabled",
                 "require_mfa": True, "block_legacy_auth": False,
                 "include_all_users": False, "risk_based": False},
                {"name": "Block legacy auth", "state": "disabled",
                 "require_mfa": False, "block_legacy_auth": True,
                 "include_all_users": True, "risk_based": False},
                {"name": "Block high-risk sign-ins", "state": "enabled",
                 "require_mfa": False, "block_legacy_auth": False,
                 "include_all_users": True, "risk_based": True},
            ],
            "guest_users": 1,
        },
        "frontdoors": [
            {"name": "fd-prod", "waf": True, "logging": True},
            {"name": "fd-legacy", "waf": False, "logging": False},
        ],
        "functions": [
            {"name": "fn-webhook", "https_only": True, "auth_level": "function"},
            {"name": "fn-legacy", "https_only": False, "auth_level": "anonymous"},
        ],
    }


def gcp_snapshot() -> Dict[str, Any]:
    return {
        "project_id": "demo-prod-gcp-123456",
        "account_name": "demo-prod-gcp",
        "principal": "security-reviewer@demo-prod-gcp-123456.iam.gserviceaccount.com",
        "iam": [
            {"member": "user:admin@example.com", "role": "roles/owner", "type": "user",
             "external": False},
            {"member": "user:vendor@partner.com", "role": "roles/viewer", "type": "user",
             "external": True},
            {"member": "group:devs@example.com", "role": "roles/viewer", "type": "group",
             "external": False},
            {"member": "serviceAccount:svc-ci@demo-prod-gcp-123456.iam.gserviceaccount.com",
             "role": "roles/cloudbuild.builds.editor", "type": "serviceAccount",
             "external": False},
        ],
        "sa_keys": [
            {"email": "svc-ci@demo-prod-gcp-123456.iam.gserviceaccount.com", "key_count": 1,
             "oldest_key_age_days": 210},
            {"email": "svc-data@demo-prod-gcp-123456.iam.gserviceaccount.com", "key_count": 0,
             "oldest_key_age_days": 0},
        ],
        "buckets": [
            {"name": "demo-prod-assets", "public": False, "uniform": True,
             "versioning": True, "cmek": True, "retention": True, "lifecycle": True,
             "logging": True},
            {"name": "demo-legacy-public", "public": True, "uniform": False,
             "versioning": True, "cmek": False, "retention": False, "lifecycle": False,
             "logging": False},
            {"name": "demo-backups", "public": False, "uniform": True,
             "versioning": False, "cmek": False, "retention": True, "lifecycle": False,
             "logging": True},
        ],
        "firewalls": [
            {"name": "allow-https", "network": "prod-vpc",
             "allowed": [{"proto": "tcp", "ports": ["443"]}],
             "source_ranges": ["0.0.0.0/0"], "disabled": False, "logging": True},
            {"name": "allow-ssh-legacy", "network": "default",
             "allowed": [{"proto": "tcp", "ports": ["22"]}],
             "source_ranges": ["0.0.0.0/0"], "disabled": False, "logging": False},
            {"name": "deny-all-egress", "network": "prod-vpc",
             "allowed": [], "source_ranges": [], "disabled": True, "logging": False},
        ],
        "disks": [
            {"name": "web-vm-disk", "cmek": True},
            {"name": "legacy-vm-disk", "cmek": False},
        ],
        "instances": [
            {"name": "web-vm", "external_ip": True, "shielded_vm": True,
             "serial_port": False, "confidential": True, "deletion_protection": True},
            {"name": "legacy-vm", "external_ip": True, "shielded_vm": False,
             "serial_port": True, "confidential": False, "deletion_protection": False},
        ],
        "sql": [
            {"name": "prod-db", "private_ip": True, "require_ssl": True, "backup_enabled": True,
             "cmek": True, "broad_authorized_networks": False, "pitr": True},
            {"name": "legacy-db", "private_ip": False, "require_ssl": False, "backup_enabled": False,
             "cmek": False, "broad_authorized_networks": True, "pitr": False},
        ],
        "kms": [
            {"key": "projects/demo-prod-gcp-123456/locations/global/keyRings/app/cryptoKeys/data",
             "rotation_period_days": 30},
            {"key": "projects/demo-prod-gcp-123456/locations/global/keyRings/legacy/cryptoKeys/db",
             "rotation_period_days": 0},
        ],
        "audit": {"admin_activity": False, "data_access": False, "log_sinks": 0},
        "gke": [
            {"name": "prod-cluster", "private_cluster": True, "network_policy": True,
             "legacy_abac": False, "release_channel": "REGULAR",
             "workload_identity": True, "shielded_nodes": True, "private_endpoint": True,
             "logging_service": "logging.googleapis.com/kubernetes",
             "monitoring_service": "monitoring.googleapis.com/kubernetes",
             "node_auto_upgrade": True, "node_auto_repair": True,
             "binary_authorization": True},
            {"name": "legacy-cluster", "private_cluster": False, "network_policy": False,
             "legacy_abac": True, "release_channel": None,
             "workload_identity": False, "shielded_nodes": False, "private_endpoint": False,
             "logging_service": "none", "monitoring_service": "none",
             "node_auto_upgrade": False, "node_auto_repair": False,
             "binary_authorization": False},
        ],
        "subnets": [
            {"name": "prod-subnet", "region": "us-central1", "enable_flow_logs": True},
            {"name": "legacy-subnet", "region": "us-central1", "enable_flow_logs": False},
        ],
        "bigquery": [
            {"dataset_id": "analytics", "public": False, "cmek": True},
            {"dataset_id": "legacy_exports", "public": True, "cmek": False},
        ],
        "secrets": [
            {"name": "db-password", "rotation": True},
            {"name": "legacy-api-key", "rotation": False},
        ],
        "dns": {"dnssec_zones": 1, "total_zones": 3},
        "org_policies": {"collected": True, "domain_restricted_sharing": False,
                          "vm_external_ip": True, "os_login": False},
        "cloudrun": [
            {"name": "public-api", "unauthenticated": True, "ingress_all": True,
             "cpu_always_allocated": False, "max_instances": 10, "vpc_connector": False},
            {"name": "internal-svc", "unauthenticated": False, "ingress_all": False,
             "cpu_always_allocated": True, "max_instances": 0, "vpc_connector": True},
        ],
        "memorystore": [
            {"name": "cache-prod", "transit_encryption": True, "auth_enabled": True,
             "private_ip": True, "persistence": True},
            {"name": "cache-legacy", "transit_encryption": False, "auth_enabled": False,
             "private_ip": False, "persistence": False},
        ],
        "artifact_repos": [
            {"name": "prod-images", "public": False, "cmk": True},
            {"name": "legacy-images", "public": True, "cmk": False},
        ],
        "functions": [
            {"name": "pub-fn", "unauthenticated": True, "vpc_connector": False},
            {"name": "internal-fn", "unauthenticated": False, "vpc_connector": True},
        ],
        "vpn_tunnels": [
            {"name": "tunnel-main", "ike_version": 2},
            {"name": "tunnel-legacy", "ike_version": 1},
        ],
        "wipools": [
            {"name": "prod-pool", "providers": 2},
            {"name": "legacy-pool", "providers": 0},
        ],
        "vertex_ai": {
            "notebooks": [
                {"name": "ml-lab", "external_ip": False, "cmek": True},
                {"name": "ml-lab-legacy", "external_ip": True, "cmek": False},
            ],
        },
        "pubsub": [
            {"name": "events-prod", "cmek": True},
            {"name": "events-legacy", "cmek": False},
        ],
    }


def oci_snapshot() -> Dict[str, Any]:
    return {
        "tenancy": "ocid1.tenancy.oc1..demo",
        "account_name": "demo-prod-oci",
        "principal": "ocid1.user.oc1..demouser",
        "users": [
            {"name": "demo.admin", "mfa_enabled": True, "has_console_password": True,
             "api_keys": 0, "max_api_key_age": 0},
            {"name": "demo.svc", "mfa_enabled": False, "has_console_password": False,
             "api_keys": 2, "max_api_key_age": 240},
        ],
        "policies": [
            {"name": "Network-Admins-Policy",
             "statements": ["Allow group Network-Admins to manage all-resources in tenancy"],
             "broad_manage": True},
            {"name": "App-Readonly-Policy",
             "statements": ["Allow group App-Readonly to read all-resources in compartment App"],
             "broad_manage": False},
        ],
        "buckets": [
            {"name": "demo-prod-objects", "public_type": "NoPublicAccess", "versioning": True,
             "cmk": True, "par_count": 0, "par_no_expiry": 0, "lifecycle_policy": True},
            {"name": "demo-legacy-share", "public_type": "ObjectRead", "versioning": False,
             "cmk": False, "par_count": 3, "par_no_expiry": 2, "lifecycle_policy": False},
        ],
        "sec_lists": [
            {"id": "ocid1.securitylist.oc1..slweb", "name": "sl-web",
             "ingress": [
                 {"proto": "tcp", "src": "0.0.0.0/0", "ports": (443, 443)},
                 {"proto": "tcp", "src": "0.0.0.0/0", "ports": (22, 22)},
             ]},
            {"id": "ocid1.securitylist.oc1..slapp", "name": "sl-app",
             "ingress": [{"proto": "tcp", "src": "10.0.0.0/8", "ports": (443, 443)}]},
        ],
        "nsgs": [
            {"id": "ocid1.nsg.oc1..nsgdb", "name": "nsg-db", "open_ingress": False,
             "referenced": True},
            {"id": "ocid1.nsg.oc1..nsglegacy", "name": "nsg-legacy", "open_ingress": True,
             "referenced": False},
        ],
        "volumes": [
            {"id": "ocid1.volume.oc1..volweb", "name": "web-boot", "type": "boot",
             "cmk": True, "backup_count": 2, "has_replica": True},
            {"id": "ocid1.volume.oc1..vollegacy", "name": "legacy-block", "type": "block",
             "cmk": False, "backup_count": 0, "has_replica": False},
        ],
        "adbs": [
            {"name": "prod-adb", "public_endpoint": False, "cmk": True, "data_guard": True,
             "backup_retention_days": 14, "auto_scaling": True},
            {"name": "legacy-adb", "public_endpoint": True, "cmk": False, "data_guard": False,
             "backup_retention_days": 3, "auto_scaling": False},
        ],
        "keys": [
            {"key": "ocid1.key.oc1..kmsapp", "rotation_enabled": True},
            {"key": "ocid1.key.oc1..kmslegacy", "rotation_enabled": False},
        ],
        "cloud_guard": {"enabled": True, "detectors_enabled": 2},
        "subnets": [
            {"name": "web-subnet", "flow_log_enabled": True},
            {"name": "legacy-subnet", "flow_log_enabled": False},
        ],
        "igws": [
            {"id": "ocid1.internetgateway.oc1..igwprod", "name": "igw-prod", "enabled": True},
            {"id": "ocid1.internetgateway.oc1..igwlegacy", "name": "igw-legacy", "enabled": True},
        ],
        "lbs": [
            {"name": "lb-web", "public": True, "ssl_listener": True},
            {"name": "lb-legacy", "public": True, "ssl_listener": False},
        ],
        "bastion": {"exists": False},
        "filesystems": [
            {"name": "fs-prod", "cmk": True, "snapshots": 2},
            {"name": "fs-legacy", "cmk": False, "snapshots": 0},
        ],
        "route_tables": [
            {"name": "rt-prod", "public_default_route": False},
            {"name": "rt-legacy", "public_default_route": True},
        ],
        "nat_gateways": 1,
        "osms": {"managed_instances": 0, "managed_instance_groups": 0},
        "audit": {"retention_days": 60},
        "nosql_tables": [
            {"name": "orders-table", "has_limits": True},
            {"name": "legacy-orders", "has_limits": False},
        ],
        "dns_zones": {"total": 3, "dnssec_off": ["legacy.example.com", "internal.example.com"]},
        "db_backups": {"count": 0, "db_systems": 1},
        "api_gateways": [
            {"name": "gw-payments", "public": True, "waf": True, "tls": True},
            {"name": "gw-legacy", "public": True, "waf": False, "tls": False},
        ],
    }


def get_demo_snapshots() -> Dict[str, Dict[str, Any]]:
    return {
        "aws": aws_snapshot(),
        "azure": azure_snapshot(),
        "gcp": gcp_snapshot(),
        "oci": oci_snapshot(),
    }
