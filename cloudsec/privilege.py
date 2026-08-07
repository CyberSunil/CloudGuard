"""Credential privilege validation and least-privilege templates.

The tool only ever performs READ operations. Before scanning it attempts a
best-effort self-check of the supplied principal's privileges and warns when
the credentials appear overly broad (e.g. Owner/Contributor, root account,
primitive roles). The templates below are the minimum policies needed.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .models import ScanResult


def check_privilege(cloud: str, result: ScanResult, snapshot: Dict[str, Any],
                    auth: Dict[str, Any]) -> Dict[str, Any]:
    """Return {'level': readonly|elevated|unknown, 'warnings': [...], 'details': ...}."""
    warnings: List[str] = []
    level = "unknown"

    try:
        if cloud == "aws":
            principal = snapshot.get("principal", "")
            if principal.endswith(":root"):
                warnings.append("Scanning with the AWS root account. Use a dedicated "
                                "ReadOnly IAM user/role instead.")
                level = "elevated"
            # account-level admin policy scan already populates admin_policies
            if snapshot.get("iam", {}).get("admin_policies"):
                warnings.append("The caller is attached to policies granting "
                                "administrative access.")
                level = "elevated"
            if not warnings:
                level = "readonly"
        elif cloud == "azure":
            assignments = snapshot.get("assignments", [])
            for a in assignments:
                role = (a.get("role") or "").lower()
                if role in ("owner", "contributor", "user access administrator"):
                    warnings.append(f"Principal '{a.get('principal')}' holds "
                                    f"'{a['role']}' at {a.get('scope', 'subscription')} "
                                    "- prefer a Reader-only service principal.")
                    level = "elevated"
                    break
            if not warnings:
                level = "readonly"
        elif cloud == "gcp":
            principal = snapshot.get("principal", "")
            for b in snapshot.get("iam", []):
                member = b.get("member", "")
                member_email = member.split(":", 1)[1] if ":" in member else member
                if member_email == principal:
                    if b.get("role") in ("roles/owner", "roles/editor"):
                        warnings.append(f"Principal holds {b['role']} - prefer a "
                                        "least-privilege service account.")
                        level = "elevated"
                        break
            if not warnings:
                level = "readonly"
        elif cloud == "oci":
            user_name = snapshot.get("principal", "")
            for p in snapshot.get("policies", []):
                if p.get("broad_manage"):
                    warnings.append(f"Policy '{p['name']}' grants manage all-resources "
                                    "in tenancy - prefer a read-only policy group.")
                    level = "elevated"
                    break
            if not warnings:
                level = "readonly"
    except Exception:
        pass

    result.extra["privilege_check"] = {"level": level, "warnings": warnings}
    return {"level": level, "warnings": warnings}


# --------------------------------------------------------------------------- #
# Least-privilege templates
# --------------------------------------------------------------------------- #
def least_privilege_templates() -> Dict[str, Any]:
    return {
        "aws": {
            "summary": "Attach the AWS managed 'ReadOnlyAccess' policy (the "
                       "equivalent of Azure's built-in Reader): it covers every "
                       "service CloudGuard calls with no blind spots, and an "
                       "explicit allow-list would produce false negatives (an "
                       "ungranted service looks identical to 'no findings'). The "
                       "scoped policy below is the documented minimum and now "
                       "matches every service the collector actually calls.",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow",
                     "Action": [
                         "s3:GetBucket*", "s3:GetAccountPublicAccessBlock",
                         "s3:ListAllMyBuckets",
                         "acm:DescribeCertificate", "acm:ListCertificates",
                         "apigateway:GET",
                         "backup:ListBackupPlans", "backup:ListBackupVaults",
                         "cloudfront:GetDistribution", "cloudfront:ListDistributions",
                         "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
                         "cloudwatch:DescribeAlarms", "cloudwatch:ListDashboards",
                         "config:DescribeConfigurationRecorders",
                         "config:DescribeDeliveryChannels",
                         "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTable",
                         "dynamodb:ListTables",
                         "ec2:Describe*", "ec2:GetEbsEncryptionByDefault",
                         "ecr:DescribeRepositories", "ecr:GetLifecyclePolicy",
                         "ecr:GetRepositoryPolicy",
                         "ecs:DescribeClusters", "ecs:DescribeTaskDefinition",
                         "ecs:ListClusters", "ecs:ListTaskDefinitions",
                         "efs:DescribeBackupPolicy", "efs:DescribeFileSystems",
                         "efs:DescribeLifecycleConfiguration",
                         "eks:DescribeCluster", "eks:ListClusters",
                         "elasticache:DescribeCacheClusters",
                         "elb:DescribeLoadBalancerAttributes", "elb:DescribeLoadBalancers",
                         "elbv2:DescribeListeners", "elbv2:DescribeLoadBalancerAttributes",
                         "elbv2:DescribeLoadBalancers",
                         "guardduty:GetDetector", "guardduty:ListDetectors",
                         "iam:Get*", "iam:List*",
                         "iot:GetLoggingOptions", "iot:GetPolicy", "iot:ListPolicies",
                         "kms:Get*", "kms:List*",
                         "lambda:GetPolicy", "lambda:ListFunctions",
                         "logs:DescribeLogGroups",
                         "rds:Describe*",
                         "redshift:DescribeClusters", "redshift:DescribeLoggingStatus",
                         "route53:GetDnssec", "route53:ListHostedZones",
                         "route53:ListQueryLoggingConfigs",
                         "secretsmanager:ListSecrets",
                         "ses:GetIdentityDkimAttributes", "ses:ListIdentities",
                         "sns:Get*", "sns:List*",
                         "sqs:GetQueueAttributes", "sqs:ListQueues",
                         "sts:GetCallerIdentity",
                         "waf-regional:ListResourcesForWebACL", "waf-regional:ListWebACLs",
                     ],
                     "Resource": "*"},
                ],
            },
            "exclusions": [
                "s3:GetObject / GetObjectVersion (no object data)",
                "secretsmanager:GetSecretValue (metadata only via ListSecrets)",
                "kms:Decrypt / kms:GenerateDataKey",
                "dynamodb:GetItem / Query / Scan (no table data)",
                "ssm:GetParameter / GetParameters (not called)",
            ],
            "note": "Prefer the built-in ReadOnlyAccess managed policy for "
                    "simplicity; the scoped policy above is the verified minimum "
                    "for the CloudGuard check set. The collector performs no "
                    "data-plane reads - only List/Describe/Get metadata calls.",
        },
        "azure": {
            "summary": "Request built-in roles at the top scope of the engagement "
                       "(management group where possible, otherwise subscription). "
                       "An explicit allow-list of Actions produces false negatives: "
                       "a resource type you were not granted looks identical to \"no "
                       "findings\". The built-in Reader is a superset of any custom "
                       "read role, so it is the primary recommendation - the custom "
                       "role below is the strict alternative (like AWS's scoped "
                       "policy), verified against every API call the collector "
                       "actually makes.",
            "custom_role": {
                "Name": "CloudGuard Reader (custom role)",
                "Description": "Strict read-only alternative to built-in Reader, "
                               "matching exactly what the CloudGuard collector calls: "
                               "ARM control-plane reads + Key Vault key METADATA. "
                               "Prefer built-in Reader - this explicit list can miss "
                               "resource types added later (false negatives).",
                "IsCustom": True,
                "Actions": [
                    # ARM control-plane reads the collector performs
                    "Microsoft.Storage/storageAccounts/read",
                    "Microsoft.Storage/storageAccounts/blobServices/read",
                    "Microsoft.KeyVault/vaults/read",
                    "Microsoft.Network/networkSecurityGroups/read",
                    "Microsoft.Network/networkSecurityGroups/securityRules/read",
                    "Microsoft.Network/networkInterfaces/read",
                    "Microsoft.Network/subnets/read",
                    "Microsoft.Network/networkWatchers/read",
                    "Microsoft.Network/networkWatchers/flowLogs/read",
                    "Microsoft.Network/bastionHosts/read",
                    "Microsoft.Network/applicationGateways/read",
                    "Microsoft.Network/ddosProtectionPlans/read",
                    "Microsoft.Network/publicIPAddresses/read",
                    "Microsoft.Sql/servers/read",
                    "Microsoft.Sql/servers/auditingSettings/read",
                    "Microsoft.Sql/servers/databases/read",
                    "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
                    "Microsoft.Sql/servers/firewallRules/read",
                    "Microsoft.Sql/servers/administrators/read",
                    "Microsoft.Sql/servers/vulnerabilityAssessments/read",
                    "Microsoft.Compute/disks/read",
                    "Microsoft.Compute/virtualMachines/read",
                    "Microsoft.Compute/virtualMachines/extensions/read",
                    "Microsoft.Insights/diagnosticSettings/read",
                    "Microsoft.Insights/activityLogAlerts/read",
                    "Microsoft.ContainerRegistry/registries/read",
                    "Microsoft.Web/sites/read",
                    "Microsoft.Web/sites/config/read",
                    "Microsoft.Web/sites/config/authsettings/read",
                    "Microsoft.DocumentDB/databaseAccounts/read",
                    "Microsoft.ApiManagement/service/read",
                    "Microsoft.Authorization/roleDefinitions/read",
                    "Microsoft.Authorization/roleAssignments/read",
                    "Microsoft.Authorization/policyAssignments/read",
                    "Microsoft.Authorization/policyExemptions/read",
                    "Microsoft.AppConfiguration/configurationStores/read",
                    "Microsoft.OperationalInsights/workspaces/read",
                    "Microsoft.SecurityInsights/alertRules/read",
                    "Microsoft.EventHub/namespaces/read",
                    "Microsoft.ServiceBus/namespaces/read",
                    "Microsoft.ContainerService/managedClusters/read",
                    "Microsoft.Cache/redis/read",
                    "Microsoft.Security/pricings/read",
                    # subscription enumeration (SubscriptionClient) + resource groups
                    "Microsoft.Resources/subscriptions/read",
                    "Microsoft.Resources/subscriptions/resourceGroups/read",
                ],
                "NotActions": [
                    "Microsoft.Storage/storageAccounts/listKeys",
                    "Microsoft.Web/sites/config/list/action",
                    "Microsoft.ContainerRegistry/registries/listCredentials",
                ],
                "DataActions": [
                    # Key Vault key METADATA only (expiry/rotation) - never values.
                    # Legacy access-policy vaults: add vault access-policy 'list' on keys.
                    "Microsoft.KeyVault/vaults/keys/read",
                ],
                "NotDataActions": [],
                "AssignableScopes": ["/subscriptions/<subscription-id>"],
            },
            "roles": [
                {"role": "Reader", "scope": "Management group / subscription",
                 "why": "All control-plane reads (*/read): storage (incl. "
                        "blobServices public access & soft delete), Key Vault "
                        "properties, network (NSGs, NICs, subnets, flow logs, "
                        "bastion, app gateways, DDoS), SQL, compute (disks, VMs, "
                        "extensions), ACR, App Service config, Cosmos DB, AKS, "
                        "Redis, Event Hub, Service Bus, API Management, App "
                        "Config, Azure Policy, Log Analytics workspaces, "
                        "Defender pricings, Resource Graph."},
                {"role": "Key Vault Reader", "scope": "Subscription",
                 "why": "Key/secret/certificate METADATA (expiry, HSM backing, "
                        "rotation) without values - required by the key-expiry "
                        "check. For vaults still on the legacy access-policy "
                        "model, add the vault access-policy permission 'list' "
                        "on keys instead."},
                {"role": "Global Reader (Entra ID)", "scope": "Tenant",
                 "why": "Identity hardening checks (MFA registration report, "
                        "conditional access policies, privileged directory role "
                        "assignments, guest users). Equivalent Microsoft Graph "
                        "app permissions: User.Read.All, "
                        "UserAuthenticationMethod.Read.All (or Reports.Read.All), "
                        "RoleManagement.Read.Directory, Policy.Read.All."},
                {"role": "Security Reader (optional)", "scope": "Subscription",
                 "why": "Defender for Cloud posture and pre-computed assessments "
                        "if secure score / recommendations are wanted in future "
                        "runs."},
                {"role": "Log Analytics Reader (optional)", "scope": "Workspace(s)",
                 "why": "Only if log queries are used to validate retention; the "
                        "check set reads workspace properties, which Reader "
                        "already covers."},
            ],
            "graph_scopes": [
                "User.Read.All",
                "UserAuthenticationMethod.Read.All (or Reports.Read.All)",
                "RoleManagement.Read.Directory",
                "Policy.Read.All",
            ],
            "exclusions": [
                "Microsoft.Storage/storageAccounts/listKeys",
                "Microsoft.Web/sites/config/list/action",
                "Microsoft.ContainerRegistry/registries/listCredentials",
                "Key Vault secret / certificate VALUES (metadata only via Key Vault Reader)",
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read "
                "(blob data is out of scope for a configuration review)",
            ],
            "note": "Keep assignments time-bound (PIM eligible or an end date "
                    "matching the engagement window). For recurring engagements "
                    "prefer Azure Lighthouse delegated access over guest accounts "
                    "in the client tenant. The 'CloudGuard Reader' custom role "
                    "above is restored as the strict alternative to built-in "
                    "Reader: it matches the collector's actual calls (ARM reads "
                    "+ Key Vault key metadata via DataActions) and explicitly "
                    "excludes the blob DataAction - blob data is out of scope "
                    "for a configuration review.",
        },
        "gcp": {
            "summary": "Grant these roles to the scanning service account. "
                       "roles/storage.objectViewer was replaced by a metadata-only "
                       "custom role: objectViewer does not even grant "
                       "storage.buckets.list (the collector lists buckets) and it "
                       "includes storage.objects.get (object data).",
            "roles": [
                "roles/viewer",
                "roles/securitycenter.viewer",
                "roles/compute.viewer",
                "roles/container.viewer",
                "roles/cloudkms.viewer",
                "roles/logging.viewer",
                "roles/cloudsql.viewer",
                "roles/artifactregistry.reader",
                "roles/bigquery.metadataViewer",
                "roles/cloudfunctions.viewer",
                "roles/dns.reader",
                "roles/orgpolicy.policyViewer",
                "roles/redis.viewer",
                "roles/run.viewer",
                "roles/secretmanager.viewer",
                {"role": "Storage metadata (custom role)", "scope": "Project",
                 "why": "storage.buckets.list, storage.buckets.get, "
                        "storage.buckets.getIamPolicy - public-access checks "
                        "with no object (data) read. If strict about secret "
                        "values: secretmanager.viewer includes "
                        "secretmanager.versions.access (data); a metadata-only "
                        "custom role is secretmanager.secrets.get, "
                        "secretmanager.secrets.list, secretmanager.locations.get."},
            ],
            "extra_permissions": "To enumerate service-account keys, add "
                                 "iam.serviceAccountKeys.list at the project "
                                 "(e.g. via a custom role).",
            "exclusions": [
                "storage.objects.get (no object data - bucket metadata only)",
                "bigquery.tables.getData (datasets/tables metadata only)",
                "secretmanager.versions.access (secret names/metadata only)",
                "cloudkms.cryptoKeyVersions.useToDecrypt (no key material)",
            ],
        },
        "oci": {
            "summary": "Add the reviewing group to a policy like: "
                       "'read all-resources' is the safety net that prevents "
                       "false negatives (like AWS ReadOnlyAccess / Azure Reader); "
                       "the granular lines document exactly what the collector "
                       "uses. Note the verbs: reading API keys / MFA TOTP "
                       "devices requires 'read users' (not 'inspect users'), and "
                       "reading NSG security RULES requires 'read "
                       "network-security-groups' (not 'inspect').",
            "policy": [
                "Allow group SecurityReviewers to read all-resources in tenancy",
                "Allow group SecurityReviewers to read users in tenancy",
                "Allow group SecurityReviewers to read policies in tenancy",
                "Allow group SecurityReviewers to read network-security-groups in tenancy",
                "Allow group SecurityReviewers to read buckets in tenancy",
                "Allow group SecurityReviewers to read keys in tenancy",
                "Allow group SecurityReviewers to read key-rings in tenancy",
                "Allow group SecurityReviewers to read vaults in tenancy",
                "Allow group SecurityReviewers to read autonomous-databases in tenancy",
                "Allow group SecurityReviewers to read db-systems in tenancy",
                "Allow group SecurityReviewers to read db-backups in tenancy",
                "Allow group SecurityReviewers to read cloud-guard-targets in tenancy",
                "Allow group SecurityReviewers to read cloud-guard-detector-recipes in tenancy",
                "Allow group SecurityReviewers to read bastions in tenancy",
                "Allow group SecurityReviewers to read load-balancers in tenancy",
                "Allow group SecurityReviewers to read file-systems in tenancy",
                "Allow group SecurityReviewers to read file-system-snapshots in tenancy",
                "Allow group SecurityReviewers to read managed-instances in tenancy",
                "Allow group SecurityReviewers to read managed-instance-groups in tenancy",
                "Allow group SecurityReviewers to read nosql-tables in tenancy",
                "Allow group SecurityReviewers to read dns-zones in tenancy",
                "Allow group SecurityReviewers to read audit-events in tenancy",
            ],
            "exclusions": [
                "No 'manage' verbs (no manage all-resources)",
                "No read of secret / customer-data payloads (bucket object bodies, "
                "NoSQL row data - metadata/list calls only)",
            ],
            "note": "Users must NOT be in any group with 'manage all-resources' "
                    "grants; use Policy Analyzer to verify. The collector uses "
                    "inspect/read list & get calls only.",
        },
    }
