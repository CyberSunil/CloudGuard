# Azure Access Requirements — Cloud Configuration Review

**Engagement:** Read-only configuration review of the Azure subscription(s) listed below.
**Tool:** CloudGuard (`cloudsecreview`) — performs **read-only API calls only**; no data is
written, no configuration is changed, and no customer data is read.
**Window:** `<engagement start date>` → `<engagement end date>` (time-bound, see below).

---

## 1. Roles requested (built-in primary)

We deliberately request **built-in Azure roles at the top scope** rather than a custom role.
An explicit allow-list of actions silently misses resource types it was not granted —
which is indistinguishable from "no findings" in a review report. Built-in `Reader`
covers the entire control plane (`*/read`) with no blind spots, and it is easier for
your security team to approve because its meaning is well understood. A verified custom
role is provided in §1a as the strict alternative for teams that require an allow-list.

| # | Built-in role | Scope | Why it is needed |
|---|---|---|---|
| 1 | **Reader** | Management group or subscription | All control-plane reads: storage (including blob public-access and soft-delete settings), Key Vault properties, networking (NSGs, flow logs, bastion, app gateways), SQL, compute (disks, VMs, extensions), ACR, App Service config, Cosmos DB, AKS, Redis, Event Hub, Service Bus, API Management, App Configuration, Azure Policy, Log Analytics workspace properties, Defender pricing, Resource Graph. |
| 2 | **Key Vault Reader** | Subscription | Read **metadata** of keys/secrets/certificates (expiry dates, HSM backing, rotation policy) — required to check for keys without expiry. **Values are never read.** For vaults on the legacy access-policy model, a vault access policy with `list` permission on keys provides the same metadata. |
| 3 | **Global Reader** (Entra ID) | Tenant | Identity hardening checks: MFA registration coverage, conditional-access policies, privileged directory-role assignments, guest-user posture. |
| 4 | *Security Reader (optional)* | Subscription | Defender for Cloud posture + pre-computed assessments, if secure score is in scope. |
| 5 | *Log Analytics Reader (optional)* | Workspace(s) | Only if log queries are needed to validate retention; otherwise workspace properties come from Reader. |

> If Global Reader cannot be granted, the same coverage is available as Microsoft Graph
> **application permissions** on the service principal:
> `User.Read.All`, `UserAuthenticationMethod.Read.All` (or `Reports.Read.All`),
> `RoleManagement.Read.Directory`, `Policy.Read.All`.

### 1a. Custom role (strict alternative to the built-in Reader)

If your security team prefers an explicit allow-list over the built-in roles, this is the
verified minimum matching exactly what CloudGuard calls — ARM control-plane reads plus
Key Vault key **metadata** (never values). It mirrors the scoped-policy alternative that
exists for AWS:

```json
{
  "Name": "CloudGuard Reader (custom role)",
  "Description": "Strict read-only alternative to built-in Reader, matching exactly what the CloudGuard collector calls.",
  "IsCustom": true,
  "Actions": [
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
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read"
  ],
  "NotActions": [
    "Microsoft.Storage/storageAccounts/listKeys",
    "Microsoft.Web/sites/config/list/action",
    "Microsoft.ContainerRegistry/registries/listCredentials"
  ],
  "DataActions": [
    "Microsoft.KeyVault/vaults/keys/read"
  ],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]
}
```

> ⚠️ An explicit allow-list silently misses resource types it was not granted —
> indistinguishable from "no findings" in the report. Prefer the built-in `Reader`;
> use the custom role only if your security team insists on an allow-list.

## 2. What we explicitly do NOT request

Stating exclusions is deliberate — it defines the blast radius of this access:

- ❌ `Microsoft.Storage/storageAccounts/listKeys`
- ❌ `Microsoft.Web/sites/config/list/action` (publishing credentials)
- ❌ `Microsoft.ContainerRegistry/registries/listCredentials`
- ❌ Key Vault **secret / certificate values** (metadata only, via Key Vault Reader)
- ❌ Blob **data** plane reads (`Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`)

No identity used in this engagement will be assigned `Owner`, `Contributor`, or
`User Access Administrator`.

## 3. Time-bound assignment

The service principal is granted access **only for the engagement window**:

> "Assign the roles above with an end date matching the engagement period
> (`<start>` → `<end>`), or as **PIM-eligible** assignments requiring activation
> for each use. All assignments are revoked no later than `<end date>`."

## 4. Recommended deployment pattern

- **Single engagement:** service principal with the roles above, time-bound.
- **Recurring engagements (preferred):** **Azure Lighthouse** delegated access from
  your tenant instead of guest accounts in the client tenant. This avoids identity
  sprawl, keeps approval on the client side, and each delegation can be scoped and
  time-limited per engagement.

## 5. Verification

After provisioning, we run CloudGuard's built-in privilege self-check
(`python3 run.py scan --cloud azure ...`), which confirms the principal is read-only
and reports any over-privilege before scanning begins. The least-privilege reference
used at scan time is printed by `python3 run.py policies --cloud azure`.
