# OCI Access Requirements — Cloud Configuration Review

**Engagement:** Read-only configuration review of the Oracle Cloud Infrastructure tenancy
/ compartments listed below.
**Tool:** CloudGuard (`cloudsecreview`) — performs **read-only API calls only**; no data is
written, no configuration is changed, and no customer data is read.
**Window:** `<engagement start date>` → `<engagement end date>` (time-bound, see below).

---

## 1. Access requested (IAM policy)

We request a **dedicated review group** in the tenancy with the policy below.
`read all-resources` is the safety net that prevents false negatives (like AWS
`ReadOnlyAccess` / Azure Reader); the granular statements document exactly what CloudGuard
uses. Note the **verbs** — reading API keys / MFA TOTP devices requires `read users`
(not `inspect users`), and reading NSG security **rules** requires
`read network-security-groups` (not `inspect`).

```text
Allow group SecurityReviewers to read all-resources in tenancy
Allow group SecurityReviewers to read users in tenancy
Allow group SecurityReviewers to read policies in tenancy
Allow group SecurityReviewers to read network-security-groups in tenancy
Allow group SecurityReviewers to read buckets in tenancy
Allow group SecurityReviewers to read keys in tenancy
Allow group SecurityReviewers to read key-rings in tenancy
Allow group SecurityReviewers to read vaults in tenancy
Allow group SecurityReviewers to read autonomous-databases in tenancy
Allow group SecurityReviewers to read db-systems in tenancy
Allow group SecurityReviewers to read db-backups in tenancy
Allow group SecurityReviewers to read cloud-guard-targets in tenancy
Allow group SecurityReviewers to read cloud-guard-detector-recipes in tenancy
Allow group SecurityReviewers to read bastions in tenancy
Allow group SecurityReviewers to read load-balancers in tenancy
Allow group SecurityReviewers to read file-systems in tenancy
Allow group SecurityReviewers to read file-system-snapshots in tenancy
Allow group SecurityReviewers to read managed-instances in tenancy
Allow group SecurityReviewers to read managed-instance-groups in tenancy
Allow group SecurityReviewers to read nosql-tables in tenancy
Allow group SecurityReviewers to read dns-zones in tenancy
Allow group SecurityReviewers to read audit-events in tenancy
```

| What it covers | Resource types |
|---|---|
| Compute, networking, storage | Instances, block & boot volumes (+ backups, replicas), VCNs, subnets, route tables, internet/NAT gateways, security lists, NSGs (incl. rules), load balancers |
| Data & databases | Object Storage buckets (incl. pre-authenticated requests & lifecycle policies), autonomous databases, DB systems, DB backups, NoSQL tables, File Storage (+ snapshots) |
| Security & identity | Cloud Guard targets & detector recipes, Bastion, KMS vaults/key-rings/keys, users (incl. MFA devices & API keys), IAM policies, audit events, OSMS managed instances/groups, DNS zones |

## 2. What we explicitly do NOT request

- ❌ No **`manage`** verbs — in particular, no `manage all-resources` anywhere
- ❌ No read of **customer-data payloads** (Object Storage object bodies, NoSQL row data) — metadata/list calls only
- ❌ No `use` verbs on keys / vaults (no decryption, no key-usage)

## 3. Time-bound assignment

> "The review user is a member of the `SecurityReviewers` group only for the engagement
> window (`<start>` → `<end>`). The user's API key expires at `<end date>` and the
> membership is removed no later than `<end date>`."

## 4. Recommended deployment pattern

- **Single engagement:** a dedicated IAM user (never a human's daily account) added to
  the review group with an **expiring API key**, removed at engagement end.
- **Scoped reviews:** replace `in tenancy` with `in compartment <name>` on the statements
  to limit blast radius to the compartments in scope (keep `read users`/`read policies`
  at tenancy if identity checks are required, or document the reduction).
- **Recurring engagements:** re-create the user + key per engagement; use Policy Analyzer
  to confirm no overlapping `manage` grants exist.

## 5. Verification

After provisioning, CloudGuard's built-in privilege self-check
(`python3 run.py scan --cloud oci --oci-config ~/.oci/config --oci-profile DEFAULT
--compartment <ocid>`) confirms the principal is read-only and flags any `manage
all-resources` grant before scanning begins. The least-privilege reference used at scan
time is printed by `python3 run.py policies --cloud oci`.
