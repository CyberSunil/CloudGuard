# GCP Access Requirements — Cloud Configuration Review

**Engagement:** Read-only configuration review of the Google Cloud project(s) listed below.
**Tool:** CloudGuard (`cloudsecreview`) — performs **read-only API calls only**; no data is
written, no configuration is changed, and no customer data is read.
**Window:** `<engagement start date>` → `<engagement end date>` (time-bound, see below).

---

## 1. Roles requested

We request a **dedicated service account** for the engagement with the role set below.
All roles are **viewer-class** (metadata only). `roles/storage.objectViewer` was
deliberately **not** requested: it does not grant `storage.buckets.list` (CloudGuard
lists buckets) and it *does* include `storage.objects.get` (object data) — so it is
replaced by a metadata-only custom role.

| # | Role | Scope | Why it is needed |
|---|---|---|---|
| 1 | `roles/viewer` | Project | Project-level read baseline (IAM policies, resource metadata, org-policy reads) |
| 2 | `roles/securitycenter.viewer` | Project | Security Command Center posture & findings |
| 3 | `roles/compute.viewer` | Project | Instances, firewalls, networks, disks, snapshots, VPN gateways |
| 4 | `roles/container.viewer` | Project | GKE clusters |
| 5 | `roles/cloudkms.viewer` | Project | KMS key rings & keys (metadata — no key material) |
| 6 | `roles/logging.viewer` | Project | Log sinks & log configuration |
| 7 | `roles/cloudsql.viewer` | Project | Cloud SQL instances (no data) |
| 8 | `roles/artifactregistry.reader` | Project | Artifact Registry repositories & IAM |
| 9 | `roles/bigquery.metadataViewer` | Project | Dataset/table **metadata only** (no `getData`) |
| 10 | `roles/cloudfunctions.viewer` | Project | Cloud Functions & IAM |
| 11 | `roles/dns.reader` | Project | Cloud DNS zones |
| 12 | `roles/orgpolicy.policyViewer` | Organization (or project) | Org policy / constraint posture (falls back to project-level constraints if org access is declined) |
| 13 | `roles/redis.viewer` | Project | Memorystore Redis instances |
| 14 | `roles/run.viewer` | Project | Cloud Run services & IAM |
| 15 | `roles/secretmanager.viewer` | Project | Secret **names/metadata only** (see note below) |
| 16 | **Storage metadata (custom role)** | Project | `storage.buckets.list`, `storage.buckets.get`, `storage.buckets.getIamPolicy` — public-access checks with no object (data) read |

> **Note on `roles/secretmanager.viewer`:** this built-in role includes
> `secretmanager.versions.access` (secret *values*). CloudGuard only calls
> `list_secrets` — it never reads values. If your policy is strict about secret data,
> replace role #15 with a metadata-only custom role granting exactly:
> `secretmanager.secrets.get`, `secretmanager.secrets.list`, `secretmanager.locations.get`.

> **Optional extra:** to enumerate service-account keys (a hardening check), add
> `iam.serviceAccountKeys.list` to the service account (e.g. via a custom role).

## 2. What we explicitly do NOT request

- ❌ `storage.objects.get` (no object data — bucket metadata only)
- ❌ `bigquery.tables.getData` (datasets/tables metadata only)
- ❌ `secretmanager.versions.access` (secret names/metadata only)
- ❌ `cloudkms.cryptoKeyVersions.useToDecrypt` (no key material)
- ❌ No `roles/owner`, `roles/editor`, or `roles/iam.securityAdmin` anywhere

## 3. Time-bound assignment

> "The service account key is issued for the engagement window only (`<start>` →
> `<end>`) with a short expiry, and the account's IAM bindings are removed no later
> than `<end date>`. Where the platform supports it, prefer Workload Identity /
> short-lived impersonation credentials over a long-lived key."

## 4. Recommended deployment pattern

- **Single engagement:** a dedicated service account in the project(s) in scope with
  the role set above and a **time-limited key** (or short-lived credentials).
- **Organization-wide posture:** add `roles/orgpolicy.policyViewer` at the organization
  level (or grant it per-folder for scoped reviews).
- **Recurring engagements:** use a key-rotation policy (e.g. 30-day expiry) and
  re-provision per engagement rather than reusing credentials.

## 5. Verification

After provisioning, CloudGuard's built-in privilege self-check
(`python3 run.py scan --cloud gcp --project-id <project> --service-account-file key.json`)
confirms the principal is read-only and flags over-privilege before scanning begins.
The least-privilege reference used at scan time is printed by
`python3 run.py policies --cloud gcp`.
