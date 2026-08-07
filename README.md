<div align="center">

# 🛡️ CloudGuard

### Multi-Cloud Configuration Review & Hardening Dashboard

**AWS · Azure · GCP · OCI — one read-only scan, one dashboard per cloud, every finding tracked to closure.**

<br>

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Checks](https://img.shields.io/badge/Checks-321-brightgreen)
![AWS](https://img.shields.io/badge/AWS-120%20checks-orange)
![Azure](https://img.shields.io/badge/Azure-90%20checks-0078D4)
![GCP](https://img.shields.io/badge/GCP-68%20checks-4285F4)
![OCI](https://img.shields.io/badge/OCI-43%20checks-red)
![Demo](https://img.shields.io/badge/demo-no%20credentials-yellow)

**Run a read-only review → see what's wrong, *where*, and *how to fix it* → prove remediation.**

</div>

---

## 🎯 The Problem

Cloud security posture assessment today is squeezed between two extremes:

- **Heavyweight scanners** (Prowler-class) dump thousands of findings you never revisit — and burn read-heavy credentials against production.
- **Stale tools** (ScoutSuite) have quietly rotted — especially on **Azure**, where identity coverage and result reliability are simply not trustworthy anymore.

Neither is built for what a **security reviewer actually does**: run a review with *minimum* credentials, explain the risk to a client, hand over a hardening plan, then come back next quarter and **prove the issues are gone**.

**CloudGuard exists for that workflow.**

> 🔍 **Scan** — read-only review of a customer environment with global-reader / read-only roles (verified least-privilege templates ship per cloud).  
> 📋 **Review** — re-check a targeted list of cases from a CSV against the live environment, fast and cheap.  
> 📊 **Compare & Drift** — prove remediation: **FIXED · STILL_REPRODUCIBLE · REGRESSED · NEW**, with a remediation rate for the report.  
> 🖥️ **Dashboard** — a gorgeous, self-contained, offline HTML report per cloud: risk score, service-grouped findings, CIS Benchmark score, coverage, least-privilege reference.  
> 📤 **GRC-ready exports** — findings-only PDF / Excel / CSV with false-positive exclusions and framework mappings (SOC 2 · PCI DSS · NIST 800-53 · HIPAA).

## 🏆 Why CloudGuard (vs the tools you know)

| | **CloudGuard** 🛡️ | **Prowler** | **ScoutSuite** |
|---|---|---|---|
| Clouds | **AWS · Azure · GCP · OCI** (first-class, incl. OCI) | AWS (+limited others) | Multi-cloud, but **unmaintained** |
| Azure identity depth | ✅ Purpose-built: Entra ID MFA, Conditional Access, Key Vault metadata, blob soft delete | Partial | ❌ The documented weak spot |
| OCI coverage | ✅ Native SDK checks | ❌ | ⚠️ |
| Review workflow | ✅ Baseline compare, review mode, drift, remediation rate | CLI-first, no review loop | ❌ |
| Least-privilege | ✅ First-class: verified templates + access-request docs per cloud | ❌ | ❌ |
| Dashboard | ✅ One offline HTML report per cloud | ❌ (CLI) | Static HTML |
| Client exports | ✅ Findings-only PDF/Excel/CSV, false-positive exclusions | ❌ | ❌ |
| Checks | **321 hand-written, SDK-backed** (120 AWS · 90 Azure · 68 GCP · 43 OCI) | ~300+ broad | ~1000 rule *firings* |

**CloudGuard deliberately optimizes for the review workflow — smaller-but-deeper where it matters (Azure, OCI, least-privilege, remediation tracking) instead of broad-but-shallow.**

## 💎 Advantages at a Glance

| Advantage | What it means for you |
|---|---|
| 🌐 **4 clouds, one tool** | Native SDK checks for AWS, Azure, GCP **and** OCI — OCI is a first-class citizen, not an afterthought |
| 🎯 **Purpose-built Azure checks** | Entra ID MFA registration, Conditional Access, Key Vault metadata expiry, blob soft delete — closing the exact gaps that made ScoutSuite's Azure results unreliable |
| 🔐 **Least-privilege by design** | Verified reader/read-only templates per cloud, a pre-scan privilege self-check, and client-ready access-request documents |
| 🔄 **Remediation tracking** | `compare` / `review` / `drift` turn a snapshot into a story: fixed vs still-open vs regressed, with a remediation rate |
| 🖥️ **One dashboard per cloud** | Findings with weighted risk score, service-grouped results, CIS Benchmark score, coverage, least-privilege views — all offline, zero CDN |
| 📤 **Client-safe exports** | Findings-only PDF/Excel/CSV with false-positive exclusion checkboxes; nothing but findings + where/impact/remediation |
| 🧪 **Zero-cost demo** | `python3 run.py demo` exercises every feature with realistic data — no credentials, no SDK installs |

---

## 📚 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [🔧 Dependencies](#-dependencies)
- [✨ Features](#-features)
- [🤖 CI/CD & Scheduled Scans](#-cicd--scheduled-scans)
- [🔑 Scan Credentials (Read-Only by Design)](#-scan-credentials-read-only-by-design)
- [📊 Baseline CSV Format](#-baseline-csv-format)
- [📁 Outputs](#-outputs)
- [🗺️ Mapping Your Own Findings to Check IDs](#️-mapping-your-own-findings-to-check-ids)
- [🧩 Extending the Catalog](#-extending-the-catalog)
- [📏 Catalog Size vs ScoutSuite / Prowler](#-catalog-size-vs-scoutsuite--prowler)
- [📦 Packaging & Distribution (apt / dpkg / pip)](#-packaging--distribution-apt--dpkg--pip)
- [🗺️ Roadmap](#️-roadmap)

---

## 🚀 Quick Start

### 🧪 Step 0 — See everything with zero credentials

```bash
# Demo mode: stdlib only, no SDKs, no cloud access. Realistic data.
python3 run.py demo
python3 run.py demo --output reports
python3 run.py demo --cloud aws --output reports/demo_aws
# Multi-cloud demo → ONE report per cloud under reports/scan_*/<cloud>/
# (index.html links them). Single-cloud demo → reports/scan_*/dashboard.html
```

### 🔍 Step 1 — Live scan (one provider per run, read-only)

```bash
pip install -r requirements.txt          # or: pip install ".[all]"

python3 run.py scan --cloud aws   --profile my-readonly-profile
python3 run.py scan --cloud azure --tenant-id ... --client-id ... --client-secret ... --subscription-id ...
python3 run.py scan --cloud gcp    --project-id my-proj --service-account-file key.json
python3 run.py scan --cloud oci    --oci-config ~/.oci/config --oci-profile DEFAULT --compartment ocid1...
```

> Live scans are intentionally **single-cloud** (one provider per run) so the dashboard, privilege check and baseline comparison stay unambiguous.

### 🔁 Step 2 — Review mode: re-check a list of cases from a CSV

```bash
# cases.csv ships with real check IDs for all 4 clouds (replace resources with your own)
python3 run.py review --cases cases.csv --cloud aws --profile my-readonly-profile
```

### 📈 Step 3 — Prove remediation

```bash
python3 run.py compare --baseline baseline.csv --scan reports/scan_20260701T120000Z
python3 run.py compare-scans --scan1 reports/scan_old --scan2 reports/scan_new
python3 run.py save-baseline --scan reports/scan_approved    # freeze a golden baseline
python3 run.py drift --baseline golden_baseline.csv --scan reports/scan_latest --output drift_report
```

### 🔭 Step 4 — Explore coverage & find the right check

```bash
python3 run.py coverage
python3 run.py checks --cloud aws
python3 run.py checks --search "public bucket"
python3 run.py checks --search "key vault" --json     # machine-readable
python3 run.py policies                                # least-privilege templates
```

### 🏗️ Framework-scoped scans (optional)

Every check maps to **SOC 2 · PCI DSS · NIST 800-53 · HIPAA** for export; `--frameworks` filters the run by the check's primary framework:

```bash
python3 run.py scan --cloud aws --frameworks pci --profile my-readonly-profile
python3 run.py demo --cloud aws --frameworks hipaa
python3 run.py review --cases cases.csv --cloud aws --frameworks pci
python3 run.py checks --cloud azure --frameworks soc2 --json
```

---

## 🔧 Dependencies

**CloudGuard is dependency-light by design: demo mode runs on the Python standard library alone.**

| Mode | Requires |
|---|---|
| 🧪 `demo` | **Nothing** — Python ≥ 3.9 standard library only |
| ☁️ Real scans | Per-cloud official SDKs (below) |

| Cloud | Packages | Install |
|---|---|---|
| **AWS** | `boto3>=1.34.0` | `pip install ".[aws]"` |
| **Azure** | `azure-identity`, `azure-mgmt-resource/storage/network/keyvault/sql/compute/monitor/containerregistry/web/cosmosdb` | `pip install ".[azure]"` |
| **GCP** | `google-cloud-storage/resource-manager/compute/sql/kms/logging/container` | `pip install ".[gcp]"` |
| **OCI** | `oci>=2.126.0` | `pip install ".[oci]"` |
| **All** | Everything above | `pip install ".[all]"` or `pip install -r requirements.txt` |

**Install options**
- 🐍 **pip** — `pip install .[all]` (installs the `cloudguard` command; `pip install .` alone is stdlib-only and demo works)
- 🐧 **apt / dpkg** — a self-contained `.deb` bundles its own Python venv with all SDKs (see [Packaging](#-packaging--distribution-apt--dpkg--pip))
- 🐳 **CI** — runs headless; a GitHub Actions workflow ships in `.github/workflows/`

**Runtime notes**
- Requires **Python ≥ 3.9** (declared in `pyproject.toml`).
- All checks perform **read-only** API calls; see [Scan Credentials](#-scan-credentials-read-only-by-design).
- Dashboard generation has **zero runtime JS dependencies** — everything is embedded, works offline, no CDN.

---

## ✨ Features

### 🌐 Multi-cloud configuration review — AWS · Azure · GCP · OCI

- **321 native SDK checks** (AWS 120 · Azure 90 · GCP 68 · OCI 43), written directly against each cloud's official SDK.
- The **Azure module is purpose-built** to close the gaps that made ScoutSuite unreliable — blob public access, Key Vault ACLs, NSG exposure, activity-log export, **Entra ID MFA & Conditional Access**.
- Coverage spans **identity** (MFA, RBAC, IAM policies, service-account keys), **storage** (S3/GCS/Blob encryption, versioning, public access), **networking** (security groups, NSGs, VPC flow logs, NACLs, firewalls), **databases** (RDS/SQL/Cloud SQL/Redshift/Cosmos/Redis), **containers & Kubernetes** (EKS/AKS/GKE/ECR/ACR), **data** (DynamoDB/EFS/ElastiCache/SQS/BigQuery), **logging & monitoring** (CloudTrail, Config, CloudWatch alarms, audit config, diagnostic settings, flow logs) and **security services** (GuardDuty, Defender, Cloud Guard, Bastion, Secrets Manager, Key Vault).

### 🔐 Credential-privilege awareness

Designed to run with a *global reader / read-only* identity. A best-effort **privilege self-check** runs pre-scan and warns if the principal is elevated (root, Owner/Contributor, primitive roles, `manage all-resources`). Least-privilege policy templates ship per cloud (`python3 run.py policies`), plus client-facing access-request documents.

### 🖥️ One self-contained HTML dashboard per cloud

- KPI row, **weighted risk score** (0–100 posture gauge with CRITICAL/HIGH/MEDIUM/LOW bands), severity distribution donut, Top-10 services, service/category breakdowns.
- **Findings default view** — severity-ordered (Critical → High → Medium → Low), grouped by service, with per-finding **Where the issue is · Impact · Remediation/hardening steps** and an official vendor reference link.
- **Dynamic SPA-style sidebar** — Overview, CIS Benchmark, Comparison, Coverage and Least-privilege views each load on click; real vendor **logo + account number** at the top of every report.
- **Zero CDN, works offline.**

### 📊 CIS Benchmark & compliance mapping

- Every check carries its **CIS Benchmark** control reference and a **CIS benchmark score per run** (grouped by control section: Identity, Storage, Logging, Networking…).
- Every finding also maps to **SOC 2 · PCI DSS · NIST 800-53 · HIPAA** — framework chips in the finding detail and dedicated columns in PDF/Excel/CSV exports.
- The compliance framework panel only appears when the scan ran with `--frameworks <name>` — a plain scan stays clean.

### 🔄 Baseline comparison, scan-to-scan diff & drift

- **Compare** a scan against a previous findings CSV → every issue classified **FIXED / STILL_REPRODUCIBLE / REGRESSED / NEW**, with a **remediation rate**.
- **Drift** against a frozen *golden baseline* → NEW & REGRESSED findings flagged as configuration drift since the approved state, with a themed `drift.html` report.

### 📤 Findings-only exports with false-positive exclusion

- **Export PDF / Excel / CSV** produce nothing but the findings — each with Where / Impact / Remediation (+ CIS & framework references).
- Every export opens a **checkbox dialog**: untick false positives and they're excluded everywhere, struck through in the table, and tracked in the Excel summary.
- **CIS checklist export** — a 2-sheet `.xls` workbook (per-control summary by benchmark section + finding detail rows).
- PDF includes a branded CloudGuard header with your logo, severity colour-coding, a per-page **"Page N of Y"** footer, and clickable hyperlinks.

### 🧪 Demo mode

A realistic multi-cloud environment so every feature works end-to-end with **zero credentials and zero SDK installs**.

---

## 🤖 CI/CD & Scheduled Scans

CloudGuard runs headless — perfect for pipelines and cron.

### Option A — GitHub Actions (`.github/workflows/cloudguard-scan.yml`)

- Runs **nightly 02:00 UTC** (change the `cron`) and on push to `cloudsec/**` or `run.py`; manual trigger via "Run workflow" (choose a provider or `all`, optionally pass a baseline).
- Authenticates with **OIDC / workload identity federation** — no long-lived keys in the repo.
- Uploads each provider's `dashboard.html` + findings as a **GitHub Actions artifact**; runs providers as independent **matrix jobs**.
- Required secrets: `AWS_ROLE_ARN`, `AWS_REGION`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT`, `GCP_PROJECT_ID`, `OCI_CONFIG`, `OCI_API_KEY`. Optional: `BASELINE_CSV`.

### Option B — plain cron / systemd timer (`tools/scan_cron.sh`)

```bash
0 2 * * *  cd /opt/cloudsec-review && ./tools/scan_cron.sh aws   >> /var/log/cloudguard.log 2>&1
0 2 * * *  cd /opt/cloudsec-review && ./tools/scan_cron.sh gcp --baseline golden_baseline.csv --retain 5
```

Pair with `drift` to alert on NEW/REGRESSED findings since a golden baseline.

---

## 🔑 Scan Credentials (Read-Only by Design)

| Cloud | Auth options | Recommended principal |
|---|---|---|
| **AWS** | `--profile <name>`, env vars, or default boto3 chain; `--regions` to override | IAM role with managed `ReadOnlyAccess` (never root). `python3 run.py policies --cloud aws` prints the verified scoped minimum + exclusions |
| **Azure** | `--tenant-id --client-id --client-secret` (SP) or `az login` / managed identity | SP with built-in **Reader** + **Key Vault Reader** + Entra **Global Reader**; strict-alternative **CloudGuard Reader custom role** available. Client-ready request: `azure_access_requirements.md` |
| **GCP** | `--project-id` + `--service-account-file key.json`, or ADC | SA with the `viewer`-family role set printed by `python3 run.py policies --cloud gcp` (plus a metadata-only storage custom role) |
| **OCI** | `--oci-config ~/.oci/config --oci-profile DEFAULT --compartment <ocid>` | Group with `read all-resources` plus granular read statements from `python3 run.py policies --cloud oci` — never `manage all-resources` |

Every check performs **read-only** API calls. The privilege self-check (`--skip-privilege` to disable) warns when the identity used is more powerful than needed.

Client-facing access-request documents ship for every cloud:
[`aws_access_requirements.md`](aws_access_requirements.md) · [`azure_access_requirements.md`](azure_access_requirements.md) · [`gcp_access_requirements.md`](gcp_access_requirements.md) · [`oci_access_requirements.md`](oci_access_requirements.md)

---

## 📊 Baseline CSV Format

The **Comparison section only appears in the dashboard when a previous report is provided** (`--baseline`); a plain scan has no comparison. Two ways to provide it:

1. **Already using CloudGuard — no format change.** Re-export an earlier run's `findings_<cloud>.csv`, or freeze an approved scan with `python3 run.py save-baseline --scan reports/scan_<ts>` (a **golden baseline**; `--fail-only` records only open issues).
2. **Manual scan or another tool (ScoutSuite / Prowler…)** — start from the draft template [`comparison_template.csv`](comparison_template.csv), which contains in-file instructions and example rows for all four clouds. You need a `check_id` (CloudGuard's catalog ID) + the exact `resource` — find the right `check_id` by pasting your misconfiguration description: `python3 run.py checks --search "<issue text>"`.

Any CSV with the columns below works (headers auto-detected, aliases accepted, `#` lines are comments):

```
cloud,check_id,severity,status,resource,title,service,category
aws,AWS-S3-001,CRITICAL,FAIL,s3://legacy-public,S3 bucket publicly accessible,S3,Storage
```

`status` `FAIL/FAILED/OPEN/NON_COMPLIANT` = open issue; `PASS/OK` = compliant.

### Outcome classification

| Outcome | Meaning |
|---|---|
| ✅ `FIXED` | was failing in baseline, now passing |
| 🔁 `STILL_REPRODUCIBLE` | was failing, still failing |
| ⚠️ `REGRESSED` | was passing in baseline, now failing (**drift**) |
| 🆕 `NEW` | failing now, not present in baseline (**drift**) |
| ❓ `NOT_VERIFIED` | could not be re-checked (permission/region gap) |

---

## 📁 Outputs

Each scan/review run creates `reports/scan_<timestamp>/`:

```
reports/scan_<timestamp>/            (live scan / single-cloud demo)
    dashboard.html                   self-contained interactive dashboard
    findings_<cloud>.csv             findings (baseline-compatible format)
    result_<cloud>.json              full machine-readable scan results
    comparison.csv                   baseline comparison (when a baseline is given)
    comparison_summary.json          outcome counts + remediation rate
    review.csv                       review-mode per-case status (review runs only)

reports/scan_<timestamp>/            (multi-cloud demo)
    index.html                       links to each per-cloud report
    aws/dashboard.html · findings_aws.csv · result_aws.json · comparison.csv ...
    azure/dashboard.html · findings_azure.csv · result_azure.json · comparison.csv ...
    gcp/dashboard.html · findings_gcp.csv · result_gcp.json · comparison.csv ...
    oci/dashboard.html · findings_oci.csv · result_oci.json · comparison.csv ...
```

The dashboard opens on the **Findings** view (risk gauge + filterable table with search, severity/category/status/**framework** filters, and CSV/Excel/PDF export). The sidebar swaps in Overview, CIS Benchmark, Comparison, Coverage and Least-privilege views on demand. Exports go through the false-positive exclusion dialog.

---

## 🗺️ Mapping Your Own Findings to Check IDs

`check_id` is the catalog's canonical ID for a *type* of misconfiguration (e.g. `AWS-S3-001` = "S3 bucket publicly accessible"); `resource` is *where* it is (e.g. `s3://backups`). To build a review cases CSV from a manual scan:

1. `python3 run.py checks --search "<your misconfiguration text>"` and pick the best-matching `check_id`.
2. Put it in the `check_id` column of `cases.csv` and the exact resource in `resource`.
3. Run `python3 run.py review --cases cases.csv --cloud <provider> ...`.

If the resource can't be found live the case is reported `NOT_VERIFIED`; a `check_id` outside the catalog is `INVALID_CHECK` — both are signals to fix the mapping, not silent failures.

---

## 🧩 Extending the Catalog

Each cloud's checks live in `cloudsec/checks/<cloud>.py` as pure functions over a normalized snapshot (see the docstring at the top of each file for the schema). Adding a check = one `Check(...)` entry: metadata + a `run(snapshot, ctx)` returning `Finding` objects. The registry, coverage report, CLI and dashboard pick it up automatically. Each check also needs a demo-data row so the dashboard/tests exercise it.

---

## 📏 Catalog Size vs ScoutSuite / Prowler

This tool ships **321 distinct, hand-written checks** (AWS 120 · Azure 90 · GCP 68 · OCI 43) — including unique coverage like AWS SageMaker ML security, Azure Front Door & Functions, GCP Vertex AI & Pub/Sub CMEK, and OCI API Gateway, which ScoutSuite does not cover at all. ScoutSuite's marketing "1000+" counts *rule firings* (each rule fired per resource × region); its distinct rule count is in the low hundreds. This is the largest per-cloud CIS-focused set where every check is backed by real read-only collection code and demo data.

---

## 📦 Packaging & Distribution (apt / dpkg / pip)

CloudGuard ships as a self-contained `.deb` that bundles its own Python virtualenv (all cloud SDKs included) — installs on any Debian/Ubuntu system and works offline with no pip installs.

### Option A — build a `.deb` directly (no Debian tooling needed)

```bash
sudo apt install dpkg-dev python3-venv
./packaging/build_deb.sh                  # bundle ALL cloud SDKs (needs network)
./packaging/build_deb.sh --clouds aws     # AWS SDK only (smaller .deb)
./packaging/build_deb.sh --demo           # stdlib only, no network (fast check)
sudo apt install ./dist/cloudguard_1.0.0_amd64.deb
cloudguard --help && cloudguard demo --cloud aws
```

### Option B — proper Debian source package (for maintainers)

```bash
sudo apt install dh-virtualenv debhelper dpkg-dev
git tag -a v1.0.0 -m "CloudGuard 1.0.0"
dpkg-buildpackage -us -uc          # builds cloudguard_1.0.0_amd64.deb
```

### Option C — host your own APT repository

Publish the `.deb`s (e.g. `reprepro`/`aptly`), sign with GPG, then users run:

```
deb [signed-by=/usr/share/keyrings/cloudguard.gpg] https://apt.example.com/cloudguard stable main
apt update && apt install cloudguard
```

### Also via pip

`pip install .[all]` installs the `cloudguard` command (SDKs as optional extras `.[aws]` `.[azure]` `.[gcp]` `.[oci]` `.[all]`; `pip install .` alone is stdlib-only — demo works).

---

## 🗺️ Roadmap

- 📈 Catalog expansion toward ~600 checks (AWS Organizations/SCPs, CloudHSM, Azure Private DNS & Firewall, GCP Cloud NAT & Spanner, OCI Functions & Streaming…)
- 🔌 Native ScoutSuite / Prowler result ingestion (today: map their output into `comparison_template.csv`)
- 🌍 Unified multi-cloud risk view for consolidated reporting (today: one dashboard per cloud, by design)
- 📋 `--frameworks cis` filter and deeper SOC 2 / PCI / NIST / HIPAA control evidence per finding

---

## 📄 License

[MIT](LICENSE) © CyberSunil — For Cloud Config Review Purpose by **CyberSunil** 🛡️
