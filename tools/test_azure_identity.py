"""End-to-end test of the Azure Entra ID identity checks (MFA + Conditional Access).

Verifies:
  1. The 5 AZ-IAM checks exist in the catalog with the right severities.
  2. The demo snapshot produces the expected FAIL/PASS posture.
  3. The honest NOT_APPLICABLE path when Entra ID data wasn't collected.
  4. Review mode classifies an AZ-IAM case against the demo snapshot.
  5. 'checks --search mfa' now surfaces Azure checks (previously zero).

Usage: python3 tools/test_azure_identity.py
"""
import argparse
import csv
import glob
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudsec import cli  # noqa: E402
from cloudsec.demo import get_demo_snapshots  # noqa: E402
from cloudsec.registry import get_checks, search_checks  # noqa: E402
from cloudsec.scanner import run_checks  # noqa: E402

fails = []


def check(cond, label):
    if cond:
        print(f"  PASS {label}")
    else:
        fails.append(label)
        print(f"  FAIL {label}")


# 1. catalog: 5 identity checks present
ids = {c.id: c for c in get_checks("azure")}
for cid, sev in (("AZ-IAM-001", "HIGH"), ("AZ-IAM-002", "CRITICAL"),
                 ("AZ-IAM-003", "HIGH"), ("AZ-IAM-004", "HIGH"),
                 ("AZ-IAM-005", "MEDIUM")):
    check(cid in ids, f"catalog has {cid}")
    if cid in ids:
        check(ids[cid].severity.value == sev, f"{cid} severity {sev}")
        check(ids[cid].cis is not None or ids[cid].guidance, f"{cid} framework ref")

# 2. demo findings
res = run_checks("azure", get_demo_snapshots()["azure"], meta={"auth_mode": "demo"})
az_iam = [f for f in res.findings if f.check_id.startswith("AZ-IAM")]
by_status = {}
for f in az_iam:
    by_status.setdefault(f.status.value, []).append(f.check_id)
check("FAIL" in by_status and "PASS" in by_status,
      f"demo has both FAIL and PASS identity findings ({ {k: len(v) for k, v in by_status.items()} })")
check(any(f.resource == "user:infra-admin@contoso.com" and f.check_id == "AZ-IAM-002"
          for f in az_iam), "demo flags privileged user without MFA (AZ-IAM-002)")
check("AZ-IAM-004" in by_status.get("FAIL", []), "demo flags unblocked legacy auth (AZ-IAM-004)")

# 3. NOT_APPLICABLE path when not collected
snap = dict(get_demo_snapshots()["azure"])
snap["aad"] = {"collected": False, "users": [], "ca_policies": []}
na = run_checks("azure", snap, meta={"auth_mode": "test"})
na_rows = [f for f in na.findings if f.check_id.startswith("AZ-IAM")]
check(len(na_rows) == 5 and all(f.status.value == "NOT_APPLICABLE" for f in na_rows),
      "not-collected -> 5 NOT_APPLICABLE findings (no false PASS)")

# 4. review mode classifies an AZ-IAM case
import cloudsec.collectors as collectors  # noqa: E402

SNAPS = get_demo_snapshots()


def fake_collect(cloud, auth):
    snap = SNAPS[cloud]
    result = run_checks(cloud, snap, meta={"auth_mode": "demo-test", "regions": []})
    return snap, result.errors


collectors.collect = fake_collect
out = tempfile.mkdtemp(prefix="azid_test_")
cases = os.path.join(out, "cases.csv")
with open(cases, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["cloud", "check_id", "resource"])
    w.writerow(["azure", "AZ-IAM-002", "user:infra-admin@contoso.com"])  # FAIL -> STILL_VULNERABLE
    w.writerow(["azure", "AZ-IAM-005", "conditional-access"])           # PASS -> FIXED
args = argparse.Namespace(
    cases=cases, cloud="azure", output=out, no_html=True, skip_privilege=True,
    profile=None, region="us-east-1", regions=None, tenant_id="t", client_id="c",
    client_secret="s", subscription_id=None, project_id=None,
    service_account_file=None, oci_config=None, oci_profile=None, compartment=None,
)
rc = cli.cmd_review(args)
check(rc == 0, f"cmd_review azure rc 0 (got {rc})")
review = glob.glob(os.path.join(out, "scan_*", "review.csv"))
check(bool(review), "review.csv written")
if review:
    rows = {r["check_id"]: r["review_status"] for r in csv.DictReader(open(review[0]))}
    check(rows.get("AZ-IAM-002") == "STILL_VULNERABLE",
          f"AZ-IAM-002 classified STILL_VULNERABLE (got {rows.get('AZ-IAM-002')})")
    check(rows.get("AZ-IAM-005") == "FIXED",
          f"AZ-IAM-005 classified FIXED (got {rows.get('AZ-IAM-005')})")

# 5. search now surfaces Azure MFA
hits = {r["check"].id for r in search_checks("azure", "mfa")}
check("AZ-IAM-001" in hits and "AZ-IAM-002" in hits,
      f"azure search 'mfa' surfaces AZ-IAM-001/002 (got {sorted(hits)})")

print()
if fails:
    print(f"{len(fails)} FAILURES: {fails}")
    sys.exit(1)
print("ALL AZURE IDENTITY TESTS PASSED")
