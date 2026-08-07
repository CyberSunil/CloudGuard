"""End-to-end review-mode test: run cmd_review with the demo snapshots
substituted for the live cloud collector (no SDKs required)."""
import argparse
import csv
import glob
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudsec import cli
from cloudsec.demo import get_demo_snapshots
from cloudsec.scanner import run_checks

# --- template sanity check: cases.csv must stay parseable with valid IDs ---
from cloudsec.output.csv_io import parse_cases_csv
from cloudsec.registry import all_checks
TPL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cases.csv")
from cloudsec.registry import all_checks
from collections import Counter
for _cid, _checks in all_checks().items():
    ids = [c.id for c in _checks]
    dups = [k for k, v in Counter(ids).items() if v > 1]
    assert not dups, f"duplicate check IDs in {_cid}: {dups}"

tpl_rows = parse_cases_csv(TPL)
assert tpl_rows, "cases.csv should parse to non-zero rows"
valid = {ch.id for lst in all_checks().values() for ch in lst}
assert all(r["check_id"] in valid for r in tpl_rows), "cases.csv has a check_id missing from the catalog"
print("template sanity OK:", len(tpl_rows), "cases, all check_ids valid")

SNAPSHOTS = get_demo_snapshots()


def fake_collect(cloud, auth):
    """Substitute the demo snapshot for live collection (with full check set)."""
    snap = SNAPSHOTS[cloud]
    result = run_checks(cloud, snap, meta={"auth_mode": "demo-test", "regions": []})
    return snap, result.errors


import cloudsec.collectors as collectors
collectors.collect = fake_collect  # monkeypatch the module imported inside cmd_review

out = tempfile.mkdtemp(prefix="review_test_")
cases = os.path.join(out, "cases.csv")
with open(cases, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["cloud", "check_id", "resource"])
    # realistic + edge cases (resources must match the demo snapshot)
    w.writerow(["aws", "AWS-S3-004", "s3://legacy-public"])           # FAIL -> STILL_VULNERABLE
    w.writerow(["aws", "AWS-IAM-002", "root-account"])               # PASS -> FIXED
    w.writerow(["aws", "AWS-S3-003", "s3://missing-bucket"])        # not in snapshot
    w.writerow(["aws", "AWS-EC2-999", "i-123"])                     # invalid check id
    w.writerow(["aws", "AWS-IAM-003", "user:ci-bot/key:AKIASTALE98765"])  # FAIL

args = argparse.Namespace(
    cases=cases, cloud="aws", output=out, no_html=True, skip_privilege=True,
    profile=None, region="us-east-1", regions=None, tenant_id=None,
    client_id=None, client_secret=None, subscription_id=None, project_id=None,
    service_account_file=None, oci_config=None, oci_profile=None, compartment=None,
)
rc = cli.cmd_review(args)
print("return code:", rc)

review = glob.glob(os.path.join(out, "scan_*", "review.csv"))[0]
print("review.csv:", review)
rows = list(csv.DictReader(open(review)))
print("review rows:", len(rows))
for r in rows:
    print(f"  {r['check_id']:<14} {r['resource']:<22} -> {r['review_status']}")

# summary assertions
statuses = {r["review_status"] for r in rows}
by_id = {r["check_id"]: r["review_status"] for r in rows}
assert by_id.get("AWS-S3-004") == "STILL_VULNERABLE", "S3-004 should be still vulnerable, got " + str(by_id.get("AWS-S3-004"))
assert by_id.get("AWS-IAM-002") == "FIXED", "IAM-002 should be fixed, got " + str(by_id.get("AWS-IAM-002"))
assert by_id.get("AWS-S3-003") == "NOT_VERIFIED", "S3-003 (missing) should be not verified"
assert by_id.get("AWS-EC2-999") == "INVALID_CHECK", "EC2-999 should be invalid check"
assert by_id.get("AWS-IAM-003") == "STILL_VULNERABLE", "IAM-003 should be still vulnerable"
print("ALL REVIEW ASSERTIONS PASSED")
