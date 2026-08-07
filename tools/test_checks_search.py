"""Test the fuzzy check-catalog search (checks --search).

Verifies that pasting a misconfiguration description surfaces the correct
check_id(s), including cross-cloud and typo-tolerant matches.
Usage: python3 tools/test_checks_search.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudsec.registry import search_checks  # noqa: E402

fails = []


def ids_for(query, cloud="all"):
    return [r["check"].id for r in search_checks(cloud, query)]


def expect(query, should_contain, cloud="all", label=None):
    got = ids_for(query, cloud)
    label = label or f"{query!r}"
    missing = [c for c in should_contain if c not in got]
    if missing:
        fails.append(f"{label}: expected {missing} in {got}")
        print(f"  FAIL {label}: missing {missing} | got {got}")
    else:
        print(f"  PASS {label} -> {got}")


# exact keyword matches
expect("S3 bucket publicly accessible", ["AWS-S3-001"])
expect("bucket public", ["AWS-S3-001"], label="'bucket public' (AWS)")
expect("root mfa", ["AWS-IAM-002"], label="'root mfa'")
expect("key vault", ["AZ-KV-001", "AZ-KV-002", "AZ-KV-003"], cloud="azure")
expect("cluster not private", ["GCP-GKE-001"])
expect("autonomous database public endpoint", ["OCI-DB-001"])

# cross-cloud: 'public bucket' should surface the public-bucket checks from
# several providers
got_all = ids_for("bucket public")
for cid in ("AWS-S3-001", "GCP-ST-001", "OCI-OS-001"):
    if cid not in got_all:
        fails.append(f"cross-cloud 'bucket public': missing {cid} in {got_all}")
        print(f"  FAIL cross-cloud 'bucket public': missing {cid} | got {got_all}")

# typo tolerance (prefix match, >=3 chars)
got_typo = ids_for("mfa disabled")
if "AWS-IAM-002" not in got_typo:
    fails.append(f"'mfa disabled': expected AWS-IAM-002, got {got_typo}")
    print(f"  FAIL 'mfa disabled' -> {got_typo}")
else:
    print(f"  PASS 'mfa disabled' -> {got_typo}")

# no-match returns empty, no crash
if search_checks("all", "zzzz-no-such-thing"):
    fails.append("garbage query should return []")
    print("  FAIL garbage query returned results")

# empty query returns [] without crashing
if search_checks("all", ""):
    fails.append("empty query should return []")
    print("  FAIL empty query returned results")

# scoped search: azure-only should not return AWS ids
got_az = ids_for("bucket public", "azure")
if any(x.startswith("AWS-") for x in got_az):
    fails.append(f"azure-scoped search leaked AWS ids: {got_az}")
    print(f"  FAIL azure scope leaked AWS -> {got_az}")
else:
    print(f"  PASS azure-scoped 'bucket public' -> {got_az}")

print()
if fails:
    print(f"{len(fails)} FAILURES")
    sys.exit(1)
print("ALL CHECK SEARCH TESTS PASSED")
