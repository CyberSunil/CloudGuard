"""Golden-baseline drift tests.

End-to-end: freeze a trusted demo scan as a golden baseline, mutate the
environment (a bucket becomes public = drift, logging is enabled = fixed),
re-scan, and assert the drift engine classifies everything correctly.
Also drives the real CLI (save-baseline + drift) to verify the report files.
"""
import argparse
import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloudsec import cli
from cloudsec.compare import (compare_scan_to_baseline, parse_baseline_csv,
                              summarize_comparison, write_golden_baseline)
from cloudsec.demo import get_demo_snapshots
from cloudsec.scanner import run_checks

CLOUD = "aws"


def scan(snapshot):
    return run_checks(CLOUD, snapshot, meta={"auth_mode": "drift-test"})


def _add_public_bucket(snap):
    snap["s3"] = list(snap["s3"]) + [{
        "name": "new-public", "public": True, "public_acl": "public-read",
        "encryption": True, "versioning": True, "logging": True}]
    return snap


def _fix_logging(snap):
    for b in snap["s3"]:
        if b["name"] == "legacy-public":
            b["logging"] = True
    return snap


def run():
    base = get_demo_snapshots()[CLOUD]
    baseline = scan(copy.deepcopy(base))
    golden_path = os.path.join(tempfile.mkdtemp(prefix="drift_"), "golden_baseline.csv")
    n = write_golden_baseline(baseline, golden_path)
    non_actionable = [f for f in baseline.findings if f.status.value not in ("FAIL", "PASS")]
    assert n == len(baseline.findings) - len(non_actionable), \
        "only FAIL/PASS findings belong in the golden baseline"
    print("golden baseline rows:", n, "(excluded non-actionable:", len(non_actionable), ")")

    # --- mutate: new public bucket (drift) + legacy logging enabled (fixed) ---
    changed = _fix_logging(_add_public_bucket(copy.deepcopy(base)))
    current = scan(changed)

    rows = compare_scan_to_baseline(current, parse_baseline_csv(golden_path),
                                    baseline_cloud=CLOUD)
    summary = summarize_comparison(rows)
    counts = summary["counts"]
    print("drift counts:", {k: v for k, v in counts.items() if v})

    by_key = {(r.check_id, r.resource, r.outcome) for r in rows}
    assert counts["NEW"] >= 1, "expected at least one NEW (drift) finding"
    assert any(r.check_id == "AWS-S3-001" and r.resource.endswith("new-public")
               and r.outcome == "NEW" for r in rows), "public bucket not flagged as NEW"
    assert counts["FIXED"] >= 1, "expected at least one FIXED finding"
    assert any(r.check_id == "AWS-S3-004" and r.resource.endswith("legacy-public")
               and r.outcome == "FIXED" for r in rows), "logging fix not flagged as FIXED"
    assert counts["STILL_REPRODUCIBLE"] >= 1, "expected remaining known issues"

    # --- CLI end-to-end: save-baseline + drift ---
    out = tempfile.mkdtemp(prefix="drift_cli_")
    base_dir = os.path.join(out, "scan_base")
    cur_dir = os.path.join(out, "scan_cur")
    os.makedirs(base_dir)
    os.makedirs(cur_dir)
    from cloudsec.output.csv_io import write_json
    write_json(os.path.join(base_dir, f"result_{CLOUD}.json"), baseline.to_dict())
    write_json(os.path.join(cur_dir, f"result_{CLOUD}.json"), current.to_dict())

    golden = os.path.join(out, "golden_baseline.csv")
    rc = cli.cmd_save_baseline(argparse.Namespace(scan=base_dir, output=golden, fail_only=False))
    assert rc == 0, f"save-baseline rc={rc}"
    assert os.path.exists(golden)

    dr_out = os.path.join(out, "drift_report")
    rc = cli.cmd_drift(argparse.Namespace(baseline=golden, scan=cur_dir,
                                          output=dr_out, no_html=False))
    assert rc == 0, f"drift rc={rc}"
    assert os.path.exists(os.path.join(dr_out, "drift.csv"))
    assert os.path.exists(os.path.join(dr_out, "drift.html"))
    with open(os.path.join(dr_out, "drift_summary.json")) as fh:
        s = json.load(fh)
    assert s["counts"]["NEW"] >= 1 and s["counts"]["FIXED"] >= 1
    html = open(os.path.join(dr_out, "drift.html")).read()
    assert "Golden Baseline Drift" in html, "drift.html missing drift title"

    print("drift tests OK: NEW/REGRESSED/FIXED/STILL + CLI (save-baseline, drift) all verified")


if __name__ == "__main__":
    run()
