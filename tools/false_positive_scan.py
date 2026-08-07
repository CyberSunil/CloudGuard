#!/usr/bin/env python3
"""False-positive analysis for CloudGuard scan results.

Reads one or more `result_<cloud>.json` files (or a report directory) and flags
findings that are *likely* false positives, with the reason for each flag. The
idea is not to silently drop findings - it is to give the reviewer a shortlist
to eyeball before ticking them out of an export.

Usage:
    python3 tools/false_positive_scan.py reports/scan_*/result_aws.json
    python3 tools/false_positive_scan.py --dir reports/scan_2026...
    python3 tools/false_positive_scan.py --dir reports/scan_2026... --out fp.csv

Heuristics (a finding can match several):
  env       resource name looks like a dev/test/sandbox environment
  placeholder  resource or detail contains placeholder/dummy markers
  weak-evidence no evidence captured at all for the flagged finding
  info      INFO-severity failure (low signal by definition)
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys

# --------------------------------------------------------------------------- #
# Heuristics
# --------------------------------------------------------------------------- #
ENV_RE = re.compile(
    r"(^|[._\-/])(dev|develop|test|testing|qa|stage|staging|sandbox|demo|sample|"
    r"example|temp|tmp|playground|lab|uat|preprod|pre-prod)([._\-/]|$)",
    re.I,
)
PLACEHOLDER_RE = re.compile(
    r"changeme|replaceme|your[-_ ]|example\.com|dummy|fake|placeholder|"
    r"xxxxxxxx|12345|test[-_ ]key|default[-_ ](key|credential)",
    re.I,
)


def analyze(finding: dict) -> list:
    """Return the list of false-positive reasons for a finding ([] = keep)."""
    reasons = []
    check_id = str(finding.get("check_id", ""))
    resource = str(finding.get("resource", ""))
    detail = str(finding.get("detail", ""))
    status = str(finding.get("status", ""))
    severity = str(finding.get("severity", ""))
    evidence = finding.get("evidence") or {}

    # 1) dev/test-style resource names
    if ENV_RE.search(resource):
        reasons.append("env: resource name suggests a non-production environment")

    # 2) placeholder / dummy markers
    if PLACEHOLDER_RE.search(resource) or PLACEHOLDER_RE.search(detail):
        reasons.append("placeholder: resource or detail contains placeholder/dummy markers")

    # 3) weak evidence - flagged resource has no evidence captured at all
    if status in ("FAIL", "FAILED", "OPEN", "NON_COMPLIANT"):
        if not evidence:
            reasons.append("weak-evidence: no evidence captured for this finding")

    # 4) INFO severity failure
    if severity == "INFO" and status in ("FAIL", "FAILED", "OPEN", "NON_COMPLIANT"):
        reasons.append("info: INFO-severity failure (low signal)")

    return reasons


# --------------------------------------------------------------------------- #
# I/O
# --------------------------------------------------------------------------- #
def load_findings(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="result_<cloud>.json file(s)")
    ap.add_argument("--dir", help="scan report directory (reads result_*.json)")
    ap.add_argument("--out", help="output CSV path (default: false_positives.csv)")
    ap.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    default="LOW",
                    help="only report flagged findings at or above this severity")
    args = ap.parse_args()

    files = list(args.files)
    if args.dir:
        files += sorted(glob.glob(os.path.join(args.dir, "result_*.json")))
    if not files:
        ap.error("no input files: pass result_*.json files or --dir <report dir>")

    rows = []          # (cloud, check_id, severity, resource, status, reasons)
    seen = 0
    for path in files:
        try:
            findings = load_findings(path)
        except Exception as exc:
            print(f"  [skip] {path}: {exc}", file=sys.stderr)
            continue
        cloud = os.path.basename(path).replace("result_", "").replace(".json", "")
        for f in findings:
            seen += 1
            reasons = analyze(f)
            if not reasons:
                continue
            sev = str(f.get("severity", "INFO"))
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            if order.get(sev, 9) > order.get(args.min_severity, 3):
                continue
            rows.append({
                "cloud": cloud or f.get("cloud", "?"),
                "check_id": f.get("check_id", "?"),
                "check_title": f.get("check_title", ""),
                "severity": sev,
                "resource": f.get("resource", "?"),
                "status": f.get("status", "?"),
                "reasons": "; ".join(reasons),
            })

    rows.sort(key=lambda r: (r["cloud"], r["severity"], r["check_id"]))
    flagged = len(rows)

    print(f"\nFalse-positive analysis: {flagged} of {seen} findings flagged "
          f"(review before excluding from exports)\n")
    for r in rows:
        print(f"  [{r['cloud']:<5}] {r['check_id']:<14} {r['severity']:<8} "
              f"{r['status']:<5} {r['resource'][:44]:<44} :: {r['reasons']}")

    if flagged:
        out = args.out or "false_positives.csv"
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nWrote {out} ({flagged} rows). Tick these off in the export "
              "dialog only after manual review.")
    else:
        print("\nNo likely false positives found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
