"""Comparison engine.

Two use cases:
  1. ``compare --baseline baseline.csv --scan <scan.json|dir>``
     Loads a previous findings export (any CSV produced by this tool, or a
     comparable export with check_id/resource/status columns) and classifies
     each baseline finding as FIXED / STILL_REPRODUCIBLE / REGRESSED /
     NOT_VERIFIED, plus NEW issues present only in the current scan.
  2. ``compare-scans --scan1 dir --scan2 dir``
     Same engine over two scan result directories.

Matching key: (cloud, check_id, normalized resource). Resource matching is
case-insensitive and tolerates URI-scheme prefixes (s3://, gs://, oci://).
"""
from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding, ScanResult, Status


@dataclass
class ComparisonRow:
    check_id: str
    resource: str
    title: str
    cloud: str
    service: str
    category: str
    severity: str
    baseline_status: str
    current_status: str
    outcome: str  # FIXED | STILL_REPRODUCIBLE | REGRESSED | NEW | NOT_VERIFIED | PASSING

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in
                ("check_id", "resource", "title", "cloud", "service", "category",
                 "severity", "baseline_status", "current_status", "outcome")}


OUTCOMES = ("FIXED", "STILL_REPRODUCIBLE", "REGRESSED", "NEW", "NOT_VERIFIED", "PASSING")

HEADER_ALIASES = {
    "check_id": ("check_id", "checkid", "check", "rule_id", "ruleid"),
    "resource": ("resource", "resource_id", "resourceid", "asset", "resource_name"),
    "status": ("status", "result", "outcome", "finding_status", "state"),
    "severity": ("severity", "risk", "risk_level"),
    "title": ("title", "check_title", "finding", "description"),
    "cloud": ("cloud", "provider", "cloud_provider"),
    "service": ("service", "service_name"),
    "category": ("category", "framework"),
}


def _norm(s: str) -> str:
    return (s or "").strip().lower().replace(" ", "").replace("_", "")


def _norm_resource(s: str) -> str:
    r = (s or "").strip().lower()
    for prefix in ("s3://", "gs://", "oci://", "azure://", "gcp://", "aws://"):
        if r.startswith(prefix):
            return r[len(prefix):]
    for prefix in ("s3:", "gs:", "oci:", "storage:", "vault:", "nsg:", "sql:",
                   "vm:", "disk:", "acr:", "app:", "cosmos:", "bucket:", "fw:",
                   "instance:", "disk:", "gke:", "user:", "sa:", "key:", "policy:",
                   "seclist:", "volume:", "adb:", "subnet:", "sg:", "vol:", "rds:",
                   "kms:", "ecr:", "lambda:", "topic:", "cloudtrail:", "config:",
                   "root-account", "iam-", "project-", "subscription-", "tenancy"):
        if r.startswith(prefix):
            return r
    return r


def _match_key(cloud: str, check_id: str, resource: str) -> Tuple[str, str, str]:
    return (cloud.lower(), _norm(check_id), _norm_resource(resource))


def write_golden_baseline(result: ScanResult, path: str, fail_only: bool = False) -> int:
    """Freeze a scan as a golden baseline CSV.

    By default every finding (FAIL + PASS) is recorded so the drift engine
    can also detect REGRESSED states (was compliant in the golden scan, now
    failing). With ``fail_only`` only the failing findings are recorded,
    producing a lighter baseline that only tracks known issues.

    Returns the number of rows written.
    """
    rows = []
    for f in result.findings:
        # Record only actionable states (FAIL/PASS). NOT_APPLICABLE/ERROR
        # findings would otherwise normalize to NOT_VERIFIED noise in drift.
        if f.status not in (Status.FAIL, Status.PASS):
            continue
        if fail_only and f.status != Status.FAIL:
            continue
        rows.append({
            "cloud": f.cloud,
            "check_id": f.check_id,
            "resource": f.resource,
            "status": f.status.value,
            "title": f.check_title,
            "service": f.service,
            "category": f.category,
            "severity": f.severity.value,
        })
    rows.sort(key=lambda r: (r["cloud"], r["check_id"], r["resource"]))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["cloud", "check_id", "resource", "status",
                            "title", "service", "category", "severity"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def parse_baseline_csv(path: str) -> List[Dict[str, Any]]:
    """Parse a baseline CSV into normalized rows.

    Lines starting with '#' are treated as comments/instructions and skipped,
    so a draft template (comparison_template.csv) can carry guidance inside the
    file itself. Column aliases (HEADER_ALIASES) accept CloudGuard exports,
    manual fills and common third-party tool headers.
    """
    with open(path, newline="", encoding="utf-8-sig") as fh:
        lines = (ln for ln in fh if not ln.lstrip().startswith("#"))
        reader = csv.DictReader(lines)
        if not reader.fieldnames:
            return []
        # map actual headers to canonical
        canon: Dict[str, str] = {}
        for header in reader.fieldnames:
            key = _norm(header)
            for canonical, aliases in HEADER_ALIASES.items():
                if key in (_norm(a) for a in aliases):
                    canon[canonical] = header
                    break
        rows: List[Dict[str, Any]] = []
        for raw in reader:
            row: Dict[str, Any] = {}
            for canonical, header in canon.items():
                row[canonical] = (raw.get(header) or "").strip()
            rows.append(row)
    return rows


def build_finding_map(result: ScanResult) -> Dict[Tuple[str, str, str], Finding]:
    m: Dict[Tuple[str, str, str], Finding] = {}
    for f in result.findings:
        m.setdefault(_match_key(f.cloud, f.check_id, f.resource), f)
    return m


def _current_status_for(fmap: Dict[Tuple[str, str, str], Finding],
                        cloud: str, check_id: str, resource: str) -> Optional[str]:
    f = fmap.get(_match_key(cloud, check_id, resource))
    if f:
        return f.status.value
    # fallback: same check but resource stripped of scheme or suffix after ':'
    return None


def compare_scan_to_baseline(result: ScanResult, baseline_rows: List[Dict[str, Any]],
                             baseline_cloud: Optional[str] = None) -> List[ComparisonRow]:
    fmap = build_finding_map(result)
    rows: List[ComparisonRow] = []
    current_fail_keys = {
        _match_key(f.cloud, f.check_id, f.resource)
        for f in result.findings if f.status == Status.FAIL
    }

    for b in baseline_rows:
        cloud = (b.get("cloud") or baseline_cloud or result.cloud).strip() or result.cloud
        check_id = b.get("check_id", "")
        resource = b.get("resource", "")
        if not check_id or not resource:
            continue
        b_status = (b.get("status") or "FAIL").upper()
        if b_status in ("", "PASS", "PASSED", "OK", "COMPLIANT", "PASSING"):
            b_status = "PASS"
        elif b_status in ("FAIL", "FAILED", "OPEN", "NON_COMPLIANT", "VIOLATION"):
            b_status = "FAIL"
        else:
            b_status = "NOT_VERIFIED"

        cur = _current_status_for(fmap, cloud, check_id, resource)
        if cur is None:
            # No finding for the exact resource. If the check ran at all, the
            # resource is no longer flagged -> its issue is resolved (FIXED).
            candidates = [f for f in result.findings
                          if f.cloud == cloud and f.check_id.lower() == check_id.lower()]
            cur = "PASS" if candidates else "NOT_VERIFIED"
        cur = "FAIL" if cur == "FAIL" else ("PASS" if cur == "PASS" else cur)

        if b_status == "FAIL":
            if cur == "FAIL":
                outcome = "STILL_REPRODUCIBLE"
            elif cur == "PASS":
                outcome = "FIXED"
            else:
                outcome = "NOT_VERIFIED"
        else:  # baseline PASS
            if cur == "FAIL":
                outcome = "REGRESSED"
            else:
                outcome = "PASSING"

        f = fmap.get(_match_key(cloud, check_id, resource))
        rows.append(ComparisonRow(
            check_id=check_id, resource=resource,
            title=(b.get("title") or (f.check_title if f else check_id)),
            cloud=cloud,
            service=(b.get("service") or (f.service if f else "")),
            category=(b.get("category") or (f.category if f else "")),
            severity=(b.get("severity") or (f.severity.value if f else "MEDIUM")),
            baseline_status=b_status, current_status=cur, outcome=outcome,
        ))

    # NEW issues in current scan absent from baseline
    baseline_keys = {
        _match_key((b.get("cloud") or baseline_cloud or result.cloud).strip() or result.cloud,
                   b.get("check_id", ""), b.get("resource", ""))
        for b in baseline_rows if b.get("check_id") and b.get("resource")
    }
    for f in result.findings:
        if f.status != Status.FAIL:
            continue
        key = _match_key(f.cloud, f.check_id, f.resource)
        if key not in baseline_keys:
            rows.append(ComparisonRow(
                check_id=f.check_id, resource=f.resource, title=f.check_title,
                cloud=f.cloud, service=f.service, category=f.category,
                severity=f.severity.value,
                baseline_status="NOT_IN_BASELINE", current_status="FAIL",
                outcome="NEW",
            ))

    rows.sort(key=lambda r: (r.outcome != "FIXED", r.severity))
    return rows


def compare_scans(scan1: ScanResult, scan2: ScanResult) -> List[ComparisonRow]:
    """scan1 = older, scan2 = newer. Diff on the same cloud/account."""
    baseline_rows = [
        {"cloud": f.cloud, "check_id": f.check_id, "resource": f.resource,
         "title": f.check_title, "severity": f.severity.value,
         "service": f.service, "category": f.category,
         "status": f.status.value}
        for f in scan1.findings
    ]
    return compare_scan_to_baseline(scan2, baseline_rows, baseline_cloud=scan1.cloud)


def summarize_comparison(rows: List[ComparisonRow]) -> Dict[str, Any]:
    counts: Dict[str, int] = {o: 0 for o in OUTCOMES}
    by_severity: Dict[str, Dict[str, int]] = {}
    for r in rows:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
        bucket = by_severity.setdefault(r.outcome, {})
        bucket[r.severity] = bucket.get(r.severity, 0) + 1
    return {
        "counts": counts,
        "total": len(rows),
        "by_severity": by_severity,
        "fix_rate": round(100.0 * counts.get("FIXED", 0) / max(1, counts.get("FIXED", 0)
                                                               + counts.get("STILL_REPRODUCIBLE", 0)), 1),
    }


def load_scan_result(path: str) -> ScanResult:
    """Load a ScanResult from a scan JSON file or a directory containing one."""
    results = load_scan_results(path)
    return results


def load_scan_results(path: str) -> ScanResult:
    """Load scan results. A directory may contain several result_<cloud>.json
    files; they are combined into one ScanResult so baseline rows for every
    cloud resolve correctly."""
    if os.path.isdir(path):
        candidates = sorted(
            f for f in os.listdir(path)
            if f.endswith(".json") and "result" in f.lower())
        if not candidates:
            candidates = sorted(f for f in os.listdir(path) if f.endswith(".json"))
        if not candidates:
            raise FileNotFoundError(f"No scan JSON found under {path}")
        loaded = []
        for fname in candidates:
            try:
                with open(os.path.join(path, fname), encoding="utf-8") as fh:
                    loaded.append(ScanResult.from_dict(json.load(fh)))
            except Exception:
                continue
        if not loaded:
            raise ValueError(f"No readable scan JSON found under {path}")
        if len(loaded) == 1:
            return loaded[0]
        findings = [f for r in loaded for f in r.findings]
        return ScanResult(
            cloud="all",
            account_id=";".join(f"{r.cloud}={r.account_id}" for r in loaded),
            account_name="combined scan",
            timestamp=loaded[0].timestamp,
            findings=findings,
            checks_executed=sum(r.checks_executed for r in loaded),
            checks_total=sum(r.checks_total for r in loaded),
            errors=[e for r in loaded for e in r.errors],
        )
    with open(path, encoding="utf-8") as fh:
        return ScanResult.from_dict(json.load(fh))
