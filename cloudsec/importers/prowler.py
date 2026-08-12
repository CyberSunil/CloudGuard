"""Import a Prowler CSV export into a CloudGuard ScanResult.

Prowler's native CSV export uses ';' as the delimiter and a much wider,
differently-named column set than CloudGuard's own findings CSV. This
module maps that format onto CloudGuard's ``ScanResult``/``Finding``
models so the *same* dashboard/CSV/JSON writers used by ``scan``/``demo``
can render a Prowler run without a live cloud credential.

Only PASS/FAIL rows contribute to the risk score and findings table;
Prowler statuses outside that pair are kept but recorded as NOT_ASSESSED
and reported back to the caller. MUTED rows are excluded by default.

Note: check_id/check_title/severity/service come straight from Prowler.
These are Prowler's own identifiers, not CloudGuard catalog IDs, so the
CIS Benchmark / compliance-framework dashboard panels (which key off
CloudGuard's own check registry) stay empty for these findings - every
other dashboard feature (risk score, severity/service breakdown,
findings table, CSV/JSON export) works the same as a native scan.
"""
from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

from ..models import Finding, ScanResult, Severity, Status

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

STATUS_MAP = {
    "PASS": Status.PASS,
    "FAIL": Status.FAIL,
}

CIS_RE = re.compile(r"CIS-[\d.]+:[\d.]+")


def _cis_ref(compliance: str) -> str:
    if not compliance:
        return ""
    hits = sorted(set(CIS_RE.findall(compliance)))
    return "; ".join(hits[:3])


def _category(categories: str, service: str) -> str:
    if categories:
        return categories.split(",")[0].strip()
    return service.title() if service else "Uncategorized"


def load_prowler_csv(path: str, include_muted: bool = False) -> List[Dict[str, str]]:
    """Read a Prowler CSV export (';'-delimited) into raw dict rows."""
    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=";")
        rows = list(reader)
    if not include_muted:
        rows = [r for r in rows if (r.get("MUTED") or "").strip().lower() != "true"]
    return rows


def build_scan_result(rows: List[Dict[str, str]], cloud: str = "azure") -> ScanResult:
    """Turn Prowler CSV rows into a CloudGuard ScanResult."""
    findings: List[Finding] = []
    unmapped_status: Counter = Counter()
    seen_finding_uids = set()

    account_id = rows[0].get("ACCOUNT_UID", "") if rows else ""
    account_name = rows[0].get("ACCOUNT_NAME", "") if rows else ""
    ts = rows[0].get("TIMESTAMP", "") if rows else ""

    for r in rows:
        uid = r.get("FINDING_UID", "")
        if uid and uid in seen_finding_uids:
            continue  # defensive de-dup: skip exact repeat rows
        if uid:
            seen_finding_uids.add(uid)

        raw_status = (r.get("STATUS") or "").strip().upper()
        status = STATUS_MAP.get(raw_status)
        if status is None:
            unmapped_status[raw_status or "(blank)"] += 1
            status = Status.NOT_ASSESSED

        raw_sev = (r.get("SEVERITY") or "").strip().lower()
        severity = SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)

        service = (r.get("SERVICE_NAME") or "general").strip()
        resource = (r.get("RESOURCE_UID") or r.get("RESOURCE_NAME") or "").strip()

        findings.append(Finding(
            check_id=r.get("CHECK_ID", ""),
            check_title=r.get("CHECK_TITLE", ""),
            cloud=cloud,
            service=service.upper() if len(service) <= 4 else service.title(),
            category=_category(r.get("CATEGORIES", ""), service),
            severity=severity,
            status=status,
            resource=resource,
            detail=r.get("STATUS_EXTENDED", ""),
            remediation=r.get("REMEDIATION_RECOMMENDATION_TEXT", ""),
            cis=_cis_ref(r.get("COMPLIANCE", "")) or None,
        ))

    check_ids = {f.check_id for f in findings}
    result = ScanResult(
        cloud=cloud,
        account_id=account_id,
        account_name=account_name,
        timestamp=ts,
        principal="prowler-import",
        auth_mode="prowler:import",
        regions=sorted({r.get("REGION", "") for r in rows if r.get("REGION")}),
        findings=findings,
        checks_total=len(check_ids),
        checks_executed=len(check_ids),
    )
    if unmapped_status:
        result.errors.append({
            "service": "prowler_import",
            "error": f"Rows with unrecognized STATUS values (kept as NOT_ASSESSED): "
                     f"{dict(unmapped_status)}",
        })
    return result


def top_failing_checks(result: ScanResult, limit: int = 15) -> List[Tuple[str, str, str, int]]:
    """(check_id, title, severity, affected_resource_count), busiest first."""
    by_check: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    for f in result.findings:
        if f.status != Status.FAIL:
            continue
        by_check[(f.check_id, f.check_title, f.severity.value)].append(f.resource)
    ranked = sorted(by_check.items(), key=lambda kv: -len(kv[1]))
    return [(cid, title, sev, len(res)) for (cid, title, sev), res in ranked[:limit]]
