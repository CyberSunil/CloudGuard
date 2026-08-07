"""CSV serialization for findings (baseline format), comparison results and reviews."""
from __future__ import annotations

import csv
import json
from typing import Any, Dict, List, Optional

from ..compare import ComparisonRow
from ..models import ScanResult

FINDING_HEADERS = ["cloud", "check_id", "check_title", "service", "category",
                   "severity", "status", "resource", "detail", "cis", "remediation"]

REVIEW_HEADERS = ["cloud", "check_id", "check_title", "resource", "severity",
                  "review_status", "detail", "remediation", "cis", "reviewed_at"]


def parse_cases_csv(path: str) -> List[Dict[str, str]]:
    """Parse a review-mode cases CSV (cloud, check_id, resource).

    Column aliases are accepted: ``check``/``control`` for check_id and
    ``resource``/``target`` for the resource.
    """
    rows: List[Dict[str, str]] = []
    with open(path, "r", newline="", encoding="utf-8") as fh:
        # Skip comment rows (starting with '#') so a template header comment
        # never becomes the fieldname row. Streams so large CSVs stay cheap.
        lines = (ln for ln in fh if not ln.lstrip().startswith("#"))
        reader = csv.DictReader(lines)
        if not reader.fieldnames:
            return rows
        names = {n.strip().lower().replace(" ", "_"): n for n in reader.fieldnames}
        cid_col = names.get("check_id") or names.get("check") or names.get("control")
        res_col = names.get("resource") or names.get("target") or names.get("object")
        cloud_col = names.get("cloud") or names.get("provider")
        for raw in reader:
            def _get(col: Optional[str]) -> str:
                return (raw.get(col) or "").strip() if col else ""
            check_id = _get(cid_col)
            resource = _get(res_col)
            if not check_id and not resource:
                continue
            rows.append({
                "cloud": _get(cloud_col).lower(),
                "check_id": check_id,
                "resource": resource,
            })
    return rows


def write_review_csv(path: str, rows: List[Dict[str, Any]]) -> str:
    """Write the review report CSV (one row per reviewed case)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=REVIEW_HEADERS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def scan_to_csv_rows(result: ScanResult) -> List[Dict[str, Any]]:
    return [
        {
            "cloud": f.cloud, "check_id": f.check_id, "check_title": f.check_title,
            "service": f.service, "category": f.category, "severity": f.severity.value,
            "status": f.status.value, "resource": f.resource, "detail": f.detail,
            "cis": f.cis or "", "remediation": f.remediation,
        }
        for f in result.findings
    ]


def write_findings_csv(path: str, result: ScanResult) -> str:
    rows = scan_to_csv_rows(result)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FINDING_HEADERS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_comparison_csv(path: str, rows: List[ComparisonRow]) -> str:
    headers = ["outcome", "check_id", "resource", "title", "cloud", "service",
               "category", "severity", "baseline_status", "current_status"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r.to_dict())
    return path


def write_json(path: str, obj: Any) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)
    return path
