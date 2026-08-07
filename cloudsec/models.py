"""Core data models shared across the scanner, checks and reporting."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}[self.value]

    @property
    def rank(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass
class Check:
    """Metadata + logic for a single configuration review check.

    ``run(snapshot, ctx)`` returns a list of Finding objects. A check may emit
    multiple findings (one per offending resource) or a single aggregate finding.
    """
    id: str                 # e.g. "AWS-S3-001"
    cloud: str              # aws | azure | gcp | oci
    service: str            # e.g. "S3", "Network", "Identity"
    category: str           # e.g. "Data Protection"
    severity: Severity
    title: str
    description: str
    remediation: str
    run: Callable[["Check", dict, dict], List["Finding"]]
    cis: Optional[str] = None       # CIS benchmark mapping when applicable
    guidance: Optional[str] = None  # framework refs e.g. "CIS 2.1.1 / SOC2"

    def key(self) -> str:
        return self.id


@dataclass
class Finding:
    check_id: str
    check_title: str
    cloud: str
    service: str
    category: str
    severity: Severity
    status: Status
    resource: str
    detail: str = ""
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cis: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        return d


@dataclass
class ScanResult:
    cloud: str
    account_id: str
    account_name: str = ""
    timestamp: str = ""
    principal: str = ""
    auth_mode: str = ""
    regions: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    checks_total: int = 0
    checks_executed: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    snapshot_summary: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ---- convenience metrics -------------------------------------------------
    @property
    def failed(self) -> List[Finding]:
        return [f for f in self.findings if f.status == Status.FAIL]

    @property
    def passed(self) -> List[Finding]:
        return [f for f in self.findings if f.status == Status.PASS]

    def count_by_status(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.status.value] = out.get(f.status.value, 0) + 1
        return out

    def count_by_severity(self, only_failed: bool = True) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            if only_failed and f.status != Status.FAIL:
                continue
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def risk_score(self) -> float:
        """0-100 weighted score. Higher = more risk."""
        if not self.findings:
            return 0.0
        raw = sum(f.severity.weight for f in self.failed)
        max_raw = self.checks_executed * 10 if self.checks_executed else 1
        return round(min(100.0, raw / max(max_raw, 1) * 100.0), 1)

    def failed_by_service(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.failed:
            out[f.service] = out.get(f.service, 0) + 1
        return out

    def failed_by_category(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.failed:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cloud": self.cloud,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "timestamp": self.timestamp,
            "principal": self.principal,
            "auth_mode": self.auth_mode,
            "regions": self.regions,
            "checks_total": self.checks_total,
            "checks_executed": self.checks_executed,
            "risk_score": self.risk_score(),
            "summary": {
                "by_status": self.count_by_status(),
                "failed_by_severity": self.count_by_severity(True),
                "failed_by_service": self.failed_by_service(),
                "failed_by_category": self.failed_by_category(),
            },
            "errors": self.errors,
            "snapshot_summary": self.snapshot_summary,
            "extra": self.extra,
            "findings": [f.to_dict() for f in self.findings],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ScanResult":
        findings = [
            Finding(
                check_id=f["check_id"],
                check_title=f["check_title"],
                cloud=f["cloud"],
                service=f["service"],
                category=f["category"],
                severity=Severity(f["severity"]),
                status=Status(f["status"]),
                resource=f["resource"],
                detail=f.get("detail", ""),
                remediation=f.get("remediation", ""),
                evidence=f.get("evidence", {}),
                cis=f.get("cis"),
            )
            for f in d.get("findings", [])
        ]
        sr = ScanResult(
            cloud=d["cloud"],
            account_id=d["account_id"],
            account_name=d.get("account_name", ""),
            timestamp=d.get("timestamp", ""),
            principal=d.get("principal", ""),
            auth_mode=d.get("auth_mode", ""),
            regions=d.get("regions", []),
            findings=findings,
            checks_total=d.get("checks_total", 0),
            checks_executed=d.get("checks_executed", 0),
            errors=d.get("errors", []),
            snapshot_summary=d.get("snapshot_summary", {}),
            extra=d.get("extra", {}),
        )
        return sr


def to_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)
