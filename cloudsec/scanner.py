"""Scanner orchestration: run the full check catalog over a normalized snapshot."""
from __future__ import annotations

import traceback
from typing import Any, Dict, List, Optional, Set

from .models import Check, Finding, ScanResult, Severity, Status
from .registry import get_checks


_CONFIG_HINT_KEYS = ("name", "id", "arn", "topic_arn", "key_id", "key",
                     "log_group", "function_name", "cluster", "repo_name",
                     "resource_id", "vault", "storage_account", "server_name")

# Top-level snapshot keys that map to well-known resource names (per cloud).
_CONFIG_TOP_ALIASES = {
    "aws": {"root-account": ["iam", "root"], "account-password-policy": ["iam", "password_policy"],
             "cloudtrail": ["trail"], "aws-config": ["config"], "iam-policies": ["iam", "policies"],
             "iam-users": ["iam", "users"], "s3-buckets": ["s3"], "object-storage": ["s3"]},
    "azure": {"root": ["assignments"], "subscription": ["assignments"]},
    "gcp": {"project": ["iam"], "audit": ["audit"]},
    "oci": {"iam-users": ["users"], "iam-policies": ["policies"], "object-storage": ["buckets"],
             "security-lists": ["sec_lists"], "network-security-groups": ["nsgs"],
             "block-storage": ["volumes"], "autonomous-db": ["adbs"], "vault-keys": ["keys"],
             "cloud-guard": ["cloud_guard"], "subnets": ["subnets"], "audit": ["audit"],
             "file-storage": ["filesystems"], "load-balancers": ["lbs"], "dns": ["dns_zones"]},
}


def _config_snippet(snapshot: Dict[str, Any], cloud: str,
                    resource: str) -> Optional[Dict[str, Any]]:
    """Best-effort: return the offending resource's configuration object from
    the snapshot so the dashboard can show a console-style config snippet.
    Falls back to the service section when a single resource cannot be pinned.
    """
    if not resource or not isinstance(snapshot, dict):
        return None
    res = resource.strip()
    # 1) known top-level names (aggregate/root resources)
    alias = _CONFIG_TOP_ALIASES.get(cloud, {}).get(res)
    if alias:
        node = snapshot
        for key in alias:
            if not isinstance(node, dict) or key not in node:
                node = None
                break
            node = node[key]
        if node is not None:
            if isinstance(node, dict):
                return node
            # aggregate list resources: cap so detail rows stay compact
            items = node if isinstance(node, list) else [node]
            return {"items": items[:6], "total": len(items)}
    # 2) needle = last ':' segment (e.g. 'user:ci-bot/key:AKIA…' -> key id)
    needle = res.split(":")[-1].strip()
    if not needle or needle == res:
        needle = res.removeprefix("s3://").strip()
    found: list = []

    def matches(item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        for k in _CONFIG_HINT_KEYS:
            v = item.get(k)
            if v is None:
                continue
            s = str(v)
            if s == needle or needle in s or s in needle:
                return True
        return False

    def walk(node: Any) -> None:
        if found:
            return
        if isinstance(node, list):
            for item in node:
                if isinstance(item, dict) and matches(item):
                    found.append(item)
                    return
                walk(item)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)

    walk(snapshot)
    if found:
        return found[0]
    return None


def run_checks(cloud: str, snapshot: Dict[str, Any],
               meta: Dict[str, Any] | None = None,
               only: Optional[set] = None) -> ScanResult:
    """Execute checks for ``cloud`` against ``snapshot``.

    ``only`` optionally limits execution to a set of check IDs (used by the
    review mode to re-check a targeted list of cases). Every executed check
    produces at least one finding: either per-resource FAIL findings or a
    single aggregate PASS finding when nothing failed.
    """
    meta = meta or {}
    checks = get_checks(cloud)
    # ``None`` = no filter (run everything); an empty set = the filter matched
    # nothing (run zero checks) - the two must stay distinct so --frameworks
    # can never silently degrade into a full scan.
    if only is not None:
        checks = [c for c in checks if c.id in only]
    result = ScanResult(
        cloud=cloud,
        account_id=str(meta.get("account_id") or snapshot.get("account_id")
                       or snapshot.get("subscription_id") or snapshot.get("project_id")
                       or snapshot.get("tenancy") or "unknown"),
        account_name=meta.get("account_name") or snapshot.get("account_name", ""),
        principal=meta.get("principal") or snapshot.get("principal", ""),
        auth_mode=meta.get("auth_mode", "unknown"),
        regions=meta.get("regions", []),
        checks_total=len(checks),
        # Which compliance framework(s) this scan was filtered to (--frameworks).
        # The dashboard hides the Compliance framework mapping panel unless a
        # framework was actually requested at scan time.
        extra={"frameworks": meta.get("frameworks") or []},
    )

    for check in checks:
        try:
            findings = check.run(check, snapshot, meta) or []
            result.checks_executed += 1
            for f in findings:
                if not f.evidence.get("config"):
                    cfg = _config_snippet(snapshot, cloud, f.resource)
                    if cfg is not None:
                        f.evidence["config"] = cfg
            result.findings.extend(findings)
        except Exception as exc:  # noqa: BLE001 - a failing check must not kill the scan
            result.checks_executed += 1
            result.errors.append({
                "check_id": check.id, "error": str(exc)[:300],
                "trace": traceback.format_exc(limit=3),
            })
            result.findings.append(Finding(
                check_id=check.id, check_title=check.title, cloud=check.cloud,
                service=check.service, category=check.category,
                severity=Severity.INFO, status=Status.ERROR,
                resource="(check errored)",
                detail=f"Check execution failed: {exc}",
                remediation=check.remediation, cis=check.cis,
            ))

    # snapshot summary for reporting (counts only, no sensitive data)
    result.snapshot_summary = {
        k: len(v) if isinstance(v, (list, dict)) else 1
        for k, v in snapshot.items() if not k.startswith("_")
    }
    return result
