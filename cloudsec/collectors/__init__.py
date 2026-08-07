"""Cloud SDK collectors producing normalized snapshots for the check engine.

Every collector returns ``(snapshot, errors)`` where ``snapshot`` matches the
layout documented in the corresponding checks module. SDKs are imported lazily
so demo mode and static analysis run without any cloud packages installed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple


def collect(cloud: str, auth: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Collect a normalized snapshot for the given cloud."""
    if cloud == "aws":
        from .aws import collect_aws
        return collect_aws(auth)
    if cloud == "azure":
        from .azure import collect_azure
        return collect_azure(auth)
    if cloud == "gcp":
        from .gcp import collect_gcp
        return collect_gcp(auth)
    if cloud == "oci":
        from .oci import collect_oci
        return collect_oci(auth)
    raise ValueError(f"Unknown cloud '{cloud}'")
