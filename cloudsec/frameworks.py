"""Compliance framework mappings for every check.

Each check is mapped to control references in up to four frameworks:

  - SOC 2            (Trust Services Criteria, 2017)
  - PCI DSS          (v4.0)
  - NIST 800-53      (Rev. 5)
  - HIPAA            (Security Rule, 45 CFR 164.308 / 164.312)

Mappings are resolved in two layers:

  1. ``EXPLICIT_MAP`` - hand-curated control references for the most
     important checks (identity, storage, encryption, logging, backup).
  2. ``KEYWORD_RULES`` - derived references for everything else, chosen
     from the check title / service / category (e.g. anything about MFA
     maps to SOC2 CC6.5 / PCI 8.x / NIST IA-2 / HIPAA 164.312(d)).

Every check therefore ends up with a reference in all four frameworks
(``frameworks_for()`` never returns an empty dict).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

FRAMEWORKS = ("SOC 2", "PCI DSS", "NIST 800-53", "HIPAA")

# --------------------------------------------------------------------------- #
# Hand-curated mappings (check_id -> {framework: control reference})
# --------------------------------------------------------------------------- #
EXPLICIT_MAP: Dict[str, Dict[str, str]] = {
    # ---------------- AWS: identity & access ----------------
    "AWS-IAM-001": {"SOC 2": "CC6.1", "PCI DSS": "8.2.4", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AWS-IAM-002": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AWS-IAM-003": {"SOC 2": "CC6.2", "PCI DSS": "8.2.4", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "AWS-IAM-004": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AWS-IAM-005": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "AWS-IAM-006": {"SOC 2": "CC6.1", "PCI DSS": "8.4.2", "NIST 800-53": "IA-5(1)", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-IAM-007": {"SOC 2": "CC6.1", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    # ---------------- AWS: storage & data ----------------
    "AWS-S3-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-S3-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-S3-003": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-S3-004": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-S3-005": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-S3-006": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-S3-007": {"SOC 2": "CC6.1", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-S3-008": {"SOC 2": "A1.2", "PCI DSS": "3.3.2", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-DDB-001": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-DDB-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-DDB-004": {"SOC 2": "A1.2", "PCI DSS": "3.3.2", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-EFS-001": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-EFS-002": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-SM-001": {"SOC 2": "CC6.2", "PCI DSS": "3.5.1", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "AWS-SM-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-KMS-001": {"SOC 2": "CC6.1", "PCI DSS": "3.5.1", "NIST 800-53": "SC-12", "HIPAA": "164.312(a)(2)(iv)"},
    # ---------------- AWS: compute & network ----------------
    "AWS-EC2-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-EC2-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-EC2-005": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-EC2-006": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(12)", "HIPAA": "164.312(d)"},
    "AWS-EC2-007": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-EC2-008": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-EC2-009": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-EC2-010": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-EC2-011": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-VPC-002": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-VPC-003": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-VPC-004": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-ECR-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-ECR-002": {"SOC 2": "CC7.2", "PCI DSS": "11.3.1", "NIST 800-53": "RA-5", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-LMB-001": {"SOC 2": "CC8.1", "PCI DSS": "6.2.4", "NIST 800-53": "SI-2(2)", "HIPAA": "164.308(a)(1)"},
    "AWS-LMB-002": {"SOC 2": "CC6.6", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "AWS-RDS-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-RDS-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-RDS-003": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-RDS-004": {"SOC 2": "A1.2", "PCI DSS": "3.3.2", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-RDS-005": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-RSH-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-RSH-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-SNS-001": {"SOC 2": "CC6.6", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "AWS-SQS-001": {"SOC 2": "CC6.6", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "AWS-SQS-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    # ---------------- AWS: logging & monitoring ----------------
    "AWS-CT-001": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-CT-005": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-CFG-001": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-CW-001": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-002": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-003": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-004": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-005": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-006": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-007": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-008": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-009": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CW-010": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AWS-CWG-001": {"SOC 2": "CC7.2", "PCI DSS": "10.5.1", "NIST 800-53": "AU-11", "HIPAA": "164.312(b)"},
    "AWS-CWG-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AWS-BACK-001": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-BACK-002": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AWS-GD-001": {"SOC 2": "CC7.2", "PCI DSS": "11.4", "NIST 800-53": "SI-4", "HIPAA": "164.308(a)(1)(ii)(D)"},
    # ---------------- AWS: web & edge ----------------
    "AWS-ELB-001": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AWS-ELB-002": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-ELB-003": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AWS-ELB-004": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AWS-ELB-005": {"SOC 2": "CC6.6", "PCI DSS": "6.6", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-CF-001": {"SOC 2": "CC6.6", "PCI DSS": "6.6", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AWS-CF-002": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AWS-CF-003": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AWS-CF-005": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AWS-ACM-001": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-12", "HIPAA": "164.312(e)(2)(ii)"},
    "AWS-R53-001": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-20", "HIPAA": "164.312(e)(2)(ii)"},
    # ---------------- Azure: identity & access ----------------
    "AZ-IAM-001": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AZ-IAM-002": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AZ-IAM-003": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AZ-IAM-004": {"SOC 2": "CC6.6", "PCI DSS": "8.5.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "AZ-IAM-005": {"SOC 2": "CC7.2", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "AZ-RBAC-001": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "AZ-RBAC-002": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "AZ-RBAC-003": {"SOC 2": "CC6.2", "PCI DSS": "7.2.1", "NIST 800-53": "AC-2(4)", "HIPAA": "164.308(a)(3)(ii)(B)"},
    "AZ-RBAC-004": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    # ---------------- Azure: storage / key vault / sql ----------------
    "AZ-STR-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-STR-002": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AZ-STR-003": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AZ-STR-004": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-STR-005": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AZ-STR-006": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AZ-KV-001": {"SOC 2": "A1.2", "PCI DSS": "3.3.2", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AZ-KV-002": {"SOC 2": "A1.2", "PCI DSS": "3.3.2", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AZ-KV-003": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-KV-006": {"SOC 2": "CC6.2", "PCI DSS": "3.5.1", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "AZ-SQL-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-SQL-002": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AZ-SQL-003": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AZ-SQL-007": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-SQL-008": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "AZ-COS-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-COS-002": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-COS-004": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    # ---------------- Azure: network / compute / app ----------------
    "AZ-NSG-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-NSG-003": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AZ-VM-001": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AZ-VM-002": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-VM-004": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "AZ-APP-001": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AZ-APP-002": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "AZ-APP-006": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2", "HIPAA": "164.312(d)"},
    "AZ-AKS-001": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "AZ-AKS-002": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "AZ-MON-001": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "AZ-MON-002": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-6", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "AZ-DEF-001": {"SOC 2": "CC7.2", "PCI DSS": "11.4", "NIST 800-53": "SI-4", "HIPAA": "164.308(a)(1)(ii)(D)"},
    # ---------------- GCP ----------------
    "GCP-IAM-001": {"SOC 2": "CC6.2", "PCI DSS": "8.2.4", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "GCP-IAM-002": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "GCP-IAM-003": {"SOC 2": "CC6.6", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "GCP-IAM-004": {"SOC 2": "CC6.2", "PCI DSS": "7.2.1", "NIST 800-53": "AC-2(4)", "HIPAA": "164.308(a)(3)(ii)(B)"},
    "GCP-IAM-005": {"SOC 2": "CC6.2", "PCI DSS": "8.2.4", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "GCP-IAM-006": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "GCP-ST-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-ST-003": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "GCP-ST-004": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "GCP-ST-007": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "GCP-FW-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-FW-002": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-CMP-001": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "GCP-CMP-003": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-SQL-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-SQL-002": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "GCP-SQL-003": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "GCP-SQL-004": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "GCP-SQL-005": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-SQL-006": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "GCP-KMS-001": {"SOC 2": "CC6.1", "PCI DSS": "3.5.1", "NIST 800-53": "SC-12", "HIPAA": "164.312(a)(2)(iv)"},
    "GCP-LOG-001": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "GCP-LOG-002": {"SOC 2": "CC7.2", "PCI DSS": "10.5.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "GCP-LOG-003": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "GCP-GKE-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-GKE-002": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-GKE-004": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2", "HIPAA": "164.312(d)"},
    "GCP-GKE-006": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-BQ-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "GCP-BQ-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "GCP-CR-001": {"SOC 2": "CC6.6", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "GCP-MEM-001": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "GCP-SM-001": {"SOC 2": "CC6.2", "PCI DSS": "3.5.1", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "GCP-ORG-001": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3", "HIPAA": "164.308(a)(4)(ii)"},
    # ---------------- OCI ----------------
    "OCI-IAM-001": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "OCI-IAM-002": {"SOC 2": "CC6.2", "PCI DSS": "8.2.4", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "OCI-IAM-003": {"SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
    "OCI-IAM-004": {"SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
    "OCI-IAM-006": {"SOC 2": "CC6.2", "PCI DSS": "8.2.4", "NIST 800-53": "IA-5(1)", "HIPAA": "164.308(a)(4)"},
    "OCI-OS-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "OCI-OS-002": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "OCI-OS-003": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "OCI-OS-004": {"SOC 2": "CC6.6", "PCI DSS": "7.2.1", "NIST 800-53": "AC-3(7)", "HIPAA": "164.312(a)(1)"},
    "OCI-NET-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "OCI-NET-002": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "OCI-BV-001": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "OCI-BV-002": {"SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
    "OCI-DB-001": {"SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
    "OCI-DB-002": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "OCI-KMS-001": {"SOC 2": "CC6.1", "PCI DSS": "3.5.1", "NIST 800-53": "SC-12", "HIPAA": "164.312(a)(2)(iv)"},
    "OCI-CG-001": {"SOC 2": "CC7.2", "PCI DSS": "11.4", "NIST 800-53": "SI-4", "HIPAA": "164.308(a)(1)(ii)(D)"},
    "OCI-NET-003": {"SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
    "OCI-NET-005": {"SOC 2": "CC6.7", "PCI DSS": "4.1", "NIST 800-53": "SC-8", "HIPAA": "164.312(e)(2)(ii)"},
    "OCI-FS-001": {"SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
    "OCI-AUDIT-001": {"SOC 2": "CC7.2", "PCI DSS": "10.5.1", "NIST 800-53": "AU-11", "HIPAA": "164.312(b)"},
}

# --------------------------------------------------------------------------- #
# Derived mappings: keyword rules applied to (title + service + category).
# Rules are evaluated in order; the first match wins. The most specific rules
# come first so e.g. "MFA" beats the generic "identity" rule.
#
# Each rule also carries the LEAD framework(s) the check primarily serves - a
# single check can be central to several regimes (e.g. encryption matters to
# NIST and HIPAA). ``--frameworks`` uses this lead to decide which checks run.
# --------------------------------------------------------------------------- #
KEYWORD_RULES: List[Tuple[Tuple[str, ...], Dict[str, str], Set[str]]] = [
    (("mfa", "multi-factor", "multi factor"), {
        "SOC 2": "CC6.5", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.312(d)"},
     {"SOC 2", "HIPAA"}),
    (("root", "admin account", "break-glass", "break glass"), {
        "SOC 2": "CC6.1", "PCI DSS": "8.3.1", "NIST 800-53": "IA-2(1)", "HIPAA": "164.308(a)(4)"},
     {"SOC 2"}),
    (("password", "credential"), {
        "SOC 2": "CC6.1", "PCI DSS": "8.4.2", "NIST 800-53": "IA-5(1)", "HIPAA": "164.312(a)(2)(iv)"},
     {"SOC 2", "HIPAA"}),
    (("public", "anonymous", "unauthenticated", "open access", "all users", "all-authenticated",
      "internet", "0.0.0.0", "management ports", "publicly"), {
        "SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
     {"PCI DSS", "NIST 800-53"}),
    (("encrypt", "encryption", "cmek", "cmk", "kms", "tls", "ssl", "https", "transit",
      "at rest", "at-rest"), {
        "SOC 2": "CC6.7", "PCI DSS": "3.4.1", "NIST 800-53": "SC-28", "HIPAA": "164.312(a)(2)(iv)"},
     {"NIST 800-53", "HIPAA"}),
    (("log", "audit", "monitor", "alarm", "trail", "diagnostic", "flow log", "tracing",
      "retention", "sentinel", "watcher", "dashboards"), {
        "SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"},
     {"SOC 2", "HIPAA"}),
    (("backup", "snapshot", "versioning", "recovery", "replica", "drift", "point-in-time",
      "deletion protection", "object lock"), {
        "SOC 2": "A1.2", "PCI DSS": "10.5.1", "NIST 800-53": "CP-9", "HIPAA": "164.308(a)(7)(ii)(A)"},
     {"SOC 2"}),
    (("waf", "firewall", "nsg", "security group", "security list", "network policy",
      "bastion", "ddos", "endpoint", "private endpoint", "private cluster", "private ip"), {
        "SOC 2": "CC6.6", "PCI DSS": "1.3.4", "NIST 800-53": "SC-7(5)", "HIPAA": "164.312(e)(1)"},
     {"PCI DSS"}),
    (("runtime", "deprecated", "version", "patch", "auto-upgrade", "auto-repair",
      "binary authorization", "image scan", "lifecycle"), {
        "SOC 2": "CC8.1", "PCI DSS": "6.2.4", "NIST 800-53": "SI-2(2)", "HIPAA": "164.308(a)(1)"},
     {"NIST 800-53"}),
    (("privilege", "role", "iam", "rbac", "least", "admin", "wildcard", "owner",
      "contributor", "policy"), {
        "SOC 2": "CC6.3", "PCI DSS": "7.2.1", "NIST 800-53": "AC-6(1)", "HIPAA": "164.308(a)(4)(ii)"},
     {"NIST 800-53", "HIPAA"}),
    (("vulnerab", "defender", "guard", "detector", "scanning", "antimalware",
      "security center", "cloud guard"), {
        "SOC 2": "CC7.2", "PCI DSS": "11.4", "NIST 800-53": "SI-4", "HIPAA": "164.308(a)(1)(ii)(D)"},
     {"NIST 800-53"}),
]

# Fallback when no keyword rule matches (should be unreachable, but guarantees
# the four-framework contract).
_DEFAULT = {
    "SOC 2": "CC7.2", "PCI DSS": "10.2.1", "NIST 800-53": "AU-12", "HIPAA": "164.312(b)"}


def frameworks_for(check) -> Dict[str, str]:
    """Return {framework: control reference} for a Check (or check_id str).

    Explicit hand-curated mappings win; otherwise the first keyword rule that
    matches the check's title/service/category applies.
    """
    cid = check.id if hasattr(check, "id") else str(check)
    explicit = EXPLICIT_MAP.get(cid)
    if explicit:
        return dict(explicit)
    if hasattr(check, "title"):
        hay = " ".join([check.title or "", check.service or "", check.category or ""]).lower()
    else:
        hay = str(check).lower()
    for keywords, mapping, _lead in KEYWORD_RULES:
        if any(k in hay for k in keywords):
            return dict(mapping)
    return dict(_DEFAULT)


# CLI names -> canonical framework names (used by ``--frameworks``).
FRAMEWORK_ALIASES = {
    "soc2": "SOC 2", "pci": "PCI DSS",
    "nist": "NIST 800-53", "hipaa": "HIPAA",
}


def lead_frameworks(check) -> Set[str]:
    """Primary framework(s) a check serves, from its first matching keyword
    rule. Because every check maps to all four frameworks for export, this
    lead is what makes ``--frameworks`` filtering meaningful: a network
    exposure check leads in PCI DSS / NIST, an MFA check in SOC 2 / HIPAA.
    """
    if hasattr(check, "title"):
        hay = " ".join([check.title or "", check.service or "", check.category or ""]).lower()
    else:
        hay = str(check).lower()
    for keywords, _mapping, lead in KEYWORD_RULES:
        if any(k in hay for k in keywords):
            return set(lead)
    return {"SOC 2"}


def framework_check_ids(cloud: str, frameworks: List[str]) -> Set[str]:
    """Check IDs for ``cloud`` whose lead framework matches any requested
    value. ``cis`` selects checks with a CIS benchmark mapping; the other
    values select checks whose lead set includes that framework. Returns an
    empty set if nothing matches, never ``None``."""
    from .registry import get_checks
    out: Set[str] = set()
    for ch in get_checks(cloud):
        for fw in frameworks:
            if fw == "cis":
                if ch.cis:
                    out.add(ch.id)
                    break
            elif FRAMEWORK_ALIASES.get(fw) in lead_frameworks(ch):
                out.add(ch.id)
                break
    return out
