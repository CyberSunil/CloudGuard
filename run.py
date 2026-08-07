#!/usr/bin/env python3
"""CloudGuard - multi-cloud configuration review.

Two operational modes:
    Scan   - full configuration scan of a live cloud (read-only).
    Review - re-check a targeted list of cases from a CSV against a live cloud.

Usage:
    python3 run.py demo
    python3 run.py scan --cloud aws --profile my-profile
    python3 run.py review --cases cases.csv --cloud aws --profile my-profile
    python3 run.py compare --baseline baseline.csv --scan reports/scan_xxxx/
    python3 run.py coverage
    python3 run.py policies
"""
import sys

from cloudsec.cli import main

if __name__ == "__main__":
    sys.exit(main())
