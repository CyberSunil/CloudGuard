"""CloudGuard command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from . import __version__
from .compare import (compare_scan_to_baseline, compare_scans, load_scan_result,
                      parse_baseline_csv, summarize_comparison, write_golden_baseline)
from .demo import get_demo_snapshots
from .frameworks import framework_check_ids
from .models import Finding, ScanResult
from .output.csv_io import (parse_cases_csv, write_comparison_csv,
                            write_findings_csv, write_json, write_review_csv)
from .output.html import build_dashboard_html, write_dashboard
from .privilege import check_privilege, least_privilege_templates
from .registry import CLOUDS, CLOUD_LABELS, coverage_report, get_checks, search_checks
from .scanner import run_checks

SEP = "=" * 76


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _out_dir(base: str) -> str:
    d = os.path.join(base, f"scan_{_ts()}")
    os.makedirs(d, exist_ok=True)
    return d


def _auth_from_args(a: argparse.Namespace) -> Dict[str, Any]:
    return {
        "profile": getattr(a, "profile", None),
        "region": getattr(a, "region", None),
        "regions": getattr(a, "regions", None),
        "tenant_id": getattr(a, "tenant_id", None),
        "client_id": getattr(a, "client_id", None),
        "client_secret": getattr(a, "client_secret", None),
        "subscription_id": getattr(a, "subscription_id", None),
        "project_id": getattr(a, "project_id", None),
        "service_account_file": getattr(a, "service_account_file", None),
        "config_file": getattr(a, "oci_config", None),
        "oci_profile": getattr(a, "oci_profile", None),
        "compartment": getattr(a, "compartment", None),
    }


def _print_result(result: ScanResult) -> None:
    print(SEP)
    label = CLOUD_LABELS.get(result.cloud, result.cloud)
    print(f"  {label} ({result.cloud})")
    print(f"  Account : {result.account_name or result.account_id}  [{result.account_id}]")
    print(f"  Time    : {result.timestamp}   Principal: {result.principal or 'n/a'}")
    print(f"  Checks  : {result.checks_executed}/{result.checks_total} executed   "
          f"Errors: {len(result.errors)}")
    by = result.count_by_status()
    print(f"  Status  : FAIL={by.get('FAIL', 0)}  PASS={by.get('PASS', 0)}  "
          f"NA={by.get('NOT_APPLICABLE', 0)}  ERR={by.get('ERROR', 0)}")
    # Distinguish check rules from finding rows: a resource-level check emits
    # one finding per affected resource (e.g. AWS-EC2-001 flags every open SG).
    failing_checks = len({f.check_id for f in result.findings
                          if f.status.value in ('FAIL', 'ERROR')})
    print(f"  Findings: {len(result.findings)} row(s) across {result.checks_total} checks "
          f"({failing_checks} check(s) failing) - resource-level checks emit one "
          f"finding per resource")
    sev = result.count_by_severity(True)
    if sev:
        print("  Severity: " + "  ".join(f"{k}={v}" for k, v in
                                         sorted(sev.items(), key=lambda x: -_RANK[x[0]])))
    print(f"  Risk    : {result.risk_score()} / 100")
    priv = result.extra.get("privilege_check")
    if priv:
        print(f"  Priv    : {priv['level']}" +
              (f"  warnings: {'; '.join(priv['warnings'])}" if priv["warnings"] else ""))
    if result.errors:
        print(f"  [!] {len(result.errors)} collector/check error(s):")
        for e in result.errors[:5]:
            print(f"      - {e.get('check_id', e.get('service', '?'))}: {e.get('error', '')[:120]}")


_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def cmd_scan(a: argparse.Namespace) -> int:
    from .collectors import collect

    # Live scans are intentionally single-cloud: one provider per run so the
    # dashboard, privilege check and baseline comparison stay unambiguous.
    clouds = [a.cloud]
    auth = _auth_from_args(a)
    out = _out_dir(a.output)
    results: Dict[str, ScanResult] = {}
    baseline_rows = (parse_baseline_csv(a.baseline)
                     if a.baseline and os.path.exists(a.baseline) else [])

    only = None
    if a.frameworks:
        only = framework_check_ids(a.cloud, a.frameworks)
        print(f"  Framework filter --frameworks {' '.join(a.frameworks)}: "
              f"{len(only)} of {len(get_checks(a.cloud))} {a.cloud} checks will run")

    for cloud in clouds:
        print(SEP)
        print(f"  Scanning {CLOUD_LABELS[cloud]} ({cloud}) ...")
        try:
            snapshot, errors = collect(cloud, auth)
        except ImportError as exc:
            print(f"  [SKIP] {cloud}: missing SDK ({exc}). Install it with:")
            print(f"         pip install -r requirements.txt")
            continue
        except Exception as exc:
            print(f"  [FAIL] {cloud}: {exc}")
            continue
        result = run_checks(cloud, snapshot,
                            meta={"auth_mode": f"live:{cloud}",
                                  "regions": auth.get("regions") or [auth.get("region")],
                                  "frameworks": a.frameworks or []},
                            only=only)
        result.errors = errors + result.errors
        if not a.skip_privilege:
            check_privilege(cloud, result, snapshot, auth)
        results[cloud] = result
        _print_result(result)
        write_findings_csv(os.path.join(out, f"findings_{cloud}.csv"), result)
        write_json(os.path.join(out, f"result_{cloud}.json"), result.to_dict())

    if not results:
        print("\nNo clouds scanned successfully.")
        return 1

    comparison_rows = None
    comparison_summary = None
    if baseline_rows:
        print(SEP)
        print("  Comparing against baseline CSV ...")
        combined = _combine(results)
        comparison_rows = compare_scan_to_baseline(combined, baseline_rows)
        comparison_summary = summarize_comparison(comparison_rows)
        write_comparison_csv(os.path.join(out, "comparison.csv"), comparison_rows)
        write_json(os.path.join(out, "comparison_summary.json"), comparison_summary)

    _finalize(results, out, comparison_rows, comparison_summary, a.no_html)
    print(SEP)
    print(f"  Output written to: {out}")
    return 0


def _combine(results: Dict[str, ScanResult]) -> ScanResult:
    findings = []
    for r in results.values():
        findings.extend(r.findings)
    return ScanResult(
        cloud="all", account_id=",".join(f"{k}={v.account_id}" for k, v in results.items()),
        account_name="combined", findings=findings,
        checks_executed=sum(r.checks_executed for r in results.values()),
        checks_total=sum(r.checks_total for r in results.values()),
        errors=[e for r in results.values() for e in r.errors])


def cmd_demo(a: argparse.Namespace) -> int:
    out = _out_dir(a.output)
    snapshots = get_demo_snapshots()
    if a.cloud:
        if a.cloud not in snapshots:
            print(f"  [FAIL] no demo snapshot for '{a.cloud}'.")
            return 1
        snapshots = {a.cloud: snapshots[a.cloud]}

    # Individual report PER CLOUD - exactly like a real single-cloud scan.
    # A multi-cloud demo writes one report directory per provider, each with
    # its own dashboard.html / findings / result + per-cloud baseline
    # comparison. A single-cloud demo (--cloud) stays flat in the scan dir,
    # identical to how a live scan writes its output.
    multi = len(snapshots) > 1
    baseline_rows = (parse_baseline_csv(a.baseline)
                     if a.baseline and os.path.exists(a.baseline) else None)
    if a.baseline and not baseline_rows:
        print(f"  [WARN] baseline file not found: {a.baseline}; skipping comparison.")
    for cloud, snapshot in snapshots.items():
        cdir = os.path.join(out, cloud) if multi else out
        os.makedirs(cdir, exist_ok=True)
        only = framework_check_ids(cloud, a.frameworks) if a.frameworks else None
        if a.frameworks:
            print(f"  Framework filter --frameworks {' '.join(a.frameworks)}: "
                  f"{len(only)} of {len(get_checks(cloud))} {cloud} checks will run")
        result = run_checks(cloud, snapshot,
                            meta={"auth_mode": "demo", "frameworks": a.frameworks or []},
                            only=only)
        check_privilege(cloud, result, snapshot, {"_demo": True})
        print(SEP)
        print(f"  {CLOUD_LABELS[cloud]} ({cloud})")
        _print_result(result)
        write_findings_csv(os.path.join(cdir, f"findings_{cloud}.csv"), result)
        write_json(os.path.join(cdir, f"result_{cloud}.json"), result.to_dict())

        # Per-cloud baseline comparison: runs ONLY when --baseline is passed
        # (exactly like a live scan without a previous report). Baseline rows
        # are filtered to this cloud before matching so each cloud's section
        # stays clean (no NOT_VERIFIED noise from other providers' rows).
        comparison_rows = None
        comparison_summary = None
        if baseline_rows:
            rows_for_cloud = [r for r in baseline_rows
                              if (r.get("cloud") or "").lower() == cloud]
            comparison_rows = compare_scan_to_baseline(result, rows_for_cloud)
            comparison_summary = summarize_comparison(comparison_rows)
            write_comparison_csv(os.path.join(cdir, "comparison.csv"), comparison_rows)
            write_json(os.path.join(cdir, "comparison_summary.json"), comparison_summary)
            print(f"  Comparison vs baseline ({cloud}): "
                  f"FIXED={comparison_summary['counts'].get('FIXED', 0)}  "
                  f"STILL_REPRODUCIBLE={comparison_summary['counts'].get('STILL_REPRODUCIBLE', 0)}  "
                  f"NEW={comparison_summary['counts'].get('NEW', 0)}  "
                  f"REGRESSED={comparison_summary['counts'].get('REGRESSED', 0)}")

        if not a.no_html:
            html = build_dashboard_html({cloud: result}, comparison_rows, comparison_summary,
                                        title="Cloud Configuration Review")
            write_dashboard(os.path.join(cdir, "dashboard.html"), html)

    if not baseline_rows:
        print(SEP)
        print("  No --baseline provided: the Comparison section is omitted.")
        print("  Pass one to enable it, e.g. python3 run.py demo --baseline sample_baseline.csv")
    if multi and not a.no_html:
        _write_demo_index(out, list(snapshots.keys()))
    print(SEP)
    print(f"  Demo output written to: {out}")
    if multi:
        for cloud in snapshots:
            print(f"    - {cloud}: {os.path.join(out, cloud, 'dashboard.html')}")
    else:
        print(f"    - {os.path.join(out, 'dashboard.html')}")
    print("  Open each cloud's dashboard HTML in a browser to explore.")
    return 0


def _write_demo_index(out: str, clouds: List[str]) -> None:
    """Small index page listing every per-cloud demo report."""
    cards = "".join(
        f'<a class="card" href="{c}/dashboard.html">'
        f'<b>{CLOUD_LABELS.get(c, c)}</b>'
        f'<span>{c}</span></a>'
        for c in clouds)
    html = ("<!doctype html><html><head><meta charset='utf-8'>"
            "<title>CloudGuard demo reports</title>"
            "<style>body{font-family:system-ui;background:#0b1120;color:#e5e7eb;"
            "margin:0;padding:40px}h1{font-size:20px;margin:0 0 6px}"
            "p{color:#94a3b8;margin:0 0 24px}.grid{display:grid;"
            "grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px}"
            "a.card{display:block;padding:18px;border-radius:12px;background:#111a2e;"
            "border:1px solid #1e293b;text-decoration:none;color:inherit}"
            "a.card:hover{border-color:#22d3ee}a.card b{display:block;font-size:18px}"
            "a.card span{color:#94a3b8;font-size:13px}</style></head><body>"
            f"<h1>CloudGuard &middot; demo scan reports</h1>"
            f"<p>One report per cloud provider - open each dashboard below.</p>"
            f"<div class='grid'>{cards}</div></body></html>")
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(html)


def _finalize(results: Dict[str, ScanResult], out: str,
              comparison_rows=None, comparison_summary=None, no_html: bool = False,
              review: bool = False) -> None:
    if no_html:
        return
    title = "Cloud Configuration Review" + (" - Review Mode" if review else "")
    html = build_dashboard_html(results, comparison_rows, comparison_summary,
                                title=title, review=review)
    write_dashboard(os.path.join(out, "dashboard.html"), html)


def cmd_save_baseline(a: argparse.Namespace) -> int:
    """Freeze a trusted scan as a golden baseline for drift detection."""
    try:
        scan = load_scan_result(a.scan)
    except Exception as exc:
        print(f"ERROR loading scan: {exc}")
        return 2
    out = a.output or "golden_baseline.csv"
    n = write_golden_baseline(scan, out, fail_only=a.fail_only)
    fails = sum(1 for f in scan.findings if f.status.value == "FAIL")
    print(SEP)
    print(f"  Golden baseline written: {out}")
    print(f"  Findings recorded: {n} (scan had {len(scan.findings)} findings, "
          f"{fails} failing)")
    if a.fail_only:
        print("  Baseline tracks failing findings only; REGRESSED detection")
        print("  (was compliant, now failing) requires a full baseline (no --fail-only).")
    print(SEP)
    print("  Use it with:  python3 run.py drift --baseline golden_baseline.csv --scan <scan>")
    return 0


def cmd_drift(a: argparse.Namespace) -> int:
    """Detect configuration drift against a saved golden baseline.

    NEW            = failing now, not in the golden baseline  (drift)
    REGRESSED      = was compliant in the golden baseline, failing now  (drift)
    FIXED          = previously failing, now compliant
    STILL_REPRODUCIBLE = previously failing, still failing
    """
    if not a.baseline or not os.path.exists(a.baseline):
        print("ERROR: --baseline golden-baseline CSV required (save one with "
              "'save-baseline').")
        return 2
    try:
        scan = load_scan_result(a.scan)
    except Exception as exc:
        print(f"ERROR loading scan: {exc}")
        return 2
    baseline_rows = parse_baseline_csv(a.baseline)
    if not baseline_rows:
        print("WARNING: baseline CSV parsed to zero rows; every failing finding "
              "will be reported as NEW drift. Is the file populated?")
    rows = compare_scan_to_baseline(scan, baseline_rows, baseline_cloud=scan.cloud)
    summary = summarize_comparison(rows)

    counts = summary["counts"]
    drift = counts.get("NEW", 0) + counts.get("REGRESSED", 0)
    print(SEP)
    print("  Golden baseline drift")
    print("  Baseline : {}".format(a.baseline))
    print("  Scan     : {}  (account {})".format(a.scan, scan.account_id or "?"))
    print("  " + "  ".join(f"{k}={v}" for k, v in counts.items() if v))
    print(f"  >>> DRIFT: {drift} new/regressed misconfiguration(s) since baseline "
          f"(NEW={counts.get('NEW', 0)}, REGRESSED={counts.get('REGRESSED', 0)})")
    print(SEP)
    print("  NEW               failing now, not in the golden baseline (drift)")
    print("  REGRESSED         was compliant in baseline, failing now (drift)")
    print("  FIXED             previously failing, now compliant")
    print("  STILL_REPRODUCIBLE  previously failing, still failing")
    print("  NOT_VERIFIED      could not be re-checked (permissions/region)")
    for r in rows:
        if r.outcome in ("NEW", "REGRESSED"):
            print(f"  [DRIFT {r.outcome:<6}] {r.check_id:<14} {r.resource} "
                  f"({r.severity})")
    for r in rows:
        if r.outcome in ("FIXED", "STILL_REPRODUCIBLE", "NOT_VERIFIED"):
            print(f"  [{r.outcome:<18}] {r.check_id:<14} {r.resource}")

    out = a.output or "drift_report"
    os.makedirs(out, exist_ok=True)
    write_comparison_csv(os.path.join(out, "drift.csv"), rows)
    write_json(os.path.join(out, "drift_summary.json"), summary)
    if not a.no_html:
        html = build_dashboard_html({scan.cloud: scan}, rows, summary,
                                    title="Golden Baseline Drift")
        write_dashboard(os.path.join(out, "drift.html"), html)
    print(f"\n  Drift report written to: {out}")
    return 0


def cmd_compare(a: argparse.Namespace) -> int:
    if not a.baseline or not os.path.exists(a.baseline):
        print("ERROR: --baseline CSV file required.")
        return 2
    try:
        scan = load_scan_result(a.scan)
    except Exception as exc:
        print(f"ERROR loading scan: {exc}")
        return 2
    baseline_rows = parse_baseline_csv(a.baseline)
    rows = compare_scan_to_baseline(scan, baseline_rows)
    summary = summarize_comparison(rows)
    _print_comparison(rows, summary)
    out = a.output or os.path.join(os.path.dirname(a.baseline), "comparison_result")
    os.makedirs(out, exist_ok=True)
    write_comparison_csv(os.path.join(out, "comparison.csv"), rows)
    write_json(os.path.join(out, "comparison_summary.json"), summary)
    print(f"\n  Comparison written to: {os.path.join(out, 'comparison.csv')}")
    return 0


def cmd_compare_scans(a: argparse.Namespace) -> int:
    try:
        s1 = load_scan_result(a.scan1)
        s2 = load_scan_result(a.scan2)
    except Exception as exc:
        print(f"ERROR loading scans: {exc}")
        return 2
    rows = compare_scans(s1, s2)
    summary = summarize_comparison(rows)
    _print_comparison(rows, summary, "Scan-to-scan comparison")
    out = a.output or "comparison_scan_diff"
    os.makedirs(out, exist_ok=True)
    write_comparison_csv(os.path.join(out, "scan_diff.csv"), rows)
    write_json(os.path.join(out, "scan_diff_summary.json"), summary)
    print(f"\n  Diff written to: {os.path.join(out, 'scan_diff.csv')}")
    return 0


def _print_comparison(rows, summary, label: str = "Baseline comparison") -> None:
    print(SEP)
    print(f"  {label}")
    c = summary["counts"]
    print("  " + "  ".join(f"{k}={v}" for k, v in c.items() if v))
    print(f"  Fix rate: {summary['fix_rate']}%  |  total baseline entries: "
          f"{summary.get('total', len(rows))}")
    print(SEP)
    print("  FIXED             previously reported, now compliant")
    print("  STILL_REPRODUCIBLE  previously reported, still failing")
    print("  REGRESSED         was compliant, now failing")
    print("  NEW               failing now, not in baseline")
    print("  NOT_VERIFIED      could not be re-checked (permissions/region)")
    for r in rows[:15]:
        print(f"  [{r.outcome:<18}] {r.check_id:<14} {r.resource}")


def cmd_review(a: argparse.Namespace) -> int:
    """Review mode: re-check a targeted list of cases (from CSV) live.

    Instead of a full scan, only the checks named in the cases CSV are
    executed against the environment; each case is classified FIXED,
    STILL_VULNERABLE, NOT_VERIFIED or ERROR in review.csv.
    """
    from .collectors import collect

    if not a.cases or not os.path.exists(a.cases):
        print("ERROR: --cases CSV file required.")
        return 2
    cases = parse_cases_csv(a.cases)
    if not cases:
        print("ERROR: no cases parsed from CSV (expect columns: cloud, check_id, resource).")
        return 2

    # Determine the target cloud (single provider per run, like scan).
    clouds_in_csv = sorted({c["cloud"] for c in cases if c["cloud"]})
    if a.cloud:
        target = a.cloud
        cases = [c for c in cases if not c["cloud"] or c["cloud"] == target]
    elif len(clouds_in_csv) == 1:
        target = clouds_in_csv[0]
    elif clouds_in_csv:
        print(f"ERROR: cases span multiple clouds ({', '.join(clouds_in_csv)}). "
              f"Pass --cloud to pick one.")
        return 2
    else:
        print("ERROR: no cloud column in cases CSV; pass --cloud.")
        return 2

    if not cases:
        print(f"ERROR: no cases match cloud '{a.cloud or '?'}' in the CSV.")
        return 2

    auth = _auth_from_args(a)
    print(SEP)
    print(f"  Review mode: re-checking {len(cases)} case(s) against "
          f"{CLOUD_LABELS[target]} ({target}) ...")
    try:
        snapshot, errors = collect(target, auth)
    except ImportError as exc:
        print(f"  [SKIP] {target}: missing SDK ({exc}). Install it with:")
        print("         pip install -r requirements.txt")
        return 1
    except Exception as exc:
        print(f"  [FAIL] {target}: {exc}")
        return 1

    only_ids = {c["check_id"] for c in cases if c["check_id"]}
    if a.frameworks:
        case_count = len(only_ids)
        only_ids &= framework_check_ids(target, a.frameworks)
        print(f"  Framework filter --frameworks {' '.join(a.frameworks)}: "
              f"{len(only_ids)} of {case_count} case check(s) match")
    result = run_checks(target, snapshot,
                        meta={"auth_mode": f"live:{target}",
                              "regions": auth.get("regions") or [auth.get("region")],
                              "frameworks": a.frameworks or []},
                        only=only_ids)
    result.errors = errors + result.errors

    by_key: Dict[tuple, Finding] = {}
    for f in result.findings:
        by_key[(f.check_id, f.resource)] = f
    checks_by_id = {ch.id: ch for ch in get_checks(target)}
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for c in cases:
        f = by_key.get((c["check_id"], c["resource"]))
        ch = checks_by_id.get(c["check_id"])
        if not ch:
            status = "INVALID_CHECK"
            title = ""
        elif f is None:
            status = "NOT_VERIFIED"  # resource/check not found or not applicable
            title = ch.title
        elif f.status.value == "FAIL":
            status = "STILL_VULNERABLE"
            title = f.check_title
        elif f.status.value == "PASS":
            status = "FIXED"
            title = f.check_title
        elif f.status.value == "ERROR":
            status = "ERROR"
            title = f.check_title
        else:
            status = "NOT_VERIFIED"
            title = f.check_title
        rows.append({
            "cloud": target,
            "check_id": c["check_id"],
            "check_title": title,
            "resource": c["resource"],
            "severity": (f.severity.value if f else ""),
            "review_status": status,
            "detail": (f.detail if f else "Not re-checked: resource/check not found in the live environment."),
            "remediation": (f.remediation if f else (ch.remediation if ch else "")) or "",
            "cis": (f.cis if f else (ch.cis if ch else "")) or "",
            "reviewed_at": ts,
        })

    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["review_status"]] = counts.get(r["review_status"], 0) + 1
    out = _out_dir(a.output or "reports")
    path = os.path.join(out, "review.csv")
    write_review_csv(path, rows)

    if not a.no_html:
        _finalize({target: result}, out, None, None, no_html=False, review=True)

    print(SEP)
    print("  Review summary:")
    for k in ("FIXED", "STILL_VULNERABLE", "NOT_VERIFIED", "ERROR", "INVALID_CHECK"):
        if counts.get(k):
            print(f"    {k:<18} {counts[k]}")
    print(f"  Total cases reviewed: {len(rows)}")
    print(f"  Review report written to: {path}")
    return 0


def cmd_coverage(a: argparse.Namespace) -> int:
    report = coverage_report(a.cloud)
    for cloud, r in report.items():
        print(SEP)
        print(f"  {CLOUD_LABELS[cloud]} ({cloud}) - {r['total_checks']} checks")
        for svc, n in r["checks_by_service"].items():
            print(f"    {svc:<28} {n} check(s)")
        print("  Areas covered:")
        for area, items in r["services"].items():
            print(f"    - {area}: {', '.join(items)}")
    return 0


def cmd_checks(a: argparse.Namespace) -> int:
    clouds = list(CLOUDS) if a.cloud == "all" else [a.cloud]
    if a.search:
        # Fuzzy search: paste a misconfiguration description, get matching check IDs.
        results = search_checks(a.cloud, a.search)
        if a.frameworks:
            results = [r for r in results
                       if r["check"].id in framework_check_ids(r["cloud"], a.frameworks)]
        if a.json:
            out = [{"cloud": r["cloud"], "score": r["score"],
                    "id": r["check"].id, "service": r["check"].service,
                    "category": r["check"].category,
                    "severity": r["check"].severity.value, "title": r["check"].title,
                    "cis": r["check"].cis, "guidance": r["check"].guidance}
                   for r in results]
            print(json.dumps(out, indent=2))
            return 0
        print(SEP)
        print(f"  Search results for '{a.search}' ({len(results)} best match(es)):")
        if not results:
            print("  No checks matched. Try fewer or broader keywords,")
            print("  or run 'checks --cloud <provider>' to browse the catalog.")
            return 0
        for r in results:
            ch = r["check"]
            cid = "" if a.cloud != "all" else f"{r['cloud'].upper()}: "
            print(f"    {ch.id:<14} [{ch.severity.value:<8}] {cid}{ch.title}")
        return 0
    def _filtered(c: str) -> Optional[Set[str]]:
        return framework_check_ids(c, a.frameworks) if a.frameworks else None

    if a.json:
        out = {}
        for c in clouds:
            fw = _filtered(c)
            out[c] = [{"id": ch.id, "service": ch.service, "category": ch.category,
                       "severity": ch.severity.value, "title": ch.title,
                       "cis": ch.cis, "guidance": ch.guidance}
                      for ch in get_checks(c) if fw is None or ch.id in fw]
        print(json.dumps(out, indent=2))
        return 0
    for c in clouds:
        fw = _filtered(c)
        checks = [ch for ch in get_checks(c) if fw is None or ch.id in fw]
        print(SEP)
        print(f"  {CLOUD_LABELS[c]} ({c}) - {len(checks)} checks"
              + (f" [--frameworks {' '.join(a.frameworks)}]" if a.frameworks else ""))
        for ch in checks:
            print(f"    {ch.id:<14} [{ch.severity.value:<8}] {ch.service:<18} {ch.title}")
    return 0


def cmd_policies(a: argparse.Namespace) -> int:
    templates = least_privilege_templates()
    for cloud, t in templates.items():
        if a.cloud and cloud != a.cloud:
            continue
        print(SEP)
        print(f"  {CLOUD_LABELS[cloud]} ({cloud})")
        if t.get("summary"):
            print(f"  {t['summary']}")
        for key in ("policy_document", "custom_role", "policy"):
            if key in t:
                print(json.dumps(t[key], indent=2) if isinstance(t[key], (dict, list))
                      else "\n".join(t[key]))
        for r in t.get("roles", []) or []:
            if isinstance(r, str):
                print(f"  - {r}")
            else:
                print(f"  - {r.get('role')}  [{r.get('scope', '')}]")
                if r.get("why"):
                    print(f"      {r['why']}")
        for s in t.get("graph_scopes", []) or []:
            print(f"  Graph scope: {s}")
        for x in t.get("exclusions", []) or []:
            print(f"  NOT requested: {x}")
        if t.get("extra_permissions"):
            print(f"  Extra: {t['extra_permissions']}")
        if t.get("note"):
            print(f"  Note: {t['note']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudguard",
        description="Multi-cloud configuration review (AWS/Azure/GCP/OCI) with "
                    "baseline comparison and HTML dashboard.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a live cloud environment (read-only, one provider per run)")
    s.add_argument("--cloud", choices=list(CLOUDS), required=True,
                   help="Cloud provider to scan: " + ", ".join(list(CLOUDS)))
    s.add_argument("--output", default="reports")
    s.add_argument("--baseline", help="Optional baseline CSV for comparison")
    s.add_argument("--no-html", action="store_true")
    s.add_argument("--skip-privilege", action="store_true")
    s.add_argument("--frameworks", nargs="+", choices=["cis", "soc2", "pci", "nist", "hipaa"],
                   help="Only run checks whose primary framework matches (cis | soc2 | pci | "
                        "nist | hipaa); combine values, e.g. --frameworks pci nist")
    # AWS
    s.add_argument("--profile")
    s.add_argument("--region", default="us-east-1")
    s.add_argument("--regions", nargs="+", help="Override region list (AWS)")
    # Azure
    s.add_argument("--tenant-id", dest="tenant_id")
    s.add_argument("--client-id", dest="client_id")
    s.add_argument("--client-secret", dest="client_secret")
    s.add_argument("--subscription-id", dest="subscription_id")
    # GCP
    s.add_argument("--project-id", dest="project_id")
    s.add_argument("--service-account-file", dest="service_account_file")
    # OCI
    s.add_argument("--oci-config", dest="oci_config")
    s.add_argument("--oci-profile", dest="oci_profile")
    s.add_argument("--compartment")
    s.set_defaults(func=cmd_scan)

    rv = sub.add_parser(
        "review",
        help="Review mode: re-check a targeted list of cases from a CSV (live, read-only)")
    rv.add_argument("--cases", required=True,
                    help="CSV of cases to review (columns: cloud, check_id, resource)")
    rv.add_argument("--cloud", choices=list(CLOUDS), default=None,
                    help="Cloud to review (defaults to the single cloud in the cases CSV)")
    rv.add_argument("--output", default=None)
    rv.add_argument("--no-html", action="store_true")
    rv.add_argument("--skip-privilege", action="store_true")
    rv.add_argument("--frameworks", nargs="+", choices=["cis", "soc2", "pci", "nist", "hipaa"],
                   help="Only re-check cases whose check's primary framework matches")
    # same auth options as scan
    rv.add_argument("--profile")
    rv.add_argument("--region", default="us-east-1")
    rv.add_argument("--regions", nargs="+")
    rv.add_argument("--tenant-id", dest="tenant_id")
    rv.add_argument("--client-id", dest="client_id")
    rv.add_argument("--client-secret", dest="client_secret")
    rv.add_argument("--subscription-id", dest="subscription_id")
    rv.add_argument("--project-id", dest="project_id")
    rv.add_argument("--service-account-file", dest="service_account_file")
    rv.add_argument("--oci-config", dest="oci_config")
    rv.add_argument("--oci-profile", dest="oci_profile")
    rv.add_argument("--compartment")
    rv.set_defaults(func=cmd_review)

    d = sub.add_parser("demo", help="Run against a built-in realistic demo environment")
    d.add_argument("--cloud", choices=list(CLOUDS), default=None,
                   help="Only run the demo for one cloud provider (default: all)")
    d.add_argument("--output", default="reports")
    d.add_argument("--baseline", help="Optional previous-report CSV (sample_baseline.csv, a findings_<cloud>.csv export, or the comparison_template.csv) to enable the Comparison section")
    d.add_argument("--no-html", action="store_true")
    d.add_argument("--frameworks", nargs="+", choices=["cis", "soc2", "pci", "nist", "hipaa"],
                   help="Only run checks whose primary framework matches (demo only)")
    d.set_defaults(func=cmd_demo)

    c = sub.add_parser("compare", help="Compare a scan against a baseline CSV")
    c.add_argument("--baseline", required=True)
    c.add_argument("--scan", required=True, help="scan JSON file or result directory")
    c.add_argument("--output", default=None)
    c.set_defaults(func=cmd_compare)

    sb = sub.add_parser("save-baseline", help="Freeze a trusted scan as a golden baseline CSV")
    sb.add_argument("--scan", required=True, help="scan JSON file or result directory")
    sb.add_argument("--output", default=None, help="baseline CSV path (default: golden_baseline.csv)")
    sb.add_argument("--fail-only", action="store_true",
                    help="Record only failing findings (lighter baseline; no REGRESSED detection)")
    sb.set_defaults(func=cmd_save_baseline)

    df = sub.add_parser("drift", help="Detect configuration drift vs a saved golden baseline")
    df.add_argument("--baseline", required=True, help="golden baseline CSV (from save-baseline)")
    df.add_argument("--scan", required=True, help="scan JSON file or result directory")
    df.add_argument("--output", default=None)
    df.add_argument("--no-html", action="store_true")
    df.set_defaults(func=cmd_drift)

    cs = sub.add_parser("compare-scans", help="Diff two scans of the same environment")
    cs.add_argument("--scan1", required=True)
    cs.add_argument("--scan2", required=True)
    cs.add_argument("--output", default=None)
    cs.set_defaults(func=cmd_compare_scans)

    cov = sub.add_parser("coverage", help="Show areas/services covered per cloud")
    cov.add_argument("--cloud", choices=list(CLOUDS), default=None)
    cov.set_defaults(func=cmd_coverage)

    chk = sub.add_parser("checks", help="List or fuzzy-search the check catalog")
    chk.add_argument("--cloud", choices=list(CLOUDS) + ["all"], default="all")
    chk.add_argument("--json", action="store_true")
    chk.add_argument("--search", metavar="TEXT",
                     help="Fuzzy-search check titles/services/categories "
                          "(e.g. 'public bucket' or 'root mfa') to find the "
                          "right check_id for review mode")
    chk.add_argument("--frameworks", nargs="+", choices=["cis", "soc2", "pci", "nist", "hipaa"],
                     help="Filter the listing/search to checks whose primary framework matches")
    chk.set_defaults(func=cmd_checks)

    pol = sub.add_parser("policies", help="Print least-privilege policy templates")
    pol.add_argument("--cloud", choices=list(CLOUDS), default=None)
    pol.set_defaults(func=cmd_policies)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
