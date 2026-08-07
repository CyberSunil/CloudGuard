#!/usr/bin/env bash
# CloudGuard - scheduled scan helper for cron / systemd timers (no GitHub needed).
#
# Usage:
#   ./tools/scan_cron.sh <cloud> [--baseline baseline.csv] [--retain N]
#
# Example crontab (nightly 02:00 UTC, all four providers):
#   0 2 * * *  cd /opt/cloudsec-review && ./tools/scan_cron.sh aws    >> /var/log/cloudguard.log 2>&1
#   0 2 * * *  cd /opt/cloudsec-review && ./tools/scan_cron.sh azure  >> /var/log/cloudguard.log 2>&1
#   0 2 * * *  cd /opt/cloudsec-review && ./tools/scan_cron.sh gcp    >> /var/log/cloudguard.log 2>&1
#   0 2 * * *  cd /opt/cloudsec-review && ./tools/scan_cron.sh oci    >> /var/log/cloudguard.log 2>&1
#
# Notes:
#   - AWS: uses the default credential chain (env, ~/.aws/credentials, instance
#     profile). Override with AWS_PROFILE / AWS_REGION env vars.
#   - Azure: uses DefaultAzureCredential (env vars, az login, managed identity).
#   - GCP: uses Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS
#     or gcloud auth application-default login).
#   - OCI: uses ~/.oci/config (OCI_CONFIG_FILE / OCI_CONFIG_PROFILE env).
#   - Pass --baseline to enable the Comparison section / drift signal.
#   - --retain N keeps the N most recent reports per cloud and deletes older ones.
set -euo pipefail

CLOUD="${1:?usage: scan_cron.sh <cloud> [--baseline FILE] [--retain N]}"
shift || true
BASELINE=""
RETAIN=5
while [ "$#" -gt 0 ]; do
  case "$1" in
    --baseline) BASELINE="${2:?--baseline needs a path}"; shift 2 ;;
    --retain)   RETAIN="${2:?--retain needs a number}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# run.py scan appends its own scan_<ts> subdir (see cli._out_dir), so we pass
# the provider folder and resolve the real report dir afterwards.
OUT_BASE="reports/${CLOUD}"
mkdir -p "$OUT_BASE"

echo "== $(date -u +%FT%TZ) CloudGuard scan: ${CLOUD}"

ARGS=(--cloud "$CLOUD" --output "$OUT_BASE")
[ -n "$BASELINE" ] && ARGS+=(--baseline "$BASELINE")

if ! python3 run.py scan "${ARGS[@]}"; then
  echo "!! scan failed for ${CLOUD} (see log above)" >&2
  exit 1
fi

LATEST="$(ls -1dt "${OUT_BASE}"/scan_* 2>/dev/null | head -1 || true)"
if [ -n "$LATEST" ]; then
  echo "== dashboard: ${LATEST}/dashboard.html"
fi

# Prune old reports (keep the newest $RETAIN).
mapfile -t OLD < <(ls -1dt "${OUT_BASE}"/scan_* 2>/dev/null | tail -n +"$((RETAIN + 1))" || true)
if [ "${#OLD[@]}" -gt 0 ]; then
  for d in "${OLD[@]}"; do
    rm -rf "$d"
    echo "== pruned: $d"
  done
fi
