#!/usr/bin/env bash
# =============================================================================
# CloudGuard - build a self-contained .deb (no Debian packaging tooling needed,
# just dpkg-deb + python3-venv).
#
# The .deb installs:
#   /opt/cloudguard/venv/     bundled Python virtualenv (all cloud SDKs)
#   /opt/cloudguard/app/      the cloudguard source tree
#   /usr/bin/cloudguard       -> /opt/cloudguard/venv/bin/cloudguard
#   /usr/share/doc/cloudguard  README, changelog, copyright
#
# Usage:
#   ./packaging/build_deb.sh                 # bundle ALL cloud SDKs (needs network)
#   ./packaging/build_deb.sh --clouds aws    # AWS SDK only
#   ./packaging/build_deb.sh --demo          # stdlib only, no network (fast check)
#   ./packaging/build_deb.sh --output /tmp   # where to write the .deb (default: dist/)
#
# The "proper" Debian maintainer route (debian/ + dh-virtualenv) is documented
# in the README ("Packaging & distribution"); this script is the no-dependency
# equivalent that works on any Debian/Ubuntu box today.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="cloudguard"
CLOUDS="all"
DEMO=0
VERSION=""
OUT=""
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clouds) CLOUDS="$2"; shift 2 ;;
    --demo)   DEMO=1; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --output) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  VERSION="$(grep -oP '__version__ = "\K[^"]+' "$REPO/cloudsec/__init__.py")"
fi
OUT="${OUT:-$REPO/dist}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

log() { echo "  [build] $*"; }

log "packaging $PKG v$VERSION (arch=$ARCH, clouds=$CLOUDS)"

# --- 1) bundled virtualenv --------------------------------------------------
VENV="$STAGE/opt/cloudguard/venv"
python3 -m venv "$VENV"

if [[ "$DEMO" = 1 ]]; then
  log "demo build: stdlib only (no cloud SDKs, no network)"
else
  log "installing cloud SDKs into the venv (this downloads packages)..."
  "$VENV/bin/pip" install --quiet --upgrade pip
  if [[ "$CLOUDS" = "all" ]]; then
    (cd "$REPO" && "$VENV/bin/pip" install --quiet ".[all]")
  else
    (cd "$REPO" && "$VENV/bin/pip" install --quiet ".[$CLOUDS]")
  fi
fi

# --- 2) application source tree ----------------------------------------------
APP="$STAGE/opt/cloudguard/app"
mkdir -p "$APP"
cp -r "$REPO/cloudsec" "$APP/"
cp "$REPO/run.py" "$APP/"
cp "$REPO/requirements.txt" "$APP/"

# console entry (uses the bundled venv's python)
cat > "$VENV/bin/cloudguard" <<'EOF'
#!/opt/cloudguard/venv/bin/python
import os, sys
sys.path.insert(0, '/opt/cloudguard/app')
from cloudsec.cli import main
sys.exit(main())
EOF
chmod +x "$VENV/bin/cloudguard"

# --- 3) /usr/bin symlink + docs ---------------------------------------------
mkdir -p "$STAGE/usr/bin"
ln -s /opt/cloudguard/venv/bin/cloudguard "$STAGE/usr/bin/cloudguard"

DOC="$STAGE/usr/share/doc/$PKG"
mkdir -p "$DOC"
cp "$REPO/README.md" "$DOC/README.md"
cp "$REPO/debian/changelog" "$DOC/changelog"
cp "$REPO/debian/copyright" "$DOC/copyright"
gzip -9 -f "$DOC/changelog"

# --- 4) control metadata ------------------------------------------------------
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: CyberSunil <you@example.com>
Depends: python3 (>= 3.9)
Section: utils
Priority: optional
Homepage: https://example.com/cloudguard
Description: Multi-cloud configuration review, comparison and dashboarding
 CloudGuard scans AWS, Azure, GCP and OCI environments read-only against a
 CIS-focused catalog of 320+ checks and produces a fully offline HTML
 dashboard with risk scoring, CIS Benchmark + SOC2/PCI/NIST/HIPAA control
 mappings, baseline comparison/review workflow, false-positive exclusion
 in exports, and least-privilege access templates.
 .
 This .deb bundles its own Python virtualenv (with the $CLOUDS cloud SDKs),
 so the installed tool works offline with no pip installs.
EOF

# --- 5) build -----------------------------------------------------------------
mkdir -p "$OUT"
DEB="$OUT/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB" >/dev/null
log "built: $DEB"
log "install with:  sudo apt install $DEB"
