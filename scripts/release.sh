#!/usr/bin/env bash
# ============================================================================
# 0trust client release pipeline
# ============================================================================
# Produces a signed, verifiable release of the 0trust CLI/GUI binaries.
#
# What it produces in releases/<version>/:
#   0trust-<version>-linux-amd64        Per-platform binaries
#   0trust-<version>-linux-arm64
#   0trust-<version>-darwin-amd64
#   0trust-<version>-darwin-arm64
#   0trust-<version>-windows-amd64.exe
#   SHA256SUMS                          One sha256 line per binary
#   SHA256SUMS.asc                      Detached ASCII PGP signature
#   pubkey.asc                          The signing key, for convenience
#   build-info.txt                      Go version, source rev, build host
#
# Reproducibility: the Makefile already uses -trimpath -buildvcs=false. Two
# builds of the same source tree with the same Go version produce byte-identical
# binaries. This script records the Go version + source rev in build-info.txt
# so an independent verifier can reproduce exactly.
#
# Usage:
#   RELEASE_SIGNER_KEY=0xDEADBEEF ./scripts/release.sh 0.1.0
#
# Env:
#   RELEASE_SIGNER_KEY   PGP key fingerprint to sign SHA256SUMS with (required)
#   RELEASE_DIR          Output directory (default: releases/<version>)
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[✓] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

VERSION="${1:-}"
[[ -n "$VERSION" ]] || die "usage: release.sh <version>  (e.g. 0.1.0)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] \
    || die "version must be semver: X.Y.Z[-suffix]"
[[ -n "${RELEASE_SIGNER_KEY:-}" ]] || die "set RELEASE_SIGNER_KEY=<PGP fingerprint>"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_DIR="$REPO_DIR/client"
RELEASE_DIR="${RELEASE_DIR:-$REPO_DIR/releases/$VERSION}"

[[ -d "$CLIENT_DIR" ]] || die "client/ not found at $CLIENT_DIR"

# ----------------------------------------------------------------------------
log "Verifying signing key is available"
# ----------------------------------------------------------------------------
gpg --list-secret-keys "$RELEASE_SIGNER_KEY" >/dev/null \
    || die "PGP key $RELEASE_SIGNER_KEY not in keyring"

# ----------------------------------------------------------------------------
log "Pre-flight: working tree clean?"
# ----------------------------------------------------------------------------
# A release built from a dirty tree is not reproducible by anyone else.
if command -v git >/dev/null && [[ -d "$REPO_DIR/.git" ]]; then
    if [[ -n "$(git -C "$REPO_DIR" status --porcelain)" ]]; then
        die "git tree has uncommitted changes — commit or stash before release"
    fi
    GIT_REV=$(git -C "$REPO_DIR" rev-parse HEAD)
    log "  rev $GIT_REV"
else
    GIT_REV="(no-vcs)"
    log "  no git available, skipping rev check"
fi

# ----------------------------------------------------------------------------
log "Pre-flight: Go toolchain"
# ----------------------------------------------------------------------------
command -v go >/dev/null || die "go not in PATH"
GO_VERSION=$(go version | awk '{print $3}')
log "  $GO_VERSION"

# ----------------------------------------------------------------------------
log "Building binaries (this drives client/Makefile)"
# ----------------------------------------------------------------------------
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

cd "$CLIENT_DIR"
make clean
VERSION="$VERSION" make all

# Move the binaries into the release dir
cp dist/0trust-* "$RELEASE_DIR/"

# ----------------------------------------------------------------------------
log "Generating SHA256SUMS"
# ----------------------------------------------------------------------------
cd "$RELEASE_DIR"
sha256sum 0trust-* | tee SHA256SUMS
binary_count=$(grep -c . SHA256SUMS || echo 0)
[[ $binary_count -ge 5 ]] || die "expected ≥5 binaries, got $binary_count"
ok "$binary_count binaries hashed"

# ----------------------------------------------------------------------------
log "Signing SHA256SUMS with $RELEASE_SIGNER_KEY"
# ----------------------------------------------------------------------------
rm -f SHA256SUMS.asc
gpg --local-user "$RELEASE_SIGNER_KEY" \
    --output SHA256SUMS.asc \
    --detach-sign --armor \
    SHA256SUMS

# Verify our own signature before we declare success
gpg --verify SHA256SUMS.asc SHA256SUMS
ok "signature verified"

# ----------------------------------------------------------------------------
log "Exporting public key for distribution"
# ----------------------------------------------------------------------------
gpg --armor --export "$RELEASE_SIGNER_KEY" > pubkey.asc

# ----------------------------------------------------------------------------
log "Recording build provenance"
# ----------------------------------------------------------------------------
cat > build-info.txt <<EOF
0trust client release manifest

Version:      $VERSION
Source rev:   $GIT_REV
Go version:   $GO_VERSION
Build host:   $(uname -srm)
Built at:     $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Signed by:    $RELEASE_SIGNER_KEY

Build flags:  -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$VERSION"

Reproducibility
---------------
With the same source rev, the same Go version, and the same build flags,
two independent builds produce byte-identical binaries. To verify:

  git checkout $GIT_REV
  cd client && VERSION=$VERSION make all
  sha256sum dist/0trust-* | diff - <(grep 0trust- ../releases/$VERSION/SHA256SUMS)

If the diff is empty, the release reproduces. If not, file an issue
with both your SHA256SUMS and the source tree state.
EOF

# ----------------------------------------------------------------------------
log "Summary"
# ----------------------------------------------------------------------------
cat <<EOF

================================================================
  Release $VERSION ready in $RELEASE_DIR

  $(ls -la "$RELEASE_DIR" | tail -n +2 | wc -l) files:
$(ls -la "$RELEASE_DIR" | awk 'NR>1{printf "    %s  %s\n", $5, $9}')

  Next steps:

  1. Verify the bundle locally:
       ./scripts/verify-release.sh $VERSION

  2. Tag the release in git:
       git tag -s v$VERSION -m "Release $VERSION"
       git push origin v$VERSION

  3. Publish to your download location (S3 / static site / IPFS).
     Recommend serving the directory verbatim with no transformations,
     so the SHA256SUMS is byte-identical to what users compute.

  4. Update https://0trustvpn.com/download with the new version.
================================================================
EOF
