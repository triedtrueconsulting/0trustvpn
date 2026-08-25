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
#   0trust_<version>_amd64.deb          Packages, when they have been built
#   0trust-<version>-x86_64.AppImage
#   0trust-<version>-x64.msi            (built on Windows; staged, see below)
#   0trust-<version>.apk                (built in Android Studio; staged)
#   SHA256SUMS                          One sha256 line per artifact
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
#   STAGING_DIR          Where artifacts built on other hosts are dropped
#                        (default: staging/). The MSI needs a Windows box and
#                        the APK needs Android Studio, so they cannot be built
#                        here; copy them in and this script signs them with
#                        everything else.
#   ALLOW_PARTIAL=1      Cut a release without them anyway. Off by default:
#                        download.html offered a .deb, an AppImage, an MSI and
#                        an APK that SHA256SUMS never covered, so the page told
#                        customers to verify four files that could not be
#                        verified. On a product whose pitch is that you do not
#                        have to trust us, that is the worst possible hole.
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
STAGING_DIR="${STAGING_DIR:-$REPO_DIR/staging}"

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
log "Collecting packages"
# ----------------------------------------------------------------------------
# Everything the download page offers has to end up in SHA256SUMS. The Linux
# packages build here; the MSI and the APK need other toolchains, so they are
# picked up from the staging directory if the operator has put them there.
cd "$REPO_DIR"
if command -v dpkg-deb >/dev/null 2>&1; then
    log "  building .deb"
    # `make all` writes versioned names for the release; the .deb script wants
    # the unversioned installer inputs, which is what `make linux` is for.
    ( cd "$CLIENT_DIR" && VERSION="$VERSION" make linux >/dev/null ) \
        || die "client linux build failed"
    VERSION="$VERSION" ./installer/linux/deb/build.sh >/dev/null \
        || die ".deb build failed"
else
    log "  dpkg-deb not present — skipping the .deb build"
fi
# The AppImage needs appimagetool, which the build script fetches from GitHub.
# Attempt it, but do not die: an unreachable network is not a reason to fail a
# release, and the cross-check below will insist the artifact be staged instead.
if [[ -x installer/linux/appimage/build.sh ]]; then
    log "  building AppImage"
    VERSION="$VERSION" ./installer/linux/appimage/build.sh >/dev/null 2>&1 \
        || log "  AppImage build unavailable here — stage it instead"
fi

for f in installer/linux/deb/out/*.deb installer/linux/appimage/out/*.AppImage; do
    [[ -e "$f" ]] || continue
    cp "$f" "$RELEASE_DIR/" && log "  $(basename "$f")"
done
if [[ -d "$STAGING_DIR" ]]; then
    for f in "$STAGING_DIR"/*; do
        [[ -f "$f" ]] || continue
        cp "$f" "$RELEASE_DIR/" && log "  $(basename "$f")  (staged)"
    done
fi

# ----------------------------------------------------------------------------
log "Cross-checking against the download page"
# ----------------------------------------------------------------------------
# One source of truth: whatever web/download.html links for this version is
# what the release must contain. Otherwise the page happily offers a file that
# was never built, never hashed and never signed.
DOWNLOAD_PAGE="$REPO_DIR/web/download.html"
missing=()
if [[ -f "$DOWNLOAD_PAGE" ]]; then
    while read -r want; do
        [[ -n "$want" ]] || continue
        # The manifest files are written further down, after this check.
        case "$want" in SHA256SUMS|SHA256SUMS.asc|pubkey.asc|build-info.txt) continue ;; esac
        [[ -e "$RELEASE_DIR/$want" ]] || missing+=("$want")
    done < <(grep -oE "/releases/$VERSION/[A-Za-z0-9._+-]+" "$DOWNLOAD_PAGE" \
             | sed "s|/releases/$VERSION/||" | sort -u)
fi
if (( ${#missing[@]} )); then
    printf '\033[1;31m[!] the download page offers files this release does not have:\033[0m\n' >&2
    printf '      %s\n' "${missing[@]}" >&2
    printf '    Build them, or drop them in %s, or set ALLOW_PARTIAL=1.\n' "$STAGING_DIR" >&2
    [[ -n "${ALLOW_PARTIAL:-}" ]] || die "refusing to sign a release the site over-promises"
    printf '\033[1;33m[!] ALLOW_PARTIAL set — continuing without them\033[0m\n' >&2
fi

# ----------------------------------------------------------------------------
log "Generating SHA256SUMS"
# ----------------------------------------------------------------------------
cd "$RELEASE_DIR"
# Everything except the manifest files themselves, so a package added above is
# covered without anyone having to remember to extend a list.
find . -maxdepth 1 -type f \
     ! -name SHA256SUMS ! -name 'SHA256SUMS.asc' \
     ! -name pubkey.asc ! -name build-info.txt \
     -printf '%P\n' | sort | xargs sha256sum | tee SHA256SUMS
artifact_count=$(grep -c . SHA256SUMS || echo 0)
[[ $artifact_count -ge 5 ]] || die "expected ≥5 artifacts, got $artifact_count"
ok "$artifact_count artifacts hashed"

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
