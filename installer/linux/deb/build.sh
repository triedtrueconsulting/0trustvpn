#!/usr/bin/env bash
# ============================================================================
# Build .deb packages for 0trust client (amd64 + arm64)
# ============================================================================
# Output: 0trust_<version>_amd64.deb  + 0trust_<version>_arm64.deb
#
# Run from anywhere; reads $VERSION (default 0.1.0) and the prebuilt binaries
# in client/dist/ (run `make linux` in client/ first to produce them).
#
# Requires: dpkg-deb (Debian/Ubuntu have this by default; on other distros,
# `apt-get install dpkg-dev` or run inside a Debian container).
# ============================================================================
set -euo pipefail

log() { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[✓] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

VERSION="${VERSION:-0.1.0}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_DIR/client/dist}"
OUT_DIR="${OUT_DIR:-$REPO_DIR/installer/linux/deb/out}"

command -v dpkg-deb >/dev/null || die "dpkg-deb not found (apt-get install dpkg-dev)"
[[ -d "$BIN_DIR" ]] || die "binary dir $BIN_DIR missing — run 'make linux' in client/ first"

mkdir -p "$OUT_DIR"

build_arch() {
    local deb_arch="$1"    # amd64 / arm64
    local go_arch="$2"     # amd64 / arm64
    local src_bin="$BIN_DIR/0trust-linux-$go_arch"
    [[ -f "$src_bin" ]] || die "$src_bin missing — build the Go client first"

    log "Packaging 0trust $VERSION for linux-$deb_arch"

    local stage; stage=$(mktemp -d)
    trap "rm -rf $stage" RETURN

    # --- Filesystem layout ----------------------------------------------
    install -Dm0755 "$src_bin"                              "$stage/usr/bin/0trust"
    install -Dm0644 "$REPO_DIR/installer/linux/deb/0trust.desktop" \
                                                            "$stage/usr/share/applications/0trust.desktop"
    install -Dm0644 "$REPO_DIR/installer/linux/deb/0trust.svg" \
                                                            "$stage/usr/share/icons/hicolor/scalable/apps/0trust.svg"
    install -Dm0644 "$REPO_DIR/installer/linux/deb/copyright" \
                                                            "$stage/usr/share/doc/0trust/copyright"

    # --- Control file ---------------------------------------------------
    mkdir -p "$stage/DEBIAN"
    cat > "$stage/DEBIAN/control" <<EOF
Package: 0trust
Version: $VERSION
Architecture: $deb_arch
Maintainer: 0trust <0trustvpn@proton.me>
Section: net
Priority: optional
Depends: wireguard-tools, libc6
Recommends: wireguard
Homepage: https://0trustvpn.com/
Description: Privacy-first mesh VPN client
 0trust is a no-logs mesh VPN with multi-hop routing across three
 jurisdictions outside the Five/Nine/Fourteen Eyes alliances
 (Switzerland, Iceland, Romania). The client provides a CLI plus a
 browser-based GUI on 127.0.0.1:51827.
 .
 This package installs the 0trust binary; the actual tunnel data plane
 is handled by the wireguard-tools package, which is listed as a
 dependency.
EOF

    cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Refresh icon + desktop database so the launcher entry appears immediately
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -f /usr/share/icons/hicolor 2>/dev/null || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q 2>/dev/null || true
fi
exit 0
EOF
    chmod 0755 "$stage/DEBIAN/postinst"

    # --- Build ----------------------------------------------------------
    local out_file="$OUT_DIR/0trust_${VERSION}_${deb_arch}.deb"
    dpkg-deb --build --root-owner-group "$stage" "$out_file" >/dev/null
    ok "$out_file ($(du -h "$out_file" | cut -f1))"
}

build_arch amd64 amd64
build_arch arm64 arm64

cat <<EOF

================================================================
  Built $(ls -1 "$OUT_DIR"/*.deb 2>/dev/null | wc -l) .deb packages in $OUT_DIR

  Install (one-machine test):
    sudo dpkg -i $OUT_DIR/0trust_${VERSION}_amd64.deb
    # if dependencies are missing:
    sudo apt-get install -f

  Distribute:
    1. Sign the .debs with debsign (requires a PGP key)
    2. Host alongside the other release artifacts at
       https://0trustvpn.com/releases/$VERSION/
    3. Optionally publish an APT repo at https://apt.0trustvpn.com/
       (instructions in installer/linux/README.md)
================================================================
EOF
