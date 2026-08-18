#!/usr/bin/env bash
# ============================================================================
# Build 0trust AppImage — a single-file portable Linux binary
# ============================================================================
# Output: 0trust-<version>-x86_64.AppImage
#
# AppImages run on virtually any distro from ~2014 onward without needing root.
# Customers download it, `chmod +x`, double-click. No package manager required.
#
# Requires: appimagetool (https://appimage.github.io/appimagetool/) — the
# script will auto-download it if missing.
# ============================================================================
set -euo pipefail

log() { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[✓] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

VERSION="${VERSION:-0.1.0}"
ARCH="${ARCH:-x86_64}"        # appimagetool's term for amd64
GO_ARCH="amd64"
[[ "$ARCH" == "aarch64" ]] && GO_ARCH="arm64"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN_DIR="${BIN_DIR:-$REPO_DIR/client/dist}"
OUT_DIR="${OUT_DIR:-$REPO_DIR/installer/linux/appimage/out}"
TOOL_DIR="${TOOL_DIR:-$HOME/.cache/appimagetool}"

src_bin="$BIN_DIR/0trust-linux-$GO_ARCH"
[[ -f "$src_bin" ]] || die "$src_bin missing — run 'make linux' in client/ first"

mkdir -p "$OUT_DIR" "$TOOL_DIR"

# --- Fetch appimagetool if missing -----------------------------------------
APPIMAGETOOL="$TOOL_DIR/appimagetool-$ARCH.AppImage"
if [[ ! -x "$APPIMAGETOOL" ]]; then
    log "Downloading appimagetool"
    curl -fsSL -o "$APPIMAGETOOL" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$ARCH.AppImage" \
        || die "couldn't fetch appimagetool"
    chmod +x "$APPIMAGETOOL"
fi

# --- Build the AppDir ------------------------------------------------------
stage=$(mktemp -d)
trap "rm -rf $stage" EXIT

APPDIR="$stage/0trust.AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/scalable/apps"

install -m0755 "$src_bin" "$APPDIR/usr/bin/0trust"
install -m0644 "$REPO_DIR/installer/linux/deb/0trust.desktop" \
               "$APPDIR/usr/share/applications/0trust.desktop"
install -m0644 "$REPO_DIR/installer/linux/deb/0trust.svg" \
               "$APPDIR/usr/share/icons/hicolor/scalable/apps/0trust.svg"

# AppImage requires top-level symlinks + an AppRun script
ln -sf usr/share/applications/0trust.desktop "$APPDIR/0trust.desktop"
ln -sf usr/share/icons/hicolor/scalable/apps/0trust.svg "$APPDIR/0trust.svg"
ln -sf 0trust.svg "$APPDIR/.DirIcon"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/0trust" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# --- Build the AppImage ----------------------------------------------------
out_file="$OUT_DIR/0trust-${VERSION}-${ARCH}.AppImage"
log "Building AppImage"
"$APPIMAGETOOL" --no-appstream "$APPDIR" "$out_file" 2>&1 \
    | grep -vE "(squashfs|^$)" || true
[[ -f "$out_file" ]] || die "AppImage build failed"
chmod +x "$out_file"
ok "$out_file ($(du -h "$out_file" | cut -f1))"

cat <<EOF

================================================================
  AppImage built: $out_file

  Try it:
    chmod +x $out_file
    $out_file gui

  Sign it (post-build) with PGP:
    gpg --detach-sign --armor $out_file
    # produces ${out_file}.asc — distribute alongside the AppImage

  Distribute by hosting at:
    https://0trustvpn.com/releases/$VERSION/0trust-${VERSION}-${ARCH}.AppImage
================================================================
EOF
