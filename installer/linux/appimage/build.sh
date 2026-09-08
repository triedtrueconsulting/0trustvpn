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

# Check the payload's architecture BEFORE packaging it. The AppImage runtime
# and the binary inside it are chosen separately, so an aarch64 AppImage
# wrapping the amd64 client builds, packages and passes a `file` check on the
# finished artifact — the runtime is the part `file` sees. It fails on the
# customer's machine, with "cannot execute binary file", after a download.
case "$(file -b "$src_bin")" in
    *x86-64*)      bin_arch=x86_64 ;;
    *aarch64*)     bin_arch=aarch64 ;;
    *)             bin_arch="unknown ($(file -b "$src_bin" | cut -c1-40))" ;;
esac
[[ "$bin_arch" == "$ARCH" ]] \
    || die "$src_bin is $bin_arch, not $ARCH — the AppImage would carry a binary that cannot run"

mkdir -p "$OUT_DIR" "$TOOL_DIR"

# --- Fetch appimagetool if missing -----------------------------------------
# appimagetool always runs as the BUILD host's architecture. Building an
# aarch64 AppImage on an x86_64 box is a cross-build: the tool is the host's,
# and only the embedded runtime has to be the target's, via --runtime-file.
# Downloading appimagetool-aarch64 and trying to execute it here would just
# fail with "Exec format error".
HOST_ARCH="$(uname -m)"
APPIMAGETOOL="$TOOL_DIR/appimagetool-$HOST_ARCH.AppImage"
if [[ ! -x "$APPIMAGETOOL" ]]; then
    log "Downloading appimagetool ($HOST_ARCH)"
    curl -fsSL -o "$APPIMAGETOOL" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$HOST_ARCH.AppImage" \
        || die "couldn't fetch appimagetool"
    chmod +x "$APPIMAGETOOL"
fi

# An AppImage is itself an AppImage, so appimagetool needs FUSE to run — and a
# build container usually has none. The runtime falls back to extracting
# itself, but it announces that on STDOUT first, which lands in the middle of
# the tool's own output. Ask for the fallback up front instead.
export APPIMAGE_EXTRACT_AND_RUN=1

RUNTIME_ARG=()
if [[ "$ARCH" != "$HOST_ARCH" ]]; then
    RUNTIME="$TOOL_DIR/runtime-$ARCH"
    if [[ ! -f "$RUNTIME" ]]; then
        log "Downloading the $ARCH runtime (cross-building from $HOST_ARCH)"
        curl -fsSL -o "$RUNTIME" \
            "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-$ARCH" \
            || die "couldn't fetch the $ARCH runtime"
    fi
    RUNTIME_ARG=(--runtime-file "$RUNTIME")
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
"$APPIMAGETOOL" --no-appstream "${RUNTIME_ARG[@]}" "$APPDIR" "$out_file" 2>&1 \
    | grep -vE "(squashfs|^$)" || true
[[ -f "$out_file" ]] || die "AppImage build failed"
chmod +x "$out_file"

# --- Verify it, rather than announcing success on the file existing --------
# A file appearing where one was asked for is not evidence that it runs; the
# same standard install.sh is held to after it printed "The VPN works"
# unconditionally, and 0trust connect after wg-quick's exit code turned out to
# mean nothing. An AppImage can be produced with the wrong runtime, a bad
# AppRun, or a binary for another architecture and look perfect until a
# customer double-clicks it.
want_machine="$ARCH"
[[ "$ARCH" == "x86_64" ]] && want_machine="x86-64"
file "$out_file" | grep -qi "$want_machine" \
    || die "$out_file is not a $ARCH executable: $(file -b "$out_file")"

if [[ "$ARCH" == "$HOST_ARCH" ]]; then
    # Native: run the thing. --appimage-extract-and-run so a builder without
    # FUSE tests the AppImage rather than testing whether it has FUSE.
    got="$("$out_file" --appimage-extract-and-run version 2>/dev/null | tr -d '\r')"
    [[ "$got" == "0trust $VERSION"* ]] \
        || die "the AppImage ran but reported '$got', not 0trust $VERSION"
    ok "runs and reports: $got"
else
    note="cross-built for $ARCH — cannot be executed on this $HOST_ARCH host"
    printf '\033[2m[i] %s\033[0m\n' "$note"
fi

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
