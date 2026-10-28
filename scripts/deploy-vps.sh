#!/usr/bin/env bash
# ============================================================================
# 0trust — one-paste VPS deploy
# ============================================================================
# scripts/install.sh does the install. This wrapper does the three things
# around it that an operator otherwise repeats by hand on every box:
#
#   1. Decides whether this box CAN host the role, BEFORE touching it.
#      A node on a kernel without WireGuard is the commonest dead end, and
#      finding out after packages, the service user, the secrets and the
#      database are already on disk wastes the box and the hour.
#
#   2. Finds the source. install.sh derives its repo from its own location,
#      so it assumes the code is already here — nothing in the tree puts it
#      here. A zip uploaded over FileZilla, an existing checkout and a git
#      clone are all normal, so all three are handled.
#
#   3. Verifies afterwards and prints what is still outstanding, instead of
#      leaving "did that actually work?" to the operator.
#
# It deliberately does NOT re-implement any of install.sh: not its flags, not
# its validators, not its pre/post checks. One definition of a valid value.
#
#   sudo bash deploy-vps.sh control --domain example.com --email you@example.com \
#        [--backup-key age1...] [--wallet zpub...] [--cloudflare]
#
#   sudo bash deploy-vps.sh node --control-url https://example.com \
#        --region zur --token-file /root/.ztv-token [--wg-port 443]
#
# Everything after the role is passed through to install.sh untouched, so any
# flag it accepts works here.
# ============================================================================
set -euo pipefail

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; DIM=$'\033[2m'; NC=$'\033[0m'
log()  { printf '%s[+] %s%s\n' "$YLW" "$*" "$NC"; }
ok()   { printf '%s[✓] %s%s\n' "$GRN" "$*" "$NC"; }
die()  { printf '%s[!] %s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }
note() { printf '%s    %s%s\n' "$DIM" "$*" "$NC"; }

ROLE="${1:-}"; shift || true
case "$ROLE" in
    control|node) ;;
    *) die "usage: deploy-vps.sh control|node [install.sh flags...]" ;;
esac
[[ $EUID -eq 0 ]] || die "must run as root (try: sudo bash $0 $ROLE ...)"

# ---------------------------------------------------------------------------
# 1. Can this box host the role?
# ---------------------------------------------------------------------------
log "Checking what this box can do"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || note "not Ubuntu (${PRETTY_NAME:-unknown}) — install.sh targets Ubuntu 24.04"
    case "${VERSION_ID:-}" in
        24.04|22.04) ;;
        *) note "Ubuntu ${VERSION_ID:-?} — 24.04 is what this is tested on" ;;
    esac
fi

# iproute2 is Essential on a stock Ubuntu image and absent from minimal
# container bases. install.sh names it as a package now, but this script
# probes with `ip` before install.sh gets a chance to install anything.
if ! command -v ip >/dev/null 2>&1; then
    log "installing iproute2 so this box can be probed at all"
    apt-get update -qq && apt-get install -y -qq iproute2
fi

# The authoritative test is creating the interface, not guessing from the
# virtualisation type — a KVM guest can still lack the module, and some
# container hosts pass it through. detect-virt only EXPLAINS the result.
WG_OK=0
if ip link add dev ztvdeployprobe type wireguard >/dev/null 2>&1; then
    ip link del ztvdeployprobe >/dev/null 2>&1 || true
    WG_OK=1
fi
VIRT_C="$(systemd-detect-virt -c 2>/dev/null || true)"
VIRT_V="$(systemd-detect-virt -v 2>/dev/null || true)"

if (( WG_OK )); then
    ok "kernel can create WireGuard interfaces${VIRT_V:+ (virt: $VIRT_V)}"
else
    printf '%s[!] this kernel cannot create a WireGuard interface%s\n' "$RED" "$NC" >&2
    if [[ -n "$VIRT_C" && "$VIRT_C" != "none" ]]; then
        note "this box is a $VIRT_C container, which cannot load kernel modules."
        note "LXC and OpenVZ VPSes are sold as 'VPS' and cannot run a node."
    else
        note "no WireGuard module. On a KVM guest: apt-get install -y wireguard"
    fi
    if [[ "$ROLE" == "node" ]]; then
        die "a node is only a node if it can carry a tunnel — nothing has been changed.
    Use a KVM VPS for mesh nodes."
    fi
    note "continuing: a control plane does not need WireGuard itself"
fi

AVAIL_MB="$(df -Pm / | awk 'NR==2 {print $4}' || true)"
[[ -n "$AVAIL_MB" ]] && (( AVAIL_MB < 2048 )) \
    && die "only ${AVAIL_MB}MB free on / — need ~2GB. Nothing has been changed."
ok "disk, kernel and OS checks passed"

# ---------------------------------------------------------------------------
# 2. Where is the source?
# ---------------------------------------------------------------------------
log "Locating the 0trust source"

# A tree is only the right tree if it carries the things we are about to run.
looks_right() { [[ -f "$1/scripts/install.sh" && -f "$1/api/main.py" ]]; }

SRC=""
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
if [[ -n "$HERE" ]] && looks_right "$HERE"; then
    SRC="$HERE"
else
    for cand in /opt/0trust-src "$HOME"/0trustvpn* /root/0trustvpn* /home/*/0trustvpn*; do
        [[ -d "$cand" ]] && looks_right "$cand" && { SRC="$cand"; break; }
    done
fi

# A zip uploaded over FileZilla, which is how this often arrives. Extracted
# into its own empty directory: an archive is untrusted input until the
# contents have been looked at, and `looks_right` below is that look.
if [[ -z "$SRC" ]]; then
    ZIP="$(ls -1t "$HOME"/*.zip /root/*.zip /home/*/*.zip 2>/dev/null | awk 'NR==1' || true)"
    if [[ -n "$ZIP" ]]; then
        command -v unzip >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y -qq unzip; }
        DEST=/opt/0trust-src
        log "extracting $(basename "$ZIP") into $DEST"
        rm -rf "$DEST"; mkdir -p "$DEST"
        unzip -q "$ZIP" -d "$DEST"
        # GitHub zips carry one top-level directory.
        if ! looks_right "$DEST"; then
            inner="$(ls -1d "$DEST"/*/ 2>/dev/null | awk 'NR==1' || true)"
            [[ -n "$inner" ]] && looks_right "${inner%/}" && DEST="${inner%/}"
        fi
        looks_right "$DEST" && SRC="$DEST"
    fi
fi

if [[ -z "$SRC" ]]; then
    die "no 0trust source found.
    Upload the repository zip to this box's home directory and re-run, or:
      git clone <your-repo> /opt/0trust-src && sudo bash /opt/0trust-src/scripts/deploy-vps.sh $ROLE ..."
fi
ok "source: $SRC"

# ---------------------------------------------------------------------------
# 3. Hand off to install.sh
# ---------------------------------------------------------------------------
# --token-file is accepted as an alias so the role syntax reads the same for
# both; install.sh's own flag is --provision-token-file. A token must not go
# in argv, where it lands in shell history and in `ps` for any local user.
ARGS=()
for a in "$@"; do
    case "$a" in
        --token-file) ARGS+=(--provision-token-file) ;;
        *)            ARGS+=("$a") ;;
    esac
done

MODE="production"; [[ "$ROLE" == "node" ]] && MODE="node"
log "Running install.sh --mode $MODE"
note "everything from here is install.sh — its validators, its questions,"
note "its own pre-flight and its own post-install probes"
echo
chmod +x "$SRC/scripts/install.sh"
set +e
"$SRC/scripts/install.sh" --mode "$MODE" "${ARGS[@]}"
INSTALL_RC=$?
set -e
echo

# ---------------------------------------------------------------------------
# 4. Verify, and say what is still outstanding
# ---------------------------------------------------------------------------
if (( INSTALL_RC != 0 )); then
    die "install.sh exited $INSTALL_RC — read the message above.
    Nothing here needs undoing: install.sh is idempotent and keeps your
    secrets, database and operator account. Fix the cause and re-run."
fi

log "Verifying what is actually running"
if [[ "$ROLE" == "control" ]]; then
    # The local probe, not the public URL: this answers "did the service come
    # up", separately from DNS, TLS and whatever is in front of it.
    if curl -fsS --max-time 10 http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1; then
        ok "control plane answering on 127.0.0.1:8080"
    else
        printf '%s[!] the API is not answering locally%s\n' "$RED" "$NC" >&2
        note "journalctl -u 0trust-api -n 50 --no-pager"
    fi
fi

if [[ -x "$SRC/scripts/audit-verify.sh" ]]; then
    log "No-logs claims against THIS box"
    set +e
    "$SRC/scripts/audit-verify.sh" 2>&1 | tail -6
    set -e
    note "a FAIL here is a claim this deployment does not keep — read it before launch"
fi

if [[ "$ROLE" == "control" && -x "$SRC/scripts/preflight.sh" ]]; then
    log "Launch gate — what is still outstanding"
    set +e
    "$SRC/scripts/preflight.sh" 2>&1 | grep -E 'BLOCKED|PASS:|FAIL:' | head -20
    set -e
fi

echo
ok "deploy-vps.sh finished for role: $ROLE"
note "This script verified the host and the service. It did NOT verify that a"
note "customer can carry traffic — that takes a real client and a handshake:"
note "  0trust connect --region zur   (then check your egress IP changed)"
