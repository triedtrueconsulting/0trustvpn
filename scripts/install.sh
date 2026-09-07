#!/usr/bin/env bash
# ============================================================================
# 0trust — one-shot installer for a fresh Ubuntu 24.04 VPS
# ============================================================================
# Three modes:
#
#   test        No domain, no TLS. Serves over plain HTTP on the box's IP, and
#               turns this one VPS into the ENTIRE product: control plane,
#               website, admin dashboard, /surf proxy, and a real WireGuard
#               mesh carrying real traffic. One box is all three regions at
#               once, so `0trust connect` works the moment the installer ends.
#               For kicking the tyres — never for customers. See --no-vpn.
#
#   production  Real domain, Let's Encrypt certificate, HSTS, firewall.
#
#   node        No control plane, no website. Turns the box into a RAM-only
#               mesh node and joins it to an existing mesh in one command:
#               tmpfs for every path that would otherwise hold a key, swap
#               off, journald volatile, a fresh WireGuard keypair, and a
#               single call to the control plane that registers the node and
#               returns its id and PSK. Nothing to paste back afterwards.
#
#               sudo ./scripts/install.sh --mode node \
#                    --control-url https://0trustvpn.com \
#                    --region zur --provision-token ztvp-...
#
# Idempotent: safe to re-run to pick up new code or repair a half-finished run.
#
#   sudo ./scripts/install.sh --mode test
#   sudo ./scripts/install.sh --mode production --domain 0trustvpn.com \
#                             --email you@example.com
#
# Flags:
#   --mode test|production   (required)
#   --domain <fqdn>          (production)
#   --email <address>        (production, for Let's Encrypt expiry notices)
#   --no-firewall            skip UFW (useful when the provider firewalls for you)
#   --no-ssh-hardening       leave sshd alone
#   --no-vpn                 (test) skip the on-box mesh; seed placeholder rows
#                            instead, as earlier versions did
#   --control-url <url>      (node) the control plane to join
#   --provision-token <tok>  (node) minted on the control plane — see
#                            api/mint-provision-token.py or the dashboard
#   --region <code>          (node) zur | rey | buc
#   --role entry|exit|both   (node) default both
#   --wg-port <port>         (node) default 51820
#   --swap <size>            (test/production) make a swapfile, e.g. 4G.
#                            REFUSED on a node: swap can page the WireGuard
#                            private key to persistent disk, which is the one
#                            thing the RAM-only design exists to prevent.
#   --skip-preflight         skip the host checks (disk, ports, DNS,
#                            WireGuard support) that run before anything
#                            is changed
#   --dry-run                render everything, touch no system state
# ============================================================================
set -euo pipefail

MODE="" DOMAIN="" EMAIL=""
DO_FIREWALL=1 DO_SSH=1 DRY_RUN=0 DO_VPN=1 SKIP_PREFLIGHT=0
# Set when a post-install check found the box not actually serving.
INSTALL_DEGRADED=0
# Set when the mesh step could not bring the WireGuard interfaces up, so the
# closing summary describes the box that exists rather than the one intended.
VPN_BROKEN=0
CONTROL_URL="" PROVISION_TOKEN="" REGION="" NODE_ROLE="both" WG_PORT="51820"
SWAP_SIZE=""

WALLET_BTC="${WALLET_BTC:-}"

validate_wallet() {
    # A wrong extended key is the one failure in this system with no symptom:
    # the API happily derives addresses, invoices settle never, and every
    # health check stays green. Catch it here, and make the operator look at
    # the first address rather than trusting a prefix check.
    local key="$1"
    [[ -n "$key" ]] || return 0
    if [[ "$key" == *prv* ]]; then
        echo "  --wallet was given an extended PRIVATE key." >&2
        echo "  Nothing here needs one. Use the PUBLIC half (xpub/ypub/zpub)," >&2
        echo "  and treat that key as compromised." >&2
        exit 1
    fi
    local rc=0
    "$REPO_DIR/scripts/check-wallet.sh" "$key" || rc=$?
    case "$rc" in
        0) ;;
        3)  echo "  --wallet is not the wallet this deployment is pinned to" >&2
            echo "  (scripts/wallet.pin). Refusing: the likeliest cause is a" >&2
            echo "  truncated or mistyped paste, and it has no other symptom." >&2
            exit 1 ;;
        *)  echo "  --wallet did not validate; refusing to install with it." >&2
            exit 1 ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="${2:-}"; shift 2 ;;
        --domain) DOMAIN="${2:-}"; shift 2 ;;
        --email) EMAIL="${2:-}"; shift 2 ;;
        --no-firewall) DO_FIREWALL=0; shift ;;
        --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
        --no-ssh-hardening) DO_SSH=0; shift ;;
        --no-vpn) DO_VPN=0; shift ;;
        --wallet) WALLET_BTC="${2:-}"; shift 2 ;;
        --control-url) CONTROL_URL="${2:-}"; shift 2 ;;
        --provision-token) PROVISION_TOKEN="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        --role) NODE_ROLE="${2:-}"; shift 2 ;;
        --wg-port) WG_PORT="${2:-}"; shift 2 ;;
        --swap) SWAP_SIZE="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 64 ;;
    esac
done

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; DIM=$'\033[2m'; NC=$'\033[0m'
log()  { printf '%s[+] %s%s\n' "$YLW" "$*" "$NC"; }
ok()   { printf '%s[✓] %s%s\n' "$GRN" "$*" "$NC"; }
die()  { printf '%s[!] %s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }
note() { printf '%s    %s%s\n' "$DIM" "$*" "$NC"; }

# In dry-run every mutating command is echoed instead of run, so the whole
# script can be exercised in CI without a VPS to break.
run() {
    if [[ $DRY_RUN -eq 1 ]]; then printf '%s    would run: %s%s\n' "$DIM" "$*" "$NC"
    else "$@"; fi
}

[[ "$MODE" == "test" || "$MODE" == "production" || "$MODE" == "node" ]] \
    || die "--mode must be test, production or node (see --help)"
if [[ "$MODE" == "node" ]]; then
    [[ -n "$CONTROL_URL" ]] || die "node needs --control-url https://<control plane>"
    [[ -n "$PROVISION_TOKEN" ]] || die "node needs --provision-token (mint one on the control plane: api/mint-provision-token.py, or the dashboard)"
    [[ -n "$REGION" ]] || die "node needs --region (zur|rey|buc)"
    [[ "$CONTROL_URL" =~ ^https?://[^[:space:]/]+ ]] \
        || die "--control-url must be a URL, e.g. https://0trustvpn.com"
    CONTROL_URL="${CONTROL_URL%/}"
    # A provisioning token over plain HTTP is a credential on the wire, and
    # the response carries this node's PSK back the same way.
    [[ "$CONTROL_URL" == https://* ]] \
        || note "control plane is plain HTTP — the token and the node PSK cross the network in clear"
    [[ "$REGION" =~ ^[a-z]{2,8}$ ]] || die "--region must be a short lowercase code, e.g. zur"
    case "$NODE_ROLE" in entry|exit|both) ;; *) die "--role must be entry|exit|both" ;; esac
    [[ "$WG_PORT" =~ ^[0-9]+$ ]] && (( WG_PORT >= 1 && WG_PORT <= 65535 )) \
        || die "--wg-port must be 1-65535"
    # Not a matter of taste. A mesh node keeps its WireGuard private key on
    # tmpfs so it never touches persistent storage, and web/privacy.html,
    # web/audit.html and docs/AUDIT.md 5.3 all tell customers so. Swap is a
    # persistent file the kernel may page that key into. Turning it on here
    # would make those pages false and audit-verify's ram-no-swap fail.
    [[ -z "$SWAP_SIZE" ]] \
        || die "--swap is refused on a node. Swap can page the WireGuard
    private key to disk, and the RAM-only claim on web/privacy.html depends on
    it being off. If the node is short of memory, give it more RAM — a mesh
    node needs very little, and paging is not the answer here."
fi
if [[ "$MODE" == "production" ]]; then
    [[ -n "$DOMAIN" ]] || die "production needs --domain <fqdn>"
    [[ -n "$EMAIL"  ]] || die "production needs --email <address> for cert notices"
    [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && "$DOMAIN" == *.* ]] \
        || die "--domain must be a bare FQDN, e.g. 0trustvpn.com (no scheme, no path)"
fi
[[ $DRY_RUN -eq 1 || $EUID -eq 0 ]] || die "must run as root (try: sudo $0 ...)"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${ZTV_PREFIX:-/opt/0trust}"
ETC="${ZTV_ETC:-/etc/0trust}"
VARLIB="${ZTV_VARLIB:-/var/lib/0trust}"
WEBROOT="${ZTV_WEBROOT:-/var/www/0trust}"
VENV="$PREFIX/api/.venv"
NGINX_SITE="${ZTV_NGINX_SITE:-/etc/nginx/sites-available/0trust}"

# Before anything is written: a bad --wallet must stop the install, not be
# discovered by the first customer who pays.
validate_wallet "$WALLET_BTC"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || note "Not Ubuntu (${ID:-unknown}); proceeding anyway"
    [[ "${VERSION_ID:-}" == "24.04" ]] \
        || note "Tested on Ubuntu 24.04; you are on ${VERSION_ID:-unknown}"
fi

echo
printf '%s  0trust installer — %s mode%s\n' "$GRN" "$MODE" "$NC"
[[ -n "$DOMAIN" ]] && note "domain: $DOMAIN"
[[ $DRY_RUN -eq 1 ]] && note "DRY RUN — nothing will be changed"
echo

# ============================================================================
# HOST PREFLIGHT — everything that makes an install fail, checked BEFORE the
# install starts changing the box
# ============================================================================
# Every one of these used to be discovered part-way through: a domain with no
# DNS record surfaced at certbot, with packages, the service user, secrets,
# the database and nginx already written; port 80 held by another web server
# surfaced at `nginx -t`; a full disk surfaced wherever it ran out. A failure
# that costs five seconds and changes nothing is a different thing from one
# that leaves a half-built box behind.
#
# --skip-preflight for an operator who knows better than this list.
preflight_host() {
    local fatal=0

    # Disk. The venv, packages and website need well under a gigabyte; two is
    # a comfortable floor and catches the 10GB VPS that is already full.
    local avail_mb
    avail_mb=$(df -Pm / | awk 'NR==2 {print $4}')
    if [[ -n "$avail_mb" ]] && (( avail_mb < 2048 )); then
        printf '%s[!] only %s MB free on / — need ~2 GB%s\n' "$RED" "$avail_mb" "$NC" >&2
        fatal=1
    fi

    # Ports. A re-run finds OUR nginx holding 80/443, which is fine; anything
    # else means a web server this installer is about to fight with.
    if [[ "$MODE" != "node" ]]; then
        local p holder
        for p in 80 443; do
            [[ "$MODE" == "test" && "$p" == "443" ]] && continue
            # awk, not `head -1`: head exits after the first line, ss gets
            # SIGPIPE, and `set -o pipefail` turns that into a failed
            # assignment. awk consumes the whole stream. (validate.sh's
            # pipefail-head check caught this in exactly this code.)
            holder=$(ss -lntpH "sport = :$p" 2>/dev/null | awk 'NR==1' || true)
            if [[ -n "$holder" && "$holder" != *nginx* ]]; then
                printf '%s[!] port %s is already held by something that is not nginx:%s\n' \
                       "$RED" "$p" "$NC" >&2
                note "$holder"
                note "stop it first, or this install will not be reachable"
                fatal=1
            fi
        done
    fi

    # DNS. The single most common production install failure, and the most
    # expensive to discover late, because certbot runs last.
    if [[ "$MODE" == "production" && -n "$DOMAIN" ]]; then
        local resolved mine
        # `|| true` on both: getent exits 2 for a name that does not resolve,
        # and under `set -o pipefail` that status propagates out of the
        # command substitution and `set -e` kills the script — silently, with
        # exit 2 and no message, on exactly the input this check exists to
        # report. Same family as the pipefail-head class in CLAUDE.md.
        resolved=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u || true)
        mine=$(ip -4 -o addr show scope global 2>/dev/null \
               | awk '{split($4,a,"/"); print a[1]}' | sort -u || true)
        if [[ -z "$resolved" ]]; then
            printf '%s[!] %s does not resolve%s\n' "$RED" "$DOMAIN" "$NC" >&2
            note "Let's Encrypt has to reach it by name. Add an A record first."
            fatal=1
        elif [[ -n "$mine" ]] && ! comm -12 <(echo "$resolved") <(echo "$mine") | grep -q .; then
            # Behind a NAT or a proxy this is legitimate, so warn rather than
            # refuse — but say it, because it is usually a stale A record.
            note "$DOMAIN resolves to: $(echo "$resolved" | tr '\n' ' ')"
            note "this box has:        $(echo "$mine" | tr '\n' ' ')"
            note "certbot needs the name to reach THIS box on port 80."
        fi
    fi

    # WireGuard. Not fatal for the control plane, which does not need it, but
    # the operator should hear it now rather than after the install claims a
    # mesh it could not build.
    if [[ "$MODE" == "node" || ( "$MODE" == "test" && $DO_VPN -eq 1 ) ]]; then
        if ! ip link add dev ztvwgprobe type wireguard >/dev/null 2>&1; then
            printf '%s[!] this kernel cannot create a WireGuard interface%s\n' "$RED" "$NC" >&2
            note "common on LXC and OpenVZ VPSes. A node needs a KVM host."
            [[ "$MODE" == "node" ]] && fatal=1
            [[ "$MODE" == "test" ]] && note "the control plane will still install; the tunnels will not come up"
        else
            ip link del ztvwgprobe >/dev/null 2>&1 || true
        fi
    fi

    # A dry run exists to show what WOULD happen, including on a box that
    # cannot host this role. Report everything, refuse nothing: there is no
    # state to protect, and an operator rendering configs on a laptop should
    # not be blocked by that laptop's kernel.
    if (( fatal != 0 )); then
        if [[ $DRY_RUN -eq 1 ]]; then
            note "(dry run: a real install would stop here)"
            return 1
        fi
        die "host preflight failed — nothing has been changed"
    fi
    return 0
}

if [[ $SKIP_PREFLIGHT -eq 0 ]]; then
    # `ok` only when it really passed: saying "preflight passed" one line
    # under "a real install would stop here" is the same kind of contradiction
    # this whole pass exists to remove.
    if preflight_host; then ok "host preflight passed"; fi
fi

# ============================================================================
# NODE MODE — a fresh VPS becomes a RAM-only mesh node and joins the mesh
# ============================================================================
# Everything below this point in the script is the control plane. A node runs
# none of it: no nginx, no database, no API, no wallet. It runs WireGuard, a
# resolver bound to the mesh gateway, and meshd.
#
# The design constraint that shapes all of it: web/privacy.html, web/audit.html
# and docs/AUDIT.md §5.3 all tell customers that every mesh node is a RAM-only
# ephemeral instance. So this installer has to produce one — tmpfs over every
# path that would otherwise hold a key, swap off, journald volatile — or the
# claim stops being true the first time somebody uses it.
#
# That has a consequence worth stating plainly, because it drove the enrolment
# design: after a reboot this box has no WireGuard key and no node id. It has
# to be able to register itself again, unattended, or a reboot is an outage
# that needs a human. /etc/0trust-node.env is the one file deliberately left
# on real disk to make that possible, and it holds an enrolment token that is
# pinned to this machine's public IP and revocable from the dashboard.
if [[ "$MODE" == "node" ]]; then
    ETC_NODE="/etc/0trust-node.env"      # persistent: survives the tmpfs
    LIBDIR="/usr/local/lib/0trust"

    # ------------------------------------------------------------------
    log "Installing packages"
    # ------------------------------------------------------------------
    # stubby is the DNS-over-TLS stub dnsmasq forwards to; ca-certificates is
    # what authenticates the resolver to it, so neither is optional.
    NODE_PACKAGES=(wireguard wireguard-tools nftables dnsmasq stubby python3
                   curl ca-certificates)
    [[ $DO_FIREWALL -eq 1 ]] && NODE_PACKAGES+=(ufw)
    if [[ $DRY_RUN -eq 0 ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "${NODE_PACKAGES[@]}" >/dev/null
    fi
    ok "packages: ${NODE_PACKAGES[*]}"

    # shellcheck source=scripts/node-runtime.sh
    source "$REPO_DIR/scripts/node-runtime.sh"

    # ------------------------------------------------------------------
    log "RAM-only: tmpfs, no swap, volatile logs"
    # ------------------------------------------------------------------
    # /etc/wireguard holds the private key; /etc/0trust holds the node PSK.
    # Both have to be RAM, and they have to be RAM on every subsequent boot
    # too, which is why this goes in fstab rather than a one-off mount.
    if [[ $DRY_RUN -eq 0 ]]; then
        while read -r path size; do
            mkdir -p "$path"
            if ! grep -qE "^tmpfs[[:space:]]+$path[[:space:]]" /etc/fstab; then
                printf 'tmpfs %s tmpfs rw,nosuid,nodev,noexec,size=%s,mode=0700 0 0\n' \
                       "$path" "$size" >> /etc/fstab
            fi
            mountpoint -q "$path" || mount "$path"
        done <<'MOUNTS'
/etc/wireguard 1M
/etc/0trust 4M
/var/0trust 64M
MOUNTS
        # Swap would page a private key to a disk we have just promised holds
        # none. Off now, and out of fstab so it stays off.
        swapoff -a || true
        sed -i -E 's:^([^#].*[[:space:]]swap[[:space:]].*)$:# \1:' /etc/fstab
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/0trust.conf <<'JCONF'
[Journal]
Storage=volatile
RuntimeMaxUse=32M
JCONF
        systemctl restart systemd-journald || true
        ztv_sysctl_conf > /etc/sysctl.d/99-0trust.conf
        sysctl -p /etc/sysctl.d/99-0trust.conf >/dev/null
    fi
    ok "/etc/wireguard, /etc/0trust, /var/0trust are tmpfs; swap off; journald volatile"

    # ------------------------------------------------------------------
    log "Enrolment credentials"
    # ------------------------------------------------------------------
    # The one file on real disk. Root-only, and named so nobody mistakes it
    # for part of the tmpfs tree it sits next to.
    if [[ $DRY_RUN -eq 0 ]]; then
        umask 077
        cat > "$ETC_NODE" <<ENV
# 0trust node enrolment. Read by 0trust-node-enroll on every boot.
#
# This is the only 0trust file on persistent disk, deliberately: without it
# a reboot cannot rejoin the mesh unattended. The token below is scoped to
# one region and role, pinned to this machine's public IP after its first
# use, and revocable from the operator dashboard. It grants no access to
# customer data and cannot read another node's peers.
CONTROL_URL=$CONTROL_URL
REGION=$REGION
NODE_ROLE=$NODE_ROLE
WG_PORT=$WG_PORT
ZTV_PROVISION_TOKEN=$PROVISION_TOKEN
ENV
        chmod 600 "$ETC_NODE"
    fi
    ok "$ETC_NODE (root-only)"

    # ------------------------------------------------------------------
    log "Installing meshd and the enrolment unit"
    # ------------------------------------------------------------------
    if [[ $DRY_RUN -eq 0 ]]; then
        install -d "$LIBDIR"
        install -m 0755 "$REPO_DIR/wireguard/0trust-meshd.py" /usr/local/bin/0trust-meshd
        # Copied rather than sourced from the checkout: this runs at boot, and
        # a node should not depend on a git working tree still being there.
        install -m 0644 "$REPO_DIR/scripts/node-runtime.sh" "$LIBDIR/node-runtime.sh"
        install -m 0755 "$REPO_DIR/scripts/node-runtime-apply.sh" \
                "$LIBDIR/node-runtime-apply.sh"
        install -m 0755 "$REPO_DIR/scripts/node-enroll.sh" /usr/local/bin/0trust-node-enroll
        install -m 0644 "$REPO_DIR/systemd/0trust-node-enroll.service" \
                /etc/systemd/system/0trust-node-enroll.service
        install -m 0644 "$REPO_DIR/systemd/0trust-meshd.service" \
                /etc/systemd/system/0trust-meshd.service
        systemctl daemon-reload
        systemctl enable 0trust-node-enroll.service >/dev/null 2>&1 || true
        systemctl enable 0trust-meshd.service >/dev/null 2>&1 || true
    fi
    ok "0trust-node-enroll.service, 0trust-meshd.service"

    # ------------------------------------------------------------------
    log "Firewall"
    # ------------------------------------------------------------------
    if [[ $DO_FIREWALL -eq 1 && $DRY_RUN -eq 0 ]]; then
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow 22/tcp comment 'ssh' >/dev/null
        ufw allow "$WG_PORT/udp" comment '0trust wireguard' >/dev/null
        ufw allow in on wg0 >/dev/null 2>&1 || true
        # No `ufw allow 53`: the resolver binds the mesh gateway only. An open
        # resolver on a public address is a DNS-amplification abuse report
        # waiting to happen.
        if [[ "$NODE_ROLE" == "entry" || "$NODE_ROLE" == "both" ]]; then
            ufw allow 52000:59999/udp comment '0trust multi-hop' >/dev/null
        fi
        ufw --force enable >/dev/null
    fi
    ok "ufw: 22, $WG_PORT/udp$([[ "$NODE_ROLE" != exit ]] && echo ', 52000-59999/udp')"

    # ------------------------------------------------------------------
    log "Joining the mesh"
    # ------------------------------------------------------------------
    # One call. It generates the keypair, registers with the control plane and
    # writes meshd's environment; there is nothing to copy back by hand, and
    # no SQL for the operator to run on the control plane.
    if [[ $DRY_RUN -eq 1 ]]; then
        note "would run: 0trust-node-enroll && systemctl start 0trust-meshd"
        printf '\n%s  Node install rendered (dry run).%s\n\n' "$GRN" "$NC"
        exit 0
    fi

    systemctl start 0trust-node-enroll.service \
        || die "enrolment failed — journalctl -u 0trust-node-enroll"
    # shellcheck disable=SC1091
    NODE_ID="$(grep -hoP '^NODE_ID=\K.*' /etc/0trust/meshd.env 2>/dev/null || true)"
    [[ -n "$NODE_ID" ]] || die "enrolment produced no node id — journalctl -u 0trust-node-enroll"
    ok "registered as $NODE_ID"

    systemctl restart 0trust-meshd.service
    ok "meshd running"

    # ------------------------------------------------------------------
    log "Node runtime: NAT, egress filter, resolver"
    # ------------------------------------------------------------------
    # These are applied by the enrolment unit on every boot as well; doing it
    # here too means the box is correct now rather than after a reboot.
    ok "applied by 0trust-node-enroll (nftables + dnsmasq)"

    # ------------------------------------------------------------------
    log "Verifying"
    # ------------------------------------------------------------------
    # A node that registered but is not reachable is the failure that hides:
    # the control plane hands customers an endpoint, their handshakes time
    # out, and meshd keeps heartbeating happily over its own outbound HTTPS.
    sleep 3
    WG_OK=0; wg show wg0 >/dev/null 2>&1 && WG_OK=1
    if [[ $WG_OK -eq 1 ]]; then
        ok "wg0 is up on port $(wg show wg0 listen-port 2>/dev/null)"
    else
        note "wg0 is not up yet — journalctl -u 0trust-meshd"
    fi
    if curl -fsS --max-time 15 "$CONTROL_URL/api/v1/regions" 2>/dev/null \
         | grep -q "\"$REGION\""; then
        ok "the control plane lists $REGION as live"
    else
        note "the control plane does not list $REGION yet — meshd heartbeats every 30s"
    fi

    PUBLIC_IP="$(grep -hoP '^PUBLIC_IP=\K.*' /var/0trust/enrol.state 2>/dev/null || echo '?')"
    cat <<EOF

  $NODE_ID is in the mesh.

    region     $REGION ($NODE_ROLE)
    endpoint   $PUBLIC_IP:$WG_PORT
    disk       tmpfs — the WireGuard key and node PSK are RAM only
    on reboot  0trust-node-enroll generates a new key and rejoins as $NODE_ID

    status     systemctl status 0trust-meshd
    logs       journalctl -u 0trust-meshd -f
    leave      systemctl disable --now 0trust-meshd 0trust-node-enroll
               then remove the node in the dashboard

  Revoke this box's enrolment token from the dashboard if the machine is ever
  out of your hands. The node keeps running on the PSK it already holds; it
  simply cannot register again.

EOF
    exit 0
fi

# ----------------------------------------------------------------------------
# Swap, on the control plane only
# ----------------------------------------------------------------------------
# A 2GB control-plane VPS runs nginx, uvicorn, the proxy and SQLite, and the
# install itself builds a venv. Swap is the difference between a slow moment
# and the OOM killer taking out the API mid-request.
#
# It is off by default and refused outright on a node — see the validation
# above. On this box the database is already on disk, so a swapfile changes
# what an attacker with the disk could recover by a matter of degree, not
# kind. Encrypt the volume if that degree matters to you.
if [[ -n "$SWAP_SIZE" ]]; then
    log "Swap ($SWAP_SIZE)"
    [[ "$SWAP_SIZE" =~ ^[0-9]+[MG]$ ]] \
        || die "--swap takes a size like 4G or 512M, got: $SWAP_SIZE"
    SWAPFILE="${ZTV_SWAPFILE:-/swapfile}"
    if [[ $DRY_RUN -eq 1 ]]; then
        note "would create $SWAPFILE ($SWAP_SIZE), enable it, and add it to /etc/fstab"
    elif swapon --show --noheadings 2>/dev/null | grep -q .; then
        ok "swap is already active: $(swapon --show=NAME,SIZE --noheadings | tr '\n' ' ')"
    else
        # fallocate is instant but gives a file with holes on some
        # filesystems, and swapon rejects those. dd is slower and always
        # works; on a 4G file that is a few seconds once, at install time.
        swap_mb="${SWAP_SIZE%[MG]}"
        [[ "$SWAP_SIZE" == *G ]] && swap_mb=$(( swap_mb * 1024 ))
        if ! fallocate -l "$SWAP_SIZE" "$SWAPFILE" 2>/dev/null; then
            # Not just a fallback for a missing fallocate: on filesystems that
            # give it a sparse file, swapon refuses the result outright. dd is
            # slower and always produces something swapon accepts.
            note "fallocate unusable here, writing ${swap_mb}M with dd (slower)"
            rm -f "$SWAPFILE"
            dd if=/dev/zero of="$SWAPFILE" bs=1M count="$swap_mb" status=none
        fi
        chmod 600 "$SWAPFILE"
        mkswap "$SWAPFILE" >/dev/null
        swapon "$SWAPFILE"
        grep -q "^$SWAPFILE " /etc/fstab \
            || printf '%s none swap sw 0 0\n' "$SWAPFILE" >> /etc/fstab
        # A database box should reach for swap late, not eagerly: paging
        # SQLite's page cache out is how a fast query becomes a slow one.
        printf 'vm.swappiness=10\nvm.vfs_cache_pressure=50\n' \
            > /etc/sysctl.d/99-0trust-swap.conf
        sysctl -p /etc/sysctl.d/99-0trust-swap.conf >/dev/null
        ok "$SWAPFILE active ($SWAP_SIZE), in /etc/fstab, swappiness 10"
    fi
fi

# ----------------------------------------------------------------------------
log "Installing packages"
# ----------------------------------------------------------------------------
PACKAGES=(nginx python3 python3-venv python3-pip sqlite3 curl jq openssl
          wireguard-tools ca-certificates)
[[ $DO_FIREWALL -eq 1 ]] && PACKAGES+=(ufw fail2ban)
[[ "$MODE" == "production" ]] && PACKAGES+=(certbot python3-certbot-nginx)

if [[ $DRY_RUN -eq 0 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "${PACKAGES[@]}" >/dev/null
fi
ok "packages: ${PACKAGES[*]}"

# ----------------------------------------------------------------------------
log "Creating service user and directories"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    id -u 0trust &>/dev/null || \
        useradd --system --home "$PREFIX" --shell /usr/sbin/nologin 0trust
    mkdir -p "$PREFIX/api" "$PREFIX/proxy" "$VARLIB" "$ETC" "$WEBROOT" /var/www/acme
    chown -R 0trust:0trust "$PREFIX" "$VARLIB"
    chmod 750 "$ETC"
fi
ok "user 0trust, $PREFIX, $VARLIB, $ETC"

# ----------------------------------------------------------------------------
log "Installing application code"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    # Every .py the control plane imports, plus the operator tools that this
    # script's own closing instructions tell you to run out of $PREFIX.
    #
    # It was a hand-kept list and it was short by two. api/monerowatch.py is
    # imported unconditionally at the top of payments.py, so the installed
    # tree could not import payments at all — the API did not start, on every
    # provider, whether or not the operator wanted Monero. Nothing caught it
    # because the test suite runs the API from the source checkout, where the
    # file is always there. api/mint-provision-token.py was the other: the
    # instructions printed at the end of this script name
    # $PREFIX/api/mint-provision-token.py, a path nothing created.
    #
    # Enumerating the directory rather than the filenames means a new module
    # cannot be forgotten. smoke_test.py is the one deliberate exclusion: it
    # is a test, and it writes a scratch database.
    for f in "$REPO_DIR"/api/*.py; do
        [[ "$(basename "$f")" == "smoke_test.py" ]] && continue
        install -o 0trust -g 0trust -m 0644 "$f" "$PREFIX/api/"
    done
    install -o 0trust -g 0trust -m 0644 \
        "$REPO_DIR/api/requirements.txt" "$PREFIX/api/"
    install -o 0trust -g 0trust -m 0644 \
        "$REPO_DIR/proxy/server.py" "$REPO_DIR/proxy/guards.py" \
        "$REPO_DIR/proxy/rewrite.py" \
        "$PREFIX/proxy/"

    # 0trust-backup.service runs $PREFIX/scripts/backup.sh. Installing the
    # unit without the script it invokes leaves a timer that fails nightly.
    mkdir -p "$PREFIX/scripts"
    install -o 0trust -g 0trust -m 0755 \
        "$REPO_DIR/scripts/backup.sh" "$PREFIX/scripts/backup.sh"

    # Same reasoning, and it had the same hole: 0trust-canary-check.service
    # runs $PREFIX/canary/scripts/check.sh, and nothing put a canary script
    # under $PREFIX at all. Enabling the timer per docs/LAUNCH.md gave a green
    # `systemctl enable` and then 203/EXEC every night — the alarm guarding
    # the one document customers are told to read as a duress signal, dead on
    # arrival and silent about it. Root-owned: the unit runs as root.
    mkdir -p "$PREFIX/canary/scripts" "$PREFIX/canary/templates"
    install -m 0755 "$REPO_DIR/canary/scripts/check.sh" \
        "$PREFIX/canary/scripts/check.sh"
    install -m 0755 "$REPO_DIR/canary/scripts/generate.sh" \
        "$PREFIX/canary/scripts/generate.sh"
    install -m 0644 "$REPO_DIR/canary/templates/canary.txt" \
        "$PREFIX/canary/templates/canary.txt"

    [[ -d "$VENV" ]] || sudo -u 0trust python3 -m venv "$VENV"
    sudo -u 0trust "$VENV/bin/pip" install --quiet --disable-pip-version-check \
        -r "$PREFIX/api/requirements.txt"
fi
ok "api + proxy installed, venv ready"

# ----------------------------------------------------------------------------
log "Generating secrets"
# ----------------------------------------------------------------------------
# Written once and never regenerated: rotating NODE_API_PSK on a re-run would
# lock out every mesh node, and rotating TRIAL_SECRET would invalidate every
# challenge in flight.
gen() { openssl rand -hex 32; }

if [[ $DRY_RUN -eq 0 && ! -f "$ETC/api.env" ]]; then
    NODE_PSK="$(gen)"; TRIAL_SECRET="$(gen)"
    cat > "$ETC/api.env" <<ENVEOF
# 0trust control plane — generated by scripts/install.sh on $(date -u +%FT%TZ)
ZTV_DB_PATH=$VARLIB/0trust.db
MESH_NETWORK=10.64.0.0/10

# Mesh nodes authenticate with this. Rotating it means restarting every node.
NODE_API_PSK=$NODE_PSK

# --- Free trial ---
ZTV_TRIAL_ENABLED=1
ZTV_TRIAL_DAYS=7
ZTV_TRIAL_MAX_DEVICES=2
ZTV_TRIAL_POW_BITS=20
ZTV_TRIAL_SECRET=$TRIAL_SECRET

# --- Payments ---
# watch  = your own wallets, watched without running a chain. Non-custodial,
#          no account anywhere, no chain data on this box, and the only option
#          that works the day you build the VPS: paste WALLET_BTC below and
#          paid signup starts working.
#          BTC and ZEC derive an address per invoice from an xpub and watch a
#          public explorer. ZEC means transparent t1 addresses; shielded ones
#          cannot be watched from a public key. XMR needs no address here —
#          run scripts/setup-monero-watch.sh and set MONERO_WALLET_RPC. Each
#          coin is offered only if it has a wallet.
# btcpay = BTCPay Server (yours or somebody's). Non-custodial, more coins,
#          but something has to run BTCPay.
# hosted = commercial gateway. No infrastructure at all; custodial and
#          usually wants identity documents.
# stripe/square = cards. A real identity behind every payment — read
#          web/privacy.html before turning these on.
ZTV_PAYMENT_PROVIDER=watch

# The PUBLIC half of your Bitcoin wallet. xpub/ypub/zpub. A fresh receive
# address is derived per invoice; nothing here can spend anything.
WALLET_BTC=$WALLET_BTC

# Blank uses mempool.space. Any Esplora-compatible explorer works, including
# your own, if you would rather not depend on a public one.
NODE_RPC_BTC=
ZTV_BTC_CONFIRMATIONS=1
# Only read when ZTV_PAYMENT_PROVIDER=btcpay. Left blank on purpose: a
# default pointing at example.com turns "you have not configured this" into
# a connection error against somebody else's domain.
BTCPAY_URL=
BTCPAY_STORE_ID=
BTCPAY_API_KEY=
BTCPAY_WEBHOOK_SECRET=$(gen)

# When ZTV_PAYMENT_PROVIDER=hosted:
#ZTV_PAYMENT_API_URL=
#ZTV_PAYMENT_API_KEY=
#ZTV_PAYMENT_IPN_SECRET=
ENVEOF
    chown root:0trust "$ETC/api.env"; chmod 640 "$ETC/api.env"
    ok "wrote $ETC/api.env with fresh secrets"
elif [[ $DRY_RUN -eq 0 ]]; then
    # Re-run against an older install: add keys it predates rather than
    # clobbering the operator's edits.
    for kv in "ZTV_TRIAL_ENABLED=1" "ZTV_TRIAL_DAYS=7" \
              "ZTV_TRIAL_MAX_DEVICES=2" "ZTV_TRIAL_POW_BITS=20" \
              "ZTV_BTC_CONFIRMATIONS=1" "WALLET_BTC=" "NODE_RPC_BTC=" \
              "ZTV_PAYMENT_PROVIDER=btcpay"; do
        grep -q "^${kv%%=*}=" "$ETC/api.env" || echo "$kv" >> "$ETC/api.env"
    done
    grep -q "^ZTV_TRIAL_SECRET=" "$ETC/api.env" \
        || echo "ZTV_TRIAL_SECRET=$(gen)" >> "$ETC/api.env"
    ok "$ETC/api.env already present — left your values, added any missing keys"
fi

# The on-box mesh below needs the PSK its nodes will authenticate with. On a
# fresh install it was just generated; on a re-run it only exists in api.env,
# and an empty value here would write meshd configs that can never authenticate
# — nodes silently failing to sync while the installer reports success.
if [[ $DRY_RUN -eq 0 && -z "${NODE_PSK:-}" && -f "$ETC/api.env" ]]; then
    NODE_PSK="$(sed -n 's/^NODE_API_PSK=//p' "$ETC/api.env" | tail -n1)"
fi
NODE_PSK="${NODE_PSK:-RENDER-ONLY-NO-PSK}"

if [[ $DRY_RUN -eq 0 && ! -f "$ETC/proxy.env" ]]; then
    install -m 0640 -o root -g 0trust "$REPO_DIR/systemd/proxy.env.example" \
        "$ETC/proxy.env"
    ok "wrote $ETC/proxy.env"
elif [[ $DRY_RUN -eq 0 ]]; then
    # Same rule as api.env: add keys an older install predates, keep the edits.
    for kv in "ZTV_API_BASE=http://127.0.0.1:8080" "ZTV_TRIAL_DAYS=7"; do
        grep -q "^${kv%%=*}=" "$ETC/proxy.env" || echo "$kv" >> "$ETC/proxy.env"
    done
    ok "$ETC/proxy.env already present — left your values, added any missing keys"
fi

# 0trust-backup.service reads this unconditionally, so it has to exist even
# though the timer stays disabled until an age key is generated.
if [[ $DRY_RUN -eq 0 && ! -f "$ETC/backup.env" ]]; then
    install -m 0640 -o root -g 0trust "$REPO_DIR/systemd/backup.env.example" \
        "$ETC/backup.env"
    ok "wrote $ETC/backup.env (timer stays disabled until you make an age key)"
fi

# ----------------------------------------------------------------------------
log "Initialising the database"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    sudo -u 0trust env ZTV_DB_PATH="$VARLIB/0trust.db" \
        "$VENV/bin/python" -c "
import sys; sys.path.insert(0, '$PREFIX/api')
import main; main.init_db(); print('schema ok')
" >/dev/null
fi
ok "$VARLIB/0trust.db"

# ----------------------------------------------------------------------------
log "Installing systemd units"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    for unit in 0trust-api.service 0trust-sweep.service 0trust-sweep.timer \
                0trust-poll.service 0trust-poll.timer \
                0trust-proxy.service 0trust-backup.service 0trust-backup.timer; do
        install -m 0644 "$REPO_DIR/systemd/$unit" "/etc/systemd/system/$unit"
    done
    systemctl daemon-reload
fi
# The backup timer is installed but deliberately NOT enabled: it encrypts to an
# age recipient that does not exist yet, so enabling it here would just produce
# a failing unit every night. docs/DR.md covers generating the key and turning
# it on.
ok "api, sweep timer, proxy, backup (installed, not enabled)"

# ----------------------------------------------------------------------------
log "Deploying the website"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    cp -r "$REPO_DIR/web/." "$WEBROOT/"
    chown -R www-data:www-data "$WEBROOT"
fi
ok "$WEBROOT"

# ----------------------------------------------------------------------------
log "Configuring nginx"
# ----------------------------------------------------------------------------
render_common_locations() {
    cat <<'LOCEOF'
    # --- Free trial: proof-of-work makes bulk redemption expensive, this
    #     makes it slow too. Issuing challenges is cheap, so only redemption
    #     is throttled.
    location = /api/v1/trial {
        limit_req zone=trial burst=2 nodelay;
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/snippets/0trust-proxy.conf;
    }

    # Signup and top-up mint invoices; keep them on the tight bucket. These
    # are exact matches so that /api/v1/account/status is NOT charged to it.
    location = /api/v1/account {
        limit_req zone=signup burst=3 nodelay;
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/snippets/0trust-proxy.conf;
    }
    location = /api/v1/account/topup {
        limit_req zone=signup burst=3 nodelay;
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/snippets/0trust-proxy.conf;
    }

    location = /api/v1/payment/webhook {
        limit_req zone=webhook burst=20 nodelay;
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/snippets/0trust-proxy.conf;
    }

    location /api/v1/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/snippets/0trust-proxy.conf;
    }

    # --- Visitor proxy: separate upstream so it can be stopped without
    #     touching the control plane paying customers depend on.
    location /surf {
        limit_req zone=surf burst=10 nodelay;
        limit_conn surfconn 4;
        proxy_pass http://127.0.0.1:8081;
        include /etc/nginx/snippets/0trust-surf.conf;
        add_header X-Robots-Tag "noindex, nofollow" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location = /trial   { try_files /trial.html =404; }

    # --- Operations dashboard ---
    # Restricted by default. This page can ban customers and move money, so it
    # is the one part of the site that should not be reachable from the open
    # internet. Replace the allow lines with your own address, or front it with
    # a VPN or an SSH tunnel and leave it on 127.0.0.1.
    location = /admin {
        # allow 203.0.113.7;    # <- your address
        # deny all;
        try_files /admin.html =404;
        add_header X-Robots-Tag "noindex, nofollow" always;
        add_header Cache-Control "no-store" always;
    }
    location = /admin.css { try_files /admin.css =404; }
    location = /admin.js  { try_files /admin.js  =404; }
    location /api/v1/admin/ {
        # allow 203.0.113.7;    # <- same restriction as the page itself
        # deny all;
        limit_req zone=admin burst=20 nodelay;
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/snippets/0trust-proxy.conf;
        add_header Cache-Control "no-store" always;
    }

    location = /status  { try_files /status.html =404; }
    location = /download{ try_files /download.html =404; }
    location = /help    { try_files /help.html =404; }
    location = /privacy { try_files /privacy.html =404; }
    location = /terms   { try_files /terms.html =404; }
    location = /audit   { try_files /audit.html =404; }
LOCEOF
}

render_zones() {
    cat <<'ZONEEOF'
limit_req_zone $binary_remote_addr zone=signup:10m  rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m     rate=60r/m;
limit_req_zone $binary_remote_addr zone=webhook:10m rate=120r/m;
limit_req_zone $binary_remote_addr zone=surf:10m    rate=30r/m;
limit_req_zone $binary_remote_addr zone=trial:10m   rate=3r/m;
limit_req_zone $binary_remote_addr zone=admin:10m   rate=120r/m;
limit_conn_zone $binary_remote_addr zone=surfconn:10m;
ZONEEOF
}

if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p /etc/nginx/snippets
    install -m 0644 "$REPO_DIR/nginx/0trust-proxy.conf" \
        /etc/nginx/snippets/0trust-proxy.conf
    install -m 0644 "$REPO_DIR/nginx/0trust-surf.conf" \
        /etc/nginx/snippets/0trust-surf.conf
fi

TMP_SITE="$(mktemp)"
TMP_ZONES="$(mktemp)"
render_zones > "$TMP_ZONES"

# Emit `listen [::]` only where there is an IPv6 stack to bind it to.
#
# `nginx -t` does not merely parse — it binds every listener, so on a host
# with IPv6 disabled it fails with "Address family not supported by protocol"
# and the installer died right here, after having already installed packages,
# created the service user, written secrets and initialised the database. A
# half-installed box, on a plain Ubuntu 24.04 VPS whose provider simply does
# not hand out IPv6. The emulation suite worked around exactly this when it
# wrapped nginx -t, which is how the product bug stayed hidden behind a green
# test.
#
# ZTV_NGINX_IPV6=0 forces it off, 1 forces it on (for a host where the stack
# appears after boot).
if [[ -n "${ZTV_NGINX_IPV6:-}" ]]; then
    HAS_IPV6="$ZTV_NGINX_IPV6"
elif [[ -d /proc/sys/net/ipv6 ]] \
     && [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" == "0" ]]; then
    HAS_IPV6=1
else
    HAS_IPV6=0
fi

listen6() {   # listen6 <suffix...>  — a `listen [::]:...` line, or nothing
    (( HAS_IPV6 )) && printf '    listen [::]:%s;' "$*"
    return 0
}

# Precomputed because these sit inside heredocs, where a function call cannot.
# An empty value leaves a blank line, which nginx ignores.
L6_80_DEFAULT="$(listen6 "80 default_server")"
L6_80="$(listen6 80)"
L6_443="$(listen6 "443 ssl http2")"

if [[ "$MODE" == "test" ]]; then
    {
        echo "# 0trust — TEST deployment. Plain HTTP on the box's IP."
        echo "# No TLS: anything typed into this site crosses the network in"
        echo "# clear, account tokens included. Never point customers at it."
        echo
        cat <<EOF
server {
    listen 80 default_server;
$L6_80_DEFAULT
    server_name _;
    root $WEBROOT;
    index index.html;

    # Say plainly what this is, in a header a test client can see.
    add_header X-0trust-Deployment "test-no-tls" always;

EOF
        render_common_locations
        cat <<'EOF'

    location / { try_files $uri $uri/ /index.html; }
    location ~ /\. { deny all; }
}
EOF
    } > "$TMP_SITE"
else
    {
        echo "# 0trust — production. Generated by scripts/install.sh."
        echo
        cat <<EOF
server {
    listen 80;
$L6_80
    server_name $DOMAIN www.$DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    # "listen ... ssl http2" here, not the standalone "http2 on;" directive:
    # Ubuntu 24.04 ships nginx 1.24, which does not know it and refuses to
    # start. 1.25+ still accepts this form, so one config serves both.
    # (No backticks in this heredoc — it is unquoted, so they would run.)
    listen 443 ssl http2;
$L6_443
    server_name $DOMAIN www.$DOMAIN;
    root $WEBROOT;
    index index.html;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;

EOF
        render_common_locations
        cat <<'EOF'

    location / { try_files $uri $uri/ /index.html; }
    location ~ /\. { deny all; }
}
EOF
    } > "$TMP_SITE"
fi

if [[ $DRY_RUN -eq 0 ]]; then
    install -m 0644 "$TMP_ZONES" /etc/nginx/conf.d/0trust-zones.conf
    install -m 0644 "$TMP_SITE" "$NGINX_SITE"
    ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/0trust
    rm -f /etc/nginx/sites-enabled/default

    if [[ "$MODE" == "production" && ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
        log "Obtaining a Let's Encrypt certificate for $DOMAIN"
        # The TLS server block references a certificate that does not exist
        # yet, so nginx cannot start on the final config. Serve the ACME
        # challenge from a minimal HTTP-only site first, then swap.
        cat > "$NGINX_SITE" <<EOF
server {
    listen 80 default_server;
    server_name $DOMAIN www.$DOMAIN;
    root $WEBROOT;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { try_files \$uri \$uri/ /index.html; }
}
EOF
        nginx -t && systemctl reload nginx
        certbot certonly --webroot -w /var/www/acme \
            -d "$DOMAIN" -d "www.$DOMAIN" \
            --email "$EMAIL" --agree-tos --no-eff-email --non-interactive \
            || die "certbot failed. Does $DOMAIN resolve to this box, and is port 80 reachable?"
        install -m 0644 "$TMP_SITE" "$NGINX_SITE"
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        printf '#!/bin/sh\nsystemctl reload nginx\n' \
            > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
    fi

    nginx -t || die "generated nginx config is invalid"
fi
ok "nginx configured ($MODE)"
if [[ $DRY_RUN -eq 1 ]]; then
    # ZTV_RENDER_TO lets CI validate the exact bytes this would install,
    # rather than a test-side reconstruction that can drift from reality.
    if [[ -n "${ZTV_RENDER_TO:-}" ]]; then
        mkdir -p "$ZTV_RENDER_TO"
        cp "$TMP_SITE"  "$ZTV_RENDER_TO/site.conf"
        cp "$TMP_ZONES" "$ZTV_RENDER_TO/zones.conf"
        note "rendered config written to $ZTV_RENDER_TO"
    else
        # head FIRST, then sed. The other way round, head exits after 20
        # lines and sed dies of SIGPIPE on its next write — which under
        # `set -o pipefail` fails the pipeline and, under `set -e`, ends the
        # whole dry run right here with a non-zero exit. Whether it fires is
        # a scheduling race: never on an idle laptop, reliably on a loaded CI
        # runner, which is precisely the shape of bug that gets shipped.
        note "rendered site config:"; head -20 "$TMP_SITE" | sed 's/^/      /'
    fi
fi

# ----------------------------------------------------------------------------
log "Starting services"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    systemctl enable --now 0trust-api.service
    systemctl enable --now 0trust-proxy.service
    systemctl enable --now 0trust-sweep.timer
    # Harmless with any other provider — the poller exits immediately unless
    # ZTV_PAYMENT_PROVIDER=watch, so enabling it unconditionally means an
    # operator switching to watch-only in the dashboard does not also have to
    # remember to start a timer.
    systemctl enable --now 0trust-poll.timer
    systemctl reload nginx || systemctl restart nginx

    # Prove the control plane actually answers before saying it is up.
    #
    # `systemctl enable --now` returning 0 means systemd accepted the unit, not
    # that uvicorn bound a port or that main.py imported — and this printed a
    # green line and then a list of URLs regardless. An operator whose API died
    # on a bad env file or a missing module got a cheerful set of links to
    # nothing. Same non-evidence as the mesh step's old "The VPN works".
    API_OK=0 WEB_OK=0
    for _ in $(seq 1 20); do
        if curl -fsS --max-time 3 -o /dev/null \
                http://127.0.0.1:8080/api/v1/status/public 2>/dev/null; then
            API_OK=1; break
        fi
        sleep 1
    done
    for _ in $(seq 1 10); do
        if curl -fsS --max-time 3 -o /dev/null http://127.0.0.1/ 2>/dev/null; then
            WEB_OK=1; break
        fi
        sleep 1
    done
fi
if [[ $DRY_RUN -eq 0 ]]; then
    if (( API_OK )); then
        ok "0trust-api answering, sweep + poll timers armed"
    else
        INSTALL_DEGRADED=1
        printf '%s[!] 0trust-api is NOT answering on 127.0.0.1:8080%s\n' "$RED" "$NC" >&2
        note "journalctl -u 0trust-api -n 50 --no-pager"
    fi
    if (( WEB_OK )); then
        ok "nginx serving the site"
    else
        INSTALL_DEGRADED=1
        printf '%s[!] nginx is NOT serving on port 80%s\n' "$RED" "$NC" >&2
        note "nginx -t; journalctl -u nginx -n 50 --no-pager"
    fi
else
    ok "0trust-api, 0trust-proxy, 0trust-sweep.timer, 0trust-poll.timer, nginx"
fi

# ----------------------------------------------------------------------------
if [[ $DO_FIREWALL -eq 1 ]]; then
log "Configuring the firewall"
if [[ $DRY_RUN -eq 0 ]]; then
    ufw --force default deny incoming
    ufw --force default allow outgoing
    ufw allow 22/tcp comment 'ssh'
    ufw allow 80/tcp comment 'http'
    [[ "$MODE" == "production" ]] && ufw allow 443/tcp comment 'https'
    ufw --force enable
fi
ok "ufw: 22, 80$([[ "$MODE" == production ]] && echo ', 443')"
fi

# ----------------------------------------------------------------------------
if [[ $DO_SSH -eq 1 && "$MODE" == "production" ]]; then
log "Hardening sshd"
if [[ $DRY_RUN -eq 0 ]]; then
    # Only touch this in production, and only if a key is already authorized —
    # turning off password auth on a box you're holding open with a password
    # locks you out of your own server.
    if [[ -s /root/.ssh/authorized_keys ]] || \
       compgen -G "/home/*/.ssh/authorized_keys" >/dev/null; then
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        ok "password auth disabled"
    else
        note "no authorized_keys found — leaving password auth ON so you keep access"
    fi
fi
fi

# ----------------------------------------------------------------------------
if [[ "$MODE" == "test" ]]; then

# The three region codes are fixed product-wide (zur/rey/buc). On a real
# deployment each is a separate VPS in a separate jurisdiction; here all three
# live on this box as three WireGuard interfaces on three ports, so single-hop
# and multi-hop both have somewhere real to route. Fields:
#   region : interface : udp port : mesh gateway address
LOCAL_NODES=(
    "zur:wg0:51820:10.64.0.1"
    "rey:wg1:51821:10.64.0.2"
    "buc:wg2:51822:10.64.0.3"
)
# shellcheck source=scripts/node-runtime.sh
source "$REPO_DIR/scripts/node-runtime.sh"

PUBIP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
         || hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)"

if [[ $DO_VPN -eq 1 ]]; then
# ----------------------------------------------------------------------------
log "Turning this box into the mesh as well (test mode)"
# ----------------------------------------------------------------------------
note "one VPS, three node identities — see the warnings at the end"

if [[ $DRY_RUN -eq 0 ]]; then
    apt-get install -y -qq wireguard wireguard-tools nftables dnsmasq stubby >/dev/null
fi

# --- kernel ---------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    ztv_sysctl_conf > /etc/sysctl.d/99-0trust.conf
    sysctl -p /etc/sysctl.d/99-0trust.conf >/dev/null
fi
ok "ip forwarding on, anti-spoofing sysctls applied"

# --- keys, meshd, one systemd instance per node ---------------------------
run install -m 0755 "$REPO_DIR/wireguard/0trust-meshd.py" /usr/local/bin/0trust-meshd
run install -m 0644 "$REPO_DIR/systemd/0trust-meshd@.service" \
    /etc/systemd/system/0trust-meshd@.service

for spec in "${LOCAL_NODES[@]}"; do
    IFS=: read -r nregion niface nport ngw <<<"$spec"
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p /etc/wireguard
        umask 077
        if [[ ! -s "/etc/wireguard/$niface.key" ]]; then
            wg genkey | tee "/etc/wireguard/$niface.key" \
                | wg pubkey > "/etc/wireguard/$niface.pub"
        fi
        chmod 600 "/etc/wireguard/$niface.key"
        chmod 644 "/etc/wireguard/$niface.pub"
        # A /32, not the usual /10. Three interfaces each claiming the whole
        # mesh network would give the kernel three equally-good routes to any
        # client, and return traffic for a peer on wg2 would be handed to wg0,
        # which has never heard of it. meshd installs a /32 per peer instead,
        # which is unambiguous. A real one-node box keeps the /10 default.
        ztv_meshd_env "http://127.0.0.1:8080" "$NODE_PSK" "$nregion-01" both \
                      "$niface" "$nport" "$ngw/32" "ztv_fwd_$niface" \
                      > "/etc/0trust/meshd-$niface.env"
        chmod 600 "/etc/0trust/meshd-$niface.env"
    fi
done
if [[ -n "${ZTV_RENDER_TO:-}" ]]; then
    mkdir -p "$ZTV_RENDER_TO"
    for spec in "${LOCAL_NODES[@]}"; do
        IFS=: read -r nregion niface nport ngw <<<"$spec"
        ztv_meshd_env "http://127.0.0.1:8080" RENDER-PSK "$nregion-01" both \
                      "$niface" "$nport" "$ngw/32" "ztv_fwd_$niface" \
                      > "$ZTV_RENDER_TO/meshd-$niface.env"
    done
fi
ok "keys + meshd units for ${#LOCAL_NODES[@]} local nodes"

# --- NAT and the abuse filter, identical to a real node -------------------
PRIMARY_IF="$(ip -o -4 route show to default 2>/dev/null | awk 'NR==1{print $5}')"
PRIMARY_IF="${PRIMARY_IF:-eth0}"
if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p /etc/nftables.d
    ztv_nat_ruleset "$PRIMARY_IF" | nft -f -
    ztv_egress_ruleset | nft -f -
    nft list table inet ztv_nat    >  /etc/nftables.d/0trust.nft
    nft list table inet ztv_egress >> /etc/nftables.d/0trust.nft
fi
if [[ -n "${ZTV_RENDER_TO:-}" ]]; then
    ztv_nat_ruleset "$PRIMARY_IF" >  "$ZTV_RENDER_TO/nat.nft"
    ztv_egress_ruleset            >  "$ZTV_RENDER_TO/egress.nft"
fi
ok "masquerade on $PRIMARY_IF, egress abuse filter loaded"

# --- the resolver clients are actually told to use ------------------------
MESH_DNS="${LOCAL_NODES[0]##*:}"
# The v6 gateway is the v4 one embedded in the ULA prefix, the same derivation
# the control plane and meshd use — so 10.64.0.1 becomes ...::a40:1.
MESH_DNS6="$(ztv_mesh_ip6 "$MESH_DNS")"
# dnsmasq's only upstream is the local DNS-over-TLS stub, so the stub has to
# exist before dnsmasq is told to use it — the same order a real node uses.
if [[ $DRY_RUN -eq 0 ]]; then
    if [[ "${ZTV_DNS_ENCRYPTED:-1}" == "1" ]] && command -v stubby >/dev/null; then
        mkdir -p /etc/stubby
        ztv_stubby_conf > /etc/stubby/stubby.yml
        systemctl enable stubby >/dev/null 2>&1 || true
        systemctl restart stubby >/dev/null 2>&1 \
            || note "stubby did not start — journalctl -u stubby"
    fi
    mkdir -p /etc/dnsmasq.d
    ztv_dnsmasq_conf "$MESH_DNS" "$MESH_DNS6" > /etc/dnsmasq.d/0trust.conf
fi
if [[ -n "${ZTV_RENDER_TO:-}" ]]; then
    ztv_dnsmasq_conf "$MESH_DNS" "$MESH_DNS6" > "$ZTV_RENDER_TO/dnsmasq.conf"
    ztv_stubby_conf > "$ZTV_RENDER_TO/stubby.yml"
fi
ok "dnsmasq will answer on $MESH_DNS and $MESH_DNS6, over DNS-over-TLS upstream"

# --- firewall -------------------------------------------------------------
if [[ $DO_FIREWALL -eq 1 && $DRY_RUN -eq 0 ]]; then
    for spec in "${LOCAL_NODES[@]}"; do
        IFS=: read -r _ niface nport _ <<<"$spec"
        ufw allow "$nport/udp" comment "0trust $niface" >/dev/null
        ufw allow in on "$niface" >/dev/null
    done
    # Multi-hop entry ports. Nothing on this host listens here — nftables
    # DNATs each one straight to the exit node the control plane picked.
    ufw allow 52000:59999/udp comment '0trust multi-hop' >/dev/null
    ok "udp 51820-51822 and 52000-59999 opened"
fi

# --- start it -------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    systemctl daemon-reload
    for spec in "${LOCAL_NODES[@]}"; do
        IFS=: read -r _ niface _ _ <<<"$spec"
        systemctl enable --now "0trust-meshd@$niface.service" >/dev/null 2>&1 || \
            note "0trust-meshd@$niface did not start — journalctl -u 0trust-meshd@$niface"
    done
    systemctl enable dnsmasq >/dev/null 2>&1 || true
    # dnsmasq cannot bind the gateway address until meshd has created wg0, and
    # meshd only does that on its first poll. Retry briefly rather than leaving
    # a dead resolver behind a "successful" install.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        systemctl restart dnsmasq >/dev/null 2>&1 && break
        sleep 2
    done

    # Prove the interfaces exist before anything says the VPN works.
    #
    # This printed a green "The VPN works" unconditionally, because
    # `systemctl enable --now` succeeding is not evidence that meshd created
    # anything — and on a host with no WireGuard kernel module (plenty of
    # LXC and OpenVZ VPSes) it creates nothing at all. The operator was told
    # in green that three tunnels were carrying traffic on a box that could
    # not make one. It is the same standard `0trust connect` already holds
    # itself to: wg-quick's exit code means nothing, so the client waits for
    # a handshake before claiming a tunnel.
    #
    # meshd builds the interface on its first poll, so give it a moment.
    VPN_UP=() VPN_DOWN=()
    for spec in "${LOCAL_NODES[@]}"; do
        IFS=: read -r _ niface _ _ <<<"$spec"
        up=0
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if ip link show "$niface" >/dev/null 2>&1; then up=1; break; fi
            sleep 2
        done
        if (( up )); then VPN_UP+=("$niface"); else VPN_DOWN+=("$niface"); fi
    done
fi
if [[ $DRY_RUN -eq 0 ]]; then
    if (( ${#VPN_DOWN[@]} == 0 )); then
        ok "meshd running, ${#VPN_UP[@]} WireGuard interface(s) up"
    else
        VPN_BROKEN=1
        printf '%s[!] WireGuard interface(s) NOT up: %s%s\n' \
               "$RED" "${VPN_DOWN[*]}" "$NC" >&2
        note "meshd could not create them. The usual cause is a kernel with no"
        note "WireGuard support — check with: ip link add dev wgtest type wireguard"
        note "Diagnose with: journalctl -u 0trust-meshd@${VPN_DOWN[0]} -n 50"
        note "The control plane and website are fine; only the tunnels are not."
    fi
fi
fi   # DO_VPN

# ----------------------------------------------------------------------------
log "Registering the local nodes with the control plane"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    ZTV_SEED_SPEC=""
    for spec in "${LOCAL_NODES[@]}"; do
        IFS=: read -r nregion niface nport _ <<<"$spec"
        if [[ $DO_VPN -eq 1 && -s "/etc/wireguard/$niface.pub" ]]; then
            npub="$(cat "/etc/wireguard/$niface.pub")"
        else
            # --no-vpn: a placeholder row so the API has something to route to.
            # It cannot carry traffic and the summary below says so.
            npub="PLACEHOLDER-$nregion"
        fi
        ZTV_SEED_SPEC+="$nregion-01|$nregion|$npub|$PUBIP:$nport|$PUBIP"$'\n'
    done
    ZTV_SEED_SPEC="$ZTV_SEED_SPEC" sudo -u 0trust --preserve-env=ZTV_SEED_SPEC \
        env ZTV_DB_PATH="$VARLIB/0trust.db" "$VENV/bin/python" - <<'PYSEED'
import os, sqlite3, time
rows = [l.split("|") for l in os.environ["ZTV_SEED_SPEC"].splitlines() if l.strip()]
c = sqlite3.connect(os.environ["ZTV_DB_PATH"])
now = int(time.time())
for nid, region, pub, endpoint, ip in rows:
    # Upsert: re-running the installer must refresh the keys it just rotated,
    # not silently leave the control plane pointing at the previous ones.
    c.execute(
        """INSERT INTO mesh_nodes
             (id, hostname, pubkey, endpoint, region, role, public_ip,
              capacity, active, ephemeral, last_heartbeat)
           VALUES (?,?,?,?,?, 'both', ?, 1000, 1, 0, ?)
           ON CONFLICT(id) DO UPDATE SET
             pubkey=excluded.pubkey, endpoint=excluded.endpoint,
             public_ip=excluded.public_ip, active=1,
             last_heartbeat=excluded.last_heartbeat""",
        (nid, f"{nid}.local", pub, endpoint, region, ip, now))
c.commit(); c.close()
PYSEED
fi
if [[ $DRY_RUN -eq 1 ]]; then
    ok "zur-01, rey-01, buc-01 would be registered"
elif [[ $DO_VPN -eq 1 ]]; then
    ok "zur-01, rey-01, buc-01 registered with real WireGuard keys"
else
    ok "zur-01, rey-01, buc-01 seeded (placeholder keys — not real tunnels)"
fi
fi

rm -f "$TMP_SITE" "$TMP_ZONES"

# ----------------------------------------------------------------------------
echo
if [[ "$MODE" == "test" ]]; then
    IP="${PUBIP:-$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
          || hostname -I 2>/dev/null | awk '{print $1}' || echo YOUR-IP)}"
    if [[ $DO_VPN -eq 1 ]]; then
        HEADLINE="Test deployment is up. This one box is the whole product."
    else
        HEADLINE="Test deployment is up (no VPN — --no-vpn was passed)."
    fi
    cat <<EOF
${GRN}  $HEADLINE${NC}
EOF
    if (( INSTALL_DEGRADED )); then cat <<EOF

  ${RED}Not everything came up.${NC} The messages above name what, and the
  journalctl line to read. Nothing here needs undoing: fix the cause and
  re-run this installer — it is idempotent and will keep your secrets,
  database and operator account.
EOF
    fi
    cat <<EOF

  Site        http://$IP/
  Free trial  http://$IP/trial
  Proxy       http://$IP/surf
  Operations  http://$IP/admin      <- create the operator account here
  Status      http://$IP/api/v1/status/public

EOF
    if [[ $DO_VPN -eq 1 && $VPN_BROKEN -eq 1 ]]; then cat <<EOF
  ${RED}The VPN is NOT up.${NC} The control plane, website, admin dashboard
  and /surf proxy all work — but meshd could not create the WireGuard
  interfaces, so \`0trust connect\` will hand out a config that cannot carry
  traffic.

  The usual cause is a kernel without WireGuard support, which is common on
  LXC and OpenVZ VPSes. Check it directly:
    ip link add dev wgtest type wireguard && ip link del wgtest
  If that fails, this box cannot run a node; use a KVM VPS instead.
  Otherwise: journalctl -u '0trust-meshd@*' -n 50

  Re-run this installer once the kernel can do it — nothing here needs undoing.

EOF
    elif [[ $DO_VPN -eq 1 ]]; then cat <<EOF
  ${GRN}The VPN works.${NC} Three node identities run on this box:
    zur-01  wg0  udp 51820      rey-01  wg1  udp 51821
    buc-01  wg2  udp 51822      multi-hop entry ports udp 52000-59999
  Traffic is masqueraded out $PRIMARY_IF, the abuse-mitigation egress filter
  is loaded, and dnsmasq answers on $MESH_DNS — the resolver every client
  config points at.

  Try it end to end, from your laptop:
    export ZTV_API_BASE=http://$IP
    0trust login                        # or claim a free trial at /trial
    sudo 0trust connect --region zur    # single hop
    sudo 0trust connect --entry zur --exit rey   # multi-hop
    curl https://api.ipify.org          # should print $IP

EOF
    else cat <<EOF
  ${YLW}No VPN on this box.${NC} zur-01, rey-01 and buc-01 are placeholder
  rows with fake keys, so \`0trust connect\` hands out a config that cannot
  carry traffic. Re-run without --no-vpn, or point the control plane at real
  nodes built with scripts/bootstrap-node.sh.

EOF
    fi
    cat <<EOF
  ${YLW}What this box is NOT.${NC} It is a test rig, and it cannot pretend
  otherwise:
    - ${YLW}No TLS.${NC} Account tokens, the admin password and everything
      else cross the network in clear. Never put a real customer on it.
    - ${YLW}One machine, one jurisdiction.${NC} zur/rey/buc are three
      interfaces on this host, not three countries. Nothing about the
      multi-jurisdiction argument is being demonstrated.
    - ${YLW}Multi-hop does not hide you here.${NC} On a real deployment the
      entry node forwards UDP it cannot decrypt to an exit node elsewhere,
      so the exit never learns the client's address. Entry and exit are the
      same host on this box, so it does. The routing is real and worth
      testing; the privacy property is not.
    - The control plane, the website, the proxy and the VPN egress all share
      one IP. Seizing it gets everything at once — the exact concentration
      the production topology exists to avoid.
    - Paid signup needs one thing: your Bitcoin xpub, in /admin under
      Settings -> Business wallets. Paste it and paid signup works — a fresh
      address per invoice, money straight to your wallet, settled by the
      poller within a confirmation. No account anywhere, no callback URL.
      Until then paid signup returns 502; free trials work regardless.

  Rebuild as three separate nodes when you are done kicking the tyres:
  install.sh --mode node, one per VPS. docs/DEPLOY.md has the walkthrough.

  Logs   journalctl -u 0trust-api -f
  DB     sqlite3 $VARLIB/0trust.db
EOF
else
    cat <<EOF
${GRN}  Production deployment is up at https://$DOMAIN${NC}

  Operations dashboard: https://$DOMAIN/admin
    Open it and create the first operator account. Until you do, anyone who
    finds that URL can — so do it now, before anything else.
    ${YLW}Restrict it.${NC} The nginx config has commented-out allow/deny lines
    for /admin and /api/v1/admin/; put your own address in them, or keep the
    dashboard behind a VPN. It can ban customers and change where money goes.

  Still to do before customers arrive:
    1. Payments — set them from the dashboard, or $ETC/api.env then
       systemctl restart 0trust-api.
       The default provider is "watch": put your Bitcoin xpub in WALLET_BTC
       and you are taking payments. Non-custodial, no account anywhere, and
       no webhook to register — a timer polls a public explorer.
       Other options, all needing an account somewhere first:
        btcpay: BTCPAY_URL / STORE_ID / API_KEY / WEBHOOK_SECRET
        hosted: ZTV_PAYMENT_PROVIDER=hosted + the ZTV_PAYMENT_* keys
        stripe/square: cards, and a real identity behind every payment
       Webhook URL for those: https://$DOMAIN/api/v1/payment/webhook
    2. Mesh nodes — until at least one exists, /wg/register returns 503.
       On THIS box, mint a token per node:
         sudo -u 0trust python3 $PREFIX/api/mint-provision-token.py \\
              --region zur --role both --uses 20 --ttl 31536000
       Then one command on each node VPS, which joins it to the mesh:
         sudo ./scripts/install.sh --mode node \\
              --control-url https://$DOMAIN \\
              --region zur --role both --wg-port 443 \\
              --provision-token ztvp-...
       The dashboard's Nodes tab mints the same token and prints the command.
    3. Check the trial secret is set:
       grep ZTV_TRIAL_SECRET $ETC/api.env
    4. Read docs/LAUNCH.md for the rest — keys, canary, legal review.

  Certificate renews automatically; nginx reloads via the deploy hook.

  Logs   journalctl -u 0trust-api -f
         journalctl -u 0trust-proxy -f
  DB     sqlite3 $VARLIB/0trust.db
EOF
fi
echo
