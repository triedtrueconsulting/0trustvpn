#!/usr/bin/env bash
# ============================================================================
# 0trust — one-shot installer for a fresh Ubuntu 24.04 VPS
# ============================================================================
# Two modes:
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
#   --dry-run                render everything, touch no system state
# ============================================================================
set -euo pipefail

MODE="" DOMAIN="" EMAIL=""
DO_FIREWALL=1 DO_SSH=1 DRY_RUN=0 DO_VPN=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="${2:-}"; shift 2 ;;
        --domain) DOMAIN="${2:-}"; shift 2 ;;
        --email) EMAIL="${2:-}"; shift 2 ;;
        --no-firewall) DO_FIREWALL=0; shift ;;
        --no-ssh-hardening) DO_SSH=0; shift ;;
        --no-vpn) DO_VPN=0; shift ;;
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

[[ "$MODE" == "test" || "$MODE" == "production" ]] \
    || die "--mode must be test or production (see --help)"
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
    install -o 0trust -g 0trust -m 0644 \
        "$REPO_DIR/api/main.py" "$REPO_DIR/api/payments.py" \
        "$REPO_DIR/api/admin.py" "$REPO_DIR/api/settings_store.py" \
        "$REPO_DIR/api/ops_alerts.py" \
        "$REPO_DIR/api/btcpay.py" "$REPO_DIR/api/sweep.py" \
        "$REPO_DIR/api/requirements.txt" \
        "$PREFIX/api/"
    install -o 0trust -g 0trust -m 0644 \
        "$REPO_DIR/proxy/server.py" "$REPO_DIR/proxy/guards.py" \
        "$REPO_DIR/proxy/rewrite.py" \
        "$PREFIX/proxy/"

    # 0trust-backup.service runs $PREFIX/scripts/backup.sh. Installing the
    # unit without the script it invokes leaves a timer that fails nightly.
    mkdir -p "$PREFIX/scripts"
    install -o 0trust -g 0trust -m 0755 \
        "$REPO_DIR/scripts/backup.sh" "$PREFIX/scripts/backup.sh"

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
# btcpay = BTCPay Server (yours or hosted). Non-custodial.
# hosted = commercial gateway. No blockchain infrastructure; custodial.
ZTV_PAYMENT_PROVIDER=btcpay
BTCPAY_URL=https://btcpay.example.com
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
    NODE_PSK="$(sed -n 's/^NODE_API_PSK=//p' "$ETC/api.env" | head -n1)"
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

if [[ "$MODE" == "test" ]]; then
    {
        echo "# 0trust — TEST deployment. Plain HTTP on the box's IP."
        echo "# No TLS: anything typed into this site crosses the network in"
        echo "# clear, account tokens included. Never point customers at it."
        echo
        cat <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
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
    listen [::]:80;
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
    listen [::]:443 ssl http2;
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
        note "rendered site config:"; sed 's/^/      /' "$TMP_SITE" | head -20
    fi
fi

# ----------------------------------------------------------------------------
log "Starting services"
# ----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    systemctl enable --now 0trust-api.service
    systemctl enable --now 0trust-proxy.service
    systemctl enable --now 0trust-sweep.timer
    systemctl reload nginx || systemctl restart nginx
fi
ok "0trust-api, 0trust-proxy, 0trust-sweep.timer, nginx"

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
    apt-get install -y -qq wireguard wireguard-tools nftables dnsmasq >/dev/null
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
PRIMARY_IF="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1)"
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
if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p /etc/dnsmasq.d
    ztv_dnsmasq_conf "$MESH_DNS" > /etc/dnsmasq.d/0trust.conf
fi
if [[ -n "${ZTV_RENDER_TO:-}" ]]; then
    ztv_dnsmasq_conf "$MESH_DNS" > "$ZTV_RENDER_TO/dnsmasq.conf"
fi
ok "dnsmasq will answer on $MESH_DNS (the DNS every client config names)"

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
fi
if [[ $DRY_RUN -eq 0 ]]; then ok "meshd running for all three nodes"; fi
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

  Site        http://$IP/
  Free trial  http://$IP/trial
  Proxy       http://$IP/surf
  Operations  http://$IP/admin      <- create the operator account here
  Status      http://$IP/api/v1/status/public

EOF
    if [[ $DO_VPN -eq 1 ]]; then cat <<EOF
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
    - Payments are unconfigured, so paid signup returns 502 until you fill
      them in at /admin. Free trials work now.

  Rebuild as three separate nodes when you are done kicking the tyres:
  scripts/bootstrap-node.sh, one per VPS. docs/DEPLOY.md has the walkthrough.

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
    1. Payments — fill in $ETC/api.env, then: systemctl restart 0trust-api
       (btcpay: BTCPAY_URL / STORE_ID / API_KEY / WEBHOOK_SECRET,
        hosted:  ZTV_PAYMENT_PROVIDER=hosted + the ZTV_PAYMENT_* keys)
       Webhook URL: https://$DOMAIN/api/v1/payment/webhook
    2. Mesh nodes — run scripts/bootstrap-node.sh on each, or mint a
       provisioning token with api/mint-provision-token.py for RAM-only nodes.
       Until at least one exists, /wg/register returns 503.
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
