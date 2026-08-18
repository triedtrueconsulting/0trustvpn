#!/usr/bin/env bash
# ============================================================================
# 0trust VPN — Control plane bootstrap (Ubuntu 24.04)
# ============================================================================
# Idempotent. Run as root on a fresh box. Sets up:
#   - hardened system (UFW, fail2ban, unattended-upgrades, sshd lockdown)
#   - nginx + certbot (TLS via Let's Encrypt)
#   - Python venv + 0trust API + systemd service
#   - 0trust user + /var/lib/0trust + /etc/0trust
#   - static site at /var/www/0trust
#
# Usage:
#   sudo DOMAIN=0trustvpn.com ADMIN_EMAIL=0trustvpn@proton.me ./bootstrap.sh
# ============================================================================
set -euo pipefail

# --- Config ---
DOMAIN="${DOMAIN:?Set DOMAIN=0trustvpn.com}"
ADMIN_EMAIL="${ADMIN_EMAIL:?Set ADMIN_EMAIL=you@example.com}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
    warn "Must run as root"
    exit 1
fi

# ----------------------------------------------------------------------------
log "Updating apt and installing base packages"
# ----------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    nginx \
    python3 \
    python3-venv \
    python3-pip \
    wireguard \
    wireguard-tools \
    ufw \
    fail2ban \
    unattended-upgrades \
    certbot \
    python3-certbot-nginx \
    sqlite3 \
    curl \
    jq \
    rng-tools5 \
    > /dev/null

# ----------------------------------------------------------------------------
log "Creating 0trust user and directories"
# ----------------------------------------------------------------------------
id -u 0trust &>/dev/null || useradd --system --home /opt/0trust --shell /usr/sbin/nologin 0trust
mkdir -p /opt/0trust/api /var/lib/0trust /etc/0trust /var/www/0trust /var/www/acme
chown -R 0trust:0trust /opt/0trust /var/lib/0trust
chmod 750 /etc/0trust

# ----------------------------------------------------------------------------
log "Installing API code"
# ----------------------------------------------------------------------------
cp "$REPO_DIR/api/main.py" /opt/0trust/api/main.py
cp "$REPO_DIR/api/btcpay.py" /opt/0trust/api/btcpay.py
cp "$REPO_DIR/api/sweep.py" /opt/0trust/api/sweep.py
cp "$REPO_DIR/api/requirements.txt" /opt/0trust/api/requirements.txt

if [[ ! -d /opt/0trust/api/.venv ]]; then
    sudo -u 0trust python3 -m venv /opt/0trust/api/.venv
fi
sudo -u 0trust /opt/0trust/api/.venv/bin/pip install --quiet --upgrade pip
sudo -u 0trust /opt/0trust/api/.venv/bin/pip install --quiet -r /opt/0trust/api/requirements.txt

# ----------------------------------------------------------------------------
log "Installing API env file (edit /etc/0trust/api.env before going live)"
# ----------------------------------------------------------------------------
if [[ ! -f /etc/0trust/api.env ]]; then
    cp "$REPO_DIR/systemd/api.env.example" /etc/0trust/api.env
    # Auto-generate the secrets that have safe defaults
    sed -i "s|replace-me-with-openssl-rand-hex-32|$(openssl rand -hex 32)|" /etc/0trust/api.env
    chown root:0trust /etc/0trust/api.env
    chmod 640 /etc/0trust/api.env
    warn "BTCPay credentials in /etc/0trust/api.env still need to be filled in"
fi

# ----------------------------------------------------------------------------
log "Installing systemd unit"
# ----------------------------------------------------------------------------
cp "$REPO_DIR/systemd/0trust-api.service" /etc/systemd/system/0trust-api.service
cp "$REPO_DIR/systemd/0trust-sweep.service" /etc/systemd/system/0trust-sweep.service
cp "$REPO_DIR/systemd/0trust-sweep.timer" /etc/systemd/system/0trust-sweep.timer
systemctl daemon-reload
systemctl enable --now 0trust-api.service
systemctl enable --now 0trust-sweep.timer

# ----------------------------------------------------------------------------
log "Deploying static site"
# ----------------------------------------------------------------------------
cp -r "$REPO_DIR/web/." /var/www/0trust/
chown -R www-data:www-data /var/www/0trust

# ----------------------------------------------------------------------------
log "Installing nginx configuration"
# ----------------------------------------------------------------------------
mkdir -p /etc/nginx/snippets
cp "$REPO_DIR/nginx/0trust-proxy.conf" /etc/nginx/snippets/0trust-proxy.conf

# Substitute domain in nginx config
sed "s/0trustvpn\.com/$DOMAIN/g" "$REPO_DIR/nginx/0trustvpn.com.conf" \
    > /etc/nginx/sites-available/0trustvpn.com

ln -sf /etc/nginx/sites-available/0trustvpn.com /etc/nginx/sites-enabled/0trustvpn.com
rm -f /etc/nginx/sites-enabled/default

# Test config before enabling TLS (cert doesn't exist yet, so do a minimal HTTP-only config first)
if [[ ! -d /etc/letsencrypt/live/$DOMAIN ]]; then
    log "Obtaining Let's Encrypt certificate"
    # Bring nginx up on port 80 only first
    cat > /etc/nginx/sites-available/0trustvpn.com <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/0trust;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { try_files \$uri \$uri/ /index.html; }
}
EOF
    nginx -t && systemctl reload nginx
    certbot certonly --webroot -w /var/www/acme \
        -d "$DOMAIN" -d "www.$DOMAIN" \
        --email "$ADMIN_EMAIL" --agree-tos --no-eff-email --non-interactive

    # Restore full TLS config
    sed "s/0trustvpn\.com/$DOMAIN/g" "$REPO_DIR/nginx/0trustvpn.com.conf" \
        > /etc/nginx/sites-available/0trustvpn.com
fi

nginx -t
systemctl reload nginx

# ----------------------------------------------------------------------------
log "Configuring UFW firewall"
# ----------------------------------------------------------------------------
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'ssh'
ufw allow 80/tcp comment 'http'
ufw allow 443/tcp comment 'https'
ufw --force enable

# ----------------------------------------------------------------------------
log "Hardening sshd (disabling password auth)"
# ----------------------------------------------------------------------------
if grep -q "^#\?PasswordAuthentication" /etc/ssh/sshd_config; then
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
fi
if grep -q "^#\?PermitRootLogin" /etc/ssh/sshd_config; then
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
fi
systemctl reload ssh || systemctl reload sshd

# ----------------------------------------------------------------------------
log "Enabling unattended-upgrades"
# ----------------------------------------------------------------------------
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# ----------------------------------------------------------------------------
log "Auto-renewal hook for certbot"
# ----------------------------------------------------------------------------
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/bin/bash
systemctl reload nginx
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

# ----------------------------------------------------------------------------
log "Done."
# ----------------------------------------------------------------------------
cat <<EOF

  Control plane is up.

  Next steps:
    1. Edit /etc/0trust/api.env and fill in BTCPay credentials
       systemctl restart 0trust-api
    2. Configure BTCPay Server (separate host recommended) and point its
       webhook at https://$DOMAIN/api/v1/payment/webhook
    3. Stand up at least one WireGuard mesh node and register it in the
       mesh_nodes table:
         sqlite3 /var/lib/0trust/0trust.db <<SQL
           INSERT INTO mesh_nodes (id, hostname, pubkey, endpoint, region)
           VALUES ('zur-01','zur-01.0trustvpn.com','<wg-pubkey>','1.2.3.4:51820','zur');
SQL
    4. Visit https://$DOMAIN

  Service: systemctl status 0trust-api
  Logs:    journalctl -u 0trust-api -f
  DB:      sqlite3 /var/lib/0trust/0trust.db

EOF
