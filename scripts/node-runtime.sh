#!/usr/bin/env bash
# ============================================================================
# 0trust node runtime — the config a mesh node needs, in one place
# ============================================================================
# Sourced by scripts/bootstrap-node.sh (a real, dedicated node) and by
# scripts/install.sh --mode test (the single-VPS deployment that plays every
# role at once). Both must end up with the SAME rules: a test box whose egress
# filter or NAT differs from production is a test box that proves nothing.
#
# Every function here only PRINTS its config. Applying it is the caller's job.
# That split is what lets tests render each ruleset and run `nft -c` over it
# without a VPS to break — the nftables mistake that shipped once (a table name
# beginning with a digit, which nft rejects, so multi-hop never worked on any
# node) was invisible precisely because nothing ever parsed these bytes in CI.
# ============================================================================

# Mesh addressing. Must match MESH_NETWORK in api/main.py.
ZTV_CLIENT_NET="${ZTV_CLIENT_NET:-10.64.0.0/10}"

# Resolvers dnsmasq forwards to. Quad9 by default: a documented no-logging
# policy, which is the least we can do given customers cannot see this choice.
ZTV_DNS_UPSTREAM="${ZTV_DNS_UPSTREAM:-9.9.9.9 149.112.112.112}"


# --- Kernel ----------------------------------------------------------------
ztv_sysctl_conf() {
    cat <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
# Drop source-routed packets, ignore ICMP redirects
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
# Reverse path filter
net.ipv4.conf.all.rp_filter=1
# Anti-spoofing
net.ipv4.conf.all.log_martians=1
EOF
}


# --- NAT: customer traffic leaves as the node's own address ----------------
# $1 = primary (internet-facing) interface
ztv_nat_ruleset() {
    local iface="$1"
    cat <<EOF
table inet ztv_nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "$iface" ip saddr $ZTV_CLIENT_NET masquerade
  }
}
EOF
}


# --- Abuse mitigation ------------------------------------------------------
# Ships on every node by default. Abuse complaints are the number one way to
# lose a VPS, and every rule here pre-empts one. See docs/ABUSE.md.
ztv_egress_ruleset() {
    cat <<EOF
table inet ztv_egress {
  chain forward {
    type filter hook forward priority 0; policy accept;

    # Only police traffic originating from VPN clients
    ip saddr != $ZTV_CLIENT_NET accept

    # Block outbound mail submission (anti-spam). A node that sends spam gets
    # its address blocklisted, which breaks the product for everyone on it.
    tcp dport { 25, 465, 587 } drop

    # Block pivoting into private / link-local / CGNAT ranges: the provider's
    # internal network, other tenants, cloud metadata services.
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop
    ip6 daddr { fc00::/7, fe80::/10 } drop

    # Throttle connection storms (scan mitigation) without touching browsing.
    ct state new limit rate over 80/second drop
  }
}
EOF
}


# --- DNS -------------------------------------------------------------------
# The control plane hands every client "DNS = 10.64.0.1", the mesh gateway.
# Nothing used to listen there, so a connected customer resolved nothing and
# the tunnel looked broken the moment they opened a browser. This is that
# resolver.
#
# $1 = address to listen on (the node's mesh gateway address)
ztv_dnsmasq_conf() {
    local listen="$1"
    {
    cat <<EOF
# 0trust mesh resolver. Managed by scripts/node-runtime.sh.

# Answer ONLY on the mesh gateway. Without bind-interfaces dnsmasq would also
# answer on the public address, turning the node into an open resolver — free
# DNS amplification for whoever finds it, and an abuse report within the day.
listen-address=$listen
bind-interfaces

# Never consult /etc/resolv.conf (systemd-resolved's stub) or /etc/hosts:
# the upstreams below are the whole story.
no-resolv
no-hosts
domain-needed
bogus-priv

EOF
    for up in $ZTV_DNS_UPSTREAM; do echo "server=$up"; done
    cat <<'EOF'

cache-size=1000

# Deliberately NOT set: log-queries. Enabling it would write every hostname a
# customer looks up into the journal — exactly the record the privacy policy
# says we do not keep. If you turn it on to debug, turn it off again, and
# know that docs/AUDIT.md's claims are false for as long as it is on.
EOF
    }
}


# --- meshd environment -----------------------------------------------------
# $1 control url  $2 node psk  $3 node id  $4 role  $5 iface  $6 port
# $7 mesh gateway (CIDR)  $8 nft table name
ztv_meshd_env() {
    cat <<EOF
CONTROL_URL=$1
NODE_API_PSK=$2
NODE_ID=$3
NODE_ROLE=$4
WG_IFACE=$5
WG_PRIVKEY=/etc/wireguard/$5.key
WG_PORT=$6
MESH_GATEWAY=$7
MESH_NETWORK=$ZTV_CLIENT_NET
ZTV_NFT_TABLE=$8
POLL_INTERVAL=30
EOF
}
