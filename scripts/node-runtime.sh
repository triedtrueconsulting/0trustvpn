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

# Mesh addressing. Must match MESH_NETWORK / MESH_NETWORK6 in api/main.py.
ZTV_CLIENT_NET="${ZTV_CLIENT_NET:-10.64.0.0/10}"
# A ULA prefix (RFC 4193). It never appears outside the mesh — the exit
# masquerades v6 exactly as it does v4 — so what a site sees is the node.
ZTV_CLIENT_NET6="${ZTV_CLIENT_NET6:-fd0e:5f7a:c21b::/48}"

# --- Upstream DNS ----------------------------------------------------------
# The resolver inside the tunnel answers from cache and forwards the rest.
# What it forwards over used to be plain UDP 53 to Quad9, which meant every
# hostname a customer looked up was readable on the node's uplink — by the
# hosting provider and by anyone between them and Quad9. The tunnel encrypted
# the customer's half of that path and then published the other half.
#
# So dnsmasq now forwards to a local DNS-over-TLS stub instead, and the
# queries leave the node encrypted and authenticated against the resolver's
# certificate. Quad9 still sees them — it has to, it is answering them — and
# privacy.html says so. What changes is that nobody else does.
ZTV_DNS_ENCRYPTED="${ZTV_DNS_ENCRYPTED:-1}"
# Where the DoT stub listens. dnsmasq is the only thing that talks to it.
ZTV_DNS_STUB="${ZTV_DNS_STUB:-127.0.0.1#5353}"
# The DoT upstreams, as "address@port#tls-authentication-name". The name is
# what the certificate is checked against, so it is not decoration: without
# it the connection is encrypted to whoever answered, which is not the same
# thing as encrypted to Quad9.
ZTV_DNS_TLS_UPSTREAM="${ZTV_DNS_TLS_UPSTREAM:-9.9.9.9@853#dns.quad9.net 149.112.112.112@853#dns.quad9.net}"
# Plain resolvers. Used only when ZTV_DNS_ENCRYPTED=0 — an operator who would
# rather have DNS that keeps working on a network that blocks 853 than DNS
# that stays private. Failing closed is the default because a VPN quietly
# downgrading to cleartext DNS is worse than one that stops resolving.
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
    # NAT66. Customers get a ULA inside the tunnel, not a routable prefix:
    # handing out real /64s needs provider-assigned space we do not have, and
    # a stable per-customer prefix would be a tracking identifier anyway. So
    # v6 leaves as the node's address, the same as v4.
    oifname "$iface" ip6 saddr $ZTV_CLIENT_NET6 masquerade
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

    # Only police traffic originating from VPN clients. Each family needs its
    # own test: inside an inet table an "ip saddr" expression cannot be
    # evaluated against a v6 packet, so the rule never matches and every rule
    # below it applied to forwarded v6 traffic whether a customer sent it or
    # not. (No backticks in this comment on purpose. The heredoc below is
    # unquoted, so a backtick pair here is command substitution, not quoting,
    # and the shell silently runs it and blanks the text.)
    ip  saddr != $ZTV_CLIENT_NET  accept
    ip6 saddr != $ZTV_CLIENT_NET6 accept

    # Block outbound mail submission (anti-spam). A node that sends spam gets
    # its address blocklisted, which breaks the product for everyone on it.
    tcp dport { 25, 465, 587 } drop

    # Block pivoting into private / link-local / CGNAT ranges: the provider's
    # internal network, other tenants, cloud metadata services.
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop
    # fc00::/7 covers our own mesh prefix, so this also stops one customer
    # reaching another over v6 — the same isolation the v4 rule gives.
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
# $1 = v4 gateway to listen on   $2 = v6 gateway (optional)
ztv_dnsmasq_conf() {
    local listen="$1" listen6="${2:-}"
    {
    cat <<EOF
# 0trust mesh resolver. Managed by scripts/node-runtime.sh.

# Answer ONLY on the mesh gateway. Without bind-interfaces dnsmasq would also
# answer on the public address, turning the node into an open resolver — free
# DNS amplification for whoever finds it, and an abuse report within the day.
listen-address=$listen${listen6:+,$listen6}
bind-interfaces

# Never consult /etc/resolv.conf (systemd-resolved's stub) or /etc/hosts:
# the upstreams below are the whole story.
no-resolv
no-hosts
domain-needed
bogus-priv

EOF
    if [[ "$ZTV_DNS_ENCRYPTED" == "1" ]]; then
        # One upstream, the local DoT stub. Listing plain resolvers alongside
        # it would let dnsmasq pick either, and the one it picked on any given
        # query would decide whether that hostname crossed the internet in
        # clear — a coin flip is not a privacy property.
        echo "server=${ZTV_DNS_STUB/\#/#}"
        echo "# Upstream is the local DNS-over-TLS stub (see ztv_stubby_conf)."
    else
        for up in $ZTV_DNS_UPSTREAM; do echo "server=$up"; done
        echo "# WARNING: ZTV_DNS_ENCRYPTED=0 — these queries leave in clear."
        echo "# web/privacy.html 4d describes the encrypted path this replaces."
    fi
    cat <<'EOF'

cache-size=1000

# Deliberately NOT set: log-queries. Enabling it would write every hostname a
# customer looks up into the journal — exactly the record the privacy policy
# says we do not keep. If you turn it on to debug, turn it off again, and
# know that docs/AUDIT.md's claims are false for as long as it is on.
EOF
    }
}


# --- DNS-over-TLS stub ------------------------------------------------------
# stubby, listening only on loopback, in front of dnsmasq. Authentication is
# by certificate name against the system CA store — no pinned key to go stale
# and no resolver list to fetch at boot, so a node that comes up on a network
# having a bad morning still resolves as soon as it can reach 853.
#
# strict mode on purpose: if the TLS connection cannot be made and verified,
# the query fails. It does not quietly retry in the clear. A customer whose
# DNS stops working notices; a customer whose DNS silently downgrades does
# not, and that is the failure this whole change exists to remove.
ztv_stubby_conf() {
    local addr="${ZTV_DNS_STUB%%#*}" port="${ZTV_DNS_STUB##*#}"
    cat <<EOF
# 0trust upstream DNS. Managed by scripts/node-runtime.sh.
resolution_type: GETDNS_RESOLUTION_STUB

# GETDNS_AUTHENTICATION_REQUIRED: no certificate, no answer.
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1

idle_timeout: 10000
round_robin_upstreams: 1

listen_addresses:
  - $addr@$port

upstream_recursive_servers:
EOF
    for up in $ZTV_DNS_TLS_UPSTREAM; do
        local host="${up%%@*}" rest="${up#*@}"
        local uport="${rest%%#*}" name="${rest##*#}"
        cat <<EOF
  - address_data: $host
    tls_port: $uport
    tls_auth_name: "$name"
EOF
    done
}


# The IPv6 mesh address for a given v4 one: the v4 address embedded in the low
# 32 bits of the ULA prefix. Same rule as mesh_ip6() in api/main.py and
# _derive_gateway6() in meshd — three implementations of one line, kept in
# step by a test rather than by hope, because a mismatch would hand clients
# an address the node does not answer on.
ztv_mesh_ip6() {
    python3 -c 'import ipaddress,sys; base=ipaddress.ip_network(sys.argv[2]).network_address; print(ipaddress.IPv6Address(int(base)+int(ipaddress.IPv4Address(sys.argv[1]))))' "$1" "$ZTV_CLIENT_NET6"
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
MESH_NETWORK6=$ZTV_CLIENT_NET6
ZTV_NFT_TABLE=$8
POLL_INTERVAL=30
EOF
}
