#!/usr/bin/env bash
# ============================================================================
# 0trust — trust Cloudflare's edge for the client address, and nothing else
# ============================================================================
# Behind Cloudflare every TCP connection to the origin comes FROM Cloudflare,
# so $remote_addr is an edge address and not the visitor. Four things in this
# deployment read it, and all four are wrong without this:
#
#   limit_req_zone $binary_remote_addr   every visitor behind one edge shares
#                                        a rate-limit bucket. The signup and
#                                        trial limits stop limiting anybody in
#                                        particular and start throttling
#                                        strangers at random.
#   X-Real-IP -> admin._login_attempts   the dashboard's lockout keys on the
#                                        edge, so eight failed guesses from
#                                        anywhere lock out the operator —
#                                        the admin-lockout DoS that keying on
#                                        127.0.0.1 caused before, restored.
#   the admin audit log                  records a Cloudflare address for
#                                        every failed login, on the one
#                                        record read after an intrusion.
#   $remote_addr_anon                    truncates an edge address to a /24,
#                                        which is privacy-preserving in the
#                                        sense that a blank page is.
#
# nginx's realip module fixes all four at once: it rewrites $remote_addr in
# the post-read phase, before rate limiting, logging or proxying look at it.
#
# WHAT MAKES THIS SAFE. CF-Connecting-IP is a header, and a header is whatever
# the client says. It is believed only from the addresses in set_real_ip_from
# below — Cloudflare's own published ranges — so a connection straight to the
# origin cannot forge one. Get that list wrong in the permissive direction and
# anyone can pick their own address: no rate limit applies, and the audit log
# records whoever they felt like being. Hence the refusals below.
#
# WHY IT FETCHES RATHER THAN SHIPPING A LIST. Cloudflare adds ranges. A list
# committed here ages into one that silently fails to restore the addresses in
# the new range — the same shape as a resolver quietly falling back to
# cleartext, and refused for the same reason. If the list cannot be fetched
# this writes nothing and exits non-zero; a stale config keeps working, and a
# box with no config keeps the pre-Cloudflare behaviour, loudly.
#
#   sudo ./scripts/cloudflare-ips.sh            fetch, install, reload nginx
#   sudo ./scripts/cloudflare-ips.sh --check    is what is installed current?
#        ./scripts/cloudflare-ips.sh --print    render to stdout, touch nothing
# ============================================================================
set -euo pipefail

CONF="${ZTV_REALIP_CONF:-/etc/nginx/conf.d/0trust-realip.conf}"
V4_URL="${ZTV_CF_V4_URL:-https://www.cloudflare.com/ips-v4}"
V6_URL="${ZTV_CF_V6_URL:-https://www.cloudflare.com/ips-v6}"

# Cloudflare publishes ~15 v4 and ~7 v6 prefixes. A list far below that is a
# captive portal, an error page, or a truncated transfer — not the answer.
MIN_V4="${ZTV_CF_MIN_V4:-8}"
MIN_V6="${ZTV_CF_MIN_V6:-3}"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; NC=$'\033[0m'
die()  { printf '%s[!] %s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }
ok()   { printf '%s[+] %s%s\n' "$GRN" "$*" "$NC"; }
note() { printf '    %s\n' "$*"; }

MODE="install"
case "${1:-}" in
    --check) MODE="check" ;;
    --print) MODE="print" ;;
    "")      ;;
    *)       die "unknown argument: $1 (use --check or --print)" ;;
esac

# ---------------------------------------------------------------------------
# Fetch and validate
# ---------------------------------------------------------------------------
fetch() {
    curl -fsS --max-time 20 --retry 2 --retry-delay 2 "$1" 2>/dev/null || true
}

# A CIDR, and specifically not one that would trust the whole internet.
# set_real_ip_from 0.0.0.0/0 turns CF-Connecting-IP into "pick your own
# address": rate limits stop applying and the audit log records a fiction.
valid_cidrs() {
    local line out=""
    while IFS= read -r line; do
        line="${line%%#*}"; line="${line//[$'\r'$'\t ']/}"
        [[ -n "$line" ]] || continue
        case "$line" in
            0.0.0.0/0|::/0|0.0.0.0/*[!0-9]*|*' '*) return 1 ;;
        esac
        [[ "$line" == "0.0.0.0/0" || "$line" == "::/0" ]] && return 1
        # v4 a.b.c.d/len or v6 hex-and-colons/len. Nothing else goes in.
        if [[ "$line" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
            [[ "${line##*/}" -ge 8 ]] || return 1
        elif [[ "$line" =~ ^[0-9A-Fa-f:]+/[0-9]{1,3}$ ]]; then
            [[ "${line##*/}" -ge 16 ]] || return 1
        else
            return 1
        fi
        out+="$line"$'\n'
    done
    printf '%s' "$out"
}

V4_RAW="$(fetch "$V4_URL")"
V6_RAW="$(fetch "$V6_URL")"

if [[ -z "$V4_RAW" || -z "$V6_RAW" ]]; then
    printf '%s[!] could not fetch Cloudflare'"'"'s published ranges%s\n' "$RED" "$NC" >&2
    note "v4: $V4_URL"
    note "v6: $V6_URL"
    note ""
    note "Nothing has been written. That is deliberate: a guessed or stale"
    note "trust list is worse than none. An existing config keeps working."
    note "Check outbound HTTPS from this box and run it again."
    exit 1
fi

V4="$(printf '%s\n' "$V4_RAW" | valid_cidrs)" \
    || die "the v4 list contains something that is not a safe CIDR — refusing"
V6="$(printf '%s\n' "$V6_RAW" | valid_cidrs)" \
    || die "the v6 list contains something that is not a safe CIDR — refusing"

n4=$(printf '%s' "$V4" | grep -c . || true)
n6=$(printf '%s' "$V6" | grep -c . || true)
(( n4 >= MIN_V4 )) || die "only $n4 v4 prefixes (expected >= $MIN_V4) — that is not the real list"
(( n6 >= MIN_V6 )) || die "only $n6 v6 prefixes (expected >= $MIN_V6) — that is not the real list"

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
render() {
    cat <<HEADER
# /etc/nginx/conf.d/0trust-realip.conf — GENERATED, do not edit by hand.
# Regenerate: sudo /opt/0trust/scripts/cloudflare-ips.sh
# Source: $V4_URL and $V6_URL
# Written: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
# Every address below is Cloudflare's. Only from these does nginx believe
# CF-Connecting-IP and replace \$remote_addr with it. From anywhere else the
# header is ignored, so a connection straight to the origin cannot claim to
# be someone it is not.
HEADER
    printf '%s\n' "$V4" "$V6" | grep . | sed 's/^/set_real_ip_from /; s/$/;/'
    cat <<'FOOTER'

real_ip_header CF-Connecting-IP;

# off, deliberately. CF-Connecting-IP holds ONE address — the visitor — not a
# chain, so there is nothing to walk. Recursion belongs to X-Forwarded-For,
# and turning it on here would have nginx step back through a header the
# client also controls.
real_ip_recursive off;
FOOTER
}

if [[ "$MODE" == "print" ]]; then
    render
    exit 0
fi

if [[ "$MODE" == "check" ]]; then
    if [[ ! -f "$CONF" ]]; then
        printf '%s[!] %s does not exist — this origin is not restoring client addresses%s\n' \
               "$YLW" "$CONF" "$NC"
        exit 1
    fi
    live="$( { printf '%s' "$V4"; printf '%s' "$V6"; } | sort)"
    have="$(grep -oP '(?<=^set_real_ip_from )[^;]+' "$CONF" | sort)"
    if [[ "$live" == "$have" ]]; then
        ok "$CONF matches Cloudflare's published ranges ($n4 v4, $n6 v6)"
        exit 0
    fi
    printf '%s[!] %s is out of date%s\n' "$YLW" "$CONF" "$NC"
    note "only in the live list:  $(comm -23 <(echo "$live") <(echo "$have") | tr '\n' ' ')"
    note "only in the installed:  $(comm -13 <(echo "$live") <(echo "$have") | tr '\n' ' ')"
    note "fix: sudo $0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root (it writes $CONF and reloads nginx)"

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
render > "$TMP"

# Test before replacing: a bad conf.d file takes the whole web tier down on
# the next reload, and this one runs unattended from a timer.
BACKUP=""
if [[ -f "$CONF" ]]; then BACKUP="$(mktemp)"; cp "$CONF" "$BACKUP"; fi
install -m 0644 "$TMP" "$CONF"
if command -v nginx >/dev/null 2>&1; then
    if ! nginx -t >/dev/null 2>&1; then
        if [[ -n "$BACKUP" ]]; then cp "$BACKUP" "$CONF"; else rm -f "$CONF"; fi
        rm -f "${BACKUP:-/dev/null}"
        die "nginx rejected the generated config — reverted, nothing changed"
    fi
    systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
fi
rm -f "${BACKUP:-/dev/null}"
ok "$CONF installed — $n4 v4 and $n6 v6 Cloudflare prefixes trusted"
note "nginx now takes the client address from CF-Connecting-IP, and only"
note "from Cloudflare. Rate limits, the admin lockout and the anonymised"
note "access log all see the real visitor again."
