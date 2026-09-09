#!/usr/bin/env bash
# ============================================================================
# 0trust audit verification
# ============================================================================
# Runs the verification matrix from docs/AUDIT.md against a live production
# host. Each check has a short ID; exit code is 0 if everything passes, or
# the count of failed checks otherwise.
#
# Usage:
#   sudo ./scripts/audit-verify.sh           # run all checks
#   sudo ./scripts/audit-verify.sh -v        # show the underlying command
#   sudo ./scripts/audit-verify.sh nginx db  # only checks containing these substrings
#
# Designed to be runnable by a third-party auditor with sudo + read-only
# intent. It does NOT modify the system.
# ============================================================================
set -uo pipefail

VERBOSE=0
FILTER=()
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        -*) echo "unknown flag: $arg" >&2; exit 64 ;;
        *) FILTER+=("$arg") ;;
    esac
done

PASS=0; FAIL=0; SKIP=0
# Two checks read a config file. On a deployed host they read the installed
# copy; run from a clone (an auditor reading the source, or CI) they fall
# back to the tree this script lives in.
# Exported because every check body runs as its own `bash -c`.
export REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; DIM=$'\033[2m'; NC=$'\033[0m'

# ----------------------------------------------------------------------------
# Test harness
# ----------------------------------------------------------------------------

# Usage: check ID "human description" -- <command...>
# Expects the command to exit 0 on PASS, 1 on FAIL.
check() {
    local id="$1" desc="$2"; shift 2
    [[ "$1" == "--" ]] && shift

    # Apply filter — skip checks that don't match any keyword
    if (( ${#FILTER[@]} > 0 )); then
        local match=0
        for f in "${FILTER[@]}"; do
            [[ "$id" == *"$f"* || "$desc" == *"$f"* ]] && match=1
        done
        (( match )) || return 0
    fi

    printf "  %-32s %s ... " "$id" "$desc"
    (( VERBOSE )) && printf "\n    ${DIM}\$ %s${NC}\n  %-32s %s ... " "$*" "" ""

    local out rc
    out=$("$@" 2>&1); rc=$?

    if (( rc == 0 )); then
        echo "${GRN}PASS${NC}"
        ((PASS++))
    elif (( rc == 77 )); then
        echo "${YLW}SKIP${NC} ${DIM}$out${NC}"
        ((SKIP++))
    else
        echo "${RED}FAIL${NC}"
        head -10 <<<"    ${DIM}${out}${NC}"
        ((FAIL++))
    fi
}

section() {
    echo
    echo "${YLW}━━━ $* ━━━${NC}"
}

# ============================================================================
# THE CHECKS
# ============================================================================

cat <<HDR
================================================================
  0trust no-logs audit verification
  Host:    $(hostname)
  Time:    $(date -u +%FT%TZ)
  Refers:  docs/AUDIT.md (read this alongside the output)
================================================================
HDR

# ----------------------------------------------------------------------------
section "§2.5 JURISDICTION RESTRICTIONS"

# These checks confirm the live mesh matches the operator's public
# commitment in AUDIT.md §2.5 and on https://0trustvpn.com/

DB_PATH="${ZTV_DB_PATH:-/var/lib/0trust/0trust.db}"

check juris-allowlist "Only zur, rey, buc regions present in mesh_nodes" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    bad=\$(sqlite3 '$DB_PATH' \"
        SELECT DISTINCT region FROM mesh_nodes WHERE active=1
        AND region NOT IN ('zur', 'rey', 'buc');
    \")
    [[ -z \"\$bad\" ]] || { echo \"unauthorized region(s) found: \$bad\"; exit 1; }
"

check juris-no-eyes-codes "No Eyes-country region codes anywhere in DB" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    # Region codes for known Eyes-jurisdiction cities. If any of these
    # appear, the operator is violating the jurisdictional commitment.
    eyes_codes=\"ams fra lon sto nyc sjc sgp tyo cph par dub bru mil mad waw vie\"
    for code in \$eyes_codes; do
        found=\$(sqlite3 '$DB_PATH' \"SELECT 1 FROM mesh_nodes WHERE region='\$code' LIMIT 1;\")
        if [[ -n \"\$found\" ]]; then
            echo \"Eyes-region code in mesh_nodes: \$code\"
            exit 1
        fi
    done
"

check juris-public-ip-geolocate "Node public IPs geolocate to declared countries" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    command -v curl >/dev/null || { echo 'curl required'; exit 77; }
    # ipapi.co rate-limits aggressively; this check uses ip-api.com which is
    # more forgiving but requires HTTP (we're checking infrastructure, not
    # exfiltrating data, so plaintext is fine).
    failed=0
    while IFS='|' read -r id region public_ip; do
        [[ -z \"\$public_ip\" || \"\$public_ip\" == \"NULL\" ]] && continue
        expected=''
        case \"\$region\" in
            zur) expected='CH' ;;
            rey) expected='IS' ;;
            buc) expected='RO' ;;
            *)   echo \"unknown region \$region\"; failed=1 ;;
        esac
        actual=\$(curl -fsS \"http://ip-api.com/json/\$public_ip?fields=countryCode\" 2>/dev/null \
                  | grep -oE '\"countryCode\":\"[A-Z]+\"' | sed 's/[^A-Z]*\"\([A-Z]*\)\"/\1/')
        if [[ \"\$actual\" != \"\$expected\" ]]; then
            echo \"node \$id (\$region): IP \$public_ip geolocates to \$actual, expected \$expected\"
            failed=1
        fi
    done < <(sqlite3 -separator '|' '$DB_PATH' \\
        'SELECT id, region, public_ip FROM mesh_nodes WHERE active=1')
    exit \$failed
"

section "§3. CONTROL-PLANE DATABASE"
# ----------------------------------------------------------------------------

check db-exists "Database file exists" -- bash -c "
    [[ -f '$DB_PATH' ]] || { echo 'db missing — non-prod host?'; exit 77; }
"

check db-no-plaintext-token "No plaintext token columns anywhere" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    leaked=\$(sqlite3 '$DB_PATH' \"
        SELECT sql FROM sqlite_master
        WHERE sql LIKE '%token%' AND sql NOT LIKE '%token_hash%';
    \")
    [[ -z \"\$leaked\" ]] || { echo \"plaintext token column: \$leaked\"; exit 1; }
"

check db-no-customer-ip "No IP-address column anywhere" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    leaked=\$(sqlite3 '$DB_PATH' \"
        SELECT sql FROM sqlite_master
        WHERE sql LIKE '%client_ip%' OR sql LIKE '%user_ip%' OR sql LIKE '%customer_ip%';
    \")
    [[ -z \"\$leaked\" ]] || { echo \"IP column found: \$leaked\"; exit 1; }
"

check db-no-private-key "No customer private-key column" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    leaked=\$(sqlite3 '$DB_PATH' \"
        SELECT sql FROM sqlite_master
        WHERE sql LIKE '%privkey%' OR sql LIKE '%private_key%';
    \")
    [[ -z \"\$leaked\" ]] || { echo \"private key column: \$leaked\"; exit 1; }
"

check db-hop-pairs-ttl "All hop_pairs have non-null expires_at" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    unbounded=\$(sqlite3 '$DB_PATH' 'SELECT COUNT(*) FROM hop_pairs WHERE expires_at IS NULL OR expires_at = 0;')
    [[ \"\$unbounded\" == '0' ]] || { echo \"\$unbounded hop_pairs have no TTL\"; exit 1; }
"

check db-failed-invoices-gc "No failed invoices older than 30d" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    cutoff=\$((  \$(date +%s) - 30*86400 ))
    stale=\$(sqlite3 '$DB_PATH' \"
        SELECT COUNT(*) FROM invoices
        WHERE status != 'Settled' AND created_at < \$cutoff;
    \")
    [[ \"\$stale\" == '0' ]] || { echo \"\$stale failed invoices >30d old\"; exit 1; }
"

# ----------------------------------------------------------------------------
section "§4. WEB-TIER (nginx) LOGS"
# ----------------------------------------------------------------------------

# scripts/install.sh symlinks the site it generates to sites-enabled/0trust —
# NOT to 0trustvpn.com.conf, which is the name of the reference file in the
# repository and a file the installer has never created. Every nginx check
# here pointed at that name, found nothing, and exited 77 — which prints SKIP,
# which is not FAIL. An auditor got a clean run against a deployment whose
# nginx was writing full client IPs, User-Agents and Referers to
# /var/log/nginx/access.log in the stock combined format. Look for what is
# actually installed, and take the http-context file too: the log format and
# both anonymizing maps live in conf.d/0trust-zones.conf, not in the site.
for _c in /etc/nginx/sites-enabled/0trust \
          /etc/nginx/sites-enabled/0trustvpn.com.conf \
          /etc/nginx/sites-available/0trust; do
    [[ -f "$_c" ]] && { NGINX_CONF="${NGINX_CONF:-$_c}"; break; }
done
export NGINX_CONF="${NGINX_CONF:-}"
export NGINX_ZONES="${NGINX_ZONES:-/etc/nginx/conf.d/0trust-zones.conf}"
NGINX_LOG="/var/log/nginx/0trust-access.log"

check nginx-conf-exists "nginx config present" -- bash -c '
    # A SKIP here is only honest on a box with no nginx at all. If nginx is
    # installed and our config is not the one it is serving, that is the
    # finding — not an absence of evidence.
    if [[ -z "$NGINX_CONF" ]]; then
        command -v nginx >/dev/null 2>&1 || exit 77
        echo "nginx is installed but no 0trust site config was found"
        exit 1
    fi
'

check nginx-no-user-agent "Access log format does not include User-Agent" -- bash -c '
    [[ -n "$NGINX_CONF" ]] || exit 77
    # combined carries $http_user_agent and $http_referer, and both are named
    # in AUDIT.md §4.1 as things the access log does not keep. The trap is
    # that nginx.conf ships `access_log /var/log/nginx/access.log;` with NO
    # format token — which silently means combined. A check that greps for
    # the word "combined" sees nothing and passes on a host logging every
    # user agent it serves. So: any ACTIVE access_log whose format is absent,
    # or is combined/main, is the finding.
    #
    # Our zones file cancels the http-level one with `access_log off;` at the
    # same level and later in the include order, so when that is present the
    # stock directive in nginx.conf is dead and only the server blocks count.
    stock_cancelled=0
    grep -qE "^[[:space:]]*access_log[[:space:]]+off[[:space:]]*;" "$NGINX_ZONES" 2>/dev/null \
        && stock_cancelled=1
    files="$NGINX_CONF"
    [[ -f "$NGINX_ZONES" ]] && files="$files $NGINX_ZONES"
    (( stock_cancelled )) || files="/etc/nginx/nginx.conf $files"
    bad=""
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        # access_log <path> [format] [buffer=… flush=… gzip if=…];
        read -r _kw _path _fmt _rest <<<"$(tr -s " \t" " " <<<"${line%;}")"
        [[ "$_path" == "off" ]] && continue
        case "$_fmt" in
            ""|buffer=*|flush=*|gzip*|if=*) bad="$bad
  $line   <- no format named, which means combined" ;;
            combined|main)                 bad="$bad
  $line   <- a stock format" ;;
        esac
    done < <(grep -hE "^[[:space:]]*access_log[[:space:]]" $files 2>/dev/null || true)
    if [[ -n "$bad" ]]; then
        echo "an active access_log uses a format carrying User-Agent/Referer:$bad"
        exit 1
    fi
    if grep -hE ".http_user_agent|.http_referer" "$NGINX_ZONES" "$NGINX_CONF" 2>/dev/null \
       | grep -qv "^[[:space:]]*#"; then
        echo "User-Agent or Referer appears in a 0trust log format"
        exit 1
    fi
'

check nginx-anonymizes-ip "Access log uses anonymized client IP" -- bash -c '
    [[ -n "$NGINX_CONF" ]] || exit 77
    if ! grep -qE "map[[:space:]]+.remote_addr[[:space:]]+.remote_addr_anon" \
           "$NGINX_ZONES" "$NGINX_CONF" /etc/nginx/nginx.conf 2>/dev/null; then
        echo "No IP-anonymization map found in the nginx config"
        exit 1
    fi
    # Defining the map is not using it. Every access_log that is actually on
    # has to name a format built from it.
    live=$(grep -hE "^[[:space:]]*access_log[[:space:]]" "$NGINX_CONF" 2>/dev/null \
           | grep -v "access_log[[:space:]]*off" || true)
    if [[ -z "$live" ]]; then
        echo "no access_log in $NGINX_CONF — requests fall through to the stock log"
        exit 1
    fi
    if grep -qv "anon" <<<"$live"; then
        echo "an active access_log does not use the anon format:"; echo "$live"
        exit 1
    fi
'


section "§5. MESH-NODE BEHAVIOR (node checks; skip on the control plane)"

check node-egress-filter "Abuse egress filter is loaded (mesh nodes)" -- bash -c "
    command -v nft >/dev/null || exit 77
    # Control-plane boxes have no mesh interface and no egress table.
    ip link show wg0 >/dev/null 2>&1 || exit 77
    nft list table inet ztv_egress >/dev/null 2>&1 || {
        echo 'ztv_egress is not loaded - clients can reach RFC1918 and send mail'
        exit 1
    }
    nft list table inet ztv_egress | grep -q 'dport' || {
        echo 'egress table is loaded but has no port rules'; exit 1; }
    nft list table inet ztv_egress | grep -q '192.168.0.0/16' || {
        echo 'private-range pivot is not blocked'; exit 1; }
"

check node-nat-table "Exit NAT table is loaded (mesh nodes)" -- bash -c "
    command -v nft >/dev/null || exit 77
    ip link show wg0 >/dev/null 2>&1 || exit 77
    nft list table inet ztv_nat >/dev/null 2>&1 || {
        echo 'ztv_nat is not loaded - client traffic is not masqueraded out'
        exit 1
    }
"

check node-dns-no-query-log "In-tunnel resolver keeps no query log (mesh nodes)" -- bash -c "
    # privacy.html \u00a74d says the resolver on the node does not log what
    # customers look up. That is a claim about a config file, so check it.
    ip link show wg0 >/dev/null 2>&1 || exit 77
    conf=/etc/dnsmasq.d/0trust.conf
    [[ -f \$conf ]] || {
        echo 'clients are handed DNS=10.64.0.1 but no resolver is configured there'
        exit 1
    }
    if grep -REq '^[[:space:]]*log-queries' \$conf /etc/dnsmasq.conf 2>/dev/null; then
        echo 'log-queries is on - every hostname a customer resolves is recorded'
        exit 1
    fi
    grep -q '^bind-interfaces' \$conf || {
        echo 'resolver is not bound to the mesh gateway - open resolver on the public IP'
        exit 1
    }
"

check node-dns-encrypted-upstream "Upstream DNS leaves the node over TLS (mesh nodes)" -- bash -c "
    # privacy.html \u00a74d says lookups reach Quad9 encrypted and
    # authenticated, and that a failed TLS connection means no answer rather
    # than a cleartext retry. Both halves are checkable here.
    ip link show wg0 >/dev/null 2>&1 || exit 77
    conf=/etc/dnsmasq.d/0trust.conf
    [[ -f \$conf ]] || exit 77

    # Every upstream dnsmasq has must be the local stub. One public resolver
    # in this list and some fraction of queries leave in clear, chosen by
    # whichever server dnsmasq felt like using.
    bad=\$(grep -E '^server=' \$conf | grep -vE '^server=127\\.0\\.0\\.1#' || true)
    if [[ -n \"\$bad\" ]]; then
        echo \"dnsmasq forwards straight to a public resolver: \$bad\"
        exit 1
    fi

    sconf=/etc/stubby/stubby.yml
    [[ -f \$sconf ]] || {
        echo 'dnsmasq points at a DoT stub but /etc/stubby/stubby.yml is missing'
        exit 1
    }
    grep -q 'GETDNS_AUTHENTICATION_REQUIRED' \$sconf || {
        echo 'stub does not require authentication - encrypted to whoever answered'
        exit 1
    }
    grep -q 'tls_auth_name' \$sconf || {
        echo 'stub checks no certificate name'
        exit 1
    }
    if grep -qE 'GETDNS_TRANSPORT_(UDP|TCP)' \$sconf; then
        echo 'a cleartext transport is in the stub list - strict mode is off'
        exit 1
    fi
    systemctl is-active --quiet stubby || {
        echo 'stubby is not running - the resolver has no upstream at all'
        exit 1
    }
"

section "§3. CONTROL-PLANE DATABASE (retention)"

check db-no-abandoned-signups "No unpaid signups retained past 7 days" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    stale=\$(sqlite3 '$DB_PATH' \"
        SELECT COUNT(*) FROM accounts
        WHERE status = 'pending_payment'
          AND created_at < strftime('%s','now') - 7*86400
          AND id NOT IN (SELECT account_id FROM invoices WHERE status='settled');
    \")
    [[ \"\$stale\" == '0' ]] || {
        echo \"\$stale abandoned signups kept past 7 days - is the sweeper running?\"
        exit 1
    }
"

check db-no-stale-trial-nonces "No trial nonces retained past 24h" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    sqlite3 '$DB_PATH' 'SELECT 1 FROM trial_grants LIMIT 1;' >/dev/null 2>&1 || exit 0
    stale=\$(sqlite3 '$DB_PATH' \"
        SELECT COUNT(*) FROM trial_grants
        WHERE redeemed_at < strftime('%s','now') - 86400;
    \")
    [[ \"\$stale\" == '0' ]] || { echo \"\$stale trial nonces kept past 24h\"; exit 1; }
"

# privacy.html §8 says expired account records are purged after the refund
# window, and docs/AUDIT.md §3.1 gives the token hash, expiry and status a
# retention of "lifetime of subscription". Both were false: sweep.py deleted
# abandoned signups and nothing else, so a lapsed customer's row lived
# forever. The claims were checkable and nothing was checking them.
check db-no-stale-expired-accounts "Expired accounts purged after the refund window" -- bash -c "
    [[ -f '$DB_PATH' ]] || exit 77
    sqlite3 '$DB_PATH' 'SELECT 1 FROM accounts LIMIT 1;' >/dev/null 2>&1 || exit 0
    days=\${ZTV_ACCOUNT_RETAIN_DAYS:-30}
    stale=\$(sqlite3 '$DB_PATH' \"
        SELECT COUNT(*) FROM accounts
        WHERE expires_at > 0
          AND status != 'pending_payment'
          AND expires_at < strftime('%s','now') - (\$days * 86400 + 86400);
    \")
    [[ \"\$stale\" == '0' ]] || {
        echo \"\$stale accounts still on disk more than \$days days after expiry — privacy.html section 8 says these are purged\"
        exit 1
    }
"

section "§4. WEB-TIER (nginx) LOGS (retention)"

check nginx-log-retention "Access log retention ≤ 7 days" -- bash -c "
    if [[ -f '$NGINX_LOG' ]]; then
        cnt=\$(ls /var/log/nginx/0trust-access.log* 2>/dev/null | wc -l)
        if (( cnt > 7 )); then
            echo \"\$cnt log files present — retention may exceed 7d\"
            exit 1
        fi
    fi
"

check nginx-canary-no-cache "Canary served with no-cache headers" -- bash -c "
    [[ -f '$NGINX_CONF' ]] || exit 77
    awk '/location = \\/canary\\.txt/,/^[[:space:]]*}/' '$NGINX_CONF' \
        | grep -q 'no-store' || { echo 'canary location missing no-store header'; exit 1; }
"

# ----------------------------------------------------------------------------
section "§5. MESH-NODE BEHAVIOR"
# ----------------------------------------------------------------------------

check meshd-installed "0trust-meshd service unit exists" -- bash -c "
    [[ -f /etc/systemd/system/0trust-meshd.service \
       || -f /lib/systemd/system/0trust-meshd.service ]] || exit 77
"

check nft-no-logging "nftables ruleset contains no log statements" -- bash -c "
    command -v nft >/dev/null || exit 77
    if nft list ruleset 2>/dev/null | grep -iE '^\\s*log( |$)'; then
        echo 'nftables log rule found — packet metadata would be logged'
        exit 1
    fi
"

check wg-no-monitoring "No periodic 'wg show' polling writing to disk" -- bash -c "
    matches=\$(grep -rE 'wg[[:space:]]+show' /etc/cron* /etc/systemd /opt/0trust 2>/dev/null \
              | grep -v meshd | grep -v audit-verify || true)
    if [[ -n \"\$matches\" ]]; then
        echo \"found suspicious 'wg show' usage: \$matches\"
        exit 1
    fi
"

check meshd-log-no-customer-data "meshd journal has no customer pubkeys" -- bash -c "
    command -v journalctl >/dev/null || exit 77
    # WG public keys are base64 with trailing '=', 44 chars total
    hit=\$(journalctl -u 0trust-meshd --since '1 hour ago' 2>/dev/null \
        | grep -oE '[A-Za-z0-9+/]{43}=' | { head -1; cat >/dev/null; } || true)
    if [[ -n \"\$hit\" ]]; then
        echo 'Potential pubkey in meshd log'
        exit 1
    fi
"

# ----------------------------------------------------------------------------
section "§5.3 EPHEMERAL (RAM-ONLY) NODES"
# ----------------------------------------------------------------------------

# These checks only apply if this host IS an ephemeral mesh node.
# If not, they SKIP rather than FAIL.

check ram-tmpfs-wireguard "Ephemeral: /etc/wireguard is tmpfs" -- bash -c "
    grep -qE '/etc/wireguard tmpfs' /proc/mounts || exit 77
"

check ram-tmpfs-0trust "Ephemeral: /var/0trust + /etc/0trust are tmpfs" -- bash -c "
    grep -qE '/etc/wireguard tmpfs' /proc/mounts || exit 77
    grep -qE '/var/0trust tmpfs' /proc/mounts \
      && grep -qE '/etc/0trust tmpfs' /proc/mounts \
      || { echo 'one or both 0trust paths are not tmpfs'; exit 1; }
"

check ram-no-swap "Ephemeral: swap is fully disabled" -- bash -c "
    grep -qE '/etc/wireguard tmpfs' /proc/mounts || exit 77
    sw=\$(swapon --show --noheadings 2>/dev/null || true)
    [[ -z \"\$sw\" ]] || { echo \"swap is active: \$sw\"; exit 1; }
"

check ram-journald-volatile "Ephemeral: journald is volatile" -- bash -c "
    grep -qE '/etc/wireguard tmpfs' /proc/mounts || exit 77
    storage=\$(grep -hE '^\\s*Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | tail -1)
    [[ \"\$storage\" == *volatile* ]] || { echo \"journald Storage=\$storage, not volatile\"; exit 1; }
"

# ----------------------------------------------------------------------------
section "§7. APPLICATION (API) LOGS"
# ----------------------------------------------------------------------------

check api-log-no-tokens "Recent API log has no account-token leakage" -- bash -c "
    command -v journalctl >/dev/null || exit 77
    # Account tokens are 16 characters of TOKEN_ALPHABET in api/main.py:
    # A-Z and 2-9 with I, O, 0 and 1 removed, so a token read off a screen
    # cannot be mistyped into a different valid one. That is NOT Crockford
    # base32 and this comment used to say it was — Crockford also drops L and
    # U, which this alphabet keeps. The distinction is not pedantic: about two
    # of every three tokens contain an L or a U, so anyone "correcting" the
    # class to match the comment would blind this check to most of them.
    #
    # Both spellings, because the server accepts both: hash_token() strips
    # the separators before hashing, so the clients hand a customer's paste
    # to the API with or without them.
    hit=\$(journalctl -u 0trust-api --since '1 hour ago' 2>/dev/null \
        | grep -oE '\\b[A-HJ-NP-Z2-9]{4}(-?[A-HJ-NP-Z2-9]{4}){3}\\b' \
        | { head -1; cat >/dev/null; } || true)
    if [[ -n \"\$hit\" ]]; then
        echo 'Account token visible in API journal'
        exit 1
    fi
"

check api-log-no-pubkeys "Recent API log has no WireGuard pubkeys" -- bash -c "
    command -v journalctl >/dev/null || exit 77
    # This used to look for the JSON shape, '\"pubkey\": \"<44 chars>\"', which
    # is the one place the key never actually appeared: request bodies are not
    # logged. The real leak was the URL. DELETE /api/v1/devices/{pubkey} puts
    # the key in the path, uvicorn's access line is the path, and the key
    # arrives percent-encoded — so '=' is '%3D' and the JSON prefix is absent.
    # The check reported green on a host that was writing a customer's device
    # key to journald on every device removal. Match the key itself, in either
    # form, wherever it appears: 43 base64 characters (raw, or %2B / %2F for
    # + and /) and the padding (raw '=' or '%3D').
    hit=\$(journalctl -u 0trust-api --since '1 hour ago' 2>/dev/null \
        | grep -oE '([A-Za-z0-9]|%2[BbFf]|[+/]){43}(=|%3[Dd])' \
        | { head -1; cat >/dev/null; } || true)
    if [[ -n \"\$hit\" ]]; then
        echo 'WireGuard pubkey visible in API journal'
        exit 1
    fi
"

check api-no-access-log "API unit does not log request paths" -- bash -c "
    # The check above catches the leak once it has happened, and only within
    # the journal's window. This one catches the cause, on any machine, with
    # no traffic needed: two of our routes carry a secret in the path
    # (the device pubkey, and the invoice capability), so uvicorn's access
    # line must be off. See systemd/0trust-api.service and AUDIT.md §7.
    unit=/etc/systemd/system/0trust-api.service
    [[ -f \"\$unit\" ]] || unit=\"\$REPO_DIR/systemd/0trust-api.service\"
    [[ -f \"\$unit\" ]] || exit 77
    # Comment lines are stripped first. The unit explains the flag in a
    # comment directly above it, and a bare grep matched the explanation —
    # so deleting the flag left this check still passing. Only the directive
    # counts.
    if ! grep -vE '^[[:space:]]*#' \"\$unit\" | grep -q -- '--no-access-log'; then
        echo \"\$unit runs uvicorn with its access log on\"
        exit 1
    fi
"

check nginx-log-no-secret-paths "Access log collapses secret-bearing paths" -- bash -c "
    # nginx logs \$uri, which is the DECODED path — the sibling copy of the
    # uvicorn leak above. The \$uri_anon map replaces the secret segment of
    # /api/v1/devices/… and /api/v1/payment/…, and the log format must use it.
    # The maps and the format live in the http-context file the installer
    # writes (conf.d/0trust-zones.conf); on a clone with nothing deployed,
    # fall back to the reference config in the tree.
    conf=\"\$NGINX_ZONES\"
    [[ -f \"\$conf\" ]] || conf=\"\$REPO_DIR/nginx/0trustvpn.com.conf\"
    [[ -f \"\$conf\" ]] || exit 77
    grep -q 'map \\\$uri \\\$uri_anon' \"\$conf\" || { echo \"no \\\$uri_anon map in \$conf\"; exit 1; }
    if grep -E '^log_format anon' -A2 \"\$conf\" | grep -qE '\\\$uri[^_a-z]'; then
        echo 'log_format anon still logs the raw \$uri'
        exit 1
    fi
"

check api-journald-retention "journald retention ≤ 7 days" -- bash -c "
    command -v journalctl >/dev/null || exit 77
    # Get the journal's earliest entry; if older than 7 days, retention is too long
    first=\$(journalctl --output=short-iso -n 1 --reverse 2>/dev/null | awk '{print \$1}')
    [[ -n \"\$first\" ]] || { echo 'no journal data'; exit 77; }
    first_epoch=\$(date -d \"\$first\" +%s 2>/dev/null || echo 0)
    age=\$(( \$(date +%s) - first_epoch ))
    if (( age > 8 * 86400 )); then
        days=\$(( age / 86400 ))
        echo \"journal entries are \$days days old\"
        exit 1
    fi
"

# ----------------------------------------------------------------------------
section "§8. BACKUPS"
# ----------------------------------------------------------------------------
# Backups now exist (encrypted) — see AUDIT.md §8. We verify they are
# ENCRYPTED rather than absent. An unencrypted DB copy on disk is the finding.

# Identify OUR database by its schema, not by the file extension. Matching any
# SQLite file called *.db flagged /root/.pki/nssdb/cert9.db on every host with a
# browser on it, and a check that fails for reasons the operator has to learn to
# ignore stops being a check. The schema text lives in plain bytes in the
# sqlite_master pages, so grep finds it without needing sqlite3 installed.
check backups-encrypted "No UNENCRYPTED database copies on disk" -- bash -c '
    plaintext=$(find / -type f \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) \
                 -not -path "'"$DB_PATH"'" \
                 -not -path "/proc/*" -not -path "/sys/*" \
                 -not -path "*/site-packages/*" \
                 2>/dev/null | while read -r f; do
        head -c 16 "$f" 2>/dev/null | grep -q "SQLite format" || continue
        # Both tables, so a database that merely has an "accounts" table is not
        # mistaken for ours.
        grep -aq "CREATE TABLE.*mesh_nodes" "$f" 2>/dev/null || continue
        grep -aq "CREATE TABLE.*accounts"  "$f" 2>/dev/null || continue
        echo "$f"
    done | { head -5; cat >/dev/null; })
    [ -z "$plaintext" ] || {
        echo "unencrypted copy of the 0trust database: $plaintext"; exit 1; }
'

check backups-no-leftover-snapshot "No leftover plaintext .snap-* snapshots" -- bash -c '
    leftover=$(find / -name ".snap-*.db" -not -path "/proc/*" 2>/dev/null \
                 | { head -3; cat >/dev/null; })
    [ -z "$leftover" ] || { echo "leftover snapshot (backup.sh should shred): $leftover"; exit 1; }
'

section "§11. KNOWN-LIMITATION DISCLOSURES"
# ----------------------------------------------------------------------------

check no-cdnjs "Landing page does not reference cdnjs or other CDNs" -- bash -c "
    web_root=/var/www/0trust
    [[ -d \$web_root ]] || exit 77
    if grep -rqE 'cdnjs|unpkg|jsdelivr|googleapis\\.com/ajax' \$web_root 2>/dev/null; then
        bad=\$(grep -rlE 'cdnjs|unpkg|jsdelivr|googleapis\\.com/ajax' \$web_root \
                 | { head -3; cat >/dev/null; })
        echo \"third-party CDN reference found in: \$bad\"
        exit 1
    fi
"

check vendor-sri-pinned "All vendored scripts have SRI integrity attributes" -- bash -c "
    web_root=/var/www/0trust
    [[ -d \$web_root ]] || exit 77
    # Find every <script src=\"/vendor/...\"> tag and ensure it has integrity=
    missing=\$(grep -hE '<script[^>]+src=\"/vendor/' \$web_root/*.html 2>/dev/null \
              | grep -v 'integrity=' || true)
    [[ -z \"\$missing\" ]] || { echo \"vendor script without integrity attr: \$missing\"; exit 1; }
"

# Delegated to the canary's own checker rather than re-implementing the age
# test here. This check used to read the file's mtime, which is the bug
# check.sh carries a comment about: rsyncing the site, reinstalling the host
# or restoring a backup all touch the file without re-signing it, so a canary
# months stale in content passed the audit. Two copies of the same arithmetic
# is how a fix lands in one of them.
CANARY_PATH="${CANARY_PATH:-/var/www/0trust/canary.txt}"
CANARY_CHECK=""
for _c in /opt/0trust/canary/scripts/check.sh \
          "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/canary/scripts/check.sh"; do
    [[ -x "$_c" ]] && { CANARY_CHECK="$_c"; break; }
done

check canary-fresh "Warrant canary is within its published signing deadline" -- bash -c "
    [[ -f '$CANARY_PATH' ]] || { echo 'no canary at $CANARY_PATH'; exit 77; }
    [[ -n '$CANARY_CHECK' ]] || { echo 'canary check.sh not found'; exit 77; }
    CANARY_PATH='$CANARY_PATH' '$CANARY_CHECK'
"

# ============================================================================
# SUMMARY
# ============================================================================
cat <<SUMMARY

================================================================
  ${GRN}PASS:${NC} $PASS    ${RED}FAIL:${NC} $FAIL    ${YLW}SKIP:${NC} $SKIP
================================================================

  SKIPs are normal — they indicate a check that doesn't apply to
  this host (e.g. ephemeral-node checks on a control-plane box).

  Any FAIL needs investigation before signing off the audit.

  Full claim/evidence matrix: docs/AUDIT.md

SUMMARY

exit $FAIL
