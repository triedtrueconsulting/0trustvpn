#!/usr/bin/env bash
# ============================================================================
# 0trust — scan for committed secrets, in HISTORY and not just the tree
# ============================================================================
# The distinction is the whole point. test_audit.py already refuses an
# extended key in the WORKING TREE, and that check has been green for months
# over a history that contains two of them: a key committed once and deleted
# in the next commit is still in the pack, still handed to everyone who
# clones, and still readable with one `git show`.
#
# For this product that is the failure with no recovery. An extended public
# key cannot be rotated — it exposes the wallet's entire balance and payment
# history to whoever holds it, forever, and the only remedy is moving the
# funds to a new wallet.
#
#   ./scripts/secret-scan.sh            history + working tree  (the gate)
#   ./scripts/secret-scan.sh --tree     working tree only, fast (pre-commit)
#
# Two scanners run, deliberately:
#
#   The BUILT-IN pass always runs. It knows the four secret classes that
#   would actually end this business, and it reads every blob reachable from
#   every ref rather than every blob in a diff. It has no dependencies, so
#   there is no arrangement of the build in which this check silently does
#   not happen — a SKIP standing in for a pass is the failure mode this
#   repository has been bitten by most.
#
#   gitleaks runs ADDITIONALLY when installed, for breadth: cloud tokens,
#   provider keys, the hundreds of patterns not worth restating here. Its
#   absence is reported, never treated as a pass.
# ============================================================================
set -uo pipefail

MODE="${1:-all}"
RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; NC=$'\033[0m'
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1
FOUND=0

# The classes that end the business, each with why it is on this list.
#   extended key  — balance and payment history, permanently, unrotatably
#   age secret    — reads every encrypted backup ever made
#   PGP private   — forges the release signature and the warrant canary
#   WG private    — impersonates a mesh node to the control plane
PATTERNS=(
  'ztv-extended-key|\b([xyz]pub|[xyz]prv)[1-9A-HJ-NP-Za-km-z]{70,}'
  'ztv-age-secret|AGE-SECRET-KEY-1[0-9A-Z]{50,}'
  'ztv-pgp-private|-----BEGIN (PGP|RSA|OPENSSH|EC) PRIVATE KEY'
  'ztv-wg-private|[Pp]rivate[Kk]ey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}'
)

# Literals that are benign and are pinned exactly, never by file or by rule.
# Allowlist a path and the next real credential pasted there passes in
# silence; these name the string itself.
#   the token alphabet, in Go and Python — fixed, high-entropy by
#     construction, secret by nothing
#   sk_live_supersecret — the fixture that PROVES masking works, asserted
#     absent from the audit log by test_admin_ui.py
ALLOW='ABCDEFGHJKLMNPQRSTUVWXYZ23456789|sk_live_supersecret|7K2M-9X4P-AQ8R-J3WN'

# Digests of exposures already recorded as outstanding operator actions.
KNOWN_FILE="$REPO/scripts/secret-scan.known"
declare -A KNOWN_NOTE=()
if [[ -r "$KNOWN_FILE" ]]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -n "${line// }" ]] || continue
        d="${line%%  *}"; KNOWN_NOTE["$d"]="${line#*  }"
    done < "$KNOWN_FILE"
fi
declare -A KNOWN_SEEN=()

# One reusable buffer for history blobs. grep reads a FILE rather than a
# shell variable because command substitution cannot carry a NUL byte, and
# bash said so 37 times on every clean run of this repository. It STRIPS the
# NULs rather than truncating there, so the old path did still find a secret
# sitting after one — checked, not assumed, before this was called a fix.
# The reason to change it is the noise: output that scrolls past on every
# green run is how a real finding gets scrolled past too, and a scanner
# nobody reads is the one failure this script cannot survive. Reading the
# file directly also drops the whole-blob copy into memory. 0600 and
# shredded on any exit — it holds whatever the blob held.
TMPBLOB="$(mktemp)"; chmod 600 "$TMPBLOB"
trap 'shred -u "$TMPBLOB" 2>/dev/null || rm -f "$TMPBLOB"' EXIT

say_hit() {
    # Never the value. The location and a digest are enough to act on, and
    # printing the secret puts it in CI logs, terminal scrollback and this
    # tool's own output — three more places it now lives.
    local rule="$1" where="$2" match="$3"
    local digest; digest="$(printf '%s' "$match" | sha256sum | cut -c1-16)"
    # Already registered as an exposure that has happened. Counted and
    # reprinted at the end as outstanding work, not waved through.
    if [[ -n "${KNOWN_NOTE[$digest]:-}" ]]; then
        KNOWN_SEEN["$digest"]=1
        return
    fi
    printf '%s  [%s] %s%s\n' "$RED" "$rule" "$where" "$NC"
    printf '        sha256:%s…  (value withheld)\n' "$digest"
    FOUND=$((FOUND + 1))
}

scan_file() {   # scan_file <label> <path-to-read>
    local where="$1" src="$2" entry rule pat
    for entry in "${PATTERNS[@]}"; do
        rule="${entry%%|*}"; pat="${entry#*|}"
        while IFS= read -r m; do
            [[ -n "$m" ]] || continue
            grep -Eq "$ALLOW" <<<"$m" && continue
            say_hit "$rule" "$where" "$m"
        # `--` is load-bearing: the PGP pattern starts with "-----", which
        # grep otherwise reads as options, and that rule silently matched
        # nothing at all until a planted key failed to trip it.
        done < <(grep -Eoha -- "$pat" "$src" 2>/dev/null)
    done
}

# --cached --others --exclude-standard, not a bare `git ls-files`: that
# lists TRACKED files only, so the one case --tree exists for — a new file
# about to be committed — was the one case it could not see. Found by
# planting a WireGuard key in an untracked wg0.conf and watching the scan
# come back clean. Gitignored files stay out on purpose: they cannot be
# committed, and sweeping them in means scanning the operator's real
# /etc/0trust material every run.
printf '%s\n' "── working tree ──────────────────────────────────────────"
while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    scan_file "$f" "$f"
done < <(git ls-files --cached --others --exclude-standard)
printf '   %s files scanned (tracked + untracked, excluding gitignored)\n' \
       "$(git ls-files --cached --others --exclude-standard | wc -l)"

if [[ "$MODE" != "--tree" ]]; then
    printf '%s\n' "── git history (every blob reachable from every ref) ─────"
    # Every blob in the object graph, not every blob in a diff: a file added
    # and removed inside one branch that was then merged still has its blob
    # reachable, and `git log -p` on the mainline can miss it.
    nblob=0
    while read -r sha path; do
        [[ -n "$sha" ]] || continue
        nblob=$((nblob + 1))
        git cat-file blob "$sha" >"$TMPBLOB" 2>/dev/null
        scan_file "history:${path:-<unnamed>} ($sha)" "$TMPBLOB"
    done < <(git rev-list --objects --all 2>/dev/null \
             | git cat-file --batch-check='%(objectname) %(objecttype) %(rest)' 2>/dev/null \
             | awk '$2=="blob" {print $1, $3}')
    printf '   %s blobs scanned across %s commits\n' \
           "$nblob" "$(git rev-list --all --count)"
fi

printf '%s\n' "── gitleaks (breadth) ────────────────────────────────────"
GL=""
command -v gitleaks >/dev/null 2>&1 && GL=gitleaks
[[ -z "$GL" && -x "$HOME/go/bin/gitleaks" ]] && GL="$HOME/go/bin/gitleaks"
if [[ -n "$GL" ]]; then
    # Written unredacted to a private temp file so each finding can be
    # digested and matched against the register, then deleted. The value
    # never reaches stdout, a log, or any path that outlives this function —
    # the alternative is re-reporting on every CI run a secret we already
    # know about, which trains people to ignore the output.
    GLJSON="$(mktemp)"; chmod 600 "$GLJSON"
    if [[ "$MODE" == "--tree" ]]; then
        "$GL" dir --no-banner -c .gitleaks.toml -f json -r "$GLJSON" . >/dev/null 2>&1
    else
        "$GL" git --no-banner -c .gitleaks.toml -f json -r "$GLJSON" . >/dev/null 2>&1
    fi
    gl_new=0
    if [[ -s "$GLJSON" ]]; then
        while IFS=$'\t' read -r digest rule where; do
            [[ -n "$digest" ]] || continue
            if [[ -n "${KNOWN_NOTE[$digest]:-}" ]]; then
                KNOWN_SEEN["$digest"]=1
            else
                printf '%s  [gitleaks:%s] %s%s\n' "$RED" "$rule" "$where" "$NC"
                printf '        sha256:%s…  (value withheld)\n' "$digest"
                gl_new=$((gl_new + 1))
            fi
        done < <(GLJSON="$GLJSON" python3 - <<'DIGEST'
import hashlib, json, os, sys
try:
    rows = json.load(open(os.environ["GLJSON"]))
except Exception:
    sys.exit(0)
seen = set()
for f in rows:
    digest = hashlib.sha256(f.get("Secret", "").encode()).hexdigest()[:16]
    path = f.get("File", "")
    if (digest, path) in seen:
        continue
    seen.add((digest, path))
    where = path + ":" + str(f.get("StartLine", ""))
    print(digest, f.get("RuleID", "?"), where, sep="\t")
DIGEST
)
    fi
    shred -u "$GLJSON" 2>/dev/null || rm -f "$GLJSON"
    if (( gl_new )); then
        FOUND=$((FOUND + gl_new))
    else
        printf '   %sclean (no findings outside the register)%s\n' "$GRN" "$NC"
    fi
else
    # Not a pass. The built-in pass above still ran and still covers the
    # classes that matter; this line says what extra coverage is missing.
    printf '   %snot installed — breadth coverage did NOT run%s\n' "$YLW" "$NC"
    printf '     go install github.com/zricethezav/gitleaks/v8@latest\n'
fi

echo
if (( ${#KNOWN_SEEN[@]} )); then
    printf '%s── KNOWN EXPOSURES — outstanding operator action ─────────%s\n' "$YLW" "$NC"
    for d in "${!KNOWN_SEEN[@]}"; do
        printf '%s  sha256:%s…%s\n' "$YLW" "$d" "$NC"
        printf '    %s\n' "${KNOWN_NOTE[$d]}"
    done
    printf '  Registered in scripts/secret-scan.known. These do NOT fail the\n'
    printf '  gate — a permanently red gate gets switched off and then the\n'
    printf '  NEXT secret goes in unnoticed. They are not resolved.\n\n'
fi

if (( FOUND )); then
    printf '%s%d finding(s). Nothing above is printed in full, deliberately.%s\n' \
           "$RED" "$FOUND" "$NC"
    printf 'A secret in HISTORY is not fixed by deleting the file: the blob\n'
    printf 'stays until the history is rewritten, and anyone who already\n'
    printf 'cloned has it regardless. Rotate the credential first.\n'
    exit 1
fi
if (( ${#KNOWN_SEEN[@]} )); then
    printf '%sNo NEW secrets. %d known exposure(s) still outstanding above.%s\n' \
           "$GRN" "${#KNOWN_SEEN[@]}" "$NC"
else
    printf '%sNo secrets found in the tree or in history.%s\n' "$GRN" "$NC"
fi
