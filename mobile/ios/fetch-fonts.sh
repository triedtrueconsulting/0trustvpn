#!/usr/bin/env bash
# ============================================================================
# Put the five brand faces into 0trust/Resources/, and prove they are the ones
# the app asks for.
# ============================================================================
# SwiftUI's Font.custom takes a PostScript name, not a file name, and when it
# does not resolve it does not fail — it silently substitutes the system font.
# So the app builds, launches, connects, and simply looks wrong, with nothing
# anywhere reporting a problem. That is the whole reason this script exists
# instead of a README line telling you to go and find five files.
#
# It downloads each face, reads the PostScript name out of the TTF's own name
# table, and names the file after it. Filename and PostScript name therefore
# agree by construction rather than by luck. Then it checks that set against
# BOTH places the app names a font — UIAppFonts in project.yml, which decides
# what iOS registers, and Font.custom in Theme.swift, which decides what the
# views ask for. Those two drifting apart is the same silent failure.
#
#   ./fetch-fonts.sh            # download into 0trust/Resources/, then verify
#   ./fetch-fonts.sh --check    # verify what is already there; no network
#
# The faces are IBM Plex Sans, Instrument Serif and JetBrains Mono, all under
# the SIL Open Font License 1.1, which permits redistribution inside an app.
# See 0trust/Resources/FONTS.md.
# ============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

OUT="0trust/Resources"
# An old User-Agent on purpose: fonts.googleapis.com serves woff2 to anything
# that admits to supporting it, and iOS UIAppFonts cannot load woff2.
UA='Mozilla/4.0'
URL='https://fonts.googleapis.com/css2?family=Instrument+Serif&family=JetBrains+Mono:wght@400;500;700&family=IBM+Plex+Sans:wght@400&display=swap'

if [[ $CHECK_ONLY -eq 0 ]]; then
  mkdir -p "$OUT"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "[+] asking Google Fonts for TTFs"
  curl -fsS -A "$UA" "$URL" -o "$tmp/src.css"
  grep -o 'https://[^)]*\.ttf' "$tmp/src.css" | sort -u > "$tmp/urls"
  n=0
  while read -r u; do
    n=$((n + 1))
    curl -fsS -o "$tmp/$n.ttf" "$u"
  done < "$tmp/urls"
  [[ $n -gt 0 ]] || { echo "no TTF URLs came back — did the API start serving woff2?" >&2; exit 1; }
  echo "[+] downloaded $n faces"
fi

# The verification, and the download's renaming step, share one parser.
CHECK_ONLY=$CHECK_ONLY OUT="$OUT" TMP="${tmp:-}" python3 - <<'PY'
import os, re, struct, shutil, sys, glob

OUT   = os.environ["OUT"]
TMP   = os.environ.get("TMP") or ""
CHECK = os.environ["CHECK_ONLY"] == "1"

def postscript_name(path):
    """Read name ID 6 out of a TrueType 'name' table. No dependencies: this
    runs on an operator's Mac before anything else is installed."""
    d = open(path, "rb").read()
    num = struct.unpack(">H", d[4:6])[0]
    tables = {}
    for i in range(num):
        off = 12 + 16 * i
        tables[d[off:off+4].decode("latin1")] = struct.unpack(">II", d[off+8:off+16])
    if "name" not in tables:
        raise SystemExit(f"{path}: no name table — not a TrueType font")
    o, _ = tables["name"]
    _, count, strOff = struct.unpack(">HHH", d[o:o+6])
    for i in range(count):
        rec = o + 6 + 12 * i
        pid, _, _, nid, ln, off = struct.unpack(">HHHHHH", d[rec:rec+12])
        if nid != 6:
            continue
        raw = d[o+strOff+off : o+strOff+off+ln]
        return raw.decode("utf-16-be") if pid == 3 else raw.decode("latin1")
    raise SystemExit(f"{path}: no PostScript name")

# --- name each downloaded file after the name the app will look it up by ---
if not CHECK and TMP:
    os.makedirs(OUT, exist_ok=True)
    for src in sorted(glob.glob(os.path.join(TMP, "*.ttf"))):
        ps = postscript_name(src)
        shutil.copyfile(src, os.path.join(OUT, ps + ".ttf"))
        print(f"    {ps}.ttf")

# --- the two places the app names a font, and what is on disk ---
have = {}
for f in sorted(glob.glob(os.path.join(OUT, "*.ttf"))):
    have[postscript_name(f)] = os.path.basename(f)

spec = open("project.yml").read()
block = re.search(r"UIAppFonts:\n((?:\s+- \S+\n)+)", spec)
listed = set(re.findall(r"- (\S+\.ttf)", block.group(1))) if block else set()

theme = open("0trust/App/Theme.swift").read()
asked = set(re.findall(r'custom\(\s*"([^"]+)"', theme))

fail = []
missing = asked - set(have)
if missing:
    fail.append(f"Theme.swift asks for {sorted(missing)}, and no file has that "
                f"PostScript name. SwiftUI would fall back to the system font "
                f"silently. Present: {sorted(have)}")
unused = set(have) - asked
if unused:
    fail.append(f"shipped but never asked for: {sorted(unused)} — bundle size "
                f"for nothing, or a rename Theme.swift did not follow")
mislisted = {n for n in have if have[n] != n + ".ttf"}
if mislisted:
    fail.append(f"filename does not match the PostScript name for {sorted(mislisted)}")
not_registered = {have[n] for n in have} - listed
if not_registered:
    fail.append(f"present but absent from UIAppFonts in project.yml: "
                f"{sorted(not_registered)} — iOS would not register them")
ghost = listed - {have[n] for n in have}
if ghost:
    fail.append(f"UIAppFonts names {sorted(ghost)}, which is not in {OUT}/")

for f in fail:
    print("  FAIL  " + f, file=sys.stderr)
if fail:
    sys.exit(1)
print(f"[ok] {len(have)} faces, each named by its PostScript name, each "
      f"registered, each asked for")
PY
