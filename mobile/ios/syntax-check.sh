#!/usr/bin/env bash
#
# Structural check over the Swift sources.
#
# READ THIS BEFORE TRUSTING IT: this is NOT a compiler. The Android side runs
# the real Kotlin compiler front-end, which can be fetched from Maven Central;
# there is no equivalent here, because swiftc does not exist for this
# environment and download.swift.org is not reachable from it. Swift also
# cannot be usefully type-checked away from the Apple SDKs regardless —
# SwiftUI, NetworkExtension and Security have no Linux implementation.
#
# So this checks the things that CAN be checked without a toolchain, and every
# one of them has been a real mistake in some codebase:
#
#   - delimiters balance, ignoring strings, comments and escapes
#   - no placeholder left behind: fatalError, TODO, unimplemented
#   - every file that uses a symbol from a framework imports it
#
# What it cannot tell you is whether the code type-checks. Only Xcode can, and
# `xcodegen generate && xcodebuild` on a Mac is the real gate before release.
set -euo pipefail
cd "$(dirname "$0")"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; DIM=$'\033[2m'; NC=$'\033[0m'
fail=0
note() { printf '  %sFAIL%s  %s\n' "$RED" "$NC" "$1"; fail=$((fail + 1)); }

mapfile -t SWIFT < <(find 0trust -name '*.swift' | sort)
if [ ${#SWIFT[@]} -eq 0 ]; then
  echo "no Swift sources found"; exit 1
fi

python3 - "${SWIFT[@]}" <<'PY'
import re, sys

PLACEHOLDERS = ("fatalError(", "TODO(", "unimplemented(", "notImplemented(")
# symbol -> module that must be imported to use it
NEEDS = {
    "NEPacketTunnelProvider": "NetworkExtension",
    "NETunnelProviderManager": "NetworkExtension",
    "NEVPNStatus": "NetworkExtension",
    "SecItemAdd": "Security",
    "View":       "SwiftUI",
    "WireGuardAdapter": "WireGuardKit",
    "TunnelConfiguration": "WireGuardKit",
    "PrivateKey": "WireGuardKit",
}

def strip(src):
    """Remove strings and comments so delimiter counting is not fooled."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:            # escape outside a string
            i += 2; continue
        if src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if src.startswith("/*", i):
            depth, i = 1, i + 2                 # Swift nests block comments
            while i < n and depth:
                if src.startswith("/*", i): depth += 1; i += 2
                elif src.startswith("*/", i): depth -= 1; i += 2
                else: i += 1
            continue
        if c == '"':
            if src.startswith('"""', i):
                j = src.find('"""', i + 3)
                i = n if j < 0 else j + 3
                continue
            i += 1
            while i < n:
                if src[i] == "\\": i += 2; continue
                if src[i] == '"': i += 1; break
                i += 1
            continue
        out.append(c); i += 1
    return "".join(out)

bad = 0
for path in sys.argv[1:]:
    src = open(path, encoding="utf-8").read()
    code = strip(src)

    stack, line = [], 1
    pairs = {")": "(", "]": "[", "}": "{"}
    for ch in code:
        if ch == "\n": line += 1
        elif ch in "([{": stack.append((ch, line))
        elif ch in ")]}":
            if not stack or stack[-1][0] != pairs[ch]:
                print(f"  FAIL  {path}:{line}: unbalanced '{ch}'"); bad += 1; break
            stack.pop()
    else:
        if stack:
            ch, ln = stack[-1]
            print(f"  FAIL  {path}: unclosed '{ch}' opened at line {ln}"); bad += 1

    for ph in PLACEHOLDERS:
        if ph in code:
            ln = code[:code.index(ph)].count("\n") + 1
            print(f"  FAIL  {path}:{ln}: placeholder {ph} left in shipping source")
            bad += 1

    imports = set(re.findall(r"^\s*import\s+(\w+)", src, re.M))
    for sym, mod in NEEDS.items():
        if re.search(rf"\b{sym}\b", code) and mod not in imports:
            print(f"  FAIL  {path}: uses {sym} but does not import {mod}")
            bad += 1

print(f"  checked {len(sys.argv) - 1} Swift files")
sys.exit(1 if bad else 0)
PY
rc=$?

if [ $rc -ne 0 ]; then fail=1; fi

if [ "$fail" -ne 0 ]; then
  printf '%sSTRUCTURAL CHECK FAILED%s\n' "$RED" "$NC"
  exit 1
fi
printf '%sPASS%s — Swift sources are structurally sound.\n' "$GRN" "$NC"
printf '       %sNot a compile. swiftc does not exist here and SwiftUI /\n' "$DIM"
printf '       NetworkExtension have no Linux SDK; run xcodegen generate &&\n'
printf '       xcodebuild on a Mac before shipping.%s\n' "$NC"
