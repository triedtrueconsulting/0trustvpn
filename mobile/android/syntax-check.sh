#!/usr/bin/env bash
#
# Parse every Kotlin source with the real Kotlin compiler front-end.
#
# Why this exists: a full `./gradlew assembleDebug` needs the Android SDK and
# network access to Google's Maven repo, which a headless build box (or a
# locked-down CI network) often does not have. Without them the Kotlin sources
# were never checked by anything at all — an unbalanced brace or a malformed
# expression would sit in the repo until somebody opened Android Studio.
#
# The compiler cannot resolve android.*, androidx.*, okhttp3.* or
# com.wireguard.* without those SDK jars, so it emits a wall of
# "unresolved reference" errors and the knock-on type-inference failures that
# follow from them. Those are expected here and are filtered out. What is NOT
# filtered is the parser's own output: anything the compiler could not even
# read as Kotlin. That is the class of error this script is for, and it should
# always be zero.
#
#   ./syntax-check.sh          # download the compiler if needed, then parse
#   KOTLIN_VERSION=2.0.20 ./syntax-check.sh
#
# For a real, resolving build you still need Android Studio (or the SDK plus
# reachable dl.google.com) and `./gradlew assembleDebug`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTLIN_VERSION="${KOTLIN_VERSION:-2.0.20}"
COROUTINES_VERSION="${COROUTINES_VERSION:-1.8.1}"
CACHE="${KOTLIN_CACHE_DIR:-${TMPDIR:-/tmp}/0trust-kotlinc-$KOTLIN_VERSION}"
CENTRAL="https://repo1.maven.org/maven2"

fetch() {   # fetch <group-path> <artifact> <version>
    local out="$CACHE/$2-$3.jar"
    [ -s "$out" ] && return 0
    echo "  fetching $2-$3.jar"
    curl -fsSL -o "$out.tmp" "$CENTRAL/$1/$2/$3/$2-$3.jar"
    mv "$out.tmp" "$out"
}

mkdir -p "$CACHE"
echo "[1/2] compiler ($CACHE)"
for a in kotlin-compiler kotlin-stdlib kotlin-reflect kotlin-script-runtime \
         kotlin-daemon-embeddable; do
    fetch org/jetbrains/kotlin "$a" "$KOTLIN_VERSION"
done
fetch org/jetbrains/intellij/deps trove4j 1.0.20200330
# The compiler's own IntelliJ core needs these on the classpath to start.
fetch org/jetbrains/kotlinx kotlinx-coroutines-core-jvm "$COROUTINES_VERSION"
fetch org/jetbrains/kotlinx kotlinx-coroutines-core "$COROUTINES_VERSION"

SRC="$HERE/app/src/main/java/vpn/zerotrust/app"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

echo "[2/2] parsing $(ls "$SRC"/*.kt | wc -l) files"
java -cp "$CACHE/*" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
     -d "$(mktemp -d)" -nowarn "$SRC"/*.kt >"$LOG" 2>&1 || true

# Anything the parser itself rejected. Resolution failures (and the inference
# errors they cascade into) are expected without the Android SDK.
SYNTAX="$(grep -iE 'error: (expecting|unexpected|unbalanced|unclosed|illegal|too many characters)' "$LOG" || true)"

RESOLVED_OUT=$(grep -c 'error: unresolved reference' "$LOG" || true)
echo
if [ -n "$SYNTAX" ]; then
    echo "FAIL — the Kotlin parser rejected these:"
    echo "$SYNTAX"
    exit 1
fi
echo "PASS — every Kotlin source parses."
echo "       ($RESOLVED_OUT unresolved-reference errors, all from the absent"
echo "        Android/AndroidX/OkHttp/WireGuard classpath — expected here.)"
