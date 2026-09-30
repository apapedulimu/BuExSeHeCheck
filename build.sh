#!/usr/bin/env bash
# Build BuExSeHeCheck.jar against the installed Burp Suite.
#
# Burp 2026.x ships Java 21 class files, so javac 17 cannot read burpsuite.jar.
# We compile with a JDK 21+ javac but emit Java 17 bytecode via --release 17.
set -euo pipefail

BURP_JAR="${BURP_JAR:-/Applications/Burp Suite.app/Contents/Resources/app/burpsuite.jar}"
OUT_DIR="${OUT_DIR:-build}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)/src"

if [[ ! -f "$BURP_JAR" ]]; then
  echo "error: Burp jar not found at: $BURP_JAR" >&2
  echo "       set BURP_JAR=/path/to/burpsuite.jar and retry" >&2
  exit 1
fi

# Prefer a JDK 21+ javac; JAVA_HOME wins if it is new enough.
if [[ -z "${JAVA_HOME:-}" ]] || ! "$JAVA_HOME/bin/javac" --release 17 -version >/dev/null 2>&1; then
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    JAVA_HOME="$(/usr/libexec/java_home -v 21+ 2>/dev/null || /usr/libexec/java_home)"
  fi
fi
JAVAC="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
JAR="${JAVA_HOME:+$JAVA_HOME/bin/}jar"

echo "==> javac: $("$JAVAC" -version 2>&1)"
echo "==> burp:  $BURP_JAR"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

"$JAVAC" -nowarn -encoding UTF-8 --release 17 \
  -cp "$BURP_JAR" -d "$OUT_DIR" "$SRC_DIR/BuExSeHeCheck.java"

"$JAR" cfm "$OUT_DIR/BuExSeHeCheck.jar" "$SRC_DIR/MANIFEST.MF" \
  -C "$OUT_DIR" BuExSeHeCheck.class \
  -C "$OUT_DIR" 'BuExSeHeCheck$HeaderTableModel.class'

echo "==> built $OUT_DIR/BuExSeHeCheck.jar"
