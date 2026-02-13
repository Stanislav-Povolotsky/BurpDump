#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "  BurpDump - Burp Suite Extension Builder"
echo "============================================"
echo

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
SRC="$ROOT/src"
API="$ROOT/api"
JAR="$BUILD/BurpDump.jar"

# ---- Optional version parameter (default: dev) ----
VER="${1:-dev}"
BUILD_DATE="$(date +%Y-%m-%d)"

# ---- Clean previous build ----
rm -rf "$BUILD"
mkdir -p "$BUILD/burp"

# ---- Generate build-info.properties ----
cat > "$BUILD/burp/build-info.properties" <<EOF
version=$VER
build.date=$BUILD_DATE
EOF

# ---- Generate MANIFEST.MF ----
cat > "$BUILD/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Implementation-Title: BurpDump
Implementation-Version: $VER
Built-Date: $BUILD_DATE
EOF

# ---- Compile ----
echo "Compiling (version $VER, date $BUILD_DATE)..."
find "$API" "$SRC" -name '*.java' > "$BUILD/sources.txt"
javac -d "$BUILD" -sourcepath "$API:$SRC" @"$BUILD/sources.txt"
rm "$BUILD/sources.txt"

# ---- Remove API interface stubs ----
rm -f "$BUILD"/burp/I*.class
rm -rf "$BUILD"/burp/api

# ---- Package ----
echo "Packaging..."
jar cfm "$JAR" "$BUILD/MANIFEST.MF" -C "$BUILD" burp

# ---- Cleanup temp files ----
rm -f "$BUILD"/burp/*.class "$BUILD"/burp/*.properties "$BUILD/MANIFEST.MF"
rmdir "$BUILD/burp" 2>/dev/null || true

echo
echo "[OK] Build successful: $JAR"
