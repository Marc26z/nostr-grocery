#!/usr/bin/env bash
# Wrap the web app into a signed Android APK with zapstore/goapk.
# No Android SDK, JDK or Gradle needed — goapk is a single self-contained binary.
#
#   go install github.com/zapstore/goapk@latest
#   ./scripts/build-apk.sh
#
# Environment overrides: PACKAGE, NAME, VERSION_CODE, VERSION_NAME, KEYSTORE, OUT.
set -euo pipefail
cd "$(dirname "$0")/.."

PACKAGE="${PACKAGE:-com.marc26z.grocery}"
NAME="${NAME:-Grocery}"
VERSION_CODE="${VERSION_CODE:-1}"
VERSION_NAME="${VERSION_NAME:-1.0.0}"
KEYSTORE="${KEYSTORE:-keystore.p12}"
OUT="${OUT:-dist/grocery.apk}"

if ! command -v goapk >/dev/null 2>&1; then
  echo "goapk not found. Install it with: go install github.com/zapstore/goapk@latest" >&2
  exit 1
fi

# Stage only the web assets the app needs.
WEB="dist/web"
rm -rf "$WEB"
mkdir -p "$WEB" dist
cp index.html styles.css app.js manifest.webmanifest "$WEB"/
cp -r src vendor icons "$WEB"/

# Reuse one keystore for every release so the app updates in place.
if [ ! -f "$KEYSTORE" ]; then
  echo "Generating signing keystore at $KEYSTORE — keep it safe and reuse it for every release."
  goapk gen "$KEYSTORE"
fi

goapk build -s "$WEB" \
  --package "$PACKAGE" \
  --name "$NAME" \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  --icon icons/icon-512.png \
  --keystore "$KEYSTORE" \
  "$OUT"

echo "Built $OUT"
