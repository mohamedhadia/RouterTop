#!/bin/zsh
# One-line installer for RouterTop:
#   curl -fsSL https://raw.githubusercontent.com/mohamedhadia/RouterTop/main/install.sh | zsh
set -euo pipefail

URL="https://github.com/mohamedhadia/RouterTop/releases/latest/download/RouterTop.zip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading RouterTop…"
curl -fsSL "$URL" -o "$TMP/RouterTop.zip"
ditto -x -k "$TMP/RouterTop.zip" "$TMP"

pkill -x RouterTop 2>/dev/null || true
DEST="/Applications"
[[ -w "$DEST" ]] || DEST="$HOME/Applications"
mkdir -p "$DEST"
rm -rf "$DEST/RouterTop.app"
cp -R "$TMP/RouterTop.app" "$DEST/"
xattr -dr com.apple.quarantine "$DEST/RouterTop.app" 2>/dev/null || true

open "$DEST/RouterTop.app"
echo "✓ Installed to $DEST/RouterTop.app"
echo "  Click the Wi-Fi icon in your menu bar and enter your router login."
