#!/bin/bash
# Embed the Share Extension into a built SecureShare.app and register it so
# Finder's right-click -> Share menu lists it. Run AFTER:
#   pyinstaller --clean --noconfirm secure-share-mac.spec
#
# NOTE: macOS 26+ silently ignores ad-hoc-signed extensions. The extension
# will only be enumerated when signed with a Developer ID (set
# SIGN_IDENTITY, e.g. SIGN_IDENTITY="Developer ID Application: Name").
# Without a Developer ID, Finder's Share menu is covered by the built-in
# NSServices fallback (right-click -> Quick Actions/Services -> Send to
# SecureShare), which needs no signing.
set -euo pipefail
cd "$(dirname "$0")/.."

SIGN_IDENTITY="${SIGN_IDENTITY:--}"

APP="dist/SecureShare.app"
if [ ! -d "$APP" ]; then
    echo "dist/SecureShare.app missing - run pyinstaller first" >&2
    exit 1
fi

./scripts/build_share_extension.sh

PLUGINS="$APP/Contents/PlugIns"
mkdir -p "$PLUGINS"
rm -rf "$PLUGINS/SecureShareShare.appex"
cp -R build/SecureShareShare.appex "$PLUGINS/"

codesign --force --deep --sign "$SIGN_IDENTITY" "$APP"

# Register with the system; -f also re-registers the containing app with
# Launch Services so the extension shows up in the Share menu.
pluginkit -a "$PLUGINS/SecureShareShare.appex" || true
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP" || true

echo "embedded + registered in $PLUGINS"
if [ "$SIGN_IDENTITY" = "-" ]; then
    echo "WARNING: ad-hoc signed; macOS 26+ will NOT enumerate this in the Share"
    echo "menu. Use SIGN_IDENTITY=\"Developer ID Application: ...\" for real"
    echo "signing; until then the NSServices fallback is the supported path."
fi
echo "Restart Finder (or log out/in) if 'SecureShare' is not visible."