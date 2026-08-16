#!/bin/bash
# Build the macOS Share Extension bundle (ad-hoc signed).
# Result: build/SecureShareShare.appex
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="build/SecureShareShare.appex"
rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS"

swiftc -O \
    -framework Cocoa \
    -framework Foundation \
    native/share_extension/ShareViewController.swift \
    -o "$OUT/Contents/MacOS/ShareViewController"

cp native/share_extension/Info.plist "$OUT/Contents/Info.plist"
codesign --force --sign - "$OUT"
echo "built $OUT"