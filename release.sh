#!/bin/sh
set -eu
cd "$(dirname "$0")"
sh build.sh
VERSION=$(cat VERSION)
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/mac-inventory-release.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT HUP INT TERM
cp -R '.build/Mac Inventory.app' "$STAGE/"
cp LICENSE INSTALL.md "$STAGE/"
ln -s /Applications "$STAGE/Applications"
mkdir -p dist
DMG="dist/Mac-Inventory-$VERSION-arm64.dmg"
# Refuse accidental replacement of a previously produced release asset.
test ! -e "$DMG"
hdiutil create -volname "Mac Inventory $VERSION" -srcfolder "$STAGE" -format UDZO -ov "$DMG"
(cd dist && shasum -a 256 "Mac-Inventory-$VERSION-arm64.dmg" > SHA256SUMS)
hdiutil verify "$DMG"
