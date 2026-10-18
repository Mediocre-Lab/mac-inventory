#!/bin/sh
set -eu
cd "$(dirname "$0")"
VERSION=$(cat VERSION)
APP='.build/Mac Inventory.app'
export MACOSX_DEPLOYMENT_TARGET=13.0
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp scan.py uninstall.py "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>MacInventory</string>
<key>CFBundleIdentifier</key><string>lab.mediocre.mac-inventory</string>
<key>CFBundleName</key><string>Mac Inventory</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>MacInventoryReleaseVersion</key><string>$VERSION</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
xcrun swiftc -parse-as-library -O -target arm64-apple-macosx13.0 InventoryViewer.swift -o "$APP/Contents/MacOS/MacInventory" -framework SwiftUI -framework AppKit -module-cache-path .build/module-cache -Xlinker -no_uuid
codesign --force --sign - --timestamp=none "$APP"
plutil -lint "$APP/Contents/Info.plist"
codesign --verify --deep --strict "$APP"
printf 'Built %s\n' "$APP"
