# Release verification — 2026-10-18

- Clean public-source suite: **81 passed** (20 scanner, 59 removal, two compiled production Swift harnesses). Synthetic fixtures only; no live disk scan or installed-software removal.
- Optimized arm64 build succeeded with explicit macOS 13 deployment target and SDK 27.0. Mach-O build metadata confirms both. One existing SwiftUI onChange deprecation warning remains.
- Plist lint and strict/deep ad-hoc signature verification passed for the built app and the app inside the read-only mounted DMG. No Developer ID identity available; not notarized.
- DMG internal checksum verification passed. Read-only mount succeeded; app bundle, source helper equality and arm64 executable verified. The image contains only app, LICENSE, INSTALL.md and an Applications link.
- SHA256SUMS validates the DMG. It binds the downloadable bytes; rebuilding may produce a different DMG due to filesystem/toolchain metadata.
- Public-source allowlist and app/image contents reviewed. No personal inventory, raw QA artifacts, private account/path data, credential files, caches or signing secrets included. No vendored third-party assets or libraries.
- GUI evidence belongs to the earlier QA build; no clean-machine GUI check of this versioned bundle was performed. Platform-blocked independent security assessment, full real-disk coverage, protected-folder coverage and other systems/architectures remain unverified.
