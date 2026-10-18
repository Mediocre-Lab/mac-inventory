# Mac Inventory

A native macOS software inventory viewer with metadata scanning, search, filters, JSON export, saved snapshots, and explicitly confirmed removal controls.

**Experimental prerelease: v0.1.0-beta.1.** Independent security assessment is incomplete. Use disposable data for evaluating removal features.

[Download the DMG and checksum](https://github.com/Mediocre-Lab/mac-inventory/releases/tag/v0.1.0-beta.1) · [Installation](INSTALL.md) · [Removal behavior](UNINSTALL.md) · [QA coverage](QA_COVERAGE.md) · [Stable release criteria](STABLE_RELEASE_CHECKLIST.md)

The arm64 download was tested on Apple silicon with macOS 27.0. The deployment target is macOS 13; earlier OS versions and Intel are unverified. A working Apple developer-tools `/usr/bin/python3` is required and is not bundled. The app is ad-hoc signed, has no Developer ID signature, and is not notarized. See INSTALL.md for requirements and Gatekeeper notes.

## Features

- Discover app bundles, executable candidates, Homebrew records, npm/Python packages, environments and repositories.
- Search and filter records; inspect evidence, reveal locations, and export metadata.
- Refresh with progress and cancellation; reopen the last successful snapshot.
- Preview ownership-checked Homebrew/npm/pip/uv removal, with explicit confirmation. Eligible manual removal offers Trash or a separately confirmed permanent action.

Scanning does not execute discovered programs. Removal invokes trusted managers only after confirmation and revalidation. See UNINSTALL.md for exact scope, refusals and recovery limits.

## Build and test

Use Apple silicon, Xcode command-line tools including Swift and the macOS SDK, and `/usr/bin/python3`. From the repository root:

```sh
sh build.sh
/usr/bin/python3 -I -B test_scan.py
/usr/bin/python3 -I -B test_uninstall.py
/usr/bin/python3 -I -B test_snapshot.py
# Additional post-release checks on main:
/usr/bin/python3 -I -B test_permissions.py
sh release.sh
```

The app is written to `.build/Mac Inventory.app`. `release.sh` builds it again, stages only the app, license, installation guide and Applications link, then writes the DMG and SHA256SUMS to `dist/`. It refuses an existing versioned DMG. It does not launch the app or scan your disk.

VERSION uses Semantic Versioning; prereleases retain a beta suffix. Bundle marketing/build versions use Apple's numeric format; MacInventoryReleaseVersion records the complete SemVer. Update VERSION and numeric bundle fields together for subsequent releases and tag the source `v<VERSION>`.

For controlled repeat builds use the same source tag, arm64 target, Xcode/Swift/macOS SDK and Python versions. Build flags, staging contents and ad-hoc signing mode are fixed in the scripts. DMG filesystem metadata and host toolchains can change bytes, so cross-machine bit-for-bit reproducibility is not promised. Verify each distributed artifact against its published SHA-256. See RELEASE_NOTES.md for the tested toolchain and evidence.

Post-release permission QA adds three passing POSIX-denial tests and a confined GUI permission-error/recovery check. See [QA_COVERAGE.md](QA_COVERAGE.md) for exact evidence, remaining gaps and the proposed self-contained Python runtime. The published beta and its 81-test release record are unchanged. `SOURCE_SHA256.json` binds the original tagged release files; subsequent documentation and tests on main are outside that immutable manifest.

## Known limitations and privacy

This is presence/metadata inventory, not proof software works. Records can represent separate installed copies, dependencies or executable candidates; totals are not unique product counts. Directory symlinks, caches, Trash, backup trees and version-control internals are skipped. A legacy exclusion for paths named QuantDinger remains. Unmounted disks, remote/container software, unrecognized metadata and protected paths may be missed. Shell access does not prove app permission coverage. No complete live-disk or protected-folder verification has been performed.

The automatic snapshot lives at `~/Library/Application Support/Mac Inventory/inventory-current.json`. Exports and snapshots contain software lists and local paths; do not publish them unreviewed. No personal inventories or raw QA logs are included in this repository.

Independent security assessment has not been completed. Passing fixture tests and source review do not establish a complete security audit. Manual removal is not transactional against hostile same-user/privileged mount or filesystem changes; partially deleted data cannot be rolled back. Package manager and environment startup hooks remain trusted code boundaries.

## License

Project-owned code is MIT licensed. See LICENSE and THIRD_PARTY_NOTICES.md. Apple frameworks, development tools, Python and third-party managers retain their respective licenses.
