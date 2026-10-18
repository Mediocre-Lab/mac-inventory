# v0.1.0-beta.1

Experimental Apple-silicon prerelease. Download the arm64 DMG with SHA256SUMS. Read INSTALL.md before installation and UNINSTALL.md before removal actions.

Build environment: macOS 27.0 (26A428), arm64; Apple Swift 6.4 (swiftlang-6.4.0.34.1), developer-tools Python 3.9.6. Build declares macOS 13 minimum but older systems are untested. No bundled runtime or third-party libraries. Ad-hoc signed; no valid release-signing identity was available. Not notarized. No new credentials were created.

Prior source QA passed 81 tests: 20 scanner, 59 removal and two compiled production Swift harnesses. Permitted GUI checks covered startup/search/filter/export, refresh/cancel/retry/persistence, and disposable Trash/permanent/mock-manager removal. Real installed packages were not removed during QA. The public source removes a machine-specific legacy launcher classification. Current release verification is recorded in RELEASE_VERIFICATION.md.

Independent security assessment remains incomplete because the review platform blocked completion. Full live-disk/protected-directory coverage and clean-machine distribution are unverified. This release is not fully security-audited. Permission changes are not prescribed without evidence of a specific OS denial.

Only intended source, synthetic tests, scripts and sanitized documentation are included. Personal inventories, raw QA logs/screenshots, account information, credentials, caches and original build artifacts are excluded. MIT applies to project-owned files; see THIRD_PARTY_NOTICES.md.
