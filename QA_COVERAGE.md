# QA coverage and remaining verification

Updated 2026-10-18 after the v0.1.0-beta.1 publication. This is a bounded engineering QA record, not a completed independent security audit.

## Completed additional permission checks

Three new tests in `test_permissions.py` passed under an unprivileged process on macOS 27.0 arm64. They exercise actual POSIX denial in newly created disposable fixtures, rather than mocking every permission error:

1. A mode-000 directory raises PermissionError; production scanning reports the denied subtree, discovers a readable sibling, and excludes the inaccessible package.
2. Mode-000 ownership metadata remains unread, scanner output includes a PermissionError warning, and the removal metadata reader refuses access. Restoring fixture permissions confirms the original bytes are unchanged; no removal manager is executed.
3. A compiled production Swift model rejects an unreadable snapshot with EACCES, refreshes instead of resurrecting a stale legacy cache, retains fresh displayed results and previous disk bytes when an atomic save is denied, and saves successfully after the disposable directory's access is restored.

Run from the source root with Apple developer tools:

```sh
/usr/bin/python3 -I -B test_permissions.py
```

The prior release suite passed 81 tests (20 scanner, 59 removal, two compiled Swift harnesses). These three additions bring the covered test cases to 84; the original 81 were not rerun for this documentation/test-only addition. Seven existing confined boundary regressions were also rerun and passed before this follow-up; they are already included in the original 81 and must not be counted twice.

## Additional live GUI evidence

A separate app fixture compiled the current production model and views, changing only the injected snapshot/legacy/scanner URLs to a new temporary directory and using a separate QA bundle identity. Its scanner was an authored synthetic adapter, with no real-disk traversal. The fixture had no bundled removal helper and no real package-manager target.

- Startup with an unreadable saved snapshot and unwritable snapshot directory completed without a UI hang. Fresh synthetic results were displayed, and a native warning explicitly said they could not be saved; Retry was available.
- Coverage exposed the fixture scope, a synthetic permission warning and the explicit statement that TCC/full-disk coverage was not established.
- After restoring only the disposable fixture file/directory modes, Retry and reopen left one persisted synthetic record and no save warning. Saved JSON was checked independently. The default Installed filter correctly excluded that Dependency record while the total remained one.
- The fixture app was quit after verification. No real installed software, snapshot or personal file was changed. Only disposable fixture permissions were altered; no macOS privacy/security settings were changed.

The first GUI observation suffered a long host-tool delay, despite the requested timeout. This does not establish an app permission fault or clean-machine performance guarantee. No new runtime bug was demonstrated by these checks, so runtime source and the published beta DMG/tag were not changed.

## Shell access observations

A previous bounded, read-only check opened Desktop, Documents, Downloads, Trash, Mail, Messages and Safari directory descriptors and read at most one directory entry in each, retaining no entry names or file contents. Those operations succeeded in the shell execution context. This does not establish native-app TCC authorization, recursive coverage or the ability to read all protected data. No actual OS denial was observed on which to base a specific permission-setting recommendation.

## Finite remaining checklist

| Remaining item | What is required to finish | Current limit |
| --- | --- | --- |
| Independent security assessment | A completed independent review tied to the release candidate | Incomplete. Fixture QA does not replace independent assessment. |
| Native-app protected-folder coverage | User-selected disposable fixtures in relevant protected locations, ordinary macOS permission behavior and a bounded native-app scan | Shell access and POSIX-denial fixtures do not prove TCC access. No Full Disk Access or other grant was requested. |
| Complete real-disk scan | A user-approved scan scope/time and review of Coverage for mounted volumes and inaccessible paths | A full real-disk pass was not completed; no exhaustiveness claim. |
| Clean-machine runtime/install validation | A disposable clean macOS environment without developer tools, plus normal Gatekeeper handling | Current beta requires developer-tools Python, is ad-hoc signed and is not notarized. |
| Minimum OS and architecture matrix | Available test systems for the declared minimum and any additional supported architectures | Only macOS 27.0 arm64 is tested; deployment metadata says macOS 13. Intel and macOS 13–26 remain unverified. |
| Developer ID signing/notarization | Existing authorized signing identity, Apple account and notarization access | No valid signing identity was available. No credentials were created or purchased and no protections bypassed. |
| Self-contained runtime | A reviewed pinned redistributable Python runtime, complete license/dependency review, bundle wiring and clean-machine tests | Proposal below only; no runtime downloaded or new release published. |

Additional local repetitions of the same fixtures cannot close these environment, access or independent-review gaps. See [stable release acceptance](STABLE_RELEASE_CHECKLIST.md) for measurable candidate gates.

## Developer-tools Python distribution limitation

The production model launches `/usr/bin/python3` for scanning and removal-helper work. On the tested Mac this is Apple's developer-tools launcher, resolving to Python 3.9.6. That runtime is not included in the DMG and cannot be assumed available on a clean Mac. Missing-runtime behavior has a synthetic regression, but this is not self-contained installation validation.

The smallest proposed self-contained improvement is to ship a private, relocatable CPython runtime inside the app, point the helper process URL to that bundle resource, and keep isolated interpreter arguments. This preserves the current Swift UI and Python helpers. Pin and review the exact runtime source/build, architecture and deployment target; include its standard library, required extension modules and dynamic libraries, and validate that no Xcode/Homebrew/system Python paths are needed. Keep third-party runtime licensing separate from this project's MIT license. Python's own [license text](https://docs.python.org/3/license.html) and [PSF bundling guidance](https://wiki.python.org/moin/PythonSoftwareFoundationLicenseFaq) require preservation of applicable licenses/notices.

Before publishing a changed runtime: audit bundle contents and dependencies, run all helper and Swift tests against the bundled interpreter, test a clean Mac without developer tools, exercise normal quarantine/Gatekeeper behavior, and sign/notarize nested components if authorized credentials are available. Copying the local Xcode Python launcher or framework is not the proposed redistribution source. This is an implementation proposal; no new runtime source was fetched and no release assets were replaced.
