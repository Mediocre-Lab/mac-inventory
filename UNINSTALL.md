# Confirmed, deterministic removal

Select an item and click **Uninstall…**. Planning reads the live filesystem and ownership metadata; it does not execute a manager, change settings or remove software. There is no LLM or network decision step.

The preview shows the exact target, owning scope, manager, argument vector and consequences. **Cancel is the default button.** Only clicking Uninstall executes a verified manager. The backend recalculates the plan immediately before execution and requires the exact confirmed token. Changed targets, alias destinations, versions, metadata, managers or declared dependents invalidate the preview.

## Supported adapters

| Adapter | Ownership proof and scope | Refusals / limits |
| --- | --- | --- |
| Homebrew formula | Actual keg location plus installed-on-request receipt; owning prefix’s brew executable | Shared/indirect dependencies, multiple kegs, protected development runtimes and registered Homebrew services are blocked. No force, ignore-dependencies, autoremove, cleanup or zap. |
| Homebrew cask | Receipt plus exact Caskroom location or registered app artifact link | Multiple claiming casks or dependency installs are blocked. Vendor lifecycle hooks may run after confirmation. No zap/force. Recognized running app bundles must be quit by the user first. |
| Global npm | Exact standard prefix/lib/node_modules package directory and matching package identity | Correct --prefix and --global scope; protected npm/corepack/node and bundled agent infrastructure are blocked. Recognized Homebrew, user-local, npm-global and nvm prefixes are supported. |
| Project npm | Project manifest declares the exact installed package, with npm ownership evidence and no competing manager | Yarn/pnpm/bun, workspaces, transitive/extraneous packages, linked lockfiles and declared shared consumers are refused. This adapter may change this project’s manifest, lockfile and dependency tree. Lifecycle scripts, audit and funding are disabled. |
| uv tool | Standard uv tool receipt, primary distribution metadata, canonical tool directory and exact owned console links | Only the primary owned tool is removable; shared/retargeted entry points, linked or ambiguous receipts and dependency distributions are refused. Removes its isolated tool environment, not other tools or runtimes. |
| pip / uv environment package | Exact isolated environment, INSTALLER provenance, REQUESTED marker, metadata, RECORD ownership and trusted interpreter location | Uses the recorded installer: pip via that interpreter’s isolated mode, or uv pip with the exact --python target. Declared reverse requirements, shared/out-of-environment recorded files, Conda and agent infrastructure are refused. No per-package filesystem fallback. |

Other managers (including Cargo, RubyGems, Conda, MacPorts, pnpm, Yarn and vendor-specific installers) are not guessed. Missing or corrupt ownership proof produces a refusal, not an arbitrary delete command. Scope checks do not prove that no external script, integration or unregistered service uses a tool; removing software can still affect its consumers.

## Manual fallback

When no verified manager is available and the target passes the existing ownership/scope protections, the preview offers **Move to Trash** and **Permanently delete…**. Cancel is the default. Permanent deletion requires a separate critical dialog and the exact phrase `DELETE <target basename>`. An available manager remains the preferred route; manager failures never silently become deletion.

The helper revalidates the confirmed plan, opens each canonical parent component without following symlinks, checks the pinned parent identity against the preview, and atomically captures the selected entry into a private sibling recovery capsule with an exclusive rename. It checks the captured device/inode/type before deleting any contents. Replacement mismatches are restored without overwriting an entry created at the original location; if restoration cannot be exclusive, all captured contents are preserved and the recovery location is reported.

Permanent deletion traverses only pinned descriptors, checks ancestor links and device identity, and removes nested symbolic links themselves rather than following them. Target/root, other-user, project, shared runtime, linked-root and mount protections remain. Cancellation before deletion restores the capture where possible; cancellation after a deletion starts can be partial and retains the remaining captured contents with a recovery journal. The app displays that recovery detail, and future scans classify valid interrupted capsules as Remnant evidence rather than installed software.

Trash uses an exclusive descriptor-relative move to the current user's private `.Trash` on the same filesystem. Existing Trash items are never overwritten; collisions get a unique name. Cross-filesystem moves refuse without copying or deleting. This direct Trash move does not register Finder **Put Back** bookkeeping; the output gives the Trash location so the item can be restored manually. No native path-only recycle handoff remains.

Recovery capsules are named `.mac-inventory-removal-<random>` beside the original target. `recovery.json` records original location, intended method and object identities before capture. Reported recovery paths are best effort if an ancestor moved; device/inode information is included. Do not assume that an interrupted permanent deletion is reversible or complete. The app does not automatically restore interrupted operations.

These safeguards resist the tested path-replacement and symlink races. They are not a transaction against an actively hostile process with the same user identity or against privileged mount/filesystem changes. No shell, wildcard or sudo is used.

## Progress, failure and cancellation

Manager output appears in Removal status. The manager runs in its own process group with a minimal environment, no inherited agent/API credentials, no Homebrew auto-update/cleanup/analytics and no interactive stdin. Cancel signals only that owned operation and its children; it escalates to killing that owned group if needed. It does not stop unrelated apps or processes. Planning, manager work and manual removal can be cancelled. A completed Trash move remains in Trash; a permanent deletion may be partial. Recovery details are retained.

Interrupted or failed removal may be partial and is not rolled back. The app reports output/errors, verifies the selected target’s absence rather than trusting exit code alone, and starts a fresh inventory after an attempted mutation. Project npm additionally checks that the declaration is gone. No failure automatically becomes forced deletion or privilege elevation.

New scans record target/alias identity fingerprints. Legacy executable-candidate snapshots require Refresh before removal; known versioned package/app previews also corroborate live ownership/version and capture fresh identities before confirmation.

