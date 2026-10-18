# Install and remove Mac Inventory beta

This experimental arm64 build was tested on Apple silicon running macOS 27.0 (26A428). The declared deployment target is macOS 13; macOS 13–26 and Intel/Rosetta have not been tested. It requires an existing working `/usr/bin/python3` from Apple's developer tools. Python is not bundled. Check `/usr/bin/python3 --version` before installing. Install Apple's developer tools through Apple's supported installer if needed.

Download the DMG and SHA256SUMS from the GitHub prerelease. In the download folder run `shasum -a 256 -c SHA256SUMS`. Open the DMG, drag Mac Inventory to Applications, and eject the image. Launch from Applications.

The app has an ad-hoc signature only. It has no Developer ID signature and is not notarized. macOS may block or warn on launch. Follow current Apple guidance for software you trust; this project does not disable Gatekeeper or remove quarantine. You can build from reviewed source instead.

Scanning reads software metadata and paths. It can take time and may encounter protected locations. Use Coverage to see exclusions and failures. No full-disk completeness is promised. Refresh/Cancel preserve the last successful snapshot. Exported JSON and the automatic snapshot contain local paths and installed-software information; review them before sharing.

To remove this app, quit it and move Mac Inventory.app to Trash. Optional: remove only `~/Library/Application Support/Mac Inventory` to discard its saved snapshot. Keep any exports you need; exports are stored wherever you chose. Removing Mac Inventory does not remove software it inventoried. For removing inventoried items, read UNINSTALL.md first. Permanent deletion cannot be undone, and package manager hooks run trusted third-party code.
