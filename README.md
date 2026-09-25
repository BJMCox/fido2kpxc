# fido2kpxc

A macOS menu-bar app that unlocks KeePassXC with a FIDO2 security key: a PIN and a touch.

When KeePassXC asks for the database password, fido2kpxc shows a PIN dialog. After the PIN and a touch, it fills KeePassXC's password field and presses Unlock. The password never reaches the clipboard. An optional "Copy Password" menu item, off by default, serves as a fallback.

The vault holds the database password, encrypted under a random data key. Each enrolled security key wraps that data key with its FIDO2 hmac-secret output. The security key checks the PIN in hardware, so a wrong PIN yields no key.

## Requirements

- macOS 13 or later
- A FIDO2 security key with hmac-secret support and a FIDO2 PIN. Any brand works, for example YubiKey, Token2, or Google Titan. `enroll` refuses a key without hmac-secret. Set the PIN with the vendor's tool, or in Chrome at `chrome://settings/securityKeys`.
- KeePassXC 2.7 or later

## Install

1. Download the `.dmg` or `.pkg` from the GitHub Release.
   - `.dmg`: open it and drag fido2kpxc to Applications.
   - `.pkg`: open it. It installs a root-owned `/Applications/fido2kpxc.app` and runs no scripts.

   Both are self-signed. On first launch, right-click the app and choose Open, because Gatekeeper does not know the certificate.
2. Write `~/Library/Application Support/fido2kpxc/config.toml`:

   ```toml
   folder = "~/Sync/fido2kpxc"        # required: the folder that holds vault.toml
   autofill = "fill-and-unlock"    # "off", "fill", or "fill-and-unlock"
   copy_password = false           # true shows "Copy Password" in the menu
   clear_seconds = 20              # clipboard clear delay for Copy Password, at most 3600
   ```

   The vault is `<folder>/vault.toml`. Give it a folder of its own. `enroll` creates `folder` when its parent exists.

3. Put the `fido2kpxc` command on your `PATH`, using any folder that is already on it:

   ```sh
   ln -s /Applications/fido2kpxc.app/Contents/MacOS/fido2kpxc ~/.local/bin/fido2kpxc
   ```

   The link follows reinstalls, so the command always matches the app.

4. In a Terminal window, enroll your security key. Enter the database password twice, then the PIN, then touch the key twice:

   ```sh
   fido2kpxc enroll --label primary
   ```

5. Open fido2kpxc. Choose "Grant Accessibility…" in its menu and allow it in System Settings.
6. Optional: choose "Start at Login".

To use the vault on another Mac, sync or copy `folder` there with any tool you like. Install the package and write that Mac's `config.toml` with its own `folder` path. No second enrollment is needed.

## Commands

| Command | Action |
|---|---|
| `fido2kpxc enroll --label NAME [--database FILE]` | Creates the vault with the first security key. |
| `fido2kpxc enroll-key --label NAME` | Adds a backup security key, which may be another brand. Unlock with an enrolled key first, then swap keys. |
| `fido2kpxc remove-key --label NAME` | Removes a key, for example a lost one, and moves the vault to a new data key. Every remaining key needs a touch. |
| `fido2kpxc set-secret [--database FILE]` | Stores the password for a database file, such as `pdb.kdbx`. Without `--database`, it applies to any database that has no entry of its own (`*`). |
| `fido2kpxc remove-secret --database FILE` | Removes the stored password for a database file. |
| `fido2kpxc list-keys` | Lists the labels of the enrolled keys. |
| `fido2kpxc list-databases` | Lists the databases with a stored password. |
| `fido2kpxc completions zsh` | Prints the zsh completion script. |
| `fido2kpxc help`, `--help`, `-h` | Shows the commands. |

The menu offers the same key and password actions without the terminal: "Set Up…", "Add Security Key…", "Remove Security Key…", and "Set Database Password…".

### Several databases

The vault stores one password per database file name. fido2kpxc reads the file name from KeePassXC's unlock screen, so it knows which password to fill. An entry named `*` covers every database without its own entry. Vaults from before this feature hold a single `*` entry and keep working.

### Tab completion (zsh)

```sh
fido2kpxc completions zsh > ~/.zfunc/_fido2kpxc   # any folder on your $fpath
exec zsh
```

It completes commands, `--label`, and the enrolled labels for `remove-key`.

## Build

### Prerequisites

- Rust 1.89 or later, from [rustup](https://rustup.rs)
- Xcode Command Line Tools: `xcode-select --install`. The FIDO2 crate compiles C code, and packaging uses `codesign`, `pkgbuild`, and `productbuild`.

### Build and test

```sh
git clone https://github.com/BJMCox/fido2kpxc.git
cd fido2kpxc
cargo test
cargo build --release    # target/release/fido2kpxc, under 1 MiB
```

For development, run the binary without a bundle:

```sh
cargo run -- enroll --label test    # terminal commands work as usual
cargo run --release                 # the menu-bar app
```

An unbundled app has two limits. macOS gives the Accessibility grant to your terminal app instead of fido2kpxc, and "Start at Login" does not work.

### Create the signing identity (once per build Mac)

```sh
cargo xtask cert
```

This creates a self-signed code-signing certificate named `fido2kpxc local signing` in your login keychain. macOS asks for your password to trust it for code signing. Check it with `security find-identity -v -p codesigning`. A second run does nothing.

macOS ties the Accessibility grant to this identity instead of to the exact binary. Rebuilds and upgrades signed with it keep the grant. Build every package on the same Mac, so every Mac that installs it gets the same identity.

To remove the identity later, run `security delete-identity -c "fido2kpxc local signing"`.

### Regenerate the app icon (only after editing the SVG)

```sh
brew install librsvg     # provides rsvg-convert
cargo xtask icon
```

This renders `assets/icon.svg` into `assets/AppIcon.icns`. The repository ships the generated `.icns`, so normal builds skip this step.

### Build the app bundle

```sh
cargo xtask bundle
```

This builds the release binary, assembles `target/bundle/fido2kpxc.app`, and signs it. `codesign -d -r- target/bundle/fido2kpxc.app` should show `certificate leaf` in the designated requirement. If it shows a `cdhash` instead, the identity is missing.

### Build the installer package

```sh
cargo xtask package
```

This writes `dist/fido2kpxc-<version>.pkg`. The version comes from `[workspace.package]` in `Cargo.toml`. The package installs only `/Applications/fido2kpxc.app`, contains no config or vault, and runs no scripts.

### Build the disk image

```sh
cargo xtask dmg
```

This writes `dist/fido2kpxc-<version>.dmg`, about 0.5 MB: the signed app next to a link to `/Applications`, compressed with LZMA.

### Release

1. Raise `version` under `[workspace.package]` in `Cargo.toml`, commit, and push to `main`.
2. Run:

   ```sh
   cargo xtask release
   ```

   It checks that the tree is clean, that `main` matches `origin/main`, and that tag `v<version>` is new. Then it runs the tests and pushes the tag.
3. Approve the `release` environment in GitHub Actions.

The release workflow builds the tag on a GitHub-hosted runner through the reusable workflow `.github/workflows/build.yml`. That workflow tests, signs, and builds the `.dmg` and `.pkg`, then creates signed SLSA build provenance for both (SLSA Build Level 3). The signing identity sits in the `release` environment, which only `v*` tags can use, and only after approval.

### Install, upgrade, and uninstall

- **Install:** open the package, or run `sudo installer -pkg dist/fido2kpxc-<version>.pkg -target /`. Then follow [Install](#install).
- **Other Macs:** copy the package with a sync tool, `scp`, or a USB drive. Copied files carry no quarantine flag, so Gatekeeper lets them install. A package downloaded through a browser needs approval under System Settings > Privacy & Security.
- **Upgrade:** choose "Quit" in the fido2kpxc menu, install the new package, and open fido2kpxc again. The Accessibility grant stays.
- **Uninstall:** uncheck "Start at Login", quit fido2kpxc, and run:

  ```sh
  sudo rm -rf /Applications/fido2kpxc.app
  sudo pkgutil --forget dev.fido2kpxc.pkg
  rm -rf ~/Library/Application\ Support/fido2kpxc
  ```

  Then remove fido2kpxc from System Settings > Privacy & Security > Accessibility. The vault folder stays where you put it.

## Verify a release

Each release carries signed SLSA build provenance, which records that GitHub Actions built the file from this repository's tag with `build.yml`. Check a download with the GitHub CLI:

```sh
gh attestation verify fido2kpxc-<version>.dmg --repo BJMCox/fido2kpxc \
  --signer-workflow BJMCox/fido2kpxc/.github/workflows/build.yml
```

`SHA256SUMS` lists the checksums of both installers. Check them with `shasum -a 256 -c SHA256SUMS`.

## Limits

- Detection matches KeePassXC's English UI text. After a KeePassXC update or with another UI language, autofill can stop. Type the password by hand, or enable `copy_password` as a fallback.
- A blocked FIDO2 PIN needs a FIDO2 reset with the vendor's tool, such as `ykman fido reset`, which erases the enrollment. Enroll a backup key with `enroll-key`.

## License

Copyright 2026 Jessica Cox <jmcox@posteo.de>

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
