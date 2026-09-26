# Contributing

## Build

You need Rust 1.89 or later from [rustup](https://rustup.rs) and the Xcode Command Line Tools (`xcode-select --install`). The FIDO2 crate compiles C code, and packaging uses `codesign`, `pkgbuild`, and `productbuild`.

```sh
git clone https://github.com/BJMCox/fido2kpxc.git
cd fido2kpxc
cargo test
cargo build --release               # target/release/fido2kpxc, under 1 MiB
cargo run -- enroll --label test    # terminal commands during development
cargo run --release                 # the menu-bar app during development
```

When the app runs unbundled, it gets no Accessibility grant of its own. macOS gives the grant to your terminal instead, and "Start at Login" does not work.

## Signing identity

```sh
cargo xtask cert
```

This creates a self-signed code-signing certificate, `fido2kpxc local signing`, in your login keychain once per build Mac. It asks for your password to trust the certificate. A second run does nothing. Check it with `security find-identity -v -p codesigning`, and remove it with `security delete-identity -c "fido2kpxc local signing"`. macOS ties the Accessibility grant to this identity rather than to the binary, so rebuilds and upgrades signed with it keep the grant. Build local packages on one Mac, so they all carry the same identity.

## App, package, and disk image

```sh
cargo xtask bundle     # target/bundle/fido2kpxc.app, signed
cargo xtask package    # dist/fido2kpxc-<version>.pkg
cargo xtask dmg        # dist/fido2kpxc-<version>.dmg, about 0.5 MB, LZMA
cargo xtask icon       # only after editing assets/*.svg; needs rsvg-convert (brew install librsvg)
```

The disk image window layout lives in `assets/dmg/DS_Store`. After changing its background or icon positions, run `cargo xtask dmg-layout`, which lays out the window with Finder and saves the file. Terminal asks once for permission to control Finder.

`codesign -d -r- target/bundle/fido2kpxc.app` should show `certificate leaf` in the designated requirement. A `cdhash` means the identity is missing. The version comes from `[workspace.package]` in `Cargo.toml`. The package installs only `/Applications/fido2kpxc.app`, with no config, vault, or scripts. Install a local package with `sudo installer -pkg dist/fido2kpxc-<version>.pkg -target /`.

## Run CodeQL locally

`cargo xtask codeql` runs the same analysis as the `codeql` workflow, with the shared config in `.github/codeql`, and fails on any finding. Run it before pushing. It needs the full CodeQL bundle, the CLI with every query pack, which GitHub's workflow uses too:

```sh
gh release download codeql-bundle-v2.27.1 -R github/codeql-action -p 'codeql-bundle-osx64.tar.zst*'
shasum -a 256 -c codeql-bundle-osx64.tar.zst.checksum.txt
mkdir -p ~/.codeql/bundle && tar -xf codeql-bundle-osx64.tar.zst -C ~/.codeql/bundle
ln -s ~/.codeql/bundle/codeql/codeql ~/.local/bin/codeql
cargo xtask codeql
```

A run takes about three minutes. Reports and databases stay in `~/Library/Caches/fido2kpxc/codeql`. Tests live in `tests.rs` files, which the config excludes because CodeQL does not recognize `#[cfg(test)]`.

## Release

1. Raise `version` under `[workspace.package]` in `Cargo.toml`, commit, and push to `main`.
2. Run `cargo xtask release`. It checks that the tree is clean, `main` matches `origin/main`, and tag `v<version>` is new, then runs the tests and pushes the tag.
3. Approve the `release` environment in GitHub Actions.

Before step 1, run the [hand checks](#hand-checks).

The release workflow builds the tag on a GitHub-hosted runner through the reusable workflow `.github/workflows/build.yml`. It tests, signs, and builds the `.dmg` and `.pkg`, and creates their signed provenance. The signing identity sits in the `release` environment, which only `v*` tags can use, and only after approval.

After the release is published, a job uploads the installers to VirusTotal and links each scan in the release notes. Its API key sits in the `virustotal` environment, which only `v*` tags can use and which needs no approval. To set it up, create the environment with a `v*` tag rule, then run `gh secret set VT_API_KEY --env virustotal` with the key from your VirusTotal account.

## Hand checks

These checks cover what the tests cannot reach. Run them on a throwaway vault in `~/fido2kpxc-test`, never on your real vault. You need two security keys, A and B, and the current stable KeePassXC. Keep autofill at `fill-and-unlock` unless a check says otherwise.

### Start

1. Write down the KeePassXC version.
2. Create `~/fido2kpxc-test/test.kdbx` and `test2.kdbx` in KeePassXC, each with a known password. Lock both.
3. Choose "Set Up…" and pick the folder `~/fido2kpxc-test` with "Choose…". Store the `test.kdbx` password with key A, and pick `test.kdbx` as the database file. The last panel must offer "Start at Login" and "Grant Accessibility…".
4. Choose "Add Security Key…" and enroll key B. It must ask you to swap keys.
5. Choose "Set Database Password…" and store the password for `test2.kdbx`.

### Unlock

6. Unlock `test.kdbx` from the main window with the toolbar shown. The PIN panel must open. On the unlock screen, "Copy Diagnostics" must show these lines:
   - `Focused element role: AXTextField, subrole: , description: secure text field`
   - `Focused element is the first text field after the path label: true`
7. Press Ctrl+H to show the password in clear, and click into the field. No PIN panel opens. Press Ctrl+H again. The PIN panel must open.
8. Enter a wrong PIN first, then the right one. The password must fill, and KeePassXC must unlock.
9. Unlock with both keys plugged in. Both must blink, and the key you touch must unlock.
10. Switch KeePassXC to German, restart it, and unlock. Switch it back afterwards.
11. Let the unlock dialog ask for `test.kdbx`, then for `test2.kdbx`. Choose "Unlock KeePassXC". The PIN panel must name `test2.kdbx`, and `test2.kdbx` must unlock.
12. Unlock a copy of `test.kdbx` with a long path in a narrow window. If the label shortens the path, no PIN panel opens.
13. Cancel a touch, then touch the key. Nothing must fill.

### No fill

14. Set a key file on `test.kdbx`. Show the password in clear and click into the key-file field. Then hide the password and click into the key-file field again. fido2kpxc must fill neither.

### Stored passwords

15. Change the `test.kdbx` password in KeePassXC, lock it, and unlock through fido2kpxc. fido2kpxc must quote KeePassXC's message and offer "Store…". Store the new password and unlock again.
16. Choose "Remove Database Password…" and remove `test2.kdbx`. Then check every password and try to remove them. fido2kpxc must refuse.

### Modes

17. Set autofill to `fill` and unlock. The password must fill, and Unlock must stay unpressed.
18. Set autofill to `off`. Focus on the unlock screen must open no PIN panel. "Unlock KeePassXC" must still open it. Set autofill back to `fill-and-unlock`.

### Vault

19. Copy `vault.toml` to `vault 2.toml`. The first menu line must show "Sync conflict: vault 2.toml" without a restart. Delete the copy. The warning must clear.
20. Choose "Remove Security Key…" and remove key B. "Check a Security Key…" with key B must report it as not enrolled.

### Other

21. Turn on "Copy Password" in "Settings…". Copy the password and keep the menu open past the clear delay. The clipboard must clear.
22. Run `cargo test -- --ignored` with KeePassXC running.

### Finish

23. Choose "Settings…" and pick your real `vault.toml`. Unlock your real database once.
24. Add this line to the release commit of step 1: "Checked by hand with KeePassXC <version> on macOS <version>. Not checked: <items>." Name every check that did not run, such as macOS 13 or quick unlock by Touch ID.
