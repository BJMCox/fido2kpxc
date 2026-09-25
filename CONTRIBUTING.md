# Contributing

## Build

You need Rust 1.89 or later from [rustup](https://rustup.rs), and the Xcode Command Line Tools (`xcode-select --install`), because the FIDO2 crate compiles C code and packaging uses `codesign`, `pkgbuild`, and `productbuild`.

```sh
git clone https://github.com/BJMCox/fido2kpxc.git
cd fido2kpxc
cargo test
cargo build --release               # target/release/fido2kpxc, under 1 MiB
cargo run -- enroll --label test    # terminal commands during development
cargo run --release                 # the menu-bar app during development
```

Run unbundled, the app gets no Accessibility grant of its own (macOS gives it to your terminal), and "Start at Login" does not work.

## Signing identity

```sh
cargo xtask cert
```

This creates a self-signed code-signing certificate, `fido2kpxc local signing`, in your login keychain once per build Mac, and asks for your password to trust it. A second run does nothing. Check it with `security find-identity -v -p codesigning`, and remove it with `security delete-identity -c "fido2kpxc local signing"`. macOS ties the Accessibility grant to this identity rather than to the binary, so rebuilds and upgrades signed with it keep the grant. Build local packages on one Mac, so they all carry the same identity.

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

The release workflow builds the tag on a GitHub-hosted runner through the reusable workflow `.github/workflows/build.yml`. It tests, signs, and builds the `.dmg` and `.pkg`, and creates their signed provenance. The signing identity sits in the `release` environment, which only `v*` tags can use, and only after approval.
