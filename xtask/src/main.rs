use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

const IDENTITY: &str = "fido2kpxc local signing";
const BUNDLE_ID: &str = "dev.fido2kpxc";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("cert") => cert(),
        Some("bundle") => bundle().map(|app| println!("Built {}", app.display())),
        Some("package") => package(&bundle()?).map(|pkg| println!("Built {}", pkg.display())),
        Some("dmg") => dmg(&bundle()?).map(|dmg| println!("Built {}", dmg.display())),
        Some("dmg-layout") => dmg_layout(),
        Some("installers") => installers(),
        Some("codeql") => codeql(),
        Some("release") => release(),
        Some("icon") => icon(),
        _ => bail!(
            "usage: cargo xtask <cert|icon|bundle|package|dmg|dmg-layout|installers|release|codeql>"
        ),
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("Cannot start {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn identity_exists() -> Result<bool> {
    let identities =
        run(Command::new("/usr/bin/security").args(["find-identity", "-v", "-p", "codesigning"]))?;
    Ok(identities.contains(IDENTITY))
}

/// Creates the self-signed code-signing identity once. TCC keys the Accessibility grant to it.
fn cert() -> Result<()> {
    if identity_exists()? {
        println!("{IDENTITY} already exists");
        return Ok(());
    }
    let work = root().join("target/cert");
    let _ = fs::remove_dir_all(&work);
    // LibreSSL writes the private key world-readable, so the directory must not be.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&work)?;
    let (key, cert, p12) = (
        work.join("key.pem"),
        work.join("cert.pem"),
        work.join("id.p12"),
    );
    let result = (|| {
        run(Command::new("/usr/bin/openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
            ])
            .args(["-subj", &format!("/CN={IDENTITY}")])
            .args(["-addext", "keyUsage=critical,digitalSignature"])
            .args(["-addext", "extendedKeyUsage=critical,codeSigning"])
            .args(["-addext", "basicConstraints=critical,CA:false"])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert))?;
        run(Command::new("/usr/bin/openssl")
            .args(["pkcs12", "-export", "-passout", "pass:fido2kpxc"])
            .arg("-inkey")
            .arg(&key)
            .arg("-in")
            .arg(&cert)
            .arg("-out")
            .arg(&p12))?;
        run(Command::new("/usr/bin/security")
            .arg("import")
            .arg(&p12)
            .args(["-P", "fido2kpxc", "-T", "/usr/bin/codesign"]))?;
        println!("macOS now asks for your password to trust the certificate for code signing.");
        let status = Command::new("/usr/bin/security")
            .args(["add-trusted-cert", "-p", "codeSign"])
            .arg(&cert)
            .status()?;
        ensure!(status.success(), "Trusting the certificate failed");
        Ok(())
    })();
    fs::remove_dir_all(&work)?;
    result?;
    ensure!(
        identity_exists()?,
        "{IDENTITY} is still not a valid code-signing identity"
    );
    println!("Created {IDENTITY}");
    Ok(())
}

fn bundle() -> Result<PathBuf> {
    ensure!(identity_exists()?, "Run `cargo xtask cert` first");
    let root = root();
    run(Command::new("cargo").current_dir(&root).args([
        "build",
        "--release",
        "--package",
        "fido2kpxc",
    ]))?;
    let app = root.join("target/bundle/fido2kpxc.app");
    let _ = fs::remove_dir_all(&app);
    fs::create_dir_all(app.join("Contents/MacOS"))?;
    fs::copy(
        root.join("target/release/fido2kpxc"),
        app.join("Contents/MacOS/fido2kpxc"),
    )?;
    fs::write(app.join("Contents/Info.plist"), info_plist())?;
    fs::create_dir_all(app.join("Contents/Resources"))?;
    fs::copy(
        root.join("assets/AppIcon.icns"),
        app.join("Contents/Resources/AppIcon.icns"),
    )?;
    run(Command::new("/usr/bin/codesign")
        // The hardened runtime blocks code injection and debugger attach, which would inherit the Accessibility grant.
        .args([
            "--force",
            "--options",
            "runtime",
            "--sign",
            IDENTITY,
            "--identifier",
            BUNDLE_ID,
        ])
        .arg(&app))?;
    run(Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&app))?;
    Ok(app)
}

fn package(app: &Path) -> Result<PathBuf> {
    let root = root();
    let stage = root.join("target/pkg");
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("root"))?;
    run(Command::new("/usr/bin/ditto")
        .arg(app)
        .arg(stage.join("root/fido2kpxc.app")))?;
    let components = stage.join("components.plist");
    run(Command::new("/usr/bin/pkgbuild")
        .arg("--analyze")
        .arg("--root")
        .arg(stage.join("root"))
        .arg(&components))?;
    // Otherwise Installer moves the update to any other copy with this bundle ID, such as target/bundle.
    run(Command::new("/usr/bin/plutil")
        .args(["-replace", "0.BundleIsRelocatable", "-bool", "NO"])
        .arg(&components))?;
    let core = stage.join("fido2kpxc-core.pkg");
    run(Command::new("/usr/bin/pkgbuild")
        .arg("--root")
        .arg(stage.join("root"))
        .arg("--component-plist")
        .arg(&components)
        .args(["--identifier", "dev.fido2kpxc.pkg", "--version", VERSION])
        .args(["--install-location", "/Applications"])
        .arg(&core))?;
    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let pkg = dist.join(format!("fido2kpxc-{VERSION}.pkg"));
    let template = fs::read_to_string(root.join("assets/pkg/distribution.xml"))?;
    let distribution = stage.join("distribution.xml");
    fs::write(&distribution, template.replace("@VERSION@", VERSION))?;
    run(Command::new("/usr/bin/productbuild")
        .arg("--distribution")
        .arg(&distribution)
        .arg("--resources")
        .arg(root.join("assets/pkg/resources"))
        .arg("--package-path")
        .arg(&stage)
        .arg(&pkg))?;
    Ok(pkg)
}

/// Puts the app, an Applications link, and the window assets in `stage`.
fn stage_dmg(app: &Path, stage: &Path, layout: bool) -> Result<()> {
    let root = root();
    let _ = fs::remove_dir_all(stage);
    fs::create_dir_all(stage.join(".background"))?;
    run(Command::new("/usr/bin/ditto")
        .arg(app)
        .arg(stage.join("fido2kpxc.app")))?;
    std::os::unix::fs::symlink("/Applications", stage.join("Applications"))?;
    fs::copy(
        root.join("assets/dmg/background.tiff"),
        stage.join(".background/background.tiff"),
    )?;
    fs::copy(
        root.join("assets/AppIcon.icns"),
        stage.join(".VolumeIcon.icns"),
    )?;
    if layout {
        fs::copy(root.join("assets/dmg/DS_Store"), stage.join(".DS_Store"))
            .context("Missing assets/dmg/DS_Store. Run `cargo xtask dmg-layout` once")?;
    }
    Ok(())
}

/// A drag-install disk image: the signed app next to a link to /Applications, on a branded
/// background, with the app icon as the volume icon.
fn dmg(app: &Path) -> Result<PathBuf> {
    let root = root();
    let stage = root.join("target/dmg");
    stage_dmg(app, &stage, true)?;
    let writable = root.join("target/dmg-rw.dmg");
    run(Command::new("/usr/bin/hdiutil")
        .args([
            "create",
            "-volname",
            "fido2kpxc",
            "-fs",
            "HFS+",
            "-format",
            "UDRW",
            "-ov",
        ])
        .arg("-srcfolder")
        .arg(&stage)
        .arg(&writable))?;
    // Finder shows .VolumeIcon.icns only when the volume root carries the custom-icon flag.
    let mount = root.join("target/dmg-mount");
    run(Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nobrowse", "-noautoopen", "-mountpoint"])
        .arg(&mount)
        .arg(&writable))?;
    let flagged = run(Command::new("/usr/bin/SetFile")
        .args(["-a", "C"])
        .arg(&mount));
    run(Command::new("/usr/bin/hdiutil")
        .args(["detach", "-quiet"])
        .arg(&mount))?;
    flagged?;
    fs::create_dir_all(root.join("dist"))?;
    let dmg = root.join(format!("dist/fido2kpxc-{VERSION}.dmg"));
    // LZMA is less than half the size of zlib here. LZMA images need macOS 10.15+.
    run(Command::new("/usr/bin/hdiutil")
        .args(["convert", "-format", "ULMO", "-ov", "-o"])
        .arg(&dmg)
        .arg(&writable))?;
    // A stray copy with the same bundle ID confuses LaunchServices.
    fs::remove_dir_all(&stage)?;
    fs::remove_file(&writable)?;
    run(Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", IDENTITY])
        .arg(&dmg))?;
    Ok(dmg)
}

/// Lays out the disk image window with Finder and saves the result as assets/dmg/DS_Store.
/// Run it once, and again only after changing the background or icon positions.
fn dmg_layout() -> Result<()> {
    let root = root();
    let stage = root.join("target/dmg");
    stage_dmg(&bundle()?, &stage, false)?;
    let writable = root.join("target/dmg-layout.dmg");
    run(Command::new("/usr/bin/hdiutil")
        .args([
            "create",
            "-volname",
            "fido2kpxc",
            "-fs",
            "HFS+",
            "-format",
            "UDRW",
            "-ov",
        ])
        .arg("-srcfolder")
        .arg(&stage)
        .arg(&writable))?;
    run(Command::new("/usr/bin/hdiutil")
        .args(["attach", "-noautoopen"])
        .arg(&writable))?;
    // Bounds include the title bar, so the content area matches the 540 x 380 background.
    let script = r#"tell application "Finder"
        tell disk "fido2kpxc"
            open
            set current view of container window to icon view
            set toolbar visible of container window to false
            set statusbar visible of container window to false
            set the bounds of container window to {200, 120, 740, 528}
            set options to the icon view options of container window
            set arrangement of options to not arranged
            set icon size of options to 112
            set text size of options to 13
            set background picture of options to file ".background:background.tiff"
            set position of item "fido2kpxc.app" of container window to {140, 170}
            set position of item "Applications" of container window to {400, 170}
            update without registering applications
            delay 2
            close
        end tell
    end tell"#;
    let laid_out = run(Command::new("/usr/bin/osascript").args(["-e", script])).and_then(|_| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        fs::copy(
            "/Volumes/fido2kpxc/.DS_Store",
            root.join("assets/dmg/DS_Store"),
        )
        .context("Finder wrote no .DS_Store")
    });
    run(Command::new("/usr/bin/hdiutil").args(["detach", "-quiet", "/Volumes/fido2kpxc"]))?;
    laid_out?;
    fs::remove_dir_all(&stage)?;
    fs::remove_file(&writable)?;
    println!("Saved assets/dmg/DS_Store");
    Ok(())
}

/// Builds the app once, then both installers and SHA256SUMS in dist/. CI runs this for releases.
/// With RELEASE_TAG set, refuses a tag that does not match the version.
fn installers() -> Result<()> {
    if let Ok(tag) = std::env::var("RELEASE_TAG") {
        ensure!(
            tag == format!("v{VERSION}"),
            "Tag {tag} does not match version {VERSION} in Cargo.toml"
        );
    }
    let app = bundle()?;
    let installers = [package(&app)?, dmg(&app)?];
    let dist = root().join("dist");
    let names: Vec<&str> = installers
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .context("Installer name")
        })
        .collect::<Result<_>>()?;
    let sums = run(Command::new("/usr/bin/shasum")
        .current_dir(&dist)
        .args(["-a", "256"])
        .args(&names))?;
    fs::write(dist.join("SHA256SUMS"), sums)?;
    println!(
        "Built {} and SHA256SUMS in {}",
        names.join(", "),
        dist.display()
    );
    Ok(())
}

/// Runs the same CodeQL analysis as the codeql workflow, with the shared config, and fails on
/// any finding. Needs the CodeQL bundle, the CLI with all query packs that GitHub's workflow uses,
/// with `codeql` on the PATH. See "Run CodeQL locally" in CONTRIBUTING.md.
fn codeql() -> Result<()> {
    let root = root();
    // The macOS place for rebuildable data. It sits outside the source tree, so extraction never
    // reads its own databases, and keeps the reports and databases for inspection after a run.
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let out = PathBuf::from(home).join("Library/Caches/fido2kpxc/codeql");
    fs::create_dir_all(&out)?;
    let config = root.join(".github/codeql/codeql-config.yml");
    let mut findings = Vec::new();
    for language in ["rust", "actions"] {
        let database = out.join(language);
        println!("CodeQL: analyzing {language}…");
        run(Command::new("codeql")
            .current_dir(&root)
            .args(["database", "create", "--overwrite", "--build-mode=none"])
            .arg(format!("--language={language}"))
            .arg(format!("--codescanning-config={}", config.display()))
            .arg("--source-root=.")
            .arg(&database))?;
        let csv = out.join(format!("{language}.csv"));
        run(Command::new("codeql")
            .args(["database", "analyze", "--format=csv"])
            .arg(format!("--output={}", csv.display()))
            .arg(&database)
            .arg(format!(
                "codeql/{language}-queries:codeql-suites/{language}-security-extended.qls"
            )))?;
        findings.extend(
            fs::read_to_string(&csv)?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| format!("{language}: {line}")),
        );
    }
    for finding in &findings {
        println!("{finding}");
    }
    println!("Reports and databases: {}", out.display());
    ensure!(
        findings.is_empty(),
        "CodeQL reported {} finding(s)",
        findings.len()
    );
    println!("CodeQL: no findings");
    Ok(())
}

/// Tags v<version> and pushes the tag. The release workflow then builds, attests, and publishes.
fn release() -> Result<()> {
    let root = root();
    let git = |args: &[&str]| run(Command::new("git").current_dir(&root).args(args));
    let tag = format!("v{VERSION}");
    ensure!(
        git(&["status", "--porcelain"])?.trim().is_empty(),
        "Commit or stash your changes first"
    );
    ensure!(
        git(&["rev-parse", "--abbrev-ref", "HEAD"])?.trim() == "main",
        "Release from main"
    );
    git(&["fetch", "--quiet", "--tags", "origin"])?;
    ensure!(
        git(&["rev-parse", "HEAD"])? == git(&["rev-parse", "origin/main"])?,
        "main must match origin/main. Push or pull first"
    );
    ensure!(
        git(&["tag", "--list", &tag])?.trim().is_empty(),
        "Tag {tag} exists. Raise version in Cargo.toml first"
    );
    run(Command::new("cargo")
        .current_dir(&root)
        .args(["test", "--workspace", "--locked"]))?;
    git(&["tag", "-a", &tag, "-m", &format!("fido2kpxc {VERSION}")])?;
    git(&["push", "origin", &tag])?;
    println!(
        "Pushed {tag}. Approve the release environment in GitHub Actions to build and publish it."
    );
    Ok(())
}

/// Regenerates assets/AppIcon.icns from assets/icon.svg and assets/menubar.pdf from
/// assets/menubar.svg. Needs `rsvg-convert` (Homebrew librsvg).
fn icon() -> Result<()> {
    let root = root();
    let set = root.join("target/AppIcon.iconset");
    let _ = fs::remove_dir_all(&set);
    fs::create_dir_all(&set)?;
    // 512 pt sizes only serve huge Finder previews and would double the file size.
    for size in [16, 32, 128, 256] {
        for (scale, suffix) in [(1, ""), (2, "@2x")] {
            let pixels = (size * scale).to_string();
            run(Command::new("rsvg-convert")
                .args(["-w", &pixels, "-h", &pixels])
                .arg(root.join("assets/icon.svg"))
                .arg("-o")
                .arg(set.join(format!("icon_{size}x{size}{suffix}.png"))))?;
        }
    }
    run(Command::new("/usr/bin/iconutil")
        .args(["-c", "icns", "-o"])
        .arg(root.join("assets/AppIcon.icns"))
        .arg(&set))?;
    for name in ["menubar", "menubar-warning"] {
        run(Command::new("rsvg-convert")
            .args(["-f", "pdf"])
            .arg(root.join(format!("assets/{name}.svg")))
            .arg("-o")
            .arg(root.join(format!("assets/{name}.pdf"))))?;
    }
    // The installer logo, at 1x and 2x in one TIFF so Installer picks the sharp one.
    let logo = |pixels: &str, name: &str| {
        run(Command::new("rsvg-convert")
            .args(["-w", pixels, "-h", pixels])
            .arg(root.join("assets/icon.svg"))
            .arg("-o")
            .arg(set.join(name)))
    };
    logo("128", "logo.png")?;
    logo("256", "logo@2x.png")?;
    run(Command::new("/usr/bin/tiffutil")
        .arg("-cathidpicheck")
        .arg(set.join("logo.png"))
        .arg(set.join("logo@2x.png"))
        .arg("-out")
        .arg(root.join("assets/pkg/resources/logo.tiff")))?;
    println!(
        "Built assets/AppIcon.icns, assets/menubar.pdf, assets/menubar-warning.pdf, and assets/pkg/resources/logo.tiff"
    );
    Ok(())
}

fn info_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{BUNDLE_ID}</string>
<key>CFBundleName</key><string>fido2kpxc</string>
<key>CFBundleExecutable</key><string>fido2kpxc</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>{VERSION}</string>
<key>CFBundleVersion</key><string>{VERSION}</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>LSUIElement</key><true/>
</dict></plist>
"#
    )
}
