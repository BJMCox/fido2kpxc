use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Autofill {
    Off,
    Fill,
    #[default]
    FillAndUnlock,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The folder that holds the vault.
    pub folder: PathBuf,
    /// `<folder>/vault.toml`.
    #[serde(skip)]
    pub vault: PathBuf,
    #[serde(default = "default_clear_seconds")]
    pub clear_seconds: u64,
    #[serde(default)]
    pub autofill: Autofill,
    /// Shows "Copy Password" in the menu. Off by default, so the password never reaches the clipboard.
    #[serde(default)]
    pub copy_password: bool,
}

/// Written by "Open Config…" when no config exists. Every key is commented out until the user edits it.
pub const TEMPLATE: &str = r#"# fido2kpxc settings. The app rereads this file every 2 seconds.

# Required: the folder that holds vault.toml.
# folder = "~/Synced/fido2kpxc"

# Seconds before Copy Password clears the clipboard, at most 3600.
# clear_seconds = 20

# What happens when KeePassXC asks for its password: "off", "fill", or "fill-and-unlock".
# autofill = "fill-and-unlock"

# Show "Copy Password" in the menu. It puts the password on the clipboard for clear_seconds.
# copy_password = false
"#;

fn default_clear_seconds() -> u64 {
    20
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(home()?.join("Library/Application Support/fido2kpxc/config.toml"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read config {}", path.display()))?;
        Self::parse(&text, &home()?).with_context(|| format!("Invalid config {}", path.display()))
    }

    /// Writes [`TEMPLATE`] to `path` unless a config already exists there.
    pub fn write_template(path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => Ok(std::io::Write::write_all(&mut file, TEMPLATE.as_bytes())?),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Fails unless the folder exists or its parent does, so `enroll` can create it.
    pub fn check_folder(&self) -> Result<()> {
        ensure!(
            self.folder.is_dir() || self.folder.parent().is_some_and(Path::is_dir),
            "Neither {} nor its parent folder exists. Check folder in the config.",
            self.folder.display()
        );
        Ok(())
    }

    fn parse(text: &str, home: &Path) -> Result<Self> {
        let mut config: Self = toml::from_str(text)?;
        // Each Mac keeps the folder under a different home, so allow `~/`.
        if let Ok(rest) = config.folder.strip_prefix("~") {
            config.folder = home.join(rest);
        }
        ensure!(
            config.clear_seconds <= 3600,
            "clear_seconds must be at most 3600"
        );
        ensure!(
            config.folder.is_absolute(),
            "folder must be an absolute path or start with ~/"
        );
        config.vault = config.folder.join("vault.toml");
        Ok(config)
    }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_lives_in_the_configured_folder() {
        let config = Config::parse(r#"folder = "/s""#, Path::new("/h")).unwrap();
        assert_eq!(config.vault, Path::new("/s/vault.toml"));
        assert_eq!(config.clear_seconds, 20);
        assert_eq!(config.autofill, Autofill::FillAndUnlock);
        assert!(!config.copy_password);
    }

    #[test]
    fn template_documents_every_key_with_its_default() {
        let uncommented = TEMPLATE
            .replace("# copy_password", "copy_password")
            .replace("# folder", "folder")
            .replace("# clear", "clear")
            .replace("# autofill", "autofill");
        let config = Config::parse(&uncommented, Path::new("/Users/me")).unwrap();
        assert_eq!(
            config.vault,
            Path::new("/Users/me/Synced/fido2kpxc/vault.toml")
        );
        assert_eq!(config.clear_seconds, default_clear_seconds());
        assert_eq!(config.autofill, Autofill::default());
        assert!(!config.copy_password);
    }

    #[test]
    fn clear_delay_beyond_an_hour_is_rejected() {
        let text = "folder = \"/s\"\nclear_seconds = 9223372036854775807";
        assert!(Config::parse(text, Path::new("/h")).is_err());
    }

    #[test]
    fn tilde_expands_to_home() {
        let config = Config::parse(
            "folder = \"~/Synced\"\nautofill = \"fill\"",
            Path::new("/Users/me"),
        )
        .unwrap();
        assert_eq!(config.vault, Path::new("/Users/me/Synced/vault.toml"));
        assert_eq!(config.autofill, Autofill::Fill);
    }
}
