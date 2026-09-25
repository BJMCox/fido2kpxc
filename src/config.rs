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

impl Autofill {
    pub const ALL: [Autofill; 3] = [Autofill::FillAndUnlock, Autofill::Fill, Autofill::Off];

    /// The value as written in the config file.
    pub fn as_str(self) -> &'static str {
        match self {
            Autofill::Off => "off",
            Autofill::Fill => "fill",
            Autofill::FillAndUnlock => "fill-and-unlock",
        }
    }
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

    /// The config file for these settings, with the same comments as [`TEMPLATE`].
    /// `folder` is kept as typed, so a `~/` path stays portable between Macs.
    pub fn render(
        folder: &str,
        autofill: Autofill,
        copy_password: bool,
        clear_seconds: u64,
    ) -> String {
        let folder = toml::Value::String(folder.to_owned());
        format!(
            "# fido2kpxc settings. The app rereads this file every 2 seconds.\n\n\
             # Required: the folder that holds vault.toml.\nfolder = {folder}\n\n\
             # Seconds before Copy Password clears the clipboard, at most 3600.\nclear_seconds = {clear_seconds}\n\n\
             # What happens when KeePassXC asks for its password: \"off\", \"fill\", or \"fill-and-unlock\".\n\
             autofill = \"{}\"\n\n\
             # Show \"Copy Password\" in the menu. It puts the password on the clipboard for clear_seconds.\n\
             copy_password = {copy_password}\n",
            autofill.as_str()
        )
    }

    /// Validates `text` as a config, as `load` would.
    pub fn check(text: &str) -> Result<Self> {
        Self::parse(text, &home()?)
    }

    /// Replaces the config file atomically.
    pub fn write(path: &Path, text: &str) -> Result<()> {
        let dir = path.parent().context("The config path has no directory")?;
        std::fs::create_dir_all(dir)?;
        let mut temp = tempfile::Builder::new()
            .prefix(".config-")
            .tempfile_in(dir)?;
        std::io::Write::write_all(&mut temp, text.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist(path)?;
        Ok(())
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

    /// Copies of the vault that a sync tool left after two Macs wrote it at once, such as
    /// Syncthing's `vault.sync-conflict-….toml`, Dropbox's `vault (… conflicted copy …).toml`,
    /// or iCloud's `vault 2.toml`. A key enrolled on one Mac may exist only in the copy.
    pub fn conflicts(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.folder) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| {
                name != "vault.toml" && name.starts_with("vault") && name.ends_with(".toml")
            })
            .collect();
        names.sort();
        names
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
mod tests;
