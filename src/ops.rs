//! Vault operations shared by the terminal commands and the menu panels. Each one loads the
//! vault, does its FIDO2 work, and saves, so callers only collect input.

use anyhow::{Result, ensure};

use crate::config::Config;
use crate::fido::{self, Key};
use crate::vault::{ANY, Unlock, Vault};

/// The security key to use: the only one plugged in, or the one the user touches among several.
pub fn choose_key() -> Result<Key> {
    Ok(fido::select(fido::devices())?)
}

/// Creates the vault with its first key. Needs two touches.
pub fn create(
    config: &Config,
    key: &Key,
    label: &str,
    database: &str,
    secret: &[u8],
    pin: &str,
) -> Result<()> {
    check_new(config)?;
    let salt = Vault::new_salt()?;
    let unlock = fido::enroll(key, pin, &salt, &[])?;
    Vault::create(salt, label, &unlock, database, secret)?.save(&config.vault, true)
}

/// Fails before any touch when `create` could not succeed.
pub fn check_new(config: &Config) -> Result<()> {
    config.check_folder()?;
    ensure!(
        !config.vault.exists(),
        "A vault already exists at {}",
        config.vault.display()
    );
    Ok(())
}

/// Derives the output of whichever enrolled key is inserted. Needs one touch.
pub fn derive(config: &Config, key: &Key, pin: &str) -> Result<Unlock> {
    let vault = Vault::load(&config.vault)?;
    Ok(fido::derive(key, pin, &vault.salt(), &vault.cred_ids())?)
}

/// Derives the output of the key enrolled as `cred_id`. Needs one touch.
pub fn derive_one(config: &Config, key: &Key, cred_id: &[u8], pin: &str) -> Result<Unlock> {
    let vault = Vault::load(&config.vault)?;
    Ok(fido::derive(key, pin, &vault.salt(), &[cred_id])?)
}

/// Enrolls the inserted key as `label`, unlocking with `current`. Needs two touches.
pub fn add_key(config: &Config, key: &Key, current: &Unlock, label: &str, pin: &str) -> Result<()> {
    let mut vault = Vault::load(&config.vault)?;
    // Checked before the touches, which vault.add_key would only reach afterwards.
    ensure!(
        vault.entries().iter().all(|(l, _)| *l != label),
        "Label {label:?} already exists"
    );
    let new = fido::enroll(key, pin, &vault.salt(), &vault.cred_ids())?;
    vault.add_key(current, label, &new)?;
    vault.save(&config.vault, false)
}

/// Removes `label` and moves every password to a new data key wrapped for `remaining`.
pub fn remove_key(config: &Config, label: &str, remaining: &[Unlock]) -> Result<()> {
    let mut vault = Vault::load(&config.vault)?;
    vault.remove_key(label, remaining)?;
    vault.save(&config.vault, false)
}

/// Labels and credential IDs of every key except `label`, which `remove_key` needs touched.
pub fn keys_to_touch(config: &Config, label: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let vault = Vault::load(&config.vault)?;
    let entries = vault.entries();
    ensure!(
        entries.iter().any(|(l, _)| *l == label),
        "No key is labeled {label:?}"
    );
    ensure!(entries.len() > 1, "The last key cannot be removed");
    Ok(entries
        .into_iter()
        .filter(|(l, _)| *l != label)
        .map(|(l, id)| (l.to_owned(), id.to_vec()))
        .collect())
}

/// Stores the password for `database`. Needs one touch.
pub fn set_secret(
    config: &Config,
    key: &Key,
    database: &str,
    secret: &[u8],
    pin: &str,
) -> Result<()> {
    let mut vault = Vault::load(&config.vault)?;
    let unlock = fido::derive(key, pin, &vault.salt(), &vault.cred_ids())?;
    vault.set_secret(&unlock, database, secret)?;
    vault.save(&config.vault, false)
}

/// Names the catch-all entry in words, so messages never show a bare `*`.
pub fn describe(database: &str) -> &str {
    if database == ANY {
        "any other database (*)"
    } else {
        database
    }
}
