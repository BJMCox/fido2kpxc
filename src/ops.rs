//! Vault operations shared by the terminal commands and the menu panels. Each one loads the
//! vault, does its FIDO2 work, and saves, so callers only collect input.

use anyhow::{Result, bail, ensure};

use crate::config::Config;
use crate::fido::{self, FidoError, Key};
use crate::vault::{ANY, Check, Unlock, Vault};

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

/// Derives the output of whichever key in `left` the inserted key is. Needs one touch.
pub fn derive_needed(
    config: &Config,
    key: &Key,
    left: &[(String, Vec<u8>)],
    pin: &str,
) -> Result<Unlock> {
    let vault = Vault::load(&config.vault)?;
    let cred_ids: Vec<&[u8]> = left.iter().map(|(_, id)| id.as_slice()).collect();
    match fido::derive(key, pin, &vault.salt(), &cred_ids) {
        Err(FidoError::NotEnrolled) => bail!("This key is not {}.", needed(left)),
        other => Ok(other?),
    }
}

/// Takes the key enrolled as `cred_id` out of `left` and returns its label.
pub fn touched(left: &mut Vec<(String, Vec<u8>)>, cred_id: &[u8]) -> Option<String> {
    let index = left.iter().position(|(_, id)| id == cred_id)?;
    Some(left.remove(index).0)
}

/// The labels in `left`, for "Insert {needed}".
pub fn needed(left: &[(String, Vec<u8>)]) -> String {
    left.iter()
        .map(|(label, _)| format!("{label:?}"))
        .collect::<Vec<_>>()
        .join(" or ")
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

/// Removes the keys in `labels` and moves every password to a new data key wrapped for `remaining`.
pub fn remove_keys(config: &Config, labels: &[String], remaining: &[Unlock]) -> Result<()> {
    let mut vault = Vault::load(&config.vault)?;
    vault.remove_keys(&as_strs(labels), remaining)?;
    vault.save(&config.vault, false)
}

/// Labels and credential IDs of every key that stays after removing `labels`. `remove_keys`
/// needs each of them touched.
pub fn keys_to_touch(config: &Config, labels: &[String]) -> Result<Vec<(String, Vec<u8>)>> {
    let vault = Vault::load(&config.vault)?;
    Ok(vault
        .kept_keys(&as_strs(labels))?
        .into_iter()
        .map(|(label, id)| (label.to_owned(), id.to_vec()))
        .collect())
}

/// The first line of the report after `remove_keys`.
pub fn removed(labels: &[String]) -> String {
    let quoted: Vec<String> = labels.iter().map(|l| format!("{l:?}")).collect();
    let names = match quoted.as_slice() {
        [one] => format!("key {one}"),
        [first, second] => format!("keys {first} and {second}"),
        [rest @ .., last] => format!("keys {}, and {last}", rest.join(", ")),
        [] => "no keys".to_owned(),
    };
    format!("Removed {names} and moved the vault to a new data key.")
}

fn as_strs(labels: &[String]) -> Vec<&str> {
    labels.iter().map(String::as_str).collect()
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

/// Reports which enrolled key is inserted and whether it opens every stored password, which
/// the second value tells scripts. Needs one touch and fills nothing.
pub fn check_key(config: &Config, key: &Key, pin: &str) -> Result<(String, bool)> {
    let vault = Vault::load(&config.vault)?;
    let unlock = fido::derive(key, pin, &vault.salt(), &vault.cred_ids())?;
    let check = vault.check(&unlock)?;
    Ok((report(&check), check_ok(&check)))
}

fn check_ok(check: &Check) -> bool {
    check.failed.is_empty()
}

/// Removes the passwords for `names` in one save. The vault keeps at least one password.
pub fn remove_secrets(config: &Config, names: &[String]) -> Result<()> {
    let mut vault = Vault::load(&config.vault)?;
    for name in names {
        vault.remove_secret(name)?;
    }
    vault.save(&config.vault, false)
}

/// The report after `remove_secrets`.
pub fn removal_report(names: &[String]) -> String {
    let described: Vec<&str> = names.iter().map(|name| describe(name)).collect();
    match described.as_slice() {
        [one] => format!("Removed the password for {one}."),
        [first, second] => format!("Removed the passwords for {first} and {second}."),
        [rest @ .., last] => format!("Removed the passwords for {}, and {last}.", rest.join(", ")),
        [] => "Removed no passwords.".to_owned(),
    }
}

/// The vault keys passwords by database file name, so a path reduces to its file name, and a
/// blank name means any database without its own entry.
pub fn database_name(input: &str) -> String {
    match input.trim() {
        "" => ANY.to_owned(),
        name => std::path::Path::new(name)
            .file_name()
            .map_or_else(|| name.to_owned(), |f| f.to_string_lossy().into_owned()),
    }
}

fn report(check: &Check) -> String {
    let list = |names: &[String]| {
        names
            .iter()
            .map(|name| describe(name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let opens = match (check.opened.as_slice(), check.failed.is_empty()) {
        ([], true) => "The vault holds no passwords yet.".to_owned(),
        ([only], true) => format!("It opens the stored password for {}.", describe(only)),
        (all, true) => format!(
            "It opens all {} stored passwords: {}.",
            all.len(),
            list(all)
        ),
        ([], false) => format!(
            "The password for {} fails to decrypt. Store it again.",
            list(&check.failed)
        ),
        (some, false) => format!(
            "It opens {}, but the password for {} fails to decrypt. Store it again.",
            list(some),
            list(&check.failed)
        ),
    };
    format!("This key is enrolled as {:?}. {opens}", check.label)
}

/// Names the catch-all entry in words, so messages never show a bare `*`.
pub fn describe(database: &str) -> &str {
    if database == ANY {
        "any other database (*)"
    } else {
        database
    }
}

#[cfg(test)]
mod tests;
