mod config;
mod fido;
mod kpxc;
mod ops;
mod panels;
mod ui;
mod vault;

use std::io::BufRead;

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

use config::Config;
use vault::{ANY, Vault};

const USAGE: &str = "usage: fido2kpxc [enroll --label NAME [--database FILE] | enroll-key --label NAME | remove-key --label NAME | set-secret [--database FILE] | remove-secret --database FILE | list-keys | list-databases | completions zsh | help]";
const HELP: &str = "fido2kpxc: unlock KeePassXC with a FIDO2 security key

Run without arguments to start the menu-bar app.

Commands:
  enroll --label NAME [--database FILE]  Create the vault with the first security key
  enroll-key --label NAME                Add a backup security key
  remove-key --label NAME                Remove a key and move the vault to a new data key
  set-secret [--database FILE]           Store the password for a database file, such as pdb.kdbx
  remove-secret --database FILE          Remove the stored password for a database file
  list-keys                              List the labels of the enrolled keys
  list-databases                         List the databases with a stored password
  completions zsh                        Print the zsh completion script
  help, --help, -h                       Show this help

Without --database, a password applies to any database that has no entry of its own (*).
Config: ~/Library/Application Support/fido2kpxc/config.toml
";
const COMPLETIONS: &str = include_str!("completions.zsh");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => ui::run(),
        ["enroll", "--label", label] => enroll(label, ANY),
        ["enroll", "--label", label, "--database", database] => enroll(label, database),
        ["enroll-key", "--label", label] => enroll_key(label),
        ["remove-key", "--label", label] => remove_key(label),
        ["set-secret"] => set_secret(ANY),
        ["set-secret", "--database", database] => set_secret(database),
        ["remove-secret", "--database", database] => remove_secret(database),
        ["list-keys"] => list_keys(),
        ["list-databases"] => list_databases(),
        ["help"] | ["--help"] | ["-h"] => {
            print!("{HELP}");
            Ok(())
        }
        ["completions", "zsh"] => {
            print!("{COMPLETIONS}");
            Ok(())
        }
        _ => bail!("{USAGE}\nRun `fido2kpxc help` for details."),
    }
}

fn enroll(label: &str, database: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    ops::check_new(&config)?;
    let secret = new_secret()?;
    let key = choose_key()?;
    let pin = hidden("FIDO2 PIN: ")?;
    println!("Touch your security key twice.");
    ops::create(&config, &key, label, database, secret.as_bytes(), &pin)?;
    println!("Created {}", config.vault.display());
    Ok(())
}

fn enroll_key(label: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let key = choose_key()?;
    let pin = hidden("PIN of an enrolled security key: ")?;
    println!("Touch the enrolled security key.");
    let current = ops::derive(&config, &key, &pin)?;
    println!("Plug in the new security key, then press Enter.");
    std::io::stdin().lock().read_line(&mut String::new())?;
    let key = choose_key()?;
    let pin = hidden("PIN of the new security key: ")?;
    println!("Touch the new security key twice.");
    ops::add_key(&config, &key, &current, label, &pin)?;
    println!("Added key {label:?}");
    Ok(())
}

fn remove_key(label: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    // The new data key must be wrapped for every remaining key, so each one needs a touch.
    let mut remaining = Vec::new();
    for (other, cred_id) in ops::keys_to_touch(&config, label)? {
        println!("Insert the key {other:?}, then press Enter.");
        std::io::stdin().lock().read_line(&mut String::new())?;
        let key = choose_key()?;
        let pin = hidden(&format!("PIN of {other:?}: "))?;
        println!("Touch the key {other:?}.");
        remaining.push(ops::derive_one(&config, &key, &cred_id, &pin)?);
    }
    ops::remove_key(&config, label, &remaining)?;
    println!("Removed key {label:?} and moved the vault to a new data key.");
    println!(
        "If that key was lost, change the database password in KeePassXC, then run `fido2kpxc set-secret`."
    );
    println!("Old copies of the vault still open with the removed key.");
    Ok(())
}

fn list_keys() -> Result<()> {
    let vault = Vault::load(&Config::load(&Config::path()?)?.vault)?;
    for (label, _) in vault.entries() {
        println!("{label}");
    }
    Ok(())
}

fn list_databases() -> Result<()> {
    let vault = Vault::load(&Config::load(&Config::path()?)?.vault)?;
    // Raw names, so shell completion can offer them. `*` is the catch-all entry.
    for database in vault.databases() {
        println!("{database}");
    }
    Ok(())
}

fn set_secret(database: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let secret = new_secret()?;
    let key = choose_key()?;
    let pin = hidden("FIDO2 PIN: ")?;
    println!("Touch your security key.");
    ops::set_secret(&config, &key, database, secret.as_bytes(), &pin)?;
    println!("Stored the password for {}", ops::describe(database));
    Ok(())
}

fn remove_secret(database: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let mut vault = Vault::load(&config.vault)?;
    vault.remove_secret(database)?;
    vault.save(&config.vault, false)?;
    println!("Removed the password for {}", ops::describe(database));
    Ok(())
}

/// Picks the security key before its PIN is asked, as the FIDO standard flow does. With several
/// keys plugged in, the user touches the one to use.
fn choose_key() -> Result<fido::Key> {
    if fido::devices().len() > 1 {
        println!("Touch the security key you want to use.");
    }
    ops::choose_key()
}

fn new_secret() -> Result<Zeroizing<String>> {
    let secret = hidden("KeePassXC database password: ")?;
    ensure!(!secret.is_empty(), "The password is empty");
    ensure!(
        *hidden("Repeat the password: ")? == *secret,
        "The passwords differ"
    );
    Ok(secret)
}

fn hidden(prompt: &str) -> Result<Zeroizing<String>> {
    let text = rpassword::prompt_password(prompt)
        .context("Cannot read a hidden prompt. Run this command in a Terminal window")?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests;
