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

const USAGE: &str = "usage: fido2kpxc [enroll --label NAME [--database FILE] | enroll-key --label NAME | remove-key --label NAME [--label NAME ...] | check-key | set-secret [--database FILE] | remove-secret --database FILE | list-keys | list-databases | completions zsh | help]";
const HELP: &str = "fido2kpxc: unlock KeePassXC with a FIDO2 security key

Run without arguments to start the menu-bar app.

Commands:
  enroll --label NAME [--database FILE]  Create the vault with the first security key
  enroll-key --label NAME                Add a backup security key
  remove-key --label NAME [--label ...]  Remove keys and move the vault to a new data key
  check-key                              Show which enrolled key is plugged in and test it
  set-secret [--database FILE]           Store the password for a database file, such as pdb.kdbx
  remove-secret --database FILE          Remove the stored password for a database file
  list-keys                              List the labels of the enrolled keys
  list-databases                         List the databases with a stored password
  completions zsh                        Print the zsh completion script
  help, --help, -h                       Show this help

FILE is a database file name. A path counts as its file name. Without --database, a password
applies to any database that has no entry of its own (*).
Config: ~/Library/Application Support/fido2kpxc/config.toml
";
const COMPLETIONS: &str = include_str!("completions.zsh");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => ui::run(),
        ["enroll", "--label", label] => enroll(label, ANY),
        ["enroll", "--label", label, "--database", database] => {
            enroll(label, &ops::database_name(database))
        }
        ["enroll-key", "--label", label] => enroll_key(label),
        ["remove-key", rest @ ..] => match labels(rest) {
            Some(labels) => remove_keys(&labels),
            None => bail!("{USAGE}\nRun `fido2kpxc help` for details."),
        },
        ["check-key"] => check_key(),
        ["set-secret"] => set_secret(ANY),
        ["set-secret", "--database", database] => set_secret(&ops::database_name(database)),
        ["remove-secret", "--database", database] => remove_secret(&ops::database_name(database)),
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
    with_pin("FIDO2 PIN: ", "Touch your security key twice.", |pin| {
        ops::create(&config, &key, label, database, secret.as_bytes(), pin)
    })?;
    println!("Created {}", config.vault.display());
    Ok(())
}

fn enroll_key(label: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let key = choose_key()?;
    let current = with_pin(
        "PIN of an enrolled security key: ",
        "Touch the enrolled security key.",
        |pin| ops::derive(&config, &key, pin),
    )?;
    println!("Plug in the new security key, then press Enter.");
    wait_for_enter()?;
    let key = choose_key()?;
    with_pin(
        "PIN of the new security key: ",
        "Touch the new security key twice.",
        |pin| ops::add_key(&config, &key, &current, label, pin),
    )?;
    println!("Added key {label:?}");
    Ok(())
}

/// The labels of `--label NAME` pairs, or `None` if `args` holds anything else.
fn labels(args: &[&str]) -> Option<Vec<String>> {
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return None;
    }
    args.chunks(2)
        .map(|pair| (pair[0] == "--label").then(|| pair[1].to_owned()))
        .collect()
}

fn remove_keys(labels: &[String]) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    // The new data key must be wrapped for every kept key, so each one needs a touch, in any
    // order. A failed touch asks again and keeps the keys already touched.
    let mut left = ops::keys_to_touch(&config, labels)?;
    let mut remaining = Vec::new();
    while !left.is_empty() {
        println!("Insert {}, then press Enter.", ops::needed(&left));
        wait_for_enter()?;
        let unlock = choose_key().and_then(|key| {
            with_pin("FIDO2 PIN: ", "Touch the key.", |pin| {
                ops::derive_needed(&config, &key, &left, pin)
            })
        });
        match unlock {
            Ok(unlock) => {
                if let Some(label) = ops::touched(&mut left, &unlock.cred_id) {
                    println!("Touched {label:?}.");
                }
                remaining.push(unlock);
            }
            Err(error) => eprintln!("{error:#}"),
        }
    }
    ops::remove_keys(&config, labels, &remaining)?;
    println!("{}", ops::removed(labels));
    println!(
        "If a removed key was lost, change the database password in KeePassXC, then run `fido2kpxc set-secret`."
    );
    println!("Old copies of the vault still open with the removed keys.");
    Ok(())
}

fn check_key() -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let key = choose_key()?;
    let (report, ok) = with_pin("FIDO2 PIN: ", "Touch your security key.", |pin| {
        ops::check_key(&config, &key, pin)
    })?;
    // A failing password exits with status 1, so scripts notice a damaged vault.
    ensure!(ok, "{report}");
    println!("{report}");
    Ok(())
}

fn list_keys() -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let vault = Vault::load(&config.vault)?;
    for (label, _) in vault.entries() {
        println!("{label}");
    }
    // On stderr, so shell completion still reads only labels.
    for name in config.conflicts() {
        eprintln!(
            "Warning: sync conflict {name} in {}. Keep both files until you have compared them. See the README.",
            config.folder.display()
        );
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
    with_pin("FIDO2 PIN: ", "Touch your security key.", |pin| {
        ops::set_secret(&config, &key, database, secret.as_bytes(), pin)
    })?;
    println!("Stored the password for {}", ops::describe(database));
    Ok(())
}

fn remove_secret(database: &str) -> Result<()> {
    let config = Config::load(&Config::path()?)?;
    let names = [database.to_owned()];
    ops::remove_secrets(&config, &names)?;
    println!("{}", ops::removal_report(&names));
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

/// Asks for the PIN, prints `touch`, and runs `op`. After a wrong PIN it asks again, while the
/// key counts down its tries.
fn with_pin<T>(prompt: &str, touch: &str, op: impl Fn(&str) -> Result<T>) -> Result<T> {
    loop {
        let pin = hidden(prompt)?;
        println!("{touch}");
        match op(&pin) {
            Err(error) if fido::wrong_pin(&error) => eprintln!("{error:#}"),
            other => return other,
        }
    }
}

/// Waits for Enter. Fails at the end of input, so a loop that waits cannot spin.
fn wait_for_enter() -> Result<()> {
    let read = std::io::stdin().lock().read_line(&mut String::new())?;
    ensure!(read > 0, "Input ended.");
    Ok(())
}

fn hidden(prompt: &str) -> Result<Zeroizing<String>> {
    let text = rpassword::prompt_password(prompt)
        .context("Cannot read a hidden prompt. Run this command in a Terminal window")?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests;
