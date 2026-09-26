use super::*;
use crate::vault::Check;

fn check(opened: &[&str], failed: &[&str]) -> Check {
    Check {
        label: "backup".to_owned(),
        opened: opened.iter().map(|s| s.to_string()).collect(),
        failed: failed.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn report_names_every_opened_password() {
    assert_eq!(
        report(&check(&["pdb.kdbx", "*"], &[])),
        "This key is enrolled as \"backup\". It opens all 2 stored passwords: pdb.kdbx, any other database (*)."
    );
}

#[test]
fn report_for_a_single_password() {
    assert_eq!(
        report(&check(&["*"], &[])),
        "This key is enrolled as \"backup\". It opens the stored password for any other database (*)."
    );
}

#[test]
fn report_names_passwords_that_fail() {
    assert_eq!(
        report(&check(&["*"], &["pdb.kdbx"])),
        "This key is enrolled as \"backup\". It opens any other database (*), but the password for pdb.kdbx fails to decrypt. Store it again."
    );
}

#[test]
fn report_for_a_vault_without_passwords() {
    assert_eq!(
        report(&check(&[], &[])),
        "This key is enrolled as \"backup\". The vault holds no passwords yet."
    );
}

#[test]
fn removed_keys_are_named_in_a_sentence() {
    let names =
        |labels: &[&str]| removed(&labels.iter().map(|l| l.to_string()).collect::<Vec<_>>());
    assert_eq!(
        names(&["lost"]),
        "Removed key \"lost\" and moved the vault to a new data key."
    );
    assert_eq!(
        names(&["a", "b"]),
        "Removed keys \"a\" and \"b\" and moved the vault to a new data key."
    );
    assert_eq!(
        names(&["a", "b", "c"]),
        "Removed keys \"a\", \"b\", and \"c\" and moved the vault to a new data key."
    );
}

#[test]
fn any_needed_key_counts_in_any_order() {
    let mut left = vec![
        ("a".to_owned(), vec![1]),
        ("b".to_owned(), vec![2]),
        ("c".to_owned(), vec![3]),
    ];
    assert_eq!(touched(&mut left, &[2]).as_deref(), Some("b"));
    assert_eq!(touched(&mut left, &[2]), None);
    assert_eq!(touched(&mut left, &[9]), None);
    assert_eq!(needed(&left), "\"a\" or \"c\"");
    assert_eq!(touched(&mut left, &[3]).as_deref(), Some("c"));
    assert_eq!(needed(&left), "\"a\"");
}

#[test]
fn a_database_path_reduces_to_the_file_name_autofill_matches() {
    assert_eq!(database_name("/x/work.kdbx"), "work.kdbx");
}

/// A config whose vault stores passwords for `*`, `a.kdbx`, and `b.kdbx`.
fn three_passwords() -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let text = format!("folder = {:?}", dir.path().display().to_string());
    let config = Config::parse(&text, std::path::Path::new("/h")).unwrap();
    let one = Unlock {
        cred_id: vec![1; 16],
        output: zeroize::Zeroizing::new([9; 32]),
    };
    let mut vault = Vault::create([7; 32], "primary", &one, ANY, b"any").unwrap();
    vault.set_secret(&one, "a.kdbx", b"a").unwrap();
    vault.set_secret(&one, "b.kdbx", b"b").unwrap();
    vault.save(&config.vault, true).unwrap();
    (dir, config)
}

#[test]
fn remove_secrets_removes_several_in_one_save() {
    let (_dir, config) = three_passwords();
    remove_secrets(&config, &["a.kdbx".into(), "b.kdbx".into()]).unwrap();
    assert_eq!(Vault::load(&config.vault).unwrap().databases(), ["*"]);
}

#[test]
fn removing_every_password_fails_and_changes_nothing() {
    let (_dir, config) = three_passwords();
    let before = std::fs::read(&config.vault).unwrap();
    let all = ["*".into(), "a.kdbx".into(), "b.kdbx".into()];
    assert!(remove_secrets(&config, &all).is_err());
    assert_eq!(std::fs::read(&config.vault).unwrap(), before);
}
