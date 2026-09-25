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
