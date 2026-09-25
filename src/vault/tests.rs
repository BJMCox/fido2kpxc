use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

fn unlock(id: u8, output: u8) -> Unlock {
    Unlock {
        cred_id: vec![id; 16],
        output: Zeroizing::new([output; 32]),
    }
}

fn two_key_vault(secret: &[u8]) -> Vault {
    let mut vault = Vault::create([7; 32], "primary", &unlock(1, 10), ANY, secret).unwrap();
    vault
        .add_key(&unlock(1, 10), "backup", &unlock(2, 20))
        .unwrap();
    vault
}

fn open(vault: &Vault, key: &Unlock, database: &str) -> Vec<u8> {
    vault.open(key, Some(database)).unwrap().to_vec()
}

#[test]
fn either_key_opens_the_vault_after_a_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"hunter2").save(&path, true).unwrap();
    let vault = Vault::load(&path).unwrap();
    assert_eq!(vault.salt(), [7; 32]);
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, &unlock(2, 20), "pdb.kdbx"), b"hunter2");
}

#[test]
fn exact_database_name_beats_the_catch_all() {
    let mut vault = two_key_vault(b"default");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    assert_eq!(open(&vault, &unlock(2, 20), "work.kdbx"), b"work");
    assert_eq!(open(&vault, &unlock(2, 20), "home.kdbx"), b"default");
}

#[test]
fn unknown_database_without_a_catch_all_has_no_secret() {
    let vault = Vault::create([7; 32], "primary", &unlock(1, 10), "work.kdbx", b"work").unwrap();
    assert!(!vault.has_secret_for(Some("home.kdbx")));
    assert!(vault.open(&unlock(1, 10), Some("home.kdbx")).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "work.kdbx"), b"work");
}

#[test]
fn set_secret_keeps_every_key_working() {
    let mut vault = two_key_vault(b"old");
    vault.set_secret(&unlock(1, 10), ANY, b"new").unwrap();
    assert_eq!(open(&vault, &unlock(2, 20), "pdb.kdbx"), b"new");
    assert_eq!(vault.databases(), vec![ANY]);
}

#[test]
fn remove_secret_falls_back_to_the_catch_all() {
    let mut vault = two_key_vault(b"default");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    vault.remove_secret("work.kdbx").unwrap();
    assert_eq!(open(&vault, &unlock(1, 10), "work.kdbx"), b"default");
    assert!(vault.remove_secret(ANY).is_err());
}

#[test]
fn remove_key_keeps_the_other_keys_working() {
    let mut vault = two_key_vault(b"hunter2");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    vault
        .add_key(&unlock(1, 10), "third", &unlock(3, 30))
        .unwrap();
    vault
        .remove_key("backup", &[unlock(1, 10), unlock(3, 30)])
        .unwrap();
    assert!(vault.open(&unlock(2, 20), None).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
    assert_eq!(open(&vault, &unlock(3, 30), "work.kdbx"), b"work");
}

#[test]
fn removed_key_cannot_read_vaults_written_after_removal() {
    let mut vault = two_key_vault(b"hunter2");
    let old_copy: Vault = toml::from_str(&toml::to_string(&vault).unwrap()).unwrap();
    vault.remove_key("backup", &[unlock(1, 10)]).unwrap();
    vault.set_secret(&unlock(1, 10), ANY, b"rotated").unwrap();
    // The removed key still opens its old copy, so it knows the old data key.
    let old_key = old_copy.unwrap(&unlock(2, 20)).unwrap();
    let secret = &vault.secrets[0];
    let payload = Payload {
        msg: &secret.ciphertext,
        aad: &secret_aad(ANY),
    };
    assert!(
        cipher(&old_key)
            .decrypt(&nonce(&secret.nonce), payload)
            .is_err()
    );
}

#[test]
fn remove_key_refuses_the_last_key() {
    let mut vault = Vault::create([7; 32], "primary", &unlock(1, 10), ANY, b"hunter2").unwrap();
    assert!(vault.remove_key("primary", &[]).is_err());
    assert_eq!(open(&vault, &unlock(1, 10), "pdb.kdbx"), b"hunter2");
}

#[test]
fn tampered_ciphertext_fails_to_open() {
    let mut vault = two_key_vault(b"hunter2");
    vault.secrets[0].ciphertext[0] ^= 1;
    assert!(vault.open(&unlock(1, 10), None).is_err());
}

#[test]
fn swapped_database_names_fail_to_open() {
    let mut vault = two_key_vault(b"home");
    vault
        .set_secret(&unlock(1, 10), "work.kdbx", b"work")
        .unwrap();
    let first = vault.secrets[0].database.clone();
    vault.secrets[0].database = vault.secrets[1].database.clone();
    vault.secrets[1].database = first;
    assert!(vault.open(&unlock(1, 10), Some("work.kdbx")).is_err());
}

#[test]
fn swapped_cred_ids_fail_to_unwrap() {
    // Both keys share one output, so only the cred_id binding can reject the swap.
    let mut vault = Vault::create([7; 32], "primary", &unlock(1, 10), ANY, b"hunter2").unwrap();
    vault
        .add_key(&unlock(1, 10), "backup", &unlock(2, 10))
        .unwrap();
    let first = vault.keys[0].cred_id.clone();
    vault.keys[0].cred_id = vault.keys[1].cred_id.clone();
    vault.keys[1].cred_id = first;
    assert!(vault.open(&unlock(2, 10), None).is_err());
}

#[test]
fn version_1_vault_opens_as_the_catch_all_and_saves_as_version_2() {
    let key = [5; 32];
    let b = |bytes: &[u8]| STANDARD.encode(bytes);
    let seal = |with: &[u8; 32], msg: &[u8], aad: &[u8], n: [u8; 24]| {
        cipher(with)
            .encrypt(&XNonce::from(n), Payload { msg, aad })
            .unwrap()
    };
    let old = unlock(1, 10);
    let v1 = format!(
        "version = 1\nsalt = \"{}\"\nnonce = \"{}\"\nciphertext = \"{}\"\n\n[[keys]]\nlabel = \"primary\"\ncred_id = \"{}\"\nnonce = \"{}\"\nwrapped_key = \"{}\"\n",
        b(&[7; 32]),
        b(&[1; 24]),
        b(&seal(&key, b"hunter2", b"fido2kpxc-vault-v1", [1; 24])),
        b(&old.cred_id),
        b(&[2; 24]),
        b(&seal(&old.output, &key, &old.cred_id, [2; 24])),
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    std::fs::write(&path, v1).unwrap();
    Vault::load(&path).unwrap().save(&path, false).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .starts_with("version = 2")
    );
    assert_eq!(
        open(&Vault::load(&path).unwrap(), &old, "any.kdbx"),
        b"hunter2"
    );
}

#[test]
fn create_refuses_to_replace_an_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.toml");
    two_key_vault(b"first").save(&path, true).unwrap();
    assert!(two_key_vault(b"second").save(&path, true).is_err());
    assert_eq!(
        open(&Vault::load(&path).unwrap(), &unlock(1, 10), "pdb.kdbx"),
        b"first"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn create_makes_a_missing_vault_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new/vault.toml");
    two_key_vault(b"hunter2").save(&path, true).unwrap();
    assert_eq!(
        open(&Vault::load(&path).unwrap(), &unlock(1, 10), "pdb.kdbx"),
        b"hunter2"
    );
}

#[test]
fn create_never_makes_a_missing_parent_folder() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing/fido2kpxc/vault.toml");
    assert!(two_key_vault(b"hunter2").save(&path, true).is_err());
    assert!(!dir.path().join("missing").exists());
}
