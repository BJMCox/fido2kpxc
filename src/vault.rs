use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const VERSION: u32 = 2;

/// The database name that matches any database without its own entry.
pub const ANY: &str = "*";

/// One security key's hmac-secret output for its enrolled credential.
pub struct Unlock {
    pub cred_id: Vec<u8>,
    pub output: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    version: u32,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    keys: Vec<KeyEntry>,
    secrets: Vec<SecretEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    label: String,
    #[serde(with = "b64")]
    cred_id: Vec<u8>,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    wrapped_key: Vec<u8>,
}

/// One database password. `database` is a file name such as `pdb.kdbx`, or [`ANY`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretEntry {
    database: String,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

/// The version 1 layout: one password, which now loads as the [`ANY`] entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultV1 {
    #[allow(dead_code)]
    version: u32,
    #[serde(with = "b64")]
    salt: Vec<u8>,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    keys: Vec<KeyEntry>,
}

impl Vault {
    pub fn new_salt() -> Result<[u8; 32]> {
        random()
    }

    pub fn create(
        salt: [u8; 32],
        label: &str,
        unlock: &Unlock,
        database: &str,
        secret: &[u8],
    ) -> Result<Self> {
        let key = Zeroizing::new(random::<32>()?);
        let mut vault = Self {
            version: VERSION,
            salt: salt.to_vec(),
            keys: Vec::new(),
            secrets: Vec::new(),
        };
        vault.seal(&key, database, secret)?;
        vault.wrap(&key, label, unlock)?;
        Ok(vault)
    }

    pub fn salt(&self) -> [u8; 32] {
        self.salt.as_slice().try_into().expect("validated on load")
    }

    pub fn cred_ids(&self) -> Vec<&[u8]> {
        self.keys.iter().map(|k| k.cred_id.as_slice()).collect()
    }

    /// Stored database names, in vault order.
    pub fn databases(&self) -> Vec<&str> {
        self.secrets.iter().map(|s| s.database.as_str()).collect()
    }

    /// True when `open` would find a password for `database`.
    pub fn has_secret_for(&self, database: Option<&str>) -> bool {
        self.secret_for(database).is_some()
    }

    /// Decrypts the password for `database`: its own entry if one exists, else the [`ANY`] entry.
    pub fn open(&self, unlock: &Unlock, database: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.unwrap(unlock)?;
        let Some(entry) = self.secret_for(database) else {
            bail!(
                "No password is stored for {}",
                database.unwrap_or("this database")
            );
        };
        let payload = Payload {
            msg: &entry.ciphertext,
            aad: &secret_aad(&entry.database),
        };
        cipher(&key)
            .decrypt(&nonce(&entry.nonce), payload)
            .map(Zeroizing::new)
            .map_err(|_| {
                anyhow!(
                    "The password for {:?} failed authentication",
                    entry.database
                )
            })
    }

    pub fn add_key(&mut self, current: &Unlock, label: &str, new: &Unlock) -> Result<()> {
        ensure!(
            self.keys.iter().all(|k| k.label != label),
            "Label {label:?} already exists"
        );
        ensure!(
            self.keys.iter().all(|k| k.cred_id != new.cred_id),
            "This security key is already enrolled"
        );
        let key = self.unwrap(current)?;
        self.wrap(&key, label, new)
    }

    /// Labels and credential IDs of the enrolled keys, in vault order.
    pub fn entries(&self) -> Vec<(&str, &[u8])> {
        self.keys
            .iter()
            .map(|k| (k.label.as_str(), k.cred_id.as_slice()))
            .collect()
    }

    /// Drops the key labeled `label` and moves every password to a new data key.
    /// A removed key that kept an old vault copy knows the old data key, so every
    /// remaining key must be present in `remaining` to wrap the new one.
    pub fn remove_key(&mut self, label: &str, remaining: &[Unlock]) -> Result<()> {
        ensure!(
            self.keys.iter().any(|k| k.label == label),
            "No key is labeled {label:?}"
        );
        ensure!(self.keys.len() > 1, "The last key cannot be removed");
        let kept: Vec<(String, &Unlock)> = self
            .keys
            .iter()
            .filter(|k| k.label != label)
            .map(|k| {
                let unlock = remaining
                    .iter()
                    .find(|u| u.cred_id == k.cred_id)
                    .with_context(|| format!("Key {:?} must be present", k.label))?;
                // Proves each output is right before the old wrapping is discarded.
                self.unwrap(unlock)?;
                Ok((k.label.clone(), unlock))
            })
            .collect::<Result<_>>()?;
        let old_key = self.unwrap(kept[0].1)?;
        let plain: Vec<(String, Zeroizing<Vec<u8>>)> = self
            .secrets
            .iter()
            .map(|entry| Ok((entry.database.clone(), self.decrypt(&old_key, entry)?)))
            .collect::<Result<_>>()?;
        let key = Zeroizing::new(random::<32>()?);
        self.secrets.clear();
        for (database, secret) in &plain {
            self.seal(&key, database, secret)?;
        }
        self.keys.clear();
        for (label, unlock) in &kept {
            self.wrap(&key, label, unlock)?;
        }
        Ok(())
    }

    /// Adds or replaces the password for `database`.
    pub fn set_secret(&mut self, unlock: &Unlock, database: &str, secret: &[u8]) -> Result<()> {
        let key = self.unwrap(unlock)?;
        self.secrets.retain(|s| s.database != database);
        self.seal(&key, database, secret)
    }

    pub fn remove_secret(&mut self, database: &str) -> Result<()> {
        ensure!(
            self.secrets.iter().any(|s| s.database == database),
            "No password is stored for {database:?}"
        );
        ensure!(
            self.secrets.len() > 1,
            "The last password cannot be removed"
        );
        self.secrets.retain(|s| s.database != database);
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read vault {}", path.display()))?;
        let vault =
            Self::parse(&text).with_context(|| format!("Invalid vault {}", path.display()))?;
        ensure!(
            vault.salt.len() == 32,
            "The vault salt has the wrong length"
        );
        ensure!(!vault.keys.is_empty(), "The vault has no enrolled keys");
        ensure!(!vault.secrets.is_empty(), "The vault holds no password");
        ensure!(
            vault.keys.iter().all(|k| k.nonce.len() == 24)
                && vault.secrets.iter().all(|s| s.nonce.len() == 24),
            "A vault nonce has the wrong length"
        );
        let databases = vault.databases();
        ensure!(
            (1..databases.len()).all(|i| !databases[..i].contains(&databases[i])),
            "The vault stores a database name twice"
        );
        Ok(vault)
    }

    fn parse(text: &str) -> Result<Self> {
        let version = toml::from_str::<toml::Table>(text)?
            .get("version")
            .and_then(toml::Value::as_integer)
            .context("The vault has no version")?;
        match version {
            1 => {
                let v1: VaultV1 = toml::from_str(text)?;
                Ok(Self {
                    version: VERSION,
                    salt: v1.salt,
                    keys: v1.keys,
                    secrets: vec![SecretEntry {
                        database: ANY.to_owned(),
                        nonce: v1.nonce,
                        ciphertext: v1.ciphertext,
                    }],
                })
            }
            2 => Ok(toml::from_str(text)?),
            other => bail!("Unsupported vault version {other}"),
        }
    }

    /// Replaces the vault atomically. With `create`, refuses to replace an existing file.
    pub fn save(&self, path: &Path, create: bool) -> Result<()> {
        let dir = path.parent().context("The vault path has no directory")?;
        if create {
            // Creates only the configured folder. A missing parent means a wrong `folder` setting.
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                    return Err(e).with_context(|| format!("Cannot create {}", dir.display()));
                }
                _ => {}
            }
        }
        // The rename below replaces the vault in one step, so readers never see a partial file.
        let mut temp = tempfile::Builder::new()
            .prefix(".fido2kpxc-")
            .suffix(".tmp")
            .tempfile_in(dir)?;
        temp.write_all(toml::to_string(self)?.as_bytes())?;
        temp.as_file().sync_all()?;
        if create {
            temp.persist_noclobber(path)?;
        } else {
            temp.persist(path)?;
        }
        Ok(())
    }

    fn secret_for(&self, database: Option<&str>) -> Option<&SecretEntry> {
        let exact = database.and_then(|name| self.secrets.iter().find(|s| s.database == name));
        exact.or_else(|| self.secrets.iter().find(|s| s.database == ANY))
    }

    fn unwrap(&self, unlock: &Unlock) -> Result<Zeroizing<[u8; 32]>> {
        let entry = self
            .keys
            .iter()
            .find(|k| k.cred_id == unlock.cred_id)
            .context("This security key is not enrolled in the vault")?;
        let payload = Payload {
            msg: &entry.wrapped_key,
            aad: &entry.cred_id,
        };
        let plain = Zeroizing::new(
            cipher(&unlock.output)
                .decrypt(&nonce(&entry.nonce), payload)
                .map_err(|_| anyhow!("Key entry {:?} failed authentication", entry.label))?,
        );
        let key: [u8; 32] = plain
            .as_slice()
            .try_into()
            .context("The wrapped key has the wrong length")?;
        Ok(Zeroizing::new(key))
    }

    fn decrypt(&self, key: &[u8; 32], entry: &SecretEntry) -> Result<Zeroizing<Vec<u8>>> {
        let payload = Payload {
            msg: &entry.ciphertext,
            aad: &secret_aad(&entry.database),
        };
        cipher(key)
            .decrypt(&nonce(&entry.nonce), payload)
            .map(Zeroizing::new)
            .map_err(|_| {
                anyhow!(
                    "The password for {:?} failed authentication",
                    entry.database
                )
            })
    }

    fn wrap(&mut self, key: &[u8; 32], label: &str, unlock: &Unlock) -> Result<()> {
        let nonce = random::<24>()?;
        let payload = Payload {
            msg: key,
            aad: &unlock.cred_id,
        };
        let wrapped_key = cipher(&unlock.output)
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| anyhow!("Encryption failed"))?;
        self.keys.push(KeyEntry {
            label: label.to_owned(),
            cred_id: unlock.cred_id.clone(),
            nonce: nonce.to_vec(),
            wrapped_key,
        });
        Ok(())
    }

    fn seal(&mut self, key: &[u8; 32], database: &str, secret: &[u8]) -> Result<()> {
        let nonce = random::<24>()?;
        let payload = Payload {
            msg: secret,
            aad: &secret_aad(database),
        };
        let ciphertext = cipher(key)
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| anyhow!("Encryption failed"))?;
        self.secrets.push(SecretEntry {
            database: database.to_owned(),
            nonce: nonce.to_vec(),
            ciphertext,
        });
        Ok(())
    }
}

/// Binds each password to its database name, so entries cannot be swapped.
/// The [`ANY`] entry keeps the version 1 value, so migrated vaults need no re-encryption.
fn secret_aad(database: &str) -> Vec<u8> {
    if database == ANY {
        b"fido2kpxc-vault-v1".to_vec()
    } else {
        format!("fido2kpxc-secret:{database}").into_bytes()
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("The random source failed: {e}"))?;
    Ok(bytes)
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&Key::from(*key))
}

fn nonce(bytes: &[u8]) -> XNonce {
    XNonce::from(<[u8; 24]>::try_from(bytes).expect("validated on load"))
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
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
        let vault =
            Vault::create([7; 32], "primary", &unlock(1, 10), "work.kdbx", b"work").unwrap();
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
}
