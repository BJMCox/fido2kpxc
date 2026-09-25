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
fn rendered_settings_load_back() {
    let text = Config::render("~/Sync/My \"Vault\"", Autofill::Fill, true, 60);
    let config = Config::parse(&text, Path::new("/Users/me")).unwrap();
    assert_eq!(
        config.vault,
        Path::new("/Users/me/Sync/My \"Vault\"/vault.toml")
    );
    assert_eq!(config.autofill, Autofill::Fill);
    assert!(config.copy_password);
    assert_eq!(config.clear_seconds, 60);
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

#[test]
fn conflicts_lists_sync_copies_of_the_vault_only() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "vault.toml",
        "vault.sync-conflict-20260925-120000-ABCDEFG.toml",
        "vault (Jessica's conflicted copy 2026-09-25).toml",
        "vault 2.toml",
        ".fido2kpxc-abc.tmp",
        "notes.toml",
        "vault.toml.bak",
    ] {
        std::fs::write(dir.path().join(name), "").unwrap();
    }
    let text = format!("folder = {:?}", dir.path());
    let config = Config::parse(&text, Path::new("/h")).unwrap();
    assert_eq!(
        config.conflicts(),
        [
            "vault (Jessica's conflicted copy 2026-09-25).toml",
            "vault 2.toml",
            "vault.sync-conflict-20260925-120000-ABCDEFG.toml",
        ]
    );
}

#[test]
fn conflicts_is_empty_for_a_missing_folder() {
    let config = Config::parse(r#"folder = "/nonexistent/fido2kpxc""#, Path::new("/h")).unwrap();
    assert!(config.conflicts().is_empty());
}
