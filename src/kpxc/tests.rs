use super::*;

fn focus<'a>(frontmost: bool, role: &'a str, window_texts: &'a [String]) -> Focus<'a> {
    Focus {
        frontmost,
        role,
        window_texts,
    }
}

fn texts(items: &[&str]) -> Vec<String> {
    items.iter().map(|t| t.to_string()).collect()
}

/// A folder with `pdb.kdbx`, which starts with the KDBX signature, and `notes.txt`, which does not.
fn files() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("pdb.kdbx");
    let other = dir.path().join("notes.txt");
    std::fs::write(&database, [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5]).unwrap();
    std::fs::write(&other, b"/etc/hosts").unwrap();
    let path = |p: std::path::PathBuf| p.to_string_lossy().into_owned();
    (dir, path(database), path(other))
}

#[test]
fn a_process_not_signed_by_keepassxc_fails_the_check() {
    assert!(!is_genuine_keepassxc(std::process::id() as i32));
}

#[test]
fn running_keepassxc_passes_the_check() {
    let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(&NSString::from_str(
        BUNDLE_ID,
    ));
    // Skips when KeePassXC is not running on the test machine.
    if let Some(app) = apps.iter().next() {
        assert!(is_genuine_keepassxc(app.processIdentifier()));
    }
}

#[test]
fn database_file_comes_from_the_path_label() {
    let (_dir, database, other) = files();
    let shown = [
        "Unlock KeePassXC Database",
        other.as_str(),
        database.as_str(),
        "Enter Password:",
    ];
    assert_eq!(database_from_texts(shown).as_deref(), Some("pdb.kdbx"));
    assert_eq!(database_from_texts(["/etc/hosts", other.as_str()]), None);
}

#[test]
fn unlock_screen_is_a_prompt_in_any_language() {
    let (_dir, database, _) = files();
    let german = texts(&[
        "KeePassXC-Datenbank entsperren",
        &database,
        "Passwort eingeben:",
    ]);
    assert!(is_password_prompt(&focus(true, "AXTextField", &german)));
}

#[test]
fn unlocked_window_is_not_a_prompt() {
    // An entry titled with a path must not count as the unlock screen's path label.
    let (_dir, _, other) = files();
    let unlocked = texts(&["Root", "/etc/hosts", &other]);
    assert!(!is_password_prompt(&focus(true, "AXTextField", &unlocked)));
}

#[test]
fn focus_outside_a_text_field_is_not_a_prompt() {
    let (_dir, database, _) = files();
    let locked = texts(&[&database]);
    assert!(!is_password_prompt(&focus(true, "AXButton", &locked)));
}

#[test]
fn background_keepassxc_is_not_a_prompt() {
    let (_dir, database, _) = files();
    let locked = texts(&[&database]);
    assert!(!is_password_prompt(&focus(false, "AXTextField", &locked)));
}
