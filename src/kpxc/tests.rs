use super::*;

/// An element of a window that a test builds. Only text fields need an `id`.
#[derive(Clone)]
struct Node {
    id: usize,
    role: &'static str,
    subrole: &'static str,
    description: &'static str,
    value: String,
    children: Vec<Node>,
}

impl Element for Node {
    fn text(&self, attribute: &str) -> String {
        match attribute {
            "AXRole" => self.role.to_owned(),
            "AXSubrole" => self.subrole.to_owned(),
            "AXRoleDescription" => self.description.to_owned(),
            "AXValue" => self.value.clone(),
            _ => String::new(),
        }
    }

    fn children(&self) -> Vec<Self> {
        self.children.clone()
    }

    fn same(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

fn node(role: &'static str, children: Vec<Node>) -> Node {
    Node {
        id: 0,
        role,
        subrole: "",
        description: "",
        value: String::new(),
        children,
    }
}

fn label(text: &str) -> Node {
    Node {
        value: text.to_owned(),
        ..node("AXStaticText", Vec::new())
    }
}

fn field(id: usize, subrole: &'static str) -> Node {
    Node {
        id,
        subrole,
        ..node("AXTextField", Vec::new())
    }
}

/// A password field as Qt 5 exposes it: no AXSubrole, and the role description names it secure.
fn qt5_field(id: usize, description: &'static str) -> Node {
    Node {
        description,
        ..field(id, "")
    }
}

const PASSWORD: usize = 1;
const KEY_FILE: usize = 2;

/// KeePassXC's main window at the unlock screen as Qt exposes it: the path label, the password
/// field, and the key-file field, which is secure too, then the toolbar's search field. Qt hides
/// the toolbar itself and lifts its children into the window.
fn unlock_screen(texts: &[&str], password: &'static str) -> Node {
    unlock_screen_with(texts, field(PASSWORD, password))
}

fn unlock_screen_with(texts: &[&str], password: Node) -> Node {
    let mut screen: Vec<Node> = texts.iter().map(|t| label(t)).collect();
    screen.push(password);
    screen.push(field(KEY_FILE, SECURE));
    node(
        "AXWindow",
        vec![node("AXGroup", screen), field(3, "AXSearchField")],
    )
}

/// The database path when `focused` is the password field of `window`.
fn prompt_path(focused: &Node, window: &Node) -> Option<String> {
    password_prompt(focused, window).map(|(path, _)| path)
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
#[ignore = "needs a running KeePassXC"]
fn running_keepassxc_passes_the_check() {
    let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(&NSString::from_str(
        BUNDLE_ID,
    ));
    let app = apps.iter().next().expect("KeePassXC is running");
    assert!(is_genuine_keepassxc(app.processIdentifier()));
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
    let german = unlock_screen(
        &[
            "KeePassXC-Datenbank entsperren",
            &database,
            "Passwort eingeben:",
        ],
        SECURE,
    );
    assert_eq!(
        prompt_path(&field(PASSWORD, SECURE), &german),
        Some(database)
    );
}

#[test]
fn a_search_field_before_the_unlock_screen_does_not_hide_the_password_field() {
    // The walk follows widget creation order, which a KeePassXC release can change.
    let (_dir, database, _) = files();
    let mut locked = unlock_screen(&[&database], SECURE);
    locked.children.reverse();
    assert_eq!(
        prompt_path(&field(PASSWORD, SECURE), &locked),
        Some(database)
    );
}

#[test]
fn unlocked_window_is_not_a_prompt() {
    // An entry titled with a path must not count as the unlock screen's path label.
    let (_dir, _, other) = files();
    let unlocked = unlock_screen(&["Root", "/etc/hosts", &other], SECURE);
    assert_eq!(prompt_path(&field(PASSWORD, SECURE), &unlocked), None);
}

#[test]
fn focus_outside_a_text_field_is_not_a_prompt() {
    // KeePassXC's quick unlock screen focuses its Unlock Database button.
    let (_dir, database, _) = files();
    let locked = unlock_screen(&[&database], SECURE);
    let button = node("AXButton", Vec::new());
    assert_eq!(prompt_path(&button, &locked), None);
}

#[test]
fn unlock_screen_gone_means_unlocked() {
    let (_dir, database, _) = files();
    let before = texts(&["Unlock KeePassXC Database", &database, "Password"]);
    let after = texts(&["Entries", "Title", "Username"]);
    assert_eq!(
        judge(&database, &before, &after, true, true),
        Some(Verdict::Unlocked)
    );
}

#[test]
fn unlock_screen_still_there_quotes_the_new_message() {
    let (_dir, database, _) = files();
    let before = texts(&["Unlock KeePassXC Database", &database, "Password"]);
    let after = texts(&[
        "Unlock KeePassXC Database",
        &database,
        "Invalid credentials were provided, please try again.",
        "Password",
    ]);
    assert_eq!(
        judge(&database, &before, &after, true, false),
        Some(Verdict::Rejected(Some(
            "Invalid credentials were provided, please try again.".to_owned()
        )))
    );
}

#[test]
fn a_message_shown_before_the_press_is_not_quoted() {
    let (_dir, database, _) = files();
    let before = texts(&[&database, "Invalid credentials", ""]);
    let after = texts(&[&database, "Invalid credentials", ""]);
    assert_eq!(
        judge(&database, &before, &after, true, true),
        Some(Verdict::Rejected(None))
    );
}

#[test]
fn another_database_on_screen_means_this_one_unlocked() {
    let (dir, database, _) = files();
    let other = dir.path().join("work.kdbx");
    std::fs::copy(&database, &other).unwrap();
    let before = texts(&[&database]);
    let after = texts(&[&other.to_string_lossy()]);
    assert_eq!(
        judge(&database, &before, &after, true, true),
        Some(Verdict::Unlocked)
    );
}

#[test]
fn a_running_unlock_is_not_judged() {
    // KeePassXC answers during a long key derivation with the unlock screen still up.
    let (_dir, database, _) = files();
    let before = texts(&["Unlock KeePassXC Database", &database, "Password"]);
    assert_eq!(judge(&database, &before, &before, true, false), None);
}

#[test]
fn a_running_unlock_ends_as_unlocked_when_the_screen_goes() {
    let (_dir, database, _) = files();
    let before = texts(&[&database]);
    assert_eq!(
        judge(&database, &before, &texts(&["Entries"]), true, false),
        Some(Verdict::Unlocked)
    );
}

#[test]
fn a_message_while_the_screen_is_disabled_is_not_a_failure() {
    // KeePassXC can show a status message of its own while it unlocks.
    let (_dir, database, _) = files();
    let before = texts(&[&database]);
    let now = texts(&[&database, "Touch your hardware key to continue"]);
    assert_eq!(judge(&database, &before, &now, false, false), None);
}

#[test]
fn a_qt5_password_field_is_a_prompt() {
    // KeePassXC 2.7 ships Qt 5, which gives the field no AXSubrole.
    let (_dir, database, _) = files();
    let hidden = qt5_field(PASSWORD, "secure text field");
    let locked = unlock_screen_with(&[&database], hidden.clone());
    assert_eq!(prompt_path(&hidden, &locked), Some(database));
}

#[test]
fn a_qt5_password_shown_in_clear_is_not_filled() {
    let (_dir, database, _) = files();
    let clear = qt5_field(PASSWORD, "text field");
    let screen = unlock_screen_with(&[&database], clear.clone());
    assert_eq!(prompt_path(&clear, &screen), None);
}

#[test]
fn a_password_shown_in_clear_is_not_filled() {
    let (_dir, database, _) = files();
    let clear = unlock_screen(&[&database], "");
    assert_eq!(prompt_path(&field(PASSWORD, ""), &clear), None);
}

#[test]
fn the_key_file_field_is_not_the_password_field() {
    let (_dir, database, _) = files();
    let locked = unlock_screen(&[&database], SECURE);
    assert_eq!(prompt_path(&field(KEY_FILE, SECURE), &locked), None);
}

#[test]
fn the_key_file_field_is_not_the_password_field_while_the_password_shows_in_clear() {
    // Showing the password in clear leaves the key-file field as the only secure field.
    let (_dir, database, _) = files();
    let clear = unlock_screen(&[&database], "");
    assert_eq!(prompt_path(&field(KEY_FILE, SECURE), &clear), None);
}

#[test]
fn two_databases_on_screen_name_no_database() {
    let (dir, database, _) = files();
    let second = dir.path().join("work.kdbx");
    std::fs::copy(&database, &second).unwrap();
    let second = second.to_string_lossy().into_owned();
    assert_eq!(
        database_from_texts([database.as_str(), second.as_str()]),
        None
    );
}

#[test]
fn a_file_with_only_the_first_signature_word_is_not_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("short.kdbx");
    std::fs::write(&path, [0x03, 0xD9, 0xA2, 0x9A]).unwrap();
    assert_eq!(database_from_texts([path.to_str().unwrap()]), None);
}

#[test]
fn a_fifo_path_does_not_block_detection() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe.kdbx");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    assert_eq!(database_from_texts([fifo.to_str().unwrap()]), None);
}

#[test]
fn only_translated_unlock_titles_count() {
    assert!(is_unlock_title("Entsperren"));
    assert!(!is_unlock_title("Schließen"));
}

#[test]
fn a_path_that_cannot_be_read_does_not_end_the_watch() {
    // A stalled mount fails every probe, but the screen still shows the path.
    let before = texts(&["Unlock KeePassXC Database", "/Volumes/stalled/pdb.kdbx"]);
    assert_eq!(
        judge("/Volumes/stalled/pdb.kdbx", &before, &before, true, false),
        None
    );
}
