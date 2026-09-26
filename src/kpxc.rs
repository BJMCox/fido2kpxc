use std::ptr::{self, NonNull};
use std::sync::{Once, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication, NSWorkspace};
use objc2_application_services::{AXError, AXUIElement};
use std::ffi::c_void;

use objc2_core_foundation::{
    CFArray, CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_foundation::{NSBundle, NSString};

const BUNDLE_ID: &str = "org.keepassxc.keepassxc";
// Bounds each call when KeePassXC hangs.
const AX_TIMEOUT_SECONDS: f32 = 0.5;
// Covers a slow key derivation. A watch that runs out ends without a verdict.
const WATCH: Duration = Duration::from_secs(120);
const SECURE: &str = "AXSecureTextField";
// Qt 5 misnames its subrole method, so it exposes no AXSubrole and names a secure field only in
// the role description. AppKit writes that text in KeePassXC's only localization, English.
const SECURE_DESCRIPTION: &str = "secure text field";
// An unlocked database window can hold thousands of rows. The unlock screen is far smaller.
const WALK_LIMIT: usize = 400;
/// KeePassXC's Unlock button title in every language it ships, from the DatabaseOpenWidget
/// translations of 2.7.12 and the 2.8 development tree. The button has no other stable identity.
const UNLOCK_TITLES: [&str; 38] = [
    "Atrakinti",
    "Ava lukk",
    "Avaa tietokanta",
    "Buka Kunci",
    "Deblocare",
    "Desbloquear",
    "Desbloqueja",
    "Déverrouiller",
    "Entsperren",
    "Feloldás",
    "I-unlock",
    "Kilidi aç",
    "Kkes asekkeṛ",
    "Lås op",
    "Lås opp",
    "Lås upp",
    "Mở khóa",
    "Odblokuj",
    "Odemknout",
    "Ontgrendelen",
    "Sblocca",
    "Shkyçe",
    "Unlock",
    "Ξεκλείδωμα",
    "Отключване",
    "Разблакіраваць",
    "Разблокировать",
    "Розблокувати",
    "שחרור נעילה",
    "افتح",
    "අගුළු හරින්න",
    "ปลดล็อก",
    "လော့ဖြည်သည်",
    "ដោះសោ",
    "ロックを解除",
    "解鎖",
    "解锁",
    "잠금 해제",
];
/// KeePass 2 databases start with these two signature words (little-endian 0x9AA2D903, 0xB54BFB67).
const KDBX: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
// A path probe gives up after this, so a stalled mount cannot freeze the menu bar.
const PROBE: Duration = Duration::from_millis(250);
// macOS's value. std names no constant for it, and the app takes no libc dependency.
const O_NONBLOCK: i32 = 0x0004;

/// An accessibility element as detection reads it, so tests can build a window of their own.
trait Element: Clone {
    fn text(&self, attribute: &str) -> String;
    fn children(&self) -> Vec<Self>;
    fn same(&self, other: &Self) -> bool;
}

impl Element for CFRetained<AXUIElement> {
    fn text(&self, attribute: &str) -> String {
        string(self, attribute)
    }

    fn children(&self) -> Vec<Self> {
        children(self)
    }

    fn same(&self, other: &Self) -> bool {
        **self == **other
    }
}

/// True for KeePassXC's Unlock button title in any shipped language. Qt marks shortcuts with `&`.
pub fn is_unlock_title(title: &str) -> bool {
    UNLOCK_TITLES.contains(&title.replace('&', "").trim())
}

/// The database path and the window texts when `field` is the unlock screen's password field in
/// `window`: a secure text field that is the first text field after the path label. Qt lists
/// widgets in creation order, so the toolbar's search field can come before or after the screen.
/// The key-file field is secure too but comes later. A password shown in clear is not secure, and
/// it still comes before the key-file field, so neither is filled. The quick unlock screen for
/// Touch ID focuses a button. Only the unlock screen, in the main window or the unlock dialog,
/// shows the database's absolute path as text, which reads the same in every UI language.
fn password_prompt<E: Element>(field: &E, window: &E) -> Option<(String, Vec<String>)> {
    let secure =
        field.text("AXSubrole") == SECURE || field.text("AXRoleDescription") == SECURE_DESCRIPTION;
    if field.text("AXRole") != "AXTextField" || !secure {
        return None;
    }
    let scan = scan(window);
    let (path, password) = scan.password_field()?;
    if !password.same(field) {
        return None;
    }
    let path = path.to_owned();
    Some((path, scan.texts))
}

/// The file name of the one KeePass database whose path the texts show, as the unlock widget's
/// path label does in the locked main window and in the unlock dialog.
pub fn database_from_texts<'a>(texts: impl IntoIterator<Item = &'a str>) -> Option<String> {
    database_path(texts).map(file_name)
}

/// The one KeePass database path among the texts. Two databases make the screen ambiguous, so
/// they give none.
fn database_path<'a>(texts: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let mut paths: Vec<&str> = texts
        .into_iter()
        .filter(|text| is_database_file(text))
        .collect();
    paths.sort_unstable();
    paths.dedup();
    match paths[..] {
        [only] => Some(only),
        _ => None,
    }
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// True for an absolute path to a regular file that starts with the KDBX signature. Any other
/// text, such as an entry titled with a path, does not count. A stalled network mount can block
/// even the metadata call, so the probe runs on its own thread and is abandoned after `PROBE`.
fn is_database_file(text: &str) -> bool {
    if !text.starts_with('/') {
        return false;
    }
    let path = text.to_owned();
    let (sender, result) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(has_kdbx_signature(&path));
    });
    result.recv_timeout(PROBE).unwrap_or(false)
}

fn has_kdbx_signature(path: &str) -> bool {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut signature = [0; 8];
    // O_NONBLOCK keeps a FIFO swapped in after the check from blocking the open.
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
        && std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(path)
            .and_then(|mut file| file.read_exact(&mut signature))
            .is_ok_and(|()| signature == KDBX)
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Unlocked,
    /// The unlock screen still shows, with KeePassXC's new message if one appeared.
    Rejected(Option<String>),
}

/// Judges an unlock attempt from the window texts before the press and now, or returns `None`
/// while it runs. KeePassXC closes the unlock screen on success. On failure it keeps the screen
/// and shows its error, so a text that was not there before is that error, in the UI language.
/// KeePassXC stays responsive during a long key derivation with the password field disabled, so
/// the screen counts as a failure only with the field `enabled`, and an unchanged screen only
/// once the attempt is known to have `finished`. The screen counts as gone once its database
/// `path` no longer shows. The path is compared as text, so a stalled mount cannot end the watch.
pub fn judge(
    path: &str,
    before: &[String],
    now: &[String],
    enabled: bool,
    finished: bool,
) -> Option<Verdict> {
    if !now.iter().any(|text| text == path) {
        return Some(Verdict::Unlocked);
    }
    if !enabled {
        return None;
    }
    let message = now
        .iter()
        .filter(|text| !text.trim().is_empty() && !before.contains(text))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    if !message.is_empty() {
        return Some(Verdict::Rejected(Some(message)));
    }
    finished.then_some(Verdict::Rejected(None))
}

/// Polls KeePassXC's focused element and reports each new password prompt once.
#[derive(Default)]
pub struct Kpxc {
    prompting: bool,
    prompt: Option<Prompt>,
    seen: Option<Seen>,
    watch: Option<Watch>,
    /// The last signature check, by pid. Window texts and paths are read only from a genuine KeePassXC.
    genuine: Option<(i32, bool)>,
}

/// An Unlock press whose result is not known yet.
struct Watch {
    path: String,
    /// The password field. KeePassXC disables it while it unlocks and enables it after a failure.
    field: CFRetained<AXUIElement>,
    /// The window of the unlock screen. Another window taking focus says nothing about this attempt.
    window: CFRetained<AXUIElement>,
    before: Vec<String>,
    /// The attempt ended: the field was disabled and is enabled again.
    finished: bool,
    busy: bool,
    until: Instant,
}

/// The verdict for one focus. Reading a window's texts walks its elements, so it is redone only
/// when the process, window, window title, or focused field changes, as on lock, unlock, or a dialog.
struct Seen {
    pid: i32,
    field: CFRetained<AXUIElement>,
    window: CFRetained<AXUIElement>,
    title: String,
    /// The database path the prompt asks for, or `None` when the focus is no password prompt.
    path: Option<String>,
}

/// A password prompt as it was seen, which an unlock attempt keeps until it fills.
#[derive(Clone)]
pub struct Prompt {
    pid: i32,
    field: CFRetained<AXUIElement>,
    window: CFRetained<AXUIElement>,
    path: String,
}

impl Prompt {
    /// The database file name, which names its stored password.
    pub fn database(&self) -> String {
        file_name(&self.path)
    }
}

/// What one walk of a window finds.
struct Scan<E> {
    texts: Vec<String>,
    /// Each text field with the number of texts that come before it.
    fields: Vec<(usize, E)>,
}

impl<E> Scan<E> {
    /// The one database path and the first text field after its label.
    fn password_field(&self) -> Option<(&str, &E)> {
        let path = database_path(self.texts.iter().map(String::as_str))?;
        let label = self.texts.iter().position(|text| text == path)?;
        let (_, field) = self.fields.iter().find(|(before, _)| *before > label)?;
        Some((path, field))
    }
}

impl Kpxc {
    /// Returns true when a password prompt gains focus. Queries KeePassXC only while it is frontmost.
    pub fn poll(&mut self) -> bool {
        // A look-alike app gets no PIN panel, and its window texts and paths are never read.
        let prompt = frontmost_pid()
            .filter(|pid| self.genuine(*pid))
            .and_then(|pid| self.focused_prompt(pid));
        let started = prompt.is_some() && !self.prompting;
        self.prompting = prompt.is_some();
        self.prompt = prompt;
        started
    }

    /// Checks the signature once per KeePassXC process, not per tick.
    fn genuine(&mut self, pid: i32) -> bool {
        match self.genuine {
            Some((checked, genuine)) if checked == pid => genuine,
            _ => {
                let genuine = is_genuine_keepassxc(pid);
                self.genuine = Some((pid, genuine));
                genuine
            }
        }
    }

    fn focused_prompt(&mut self, pid: i32) -> Option<Prompt> {
        let (field, window) = focused(pid)?;
        let title = string(&window, "AXTitle");
        let known = self.seen.as_ref().is_some_and(|seen| {
            seen.pid == pid
                && *seen.field == *field
                && *seen.window == *window
                && seen.title == title
        });
        if !known {
            let path = password_prompt(&field, &window).map(|(path, _)| path);
            self.seen = Some(Seen {
                pid,
                field: field.clone(),
                window: window.clone(),
                title,
                path,
            });
        }
        let path = self.seen.as_ref()?.path.clone()?;
        Some(Prompt {
            pid,
            field,
            window,
            path,
        })
    }

    /// Writes `secret` into `prompt`'s field, then optionally presses Unlock and watches for the
    /// result, which `unlock_result` reports. The PIN and touch take seconds, so the field must
    /// still be the password field of a screen that shows the same database, or nothing is
    /// written. Focus is not required: KeePassXC's window is not key while fido2kpxc's panel is.
    pub fn fill(&mut self, prompt: &Prompt, secret: &str, press_unlock: bool) -> Result<()> {
        let Prompt {
            pid,
            field,
            window,
            path,
        } = prompt;
        ensure!(
            is_genuine_keepassxc(*pid),
            "The window asking for the password is not the signed KeePassXC"
        );
        let changed = "The KeePassXC password prompt changed or closed";
        let (shown, before) = password_prompt(field, window).context(changed)?;
        ensure!(shown == *path, "{changed}");
        let button = if press_unlock {
            let missing = "The Unlock button is missing. Set autofill to \"fill\"";
            Some(find_button(window).context(missing)?)
        } else {
            None
        };
        let status = unsafe { field.set_attribute_value(&cf("AXValue"), &cf(secret)) };
        ensure!(
            status == AXError::Success,
            "KeePassXC rejected the password field write ({status:?})"
        );
        if let Some(button) = button {
            let status = unsafe { button.perform_action(&cf("AXPress")) };
            // Qt queues the click, so Success means only that the press arrived. So does a timeout.
            ensure!(
                matches!(status, AXError::Success | AXError::CannotComplete),
                "Pressing Unlock failed ({status:?})"
            );
            self.watch = Some(Watch {
                path: path.clone(),
                field: field.clone(),
                window: window.clone(),
                before,
                finished: false,
                busy: false,
                until: Instant::now() + WATCH,
            });
        }
        Ok(())
    }

    /// The result of the watched Unlock press, once it is known, with the database name. It reads
    /// the unlock screen's own window, so another window taking focus neither ends nor judges the
    /// attempt.
    pub fn unlock_result(&mut self) -> Option<(String, Verdict)> {
        let watch = self.watch.as_mut()?;
        if Instant::now() >= watch.until {
            self.watch = None;
            return None;
        }
        // The unlock dialog closes on success.
        if matches!(
            attribute_status(&watch.window, "AXRole"),
            Err(AXError::InvalidUIElement)
        ) {
            let watch = self.watch.take()?;
            return Some((file_name(&watch.path), Verdict::Unlocked));
        }
        let now = scan(&watch.window).texts;
        // Focus leaves the password field while KeePassXC disables it, so read the field itself.
        let enabled = enabled(&watch.field);
        watch.busy |= !enabled;
        watch.finished |= watch.busy && enabled;
        let verdict = judge(&watch.path, &watch.before, &now, enabled, watch.finished)?;
        let watch = self.watch.take()?;
        Some((file_name(&watch.path), verdict))
    }

    /// Reports a prompt that is still on screen as new at the next poll, as after a stored password
    /// replaced one that KeePassXC refused.
    pub fn rearm(&mut self) {
        self.prompting = false;
    }

    /// Whether ticks must come fast: an Unlock press is being watched, or KeePassXC is frontmost
    /// and `autofill` needs its prompts.
    pub fn active(&self, autofill: bool) -> bool {
        self.watch.is_some() || (autofill && frontmost_pid().is_some())
    }

    /// True while KeePassXC's unlock screen has focus, so "Unlock KeePassXC" can fill it.
    pub fn at_prompt(&self) -> bool {
        self.prompting && self.prompt.is_some()
    }

    /// The prompt that has focus now, for an unlock attempt to keep. It is read again because the
    /// unlock dialog reuses one password field and title for every database, so a switch between
    /// its databases leaves the cached verdict unchanged.
    pub fn prompt(&self) -> Option<Prompt> {
        let prompt = self.prompt.as_ref()?;
        let (path, _) = password_prompt(&prompt.field, &prompt.window)?;
        Some(Prompt {
            path,
            ..prompt.clone()
        })
    }

    /// The database that the prompt with focus asks for.
    pub fn database(&self) -> Option<String> {
        Some(self.prompt()?.database())
    }

    /// Returns keyboard focus to KeePassXC after the PIN dialog.
    pub fn activate() {
        for app in NSRunningApplication::runningApplicationsWithBundleIdentifier(
            &NSString::from_str(BUNDLE_ID),
        ) {
            app.activateWithOptions(NSApplicationActivationOptions::empty());
        }
    }
}

/// KeePassXC's Developer ID signature. Any app can claim KeePassXC's bundle ID, so the
/// password goes only to a process whose running code satisfies this requirement.
const KEEPASSXC_REQUIREMENT: &str = r#"identifier "org.keepassxc.keepassxc" and anchor apple generic and certificate leaf[subject.OU] = "G2S7P7J672""#;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: &'static CFString;
    fn SecCodeCopyGuestWithAttributes(
        host: *const c_void,
        attributes: &CFDictionary,
        flags: u32,
        guest: *mut *mut CFType,
    ) -> i32;
    fn SecRequirementCreateWithString(
        text: &CFString,
        flags: u32,
        requirement: *mut *mut CFType,
    ) -> i32;
    fn SecCodeCheckValidity(code: &CFType, flags: u32, requirement: &CFType) -> i32;
}

/// Checks the running code of `pid` against KeePassXC's signature.
pub fn is_genuine_keepassxc(pid: i32) -> bool {
    // SAFETY: each Copy/Create call transfers one retain count, which `owned` adopts.
    unsafe {
        let pid = CFNumber::new_i32(pid);
        let attributes = CFDictionary::from_slices(&[kSecGuestAttributePid], &[&*pid]);
        let mut code = ptr::null_mut();
        let mut requirement = ptr::null_mut();
        if SecCodeCopyGuestWithAttributes(ptr::null(), attributes.as_opaque(), 0, &mut code) != 0
            || SecRequirementCreateWithString(&cf(KEEPASSXC_REQUIREMENT), 0, &mut requirement) != 0
        {
            return false;
        }
        match (owned(code), owned(requirement)) {
            (Some(code), Some(requirement)) => SecCodeCheckValidity(&code, 0, &requirement) == 0,
            _ => false,
        }
    }
}

unsafe fn owned(value: *mut CFType) -> Option<CFRetained<CFType>> {
    NonNull::new(value).map(|v| unsafe { CFRetained::from_raw(v) })
}

/// What detection sees right now, for "Copy Diagnostics". Holds no secrets.
pub fn diagnose() -> Vec<String> {
    let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(&NSString::from_str(
        BUNDLE_ID,
    ));
    let Some(app) = apps.iter().next() else {
        return vec!["KeePassXC: not running".to_owned()];
    };
    let pid = app.processIdentifier();
    let version = app
        .bundleURL()
        .and_then(|url| NSBundle::bundleWithURL(&url))
        .and_then(|bundle| {
            bundle.objectForInfoDictionaryKey(&NSString::from_str("CFBundleShortVersionString"))
        })
        .and_then(|value| value.downcast::<NSString>().ok())
        .map_or_else(|| "unknown".to_owned(), |v| v.to_string());
    let mut lines = vec![
        format!("KeePassXC: running, version {version}, pid {pid}"),
        format!(
            "KeePassXC signature check: {}",
            if is_genuine_keepassxc(pid) {
                "passed"
            } else {
                "FAILED"
            }
        ),
        format!("KeePassXC frontmost: {}", frontmost_pid() == Some(pid)),
    ];
    match focused(pid) {
        None => lines.push("Focused window: none".to_owned()),
        Some((field, window)) => {
            let scan = scan(&window);
            let first = scan
                .password_field()
                .is_some_and(|(_, first)| first.same(&field));
            let database = database_from_texts(scan.texts.iter().map(String::as_str));
            lines.push(format!("Focused window: {:?}", string(&window, "AXTitle")));
            lines.push(format!(
                "Focused element role: {}, subrole: {}, description: {}",
                string(&field, "AXRole"),
                string(&field, "AXSubrole"),
                string(&field, "AXRoleDescription")
            ));
            lines.push(format!(
                "Focused element is the first text field after the path label: {first}"
            ));
            lines.push(format!(
                "Database path label: {}",
                database.as_deref().unwrap_or("not found")
            ));
            lines.push(format!(
                "Password prompt when frontmost: {}",
                password_prompt(&field, &window).is_some()
            ));
        }
    }
    lines
}

pub fn accessibility_trusted() -> bool {
    unsafe { objc2_application_services::AXIsProcessTrusted() }
}

fn frontmost_pid() -> Option<i32> {
    let app = NSWorkspace::sharedWorkspace().frontmostApplication()?;
    (app.bundleIdentifier()?.to_string() == BUNDLE_ID).then(|| app.processIdentifier())
}

/// KeePassXC's focused element and focused window.
fn focused(pid: i32) -> Option<(CFRetained<AXUIElement>, CFRetained<AXUIElement>)> {
    // On the system-wide element the timeout applies to every AX call, not just this one.
    static TIMEOUT: Once = Once::new();
    TIMEOUT.call_once(|| unsafe {
        AXUIElement::new_system_wide().set_messaging_timeout(AX_TIMEOUT_SECONDS);
    });
    let app = unsafe { AXUIElement::new_application(pid) };
    let field = element(&app, "AXFocusedUIElement")?;
    // Qt gives the focused field no AXWindow attribute, so ask the app for its focused window.
    let window = element(&app, "AXFocusedWindow")?;
    Some((field, window))
}

/// The static texts and text fields in `window`, depth first. The walk stops after `WALK_LIMIT`
/// elements.
fn scan<E: Element>(window: &E) -> Scan<E> {
    fn walk<E: Element>(element: &E, depth: usize, visited: &mut usize, out: &mut Scan<E>) {
        *visited += 1;
        match element.text("AXRole").as_str() {
            "AXStaticText" => out.texts.push(element.text("AXValue")),
            "AXTextField" => out.fields.push((out.texts.len(), element.clone())),
            _ => {}
        }
        if depth >= 25 {
            return;
        }
        for child in element.children() {
            if *visited >= WALK_LIMIT {
                return;
            }
            walk(&child, depth + 1, visited, out);
        }
    }
    let mut out = Scan {
        texts: Vec::new(),
        fields: Vec::new(),
    };
    walk(window, 0, &mut 0, &mut out);
    out
}

fn children(element: &AXUIElement) -> Vec<CFRetained<AXUIElement>> {
    let Some(children) =
        attribute(element, "AXChildren").and_then(|c| c.downcast::<CFArray>().ok())
    else {
        return Vec::new();
    };
    // SAFETY: AXChildren is documented to hold AXUIElement values.
    let children = unsafe { children.cast_unchecked::<AXUIElement>() };
    children.iter().collect()
}

/// The Unlock button in `window`, depth first, within the same element budget as `scan`.
fn find_button(window: &CFRetained<AXUIElement>) -> Option<CFRetained<AXUIElement>> {
    fn walk(
        element: &AXUIElement,
        depth: usize,
        visited: &mut usize,
    ) -> Option<CFRetained<AXUIElement>> {
        for child in children(element) {
            *visited += 1;
            if *visited > WALK_LIMIT {
                return None;
            }
            if string(&child, "AXRole") == "AXButton" && is_unlock_title(&string(&child, "AXTitle"))
            {
                return Some(child);
            }
            if depth < 25
                && let Some(found) = walk(&child, depth + 1, visited)
            {
                return Some(found);
            }
        }
        None
    }
    walk(window, 0, &mut 0)
}

fn attribute(element: &AXUIElement, name: &str) -> Option<CFRetained<CFType>> {
    attribute_status(element, name).ok()
}

fn attribute_status(element: &AXUIElement, name: &str) -> Result<CFRetained<CFType>, AXError> {
    let mut value: *const CFType = ptr::null();
    let status = unsafe { element.copy_attribute_value(&cf(name), NonNull::from(&mut value)) };
    // SAFETY: the Copy rule transfers one retain count to the caller.
    let value = NonNull::new(value.cast_mut()).map(|v| unsafe { CFRetained::from_raw(v) });
    match (status, value) {
        (AXError::Success, Some(value)) => Ok(value),
        (AXError::Success, None) => Err(AXError::NoValue),
        (status, _) => Err(status),
    }
}

fn element(parent: &AXUIElement, name: &str) -> Option<CFRetained<AXUIElement>> {
    attribute(parent, name)?.downcast::<AXUIElement>().ok()
}

fn string(element: &AXUIElement, name: &str) -> String {
    attribute(element, name)
        .and_then(|v| v.downcast::<CFString>().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// False only when the element reports itself disabled. An element without the attribute counts
/// as enabled, so an unlocked window with an unusual focus still ends the watch.
fn enabled(element: &AXUIElement) -> bool {
    attribute(element, "AXEnabled")
        .and_then(|v| v.downcast::<CFBoolean>().ok())
        .is_none_or(|b| b.as_bool())
}

fn cf(text: &str) -> CFRetained<CFString> {
    CFString::from_str(text)
}

#[cfg(test)]
mod tests;
