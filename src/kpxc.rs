use std::ptr::{self, NonNull};
use std::sync::Once;

use anyhow::{Context, Result, ensure};
use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication, NSWorkspace};
use objc2_application_services::{AXError, AXUIElement};
use std::ffi::c_void;

use objc2_core_foundation::{CFArray, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_foundation::{NSBundle, NSString};

const BUNDLE_ID: &str = "org.keepassxc.keepassxc";
// Bounds each call when KeePassXC hangs.
const AX_TIMEOUT_SECONDS: f32 = 0.5;

/// What decides whether KeePassXC asks for the database password.
pub struct Focus<'a> {
    pub frontmost: bool,
    /// The focused element's role.
    pub role: &'a str,
    /// Every static text in the focused window.
    pub window_texts: &'a [String],
}

pub fn is_password_prompt(focus: &Focus) -> bool {
    // Only the unlock screen, in the main window or the unlock dialog, shows the database's
    // absolute path as text. A path reads the same in every UI language, unlike labels and titles.
    focus.frontmost
        && focus.role == "AXTextField"
        && database_from_texts(focus.window_texts.iter().map(String::as_str)).is_some()
}

/// The file name of the first text that is the path of a KeePass database, which is what the
/// unlock widget's path label shows in both the locked main window and the unlock dialog.
pub fn database_from_texts<'a>(texts: impl IntoIterator<Item = &'a str>) -> Option<String> {
    texts
        .into_iter()
        .find(|text| is_database_file(text))
        .and_then(|path| std::path::Path::new(path).file_name())
        .map(|name| name.to_string_lossy().into_owned())
}

/// True for an absolute path to a file that starts with the KDBX signature. Any other text, such
/// as an entry titled with a path, does not count.
fn is_database_file(text: &str) -> bool {
    use std::io::Read;
    const KDBX: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
    let mut signature = [0; 4];
    text.starts_with('/')
        && std::fs::File::open(text)
            .and_then(|mut file| file.read_exact(&mut signature))
            .is_ok_and(|()| signature == KDBX)
}

/// Polls KeePassXC's focused element and reports each new password prompt once.
#[derive(Default)]
pub struct Kpxc {
    prompting: bool,
    prompt: Option<Prompt>,
    seen: Option<Seen>,
}

/// The verdict for one focus. Reading a window's texts walks its elements, so it is redone only
/// when the process, window title, or focused field changes, as happens on lock, unlock, or a dialog.
struct Seen {
    key: (i32, String, String),
    prompt: bool,
    database: Option<String>,
}

struct Prompt {
    pid: i32,
    field: CFRetained<AXUIElement>,
    window: CFRetained<AXUIElement>,
    database: Option<String>,
}

impl Kpxc {
    /// Returns true when a password prompt gains focus. Queries KeePassXC only while it is frontmost.
    pub fn poll(&mut self) -> bool {
        let prompt = frontmost_pid().and_then(|pid| self.focused_prompt(pid));
        let started = prompt.is_some() && !self.prompting;
        self.prompting = prompt.is_some();
        match prompt {
            // A look-alike window gets no PIN panel. The check runs once per prompt, not per tick.
            Some(prompt) if started && !is_genuine_keepassxc(prompt.pid) => {
                self.prompt = None;
                false
            }
            Some(prompt) => {
                self.prompt = Some(prompt);
                started
            }
            None => started,
        }
    }

    fn focused_prompt(&mut self, pid: i32) -> Option<Prompt> {
        let (field, window) = focused(pid)?;
        let key = (
            pid,
            string(&window, "AXTitle"),
            string(&field, "AXDescription"),
        );
        if self.seen.as_ref().is_none_or(|seen| seen.key != key) {
            let role = string(&field, "AXRole");
            let texts = if role == "AXTextField" {
                static_texts(&window)
            } else {
                Vec::new()
            };
            let focus = Focus {
                frontmost: true,
                role: &role,
                window_texts: &texts,
            };
            self.seen = Some(Seen {
                key,
                prompt: is_password_prompt(&focus),
                database: database_from_texts(texts.iter().map(String::as_str)),
            });
        }
        let seen = self.seen.as_ref()?;
        seen.prompt.then(|| Prompt {
            pid,
            field,
            window,
            database: seen.database.clone(),
        })
    }

    /// Writes `secret` into the last prompt's field, then optionally presses Unlock.
    pub fn fill(&self, secret: &str, press_unlock: bool) -> Result<()> {
        let Prompt {
            pid, field, window, ..
        } = self
            .prompt
            .as_ref()
            .context("No KeePassXC password prompt is known")?;
        ensure!(
            is_genuine_keepassxc(*pid),
            "The window asking for the password is not the signed KeePassXC"
        );
        let status = unsafe { field.set_attribute_value(&cf("AXValue"), &cf(secret)) };
        ensure!(
            status == AXError::Success,
            "KeePassXC rejected the password field write ({status:?})"
        );
        if press_unlock {
            let button =
                find_button(window, "Unlock", 0).context("The Unlock button is missing")?;
            let status = unsafe { button.perform_action(&cf("AXPress")) };
            // KeePassXC runs the key derivation before it answers, so a timeout means the press arrived.
            ensure!(
                matches!(status, AXError::Success | AXError::CannotComplete),
                "Pressing Unlock failed ({status:?})"
            );
        }
        Ok(())
    }

    /// The database the last prompt asks for, when its window title names one.
    pub fn database(&self) -> Option<String> {
        self.prompt.as_ref()?.database.clone()
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
            let role = string(&field, "AXRole");
            let texts = static_texts(&window);
            let database = database_from_texts(texts.iter().map(String::as_str));
            lines.push(format!("Focused window: {:?}", string(&window, "AXTitle")));
            lines.push(format!("Focused element role: {role}"));
            lines.push(format!(
                "Database path label: {}",
                database.as_deref().unwrap_or("not found")
            ));
            let focus = Focus {
                frontmost: true,
                role: &role,
                window_texts: &texts,
            };
            lines.push(format!(
                "Password prompt when frontmost: {}",
                is_password_prompt(&focus)
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

/// Values of the static texts in `parent`, depth first. An unlocked database window can hold
/// thousands of rows, so the walk stops after `LIMIT` elements. The unlock screen is far smaller.
fn static_texts(parent: &AXUIElement) -> Vec<String> {
    const LIMIT: usize = 400;
    fn walk(element: &AXUIElement, depth: usize, visited: &mut usize, out: &mut Vec<String>) {
        *visited += 1;
        if *visited > LIMIT || depth > 25 {
            return;
        }
        if string(element, "AXRole") == "AXStaticText" {
            out.push(string(element, "AXValue"));
        }
        let Some(children) =
            attribute(element, "AXChildren").and_then(|c| c.downcast::<CFArray>().ok())
        else {
            return;
        };
        // SAFETY: AXChildren is documented to hold AXUIElement values.
        let children = unsafe { children.cast_unchecked::<AXUIElement>() };
        for child in children.iter() {
            walk(&child, depth + 1, visited, out);
        }
    }
    let mut out = Vec::new();
    walk(parent, 0, &mut 0, &mut out);
    out
}

fn find_button(parent: &AXUIElement, title: &str, depth: usize) -> Option<CFRetained<AXUIElement>> {
    let children = attribute(parent, "AXChildren")?
        .downcast::<CFArray>()
        .ok()?;
    // SAFETY: AXChildren is documented to hold AXUIElement values.
    let children = unsafe { children.cast_unchecked::<AXUIElement>() };
    for child in children.iter() {
        if string(&child, "AXRole") == "AXButton" && string(&child, "AXTitle") == title {
            return Some(child);
        }
        if depth < 25
            && let Some(found) = find_button(&child, title, depth + 1)
        {
            return Some(found);
        }
    }
    None
}

fn attribute(element: &AXUIElement, name: &str) -> Option<CFRetained<CFType>> {
    let mut value: *const CFType = ptr::null();
    let status = unsafe { element.copy_attribute_value(&cf(name), NonNull::from(&mut value)) };
    if status != AXError::Success {
        return None;
    }
    // SAFETY: the Copy rule transfers one retain count to the caller.
    NonNull::new(value.cast_mut()).map(|v| unsafe { CFRetained::from_raw(v) })
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

fn cf(text: &str) -> CFRetained<CFString> {
    CFString::from_str(text)
}

#[cfg(test)]
mod tests;
