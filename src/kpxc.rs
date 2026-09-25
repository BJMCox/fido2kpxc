use std::ptr::{self, NonNull};
use std::sync::Once;

use anyhow::{Context, Result, ensure};
use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication, NSWorkspace};
use objc2_application_services::{AXError, AXUIElement};
use std::ffi::c_void;

use objc2_core_foundation::{CFArray, CFDictionary, CFNumber, CFRetained, CFString, CFType};
use objc2_foundation::NSString;

const BUNDLE_ID: &str = "org.keepassxc.keepassxc";
// Bounds each call when KeePassXC hangs.
const AX_TIMEOUT_SECONDS: f32 = 0.5;

/// The focused element's attributes that decide whether KeePassXC asks for the database password.
pub struct Focus<'a> {
    pub frontmost: bool,
    pub role: &'a str,
    pub description: &'a str,
    pub window_title: &'a str,
}

pub fn is_password_prompt(focus: &Focus) -> bool {
    focus.frontmost
        && focus.role == "AXTextField"
        // 2.7.12 ships "visibilty". Upstream main fixed the spelling.
        && focus.description.starts_with("Toggle password visib")
        // The entry editor reuses this field, but a locked database has no open editor.
        && (focus.window_title.contains("[Locked]") || focus.window_title.starts_with("Unlock Database"))
}

/// The database file name in a locked main window's title, such as `pdb.kdbx [Locked] - KeePassXC`.
/// The separate unlock dialog's title names no database.
pub fn database_name(window_title: &str) -> Option<&str> {
    window_title
        .split_once(" [Locked]")
        .map(|(name, _)| name)
        .filter(|name| !name.is_empty())
}

/// The database file name from the unlock widget's path label, which both the locked main
/// window and the separate unlock dialog show. It is the only text that is an absolute path.
pub fn database_from_texts<'a>(texts: impl IntoIterator<Item = &'a str>) -> Option<String> {
    texts
        .into_iter()
        .find(|text| text.starts_with('/'))
        .and_then(|path| std::path::Path::new(path).file_name())
        .map(|name| name.to_string_lossy().into_owned())
}

/// Polls KeePassXC's focused element and reports each new password prompt once.
#[derive(Default)]
pub struct Kpxc {
    prompting: bool,
    prompt: Option<Prompt>,
}

struct Prompt {
    pid: i32,
    field: CFRetained<AXUIElement>,
    window: CFRetained<AXUIElement>,
    window_title: String,
    /// Read once per prompt, because it walks the window's elements.
    database: Option<String>,
}

impl Kpxc {
    /// Returns true when a password prompt gains focus. Queries KeePassXC only while it is frontmost.
    pub fn poll(&mut self) -> bool {
        let prompt = frontmost_pid().and_then(focused_prompt);
        let started = prompt.is_some() && !self.prompting;
        self.prompting = prompt.is_some();
        match prompt {
            // A look-alike window gets no PIN panel. The check runs once per prompt, not per tick.
            Some(prompt) if started && !is_genuine_keepassxc(prompt.pid) => {
                self.prompt = None;
                false
            }
            Some(mut prompt) => {
                if started {
                    prompt.database = database_from_texts(
                        static_texts(&prompt.window).iter().map(String::as_str),
                    )
                    .or_else(|| database_name(&prompt.window_title).map(str::to_owned));
                } else if let Some(previous) = self.prompt.take() {
                    prompt.database = previous.database;
                }
                self.prompt = Some(prompt);
                started
            }
            None => started,
        }
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

pub fn accessibility_trusted() -> bool {
    unsafe { objc2_application_services::AXIsProcessTrusted() }
}

fn frontmost_pid() -> Option<i32> {
    let app = NSWorkspace::sharedWorkspace().frontmostApplication()?;
    (app.bundleIdentifier()?.to_string() == BUNDLE_ID).then(|| app.processIdentifier())
}

fn focused_prompt(pid: i32) -> Option<Prompt> {
    // On the system-wide element the timeout applies to every AX call, not just this one.
    static TIMEOUT: Once = Once::new();
    TIMEOUT.call_once(|| unsafe {
        AXUIElement::new_system_wide().set_messaging_timeout(AX_TIMEOUT_SECONDS);
    });
    let app = unsafe { AXUIElement::new_application(pid) };
    let field = element(&app, "AXFocusedUIElement")?;
    // Qt gives the focused field no AXWindow attribute, so ask the app for its focused window.
    let window = element(&app, "AXFocusedWindow")?;
    let window_title = string(&window, "AXTitle");
    let focus = Focus {
        frontmost: true,
        role: &string(&field, "AXRole"),
        description: &string(&field, "AXDescription"),
        window_title: &window_title,
    };
    is_password_prompt(&focus).then_some(Prompt {
        pid,
        field,
        window,
        window_title,
        database: None,
    })
}

/// Values of every static text in `parent`, depth first.
fn static_texts(parent: &AXUIElement) -> Vec<String> {
    fn walk(element: &AXUIElement, depth: usize, out: &mut Vec<String>) {
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
        if depth < 25 {
            for child in children.iter() {
                walk(&child, depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(parent, 0, &mut out);
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
mod tests {
    use super::*;

    const RELEASED: &str = "Toggle password visibilty using Control + H. Open the password generator using Control + G.";
    const UPSTREAM: &str = "Toggle password visibility using Control + H. Open the password generator using Control + G.";

    fn focus<'a>(frontmost: bool, description: &'a str, window_title: &'a str) -> Focus<'a> {
        Focus {
            frontmost,
            role: "AXTextField",
            description,
            window_title,
        }
    }

    #[test]
    fn a_process_not_signed_by_keepassxc_fails_the_check() {
        assert!(!is_genuine_keepassxc(std::process::id() as i32));
    }

    #[test]
    fn running_keepassxc_passes_the_check() {
        let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(
            &NSString::from_str(BUNDLE_ID),
        );
        // Skips when KeePassXC is not running on the test machine.
        if let Some(app) = apps.iter().next() {
            assert!(is_genuine_keepassxc(app.processIdentifier()));
        }
    }

    #[test]
    fn database_file_comes_from_the_path_label() {
        let texts = [
            "Unlock KeePassXC Database",
            "/Users/me/Synced/work.kdbx",
            "Enter Password:",
        ];
        assert_eq!(database_from_texts(texts).as_deref(), Some("work.kdbx"));
        assert_eq!(database_from_texts(["Enter Password:"]), None);
    }

    #[test]
    fn database_name_comes_from_the_locked_window_title() {
        assert_eq!(
            database_name("pdb.kdbx [Locked] - KeePassXC"),
            Some("pdb.kdbx")
        );
        assert_eq!(database_name("Unlock Database - KeePassXC"), None);
    }

    #[test]
    fn locked_main_window_is_a_prompt() {
        assert!(is_password_prompt(&focus(
            true,
            RELEASED,
            "pdb.kdbx [Locked] - KeePassXC"
        )));
    }

    #[test]
    fn unlock_dialog_is_a_prompt_with_the_upstream_spelling() {
        assert!(is_password_prompt(&focus(
            true,
            UPSTREAM,
            "Unlock Database - KeePassXC"
        )));
    }

    #[test]
    fn entry_editor_password_field_is_not_a_prompt() {
        assert!(!is_password_prompt(&focus(
            true,
            RELEASED,
            "pdb.kdbx - KeePassXC"
        )));
    }

    #[test]
    fn background_keepassxc_is_not_a_prompt() {
        assert!(!is_password_prompt(&focus(
            false,
            RELEASED,
            "pdb.kdbx [Locked] - KeePassXC"
        )));
    }
}
