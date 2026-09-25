use std::cell::RefCell;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{
    AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel,
};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSButton, NSControlStateValueOff,
    NSControlStateValueOn, NSImage, NSMenu, NSMenuDelegate, NSMenuItem, NSPasteboard,
    NSPasteboardContentsOptions, NSPasteboardTypeString, NSStatusBar, NSStatusItem,
    NSVariableStatusItemLength,
};
use objc2_foundation::{
    NSData, NSObject, NSObjectProtocol, NSProcessInfo, NSSize, NSString, NSTimer, ns_string,
};
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use zeroize::Zeroizing;

use crate::config::{Autofill, Config};
use crate::fido::{self, FidoError};
use crate::kpxc::{self, Kpxc};
use crate::ops;
use crate::panels::{self, Button, Field, Form, Key};
use crate::vault::{ANY, Unlock, Vault};

const TICK_SECONDS: f64 = 0.25;
const REPOSITORY: &str = "https://github.com/BJMCox/fido2kpxc";
// Stops the refocus after a closed dialog from reopening it at once.
const SUPPRESS: Duration = Duration::from_secs(3);
const RECHECK: Duration = Duration::from_secs(2);

#[derive(Clone, PartialEq)]
enum Target {
    Fill,
    /// Copies the password stored for this database name.
    Copy(String),
}

/// The open PIN panel, waiting for Unlock or Cancel.
struct Asking {
    target: Target,
    database: Option<String>,
    form: Form,
}

/// An open message panel. `retry` holds the attempt that Retry would restart.
struct Message {
    form: Form,
    retry: Option<Target>,
}

struct Pending {
    target: Target,
    result: Receiver<Result<Zeroizing<Vec<u8>>, FidoError>>,
    touch: Form,
}

/// A key-management step waiting for input in a form.
struct Setup {
    step: Step,
    form: Form,
}

enum Step {
    Create,
    AddCurrent,
    AddNew {
        current: Unlock,
    },
    RemoveChoose,
    /// Collects an output from each key in `left`, which the new data key must be wrapped for.
    RemoveTouch {
        label: String,
        left: Vec<(String, Vec<u8>)>,
        collected: Vec<Unlock>,
    },
    SetPassword,
    /// `draft` holds the values of a rejected attempt, so the form reopens with them.
    Settings {
        draft: Option<Vec<String>>,
    },
}

/// A key-management operation on the worker thread, and what follows it.
struct Job {
    next: Next,
    touch: Option<Form>,
    result: Receiver<Result<Outcome>>,
}

/// What continues once the security key for a flow is known.
enum AfterKey {
    Unlock(Target),
    Setup(Step),
}

enum Next {
    /// Counted the plugged-in keys. One key continues at once, several need a touch to choose.
    Devices(AfterKey),
    /// The user touched the key to use.
    Chosen(AfterKey),
    Report(String),
    AskNewKey,
    Collect {
        label: String,
        left: Vec<(String, Vec<u8>)>,
        collected: Vec<Unlock>,
    },
}

enum Outcome {
    Done,
    Unlock(Unlock),
    Devices(Vec<fido::Device>),
    Key(fido::Key),
}

struct Menu {
    status: Retained<NSMenuItem>,
    copy: Retained<NSMenuItem>,
    grant: Retained<NSMenuItem>,
    login: Retained<NSMenuItem>,
    set_up: Retained<NSMenuItem>,
    manage: Vec<Retained<NSMenuItem>>,
    item: Retained<NSStatusItem>,
    key_icon: Option<Retained<NSImage>>,
    warning_icon: Option<Retained<NSImage>>,
}

/// Runs all security-key work on one long-lived thread. hidapi binds its global HID manager
/// to the run loop of the first thread that uses it. A short-lived thread frees that run loop,
/// and the next device lookup then crashes in IOKit.
struct Worker(mpsc::Sender<Box<dyn FnOnce() + Send>>);

impl Default for Worker {
    fn default() -> Self {
        let (sender, jobs) = mpsc::channel::<Box<dyn FnOnce() + Send>>();
        std::thread::spawn(move || {
            for job in jobs {
                job();
            }
        });
        Self(sender)
    }
}

impl Worker {
    fn run(&self, job: impl FnOnce() + Send + 'static) {
        let _ = self.0.send(Box::new(job));
    }
}

#[derive(Default)]
struct State {
    worker: Worker,
    kpxc: Kpxc,
    asking: Option<Asking>,
    pending: Option<Pending>,
    message: Option<Message>,
    setup: Option<Setup>,
    job: Option<Job>,
    /// The security key the current flow uses, chosen before its PIN is asked.
    key: Option<fido::Key>,
    suppress_until: Option<Instant>,
    clear: Option<(Instant, isize)>,
    menu: Option<Menu>,
    /// The last config and vault check. An error keeps the app idle until the files are fixed.
    health: Option<(Instant, Result<Config, String>)>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "Fido2kpxcController"]
    #[ivars = RefCell<State>]
    struct Controller;

    unsafe impl NSObjectProtocol for Controller {}

    unsafe impl NSMenuDelegate for Controller {
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            self.refresh_menu();
        }
    }

    impl Controller {
        #[unsafe(method(tick:))]
        fn tick(&self, _timer: &NSTimer) {
            self.on_tick();
        }

        #[unsafe(method(copyPassword:))]
        fn copy_password(&self, sender: &AnyObject) {
            // Each menu item carries its database name, so one action serves the whole submenu.
            let database = sender
                .downcast_ref::<NSMenuItem>()
                .and_then(|item| item.representedObject())
                .and_then(|object| object.downcast::<NSString>().ok())
                .map_or_else(|| ANY.to_owned(), |name| name.to_string());
            if self.check_health(true).is_some_and(|c| c.copy_password) {
                self.start(Target::Copy(database), None);
            }
        }

        #[unsafe(method(grantAccessibility:))]
        fn grant_accessibility(&self, _sender: &AnyObject) {
            request_accessibility();
        }

        #[unsafe(method(toggleLogin:))]
        fn toggle_login(&self, _sender: &AnyObject) {
            let service = unsafe { SMAppService::mainAppService() };
            let result = unsafe {
                if service.status() == SMAppServiceStatus::Enabled {
                    service.unregisterAndReturnError()
                } else {
                    service.registerAndReturnError()
                }
            };
            if let Err(error) = result {
                self.alert(&format!("Start at Login failed: {}", error.localizedDescription()));
            }
            self.refresh_menu();
        }

        #[unsafe(method(pinSubmit:))]
        fn pin_submit(&self, _sender: &AnyObject) {
            // Return fires both the field's action and the default button, so the second call finds nothing.
            let Some(asking) = self.ivars().borrow_mut().asking.take() else {
                return;
            };
            let pin = asking.form.take_values().remove(0);
            asking.form.close();
            let vault = match load() {
                Ok((_, vault)) if !pin.is_empty() => vault,
                _ => return self.done(asking.target),
            };
            let Some(key) = self.ivars().borrow().key.clone() else {
                return self.done(asking.target);
            };
            let (sender, result) = mpsc::channel();
            let database = asking.database;
            self.ivars().borrow().worker.run(move || {
                let secret = fido::derive(&key, &pin, &vault.salt(), &vault.cred_ids())
                    .and_then(|unlock| {
                        vault
                            .open(&unlock, database.as_deref())
                            .map_err(FidoError::Other)
                    });
                let _ = sender.send(secret);
            });
            let touch = touch_form(self.mtm(), self, "Touch your security key now.");
            self.ivars().borrow_mut().pending = Some(Pending {
                target: asking.target,
                result,
                touch,
            });
        }

        #[unsafe(method(messageDismiss:))]
        fn message_dismiss(&self, _sender: &AnyObject) {
            if let Some(target) = self.close_message() {
                self.done(target);
            }
        }

        #[unsafe(method(messageRetry:))]
        fn message_retry(&self, _sender: &AnyObject) {
            if let Some(target) = self.close_message() {
                self.start(target, None);
            }
        }

        #[unsafe(method(pinCancel:))]
        fn pin_cancel(&self, _sender: &AnyObject) {
            let Some(asking) = self.ivars().borrow_mut().asking.take() else {
                return;
            };
            asking.form.take_values();
            asking.form.close();
            self.done(asking.target);
        }

        #[unsafe(method(setUp:))]
        fn set_up(&self, _sender: &AnyObject) {
            self.begin_flow();
            self.open_setup(Step::Create, None);
        }

        #[unsafe(method(addKey:))]
        fn add_key(&self, _sender: &AnyObject) {
            self.begin_flow();
            self.open_setup(Step::AddCurrent, None);
        }

        #[unsafe(method(removeKey:))]
        fn remove_key(&self, _sender: &AnyObject) {
            self.begin_flow();
            self.open_setup(Step::RemoveChoose, None);
        }

        #[unsafe(method(setPassword:))]
        fn set_password(&self, _sender: &AnyObject) {
            self.begin_flow();
            self.open_setup(Step::SetPassword, None);
        }

        #[unsafe(method(setupSubmit:))]
        fn setup_submit(&self, _sender: &AnyObject) {
            self.submit_setup();
        }

        #[unsafe(method(toggleReveal:))]
        fn toggle_reveal(&self, sender: &AnyObject) {
            let Some(button) = sender.downcast_ref::<NSButton>() else {
                return;
            };
            if let Some(setup) = self.ivars().borrow().setup.as_ref() {
                setup.form.toggle_reveal(button.tag() as usize);
            }
        }

        #[unsafe(method(setupCancel:))]
        fn setup_cancel(&self, _sender: &AnyObject) {
            let setup = self.ivars().borrow_mut().setup.take();
            if let Some(setup) = setup {
                setup.form.take_values();
                setup.form.close();
            }
        }

        #[unsafe(method(openSettings:))]
        fn open_settings(&self, _sender: &AnyObject) {
            self.open_setup(Step::Settings { draft: None }, None);
        }

        #[unsafe(method(openConfig:))]
        fn open_config(&self, _sender: &AnyObject) {
            let result = Config::path().and_then(|path| {
                Config::write_template(&path)?;
                open(&["-t"], &path)
            });
            if let Err(error) = result {
                self.alert(&format!("Cannot open the config: {error:#}"));
            }
        }

        #[unsafe(method(showVault:))]
        fn show_vault(&self, _sender: &AnyObject) {
            let result = Config::path().and_then(|path| Config::load(&path)).and_then(|config| {
                if config.vault.exists() {
                    open(&["-R"], &config.vault)
                } else {
                    open(&[], &config.folder)
                }
            });
            if let Err(error) = result {
                self.alert(&format!("Cannot show the vault: {error:#}"));
            }
        }

        #[unsafe(method(copyDiagnostics:))]
        fn copy_diagnostics(&self, _sender: &AnyObject) {
            let report = self.diagnostics();
            let pasteboard = NSPasteboard::generalPasteboard();
            pasteboard.clearContents();
            pasteboard.setString_forType(&NSString::from_str(&report), unsafe { NSPasteboardTypeString });
            self.alert("Copied diagnostics to the clipboard. They contain no passwords or key material.");
        }

        #[unsafe(method(showHelp:))]
        fn show_help(&self, _sender: &AnyObject) {
            self.alert(&help_text());
        }

        #[unsafe(method(showAbout:))]
        fn show_about(&self, _sender: &AnyObject) {
            self.close_message();
            let text = format!(
                "fido2kpxc {}\nUnlock KeePassXC with a FIDO2 security key.\n\nCopyright 2026 Jessica Cox <jmcox@posteo.de>\nLicensed under the Apache License, Version 2.0.",
                env!("CARGO_PKG_VERSION")
            );
            let buttons = [
                Button { title: "OK", action: sel!(messageDismiss:), key: Key::Return },
                Button { title: "Source Code", action: sel!(openRepository:), key: Key::Escape },
            ];
            let form = panels::form(self.mtm(), self, "About fido2kpxc", &text, &[], &buttons);
            self.ivars().borrow_mut().message = Some(Message { form, retry: None });
        }

        #[unsafe(method(openRepository:))]
        fn open_repository(&self, _sender: &AnyObject) {
            self.close_message();
            let _ = open(&[], std::path::Path::new(REPOSITORY));
        }

        #[unsafe(method(quit:))]
        fn quit(&self, _sender: &AnyObject) {
            self.clear_clipboard(true);
            NSApplication::sharedApplication(self.mtm()).terminate(None);
        }
    }
);

impl Controller {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(RefCell::new(State::default()));
        unsafe { msg_send![super(this), init] }
    }

    fn on_tick(&self) {
        let finished = {
            let mut state = self.ivars().borrow_mut();
            match state.pending.as_ref().map(|p| p.result.try_recv()) {
                Some(Ok(result)) => state.pending.take().map(|p| (p, result)),
                Some(Err(TryRecvError::Disconnected)) => state.pending.take().map(|p| {
                    (
                        p,
                        Err(FidoError::Other(anyhow::anyhow!(
                            "The unlock worker stopped"
                        ))),
                    )
                }),
                Some(Err(TryRecvError::Empty)) | None => None,
            }
        };
        if let Some((pending, result)) = finished {
            self.finish(pending, result);
        }

        let job_done = {
            let mut state = self.ivars().borrow_mut();
            match state.job.as_ref().map(|j| j.result.try_recv()) {
                Some(Ok(result)) => state.job.take().map(|j| (j, result)),
                Some(Err(TryRecvError::Disconnected)) => state
                    .job
                    .take()
                    .map(|j| (j, Err(anyhow::anyhow!("The worker stopped")))),
                Some(Err(TryRecvError::Empty)) | None => None,
            }
        };
        if let Some((job, result)) = job_done {
            if let Some(touch) = &job.touch {
                touch.close();
            }
            self.after_job(job.next, result);
        }

        self.clear_clipboard(false);

        let Some(config) = self.check_health(false) else {
            return;
        };
        if config.autofill == Autofill::Off {
            return;
        }
        let prompt = {
            let mut state = self.ivars().borrow_mut();
            let started = state.kpxc.poll();
            let suppressed = state.suppress_until.is_some_and(|t| Instant::now() < t);
            started && !suppressed && state.pending.is_none() && state.asking.is_none()
        };
        if prompt {
            self.start(Target::Fill, None);
        }
    }

    /// Clears a copied password once its delay passes, or at once with `now`.
    /// Leaves the clipboard alone when something newer replaced the password.
    fn clear_clipboard(&self, now: bool) {
        let clear = self.ivars().borrow().clear;
        if let Some((due, change_count)) = clear
            && (now || Instant::now() >= due)
        {
            let pasteboard = NSPasteboard::generalPasteboard();
            if pasteboard.changeCount() == change_count {
                pasteboard.clearContents();
            }
            self.ivars().borrow_mut().clear = None;
        }
    }

    /// Rechecks the config and the vault when the last check is stale or `force` is set.
    /// Returns the config when both load.
    fn check_health(&self, force: bool) -> Option<Config> {
        let stale = self
            .ivars()
            .borrow()
            .health
            .as_ref()
            .is_none_or(|(at, _)| force || at.elapsed() >= RECHECK);
        if stale {
            let health = load()
                .map(|(config, _)| config)
                .map_err(|e| format!("{e:#}"));
            self.ivars().borrow_mut().health = Some((Instant::now(), health));
            self.update_icon();
        }
        let state = self.ivars().borrow();
        state
            .health
            .as_ref()
            .and_then(|(_, health)| health.as_ref().ok().cloned())
    }

    fn update_icon(&self) {
        let state = self.ivars().borrow();
        let (Some(menu), Some((_, health))) = (state.menu.as_ref(), state.health.as_ref()) else {
            return;
        };
        let (icon, fallback, description) = match health {
            Ok(_) => (
                &menu.key_icon,
                ns_string!("key.fill"),
                ns_string!("fido2kpxc"),
            ),
            Err(_) => (
                &menu.warning_icon,
                ns_string!("exclamationmark.triangle.fill"),
                ns_string!("fido2kpxc: needs attention"),
            ),
        };
        let image = icon.clone().or_else(|| {
            NSImage::imageWithSystemSymbolName_accessibilityDescription(fallback, Some(description))
        });
        if let Some(button) = menu.item.button(self.mtm()) {
            button.setImage(image.as_deref());
        }
    }

    /// A plain-text report for bug reports. It lists names and states, never secrets.
    fn diagnostics(&self) -> String {
        let mut lines = vec![
            format!("fido2kpxc {} diagnostics", env!("CARGO_PKG_VERSION")),
            format!(
                "macOS: {}",
                NSProcessInfo::processInfo().operatingSystemVersionString()
            ),
        ];
        match Config::path().and_then(|path| Config::load(&path).map(|config| (path, config))) {
            Err(error) => lines.push(format!("Config: {error:#}")),
            Ok((path, config)) => {
                lines.push(format!("Config: {} (loads)", path.display()));
                lines.push(format!(
                    "Autofill: {:?}, Copy Password: {}, clear after {} s",
                    config.autofill, config.copy_password, config.clear_seconds
                ));
                match Vault::load(&config.vault) {
                    Err(error) => lines.push(format!("Vault: {error:#}")),
                    Ok(vault) => {
                        let keys: Vec<&str> = vault
                            .entries()
                            .into_iter()
                            .map(|(label, _)| label)
                            .collect();
                        lines.push(format!("Vault: {} (loads)", config.vault.display()));
                        lines.push(format!("Keys: {}", keys.join(", ")));
                        lines.push(format!(
                            "Stored passwords: {}",
                            vault.databases().join(", ")
                        ));
                    }
                }
            }
        }
        lines.push(format!(
            "Accessibility: {}",
            if kpxc::accessibility_trusted() {
                "granted"
            } else {
                "not granted"
            }
        ));
        let login =
            unsafe { SMAppService::mainAppService().status() } == SMAppServiceStatus::Enabled;
        lines.push(format!("Start at Login: {login}"));
        lines.extend(kpxc::diagnose());
        lines.join("\n") + "\n"
    }

    fn open_setup_fresh(&self, step: Step, note: Option<&str>) {
        self.begin_flow();
        self.open_setup(step, note);
    }

    /// Validates and writes the settings form, or reopens it with the problem and the typed values.
    fn save_settings(&self, draft: Vec<String>) {
        let autofill = AUTOFILL_LABELS
            .iter()
            .position(|label| *label == draft[1])
            .map_or(Autofill::default(), |i| Autofill::ALL[i]);
        let problem = match draft[3].trim().parse::<u64>() {
            Err(_) => Some("Clear after must be a whole number of seconds.".to_owned()),
            Ok(clear) => {
                let text = Config::render(draft[0].trim(), autofill, draft[2] == "On", clear);
                Config::check(&text)
                    .and_then(|_| Config::write(&Config::path()?, &text))
                    .err()
                    .map(|error| format!("{error:#}"))
            }
        };
        match problem {
            Some(problem) => self.open_setup(Step::Settings { draft: Some(draft) }, Some(&problem)),
            None => {
                self.check_health(true);
                self.alert("Saved the settings.");
            }
        }
    }

    fn busy(&self) -> bool {
        let state = self.ivars().borrow();
        state.asking.is_some()
            || state.pending.is_some()
            || state.setup.is_some()
            || state.job.is_some()
    }

    /// Shows the form for `step`. `note` explains why the previous input was rejected.
    fn open_setup(&self, step: Step, note: Option<&str>) {
        if self.busy() {
            return;
        }
        if needs_key(&step) && self.ivars().borrow().key.is_none() {
            return self.with_key(AfterKey::Setup(step));
        }
        // Settings must open even without a working config, so they can fix it.
        let loaded = Config::path().and_then(|path| Config::load(&path));
        let config = match (&step, loaded) {
            (Step::Settings { .. }, loaded) => loaded.ok(),
            (_, Ok(config)) => Some(config),
            (_, Err(error)) => {
                return self.alert(&format!("{error:#}\n\nChoose Settings… first."));
            }
        };
        let vault = config.as_ref().map(|c| Vault::load(&c.vault));
        if !matches!(step, Step::Create | Step::Settings { .. })
            && let Some(Err(error)) = &vault
        {
            return self.alert(&format!("{error:#}\n\nChoose Set Up… first."));
        }
        let vault = vault.and_then(Result::ok);
        let (folder_value, clear_value, autofill_index, copy_index) =
            settings_values(&step, config.as_ref());
        let pin = Field::secret("PIN");
        let password = Field::revealable("Password", sel!(toggleReveal:));
        let repeat = Field::revealable("Repeat", sel!(toggleReveal:));
        let database = Field::plain("Database file", "");
        let (message, fields, submit) = match &step {
            Step::Create => {
                let Some(config) = &config else {
                    return;
                };
                if let Err(error) = ops::check_new(config) {
                    return self.alert(&format!("{error:#}"));
                }
                let text = format!(
                    "Set up fido2kpxc with this security key. The vault goes to {}. Leave the database file blank to use the password for any database. After Set Up, touch the key twice.",
                    config.vault.display()
                );
                let label = Field::plain("Key label", "primary");
                (text, vec![label, database, password, repeat, pin], "Set Up")
            }
            Step::AddCurrent => (
                "Insert a security key that is already enrolled, and enter its PIN. Then touch it.".to_owned(),
                vec![pin],
                "Continue",
            ),
            Step::AddNew { .. } => (
                "Remove the enrolled key and insert the new one. Enter a label for it and its PIN, then touch it twice.".to_owned(),
                vec![Field::plain("Key label", ""), pin],
                "Add Key",
            ),
            Step::RemoveChoose => {
                let labels = vault
                    .as_ref()
                    .map(|v| v.entries().into_iter().map(|(l, _)| l.to_owned()).collect())
                    .unwrap_or_default();
                (
                    "Choose the key to remove. Afterwards, each remaining key needs its PIN and a touch.".to_owned(),
                    vec![Field::choice("Key", labels, 0)],
                    "Continue",
                )
            }
            Step::RemoveTouch { left, .. } => (
                format!("Insert the key \"{}\", enter its PIN, then touch it.", left[0].0),
                vec![pin],
                "Continue",
            ),
            Step::SetPassword => {
                let stored = vault
                    .as_ref()
                    .map(|v| v.databases().into_iter().map(ops::describe).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default();
                let text = format!(
                    "Enter the database file name, such as pdb.kdbx, and its password. Leave the name blank for any other database. Stored now: {stored}. Then touch your security key."
                );
                (text, vec![database, password, repeat, pin], "Save")
            }
            Step::Settings { .. } => {
                let path = Config::path().map_or_else(|_| "the config file".to_owned(), |p| p.display().to_string());
                let text = format!(
                    "The vault lives in the vault folder as vault.toml. A path starting with ~/ works on every Mac. Settings are saved to {path}."
                );
                let fields = vec![
                    Field::plain("Vault folder", &folder_value),
                    Field::choice("Autofill", AUTOFILL_LABELS.map(str::to_owned).to_vec(), autofill_index),
                    Field::choice("Copy Password", vec!["Off".to_owned(), "On".to_owned()], copy_index),
                    Field::plain("Clear after (s)", &clear_value),
                ];
                (text, fields, "Save")
            }
        };
        let message = match note {
            Some(note) => format!("{note}\n\n{message}"),
            None => message,
        };
        self.close_message();
        let form = panels::form(
            self.mtm(),
            self,
            "fido2kpxc",
            &message,
            &fields,
            &[
                Button {
                    title: submit,
                    action: sel!(setupSubmit:),
                    key: Key::Return,
                },
                Button {
                    title: "Cancel",
                    action: sel!(setupCancel:),
                    key: Key::Escape,
                },
            ],
        );
        self.ivars().borrow_mut().setup = Some(Setup { step, form });
    }

    /// Validates the open form and starts its operation, or reopens it with a note.
    fn submit_setup(&self) {
        let setup = self.ivars().borrow_mut().setup.take();
        let Some(Setup { step, form }) = setup else {
            return;
        };
        let values = form.take_values();
        form.close();
        if let Step::Settings { .. } = step {
            return self.save_settings(values.iter().map(|v| v.to_string()).collect());
        }
        let Ok(config) = Config::path().and_then(|path| Config::load(&path)) else {
            return;
        };
        let owned = |i: usize| Zeroizing::new(values[i].trim().to_owned());
        // Steps that ask for a PIN run only after their key was chosen, so the key is set here.
        let key = self.ivars().borrow().key.clone();
        match step {
            Step::Create => {
                let (label, database, pin) = (owned(0), database_or_any(&values[1]), owned(4));
                let secret = Zeroizing::new(values[2].to_string());
                let problem = password_problem(&values[2], &values[3])
                    .or_else(|| label.is_empty().then_some("Enter a key label."))
                    .or_else(|| pin.is_empty().then_some("Enter the PIN."));
                if let Some(problem) = problem {
                    return self.open_setup(Step::Create, Some(problem));
                }
                let report = format!("Created the vault at {}.", config.vault.display());
                self.spawn(
                    Next::Report(report),
                    Some("Touch your security key twice."),
                    move || {
                        ops::create(
                            &config,
                            &key.context("No security key was chosen")?,
                            &label,
                            &database,
                            secret.as_bytes(),
                            &pin,
                        )
                        .map(|()| Outcome::Done)
                    },
                );
            }
            Step::AddCurrent => {
                let pin = owned(0);
                if pin.is_empty() {
                    return self.open_setup(Step::AddCurrent, Some("Enter the PIN."));
                }
                self.spawn(
                    Next::AskNewKey,
                    Some("Touch the enrolled security key."),
                    move || {
                        ops::derive(&config, &key.context("No security key was chosen")?, &pin)
                            .map(Outcome::Unlock)
                    },
                );
            }
            Step::AddNew { current } => {
                let (label, pin) = (owned(0), owned(1));
                if label.is_empty() || pin.is_empty() {
                    return self.open_setup(
                        Step::AddNew { current },
                        Some("Enter a key label and the PIN."),
                    );
                }
                let report = format!("Added key {:?}.", label.as_str());
                self.spawn(
                    Next::Report(report),
                    Some("Touch the new security key twice."),
                    move || {
                        ops::add_key(
                            &config,
                            &key.context("No security key was chosen")?,
                            &current,
                            &label,
                            &pin,
                        )
                        .map(|()| Outcome::Done)
                    },
                );
            }
            Step::RemoveChoose => {
                let label = values[0].to_string();
                match ops::keys_to_touch(&config, &label) {
                    Ok(left) => self.open_setup_fresh(
                        Step::RemoveTouch {
                            label,
                            left,
                            collected: Vec::new(),
                        },
                        None,
                    ),
                    Err(error) => self.alert(&format!("{error:#}")),
                }
            }
            Step::RemoveTouch {
                label,
                mut left,
                collected,
            } => {
                let pin = owned(0);
                if pin.is_empty() {
                    return self.open_setup(
                        Step::RemoveTouch {
                            label,
                            left,
                            collected,
                        },
                        Some("Enter the PIN."),
                    );
                }
                let (name, cred_id) = left.remove(0);
                let touch = format!("Touch the key \"{name}\".");
                self.spawn(
                    Next::Collect {
                        label,
                        left,
                        collected,
                    },
                    Some(&touch),
                    move || {
                        ops::derive_one(
                            &config,
                            &key.context("No security key was chosen")?,
                            &cred_id,
                            &pin,
                        )
                        .map(Outcome::Unlock)
                    },
                );
            }
            Step::Settings { .. } => {}
            Step::SetPassword => {
                let (database, pin) = (database_or_any(&values[0]), owned(3));
                let secret = Zeroizing::new(values[1].to_string());
                let problem = password_problem(&values[1], &values[2])
                    .or_else(|| pin.is_empty().then_some("Enter the PIN."));
                if let Some(problem) = problem {
                    return self.open_setup(Step::SetPassword, Some(problem));
                }
                let report = format!("Stored the password for {}.", ops::describe(&database));
                self.spawn(
                    Next::Report(report),
                    Some("Touch your security key."),
                    move || {
                        ops::set_secret(
                            &config,
                            &key.context("No security key was chosen")?,
                            &database,
                            secret.as_bytes(),
                            &pin,
                        )
                        .map(|()| Outcome::Done)
                    },
                );
            }
        }
    }

    /// Runs `work` on a worker thread while a panel shows `touch`.
    fn spawn(
        &self,
        next: Next,
        touch: Option<&str>,
        work: impl FnOnce() -> Result<Outcome> + Send + 'static,
    ) {
        let (sender, result) = mpsc::channel();
        self.ivars().borrow().worker.run(move || {
            let _ = sender.send(work());
        });
        let touch = touch.map(|text| touch_form(self.mtm(), self, text));
        self.ivars().borrow_mut().job = Some(Job {
            next,
            touch,
            result,
        });
    }

    fn after_job(&self, next: Next, result: Result<Outcome>) {
        match (next, result) {
            (Next::Devices(after) | Next::Chosen(after), Err(error)) => {
                if let AfterKey::Unlock(target) = after {
                    return self.show(&format!("{error:#}"), Some(target));
                }
                self.alert(&format!("{error:#}"));
            }
            (_, Err(error)) => self.alert(&format!("{error:#}")),
            (Next::Devices(after), Ok(Outcome::Devices(devices))) => {
                if devices.len() > 1 {
                    let touch = "Touch the security key you want to use.";
                    return self.spawn(Next::Chosen(after), Some(touch), move || {
                        Ok(Outcome::Key(fido::select(devices)?))
                    });
                }
                match fido::select(devices) {
                    Ok(key) => {
                        self.ivars().borrow_mut().key = Some(key);
                        self.continue_with_key(after);
                    }
                    Err(error) => match after {
                        AfterKey::Unlock(target) => self.show(&error.to_string(), Some(target)),
                        AfterKey::Setup(_) => self.alert(&error.to_string()),
                    },
                }
            }
            (Next::Chosen(after), Ok(Outcome::Key(key))) => {
                self.ivars().borrow_mut().key = Some(key);
                self.continue_with_key(after);
            }
            (Next::Report(report), Ok(_)) => {
                self.check_health(true);
                self.alert(&report);
            }
            (Next::AskNewKey, Ok(Outcome::Unlock(current))) => {
                // The new key is a different key, so it is chosen again.
                self.begin_flow();
                self.open_setup(Step::AddNew { current }, None);
            }
            (
                Next::Collect {
                    label,
                    left,
                    mut collected,
                },
                Ok(Outcome::Unlock(unlock)),
            ) => {
                collected.push(unlock);
                if !left.is_empty() {
                    // Each remaining key is a different key, so it is chosen again.
                    self.begin_flow();
                    return self.open_setup(
                        Step::RemoveTouch {
                            label,
                            left,
                            collected,
                        },
                        None,
                    );
                }
                let Ok(config) = Config::path().and_then(|path| Config::load(&path)) else {
                    return;
                };
                let report = format!(
                    "Removed key {label:?} and moved the vault to a new data key. If the key was lost, change the database password in KeePassXC, then choose Set Database Password…."
                );
                self.spawn(
                    Next::Report(report),
                    Some("Saving the vault…"),
                    move || ops::remove_key(&config, &label, &collected).map(|()| Outcome::Done),
                );
            }
            (_, Ok(_)) => self.alert("The operation returned an unexpected result."),
        }
    }

    /// Starts an unlock or copy. A retry after a wrong PIN (`message`) reuses the chosen key and
    /// goes straight to the PIN panel. A new attempt first chooses the key, as the FIDO flow does.
    fn start(&self, target: Target, message: Option<&str>) {
        if message.is_none() {
            if self.busy() || !self.ready_for(&target) {
                return;
            }
            self.begin_flow();
            return self.with_key(AfterKey::Unlock(target));
        }
        self.pin_panel(target, message);
    }

    /// Checks that a password exists for the target's database before any key is touched.
    fn ready_for(&self, target: &Target) -> bool {
        // A broken config or vault keeps the app idle. The menu shows the error.
        let Ok((_, vault)) = load() else {
            return false;
        };
        let database = match target {
            Target::Fill => self.ivars().borrow().kpxc.database(),
            Target::Copy(database) => Some(database.clone()),
        };
        if vault.has_secret_for(database.as_deref()) {
            return true;
        }
        let name = database.as_deref().unwrap_or("this database");
        self.alert(&format!(
            "No password is stored for {name}. Add one with Set Database Password… in the menu, or run:\nfido2kpxc set-secret --database {name}"
        ));
        self.done(target.clone());
        false
    }

    /// Forgets the key of a previous flow, so a new flow chooses again.
    fn begin_flow(&self) {
        self.ivars().borrow_mut().key = None;
    }

    /// Chooses the security key, then continues with `after`. One plugged-in key is used at once.
    /// With several, all blink and the first one touched is used.
    fn with_key(&self, after: AfterKey) {
        self.close_message();
        self.spawn(Next::Devices(after), None, || {
            Ok(Outcome::Devices(fido::devices()))
        });
    }

    fn continue_with_key(&self, after: AfterKey) {
        match after {
            AfterKey::Unlock(target) => self.pin_panel(target, None),
            AfterKey::Setup(step) => self.open_setup(step, None),
        }
    }

    /// Opens the PIN panel. `pin_submit` derives and decrypts on a worker thread.
    fn pin_panel(&self, target: Target, message: Option<&str>) {
        if self.busy() {
            return;
        }
        self.close_message();
        let database = match &target {
            Target::Fill => self.ivars().borrow().kpxc.database(),
            Target::Copy(database) => Some(database.clone()),
        };
        let message = match (message, &database) {
            (Some(message), _) => message.to_owned(),
            (None, Some(database)) => {
                format!("Enter your security key's FIDO2 PIN to unlock {database}.")
            }
            (None, None) => "Enter your security key's FIDO2 PIN.".to_owned(),
        };
        let form = panels::form(
            self.mtm(),
            self,
            "Unlock with Security Key",
            &message,
            &[Field::secret("PIN")],
            &[
                Button {
                    title: "Unlock",
                    action: sel!(pinSubmit:),
                    key: Key::Return,
                },
                Button {
                    title: "Cancel",
                    action: sel!(pinCancel:),
                    key: Key::Escape,
                },
            ],
        );
        self.ivars().borrow_mut().asking = Some(Asking {
            target,
            database,
            form,
        });
    }

    fn finish(&self, pending: Pending, result: Result<Zeroizing<Vec<u8>>, FidoError>) {
        pending.touch.close();
        let secret = match result {
            Ok(secret) => secret,
            Err(error @ FidoError::WrongPin { .. }) => {
                return self.start(pending.target, Some(&error.to_string()));
            }
            Err(error @ (FidoError::NoDevice | FidoError::Timeout)) => {
                return self.show(&error.to_string(), Some(pending.target));
            }
            Err(error) => {
                self.alert(&error.to_string());
                return self.done(pending.target);
            }
        };
        let Ok(text) = std::str::from_utf8(&secret) else {
            self.alert("The stored password is not valid UTF-8.");
            return self.done(pending.target);
        };
        match &pending.target {
            Target::Copy(_) => {
                let change_count = copy_concealed(text);
                let seconds = self.check_health(false).map_or(20, |c| c.clear_seconds);
                self.ivars().borrow_mut().clear =
                    Some((Instant::now() + Duration::from_secs(seconds), change_count));
            }
            Target::Fill => {
                let press = self
                    .check_health(false)
                    .is_some_and(|c| c.autofill == Autofill::FillAndUnlock);
                let filled = self.ivars().borrow().kpxc.fill(text, press);
                if let Err(error) = filled {
                    self.alert(&format!(
                        "Autofill failed: {error:#}. Type the password in KeePassXC, or set copy_password = true for a Copy Password fallback."
                    ));
                }
            }
        }
        self.done(pending.target);
    }

    /// Ends an unlock attempt. For autofill, hands focus back to KeePassXC inside the
    /// suppression window, so its password field does not count as a new prompt.
    fn done(&self, target: Target) {
        if target == Target::Fill {
            Kpxc::activate();
        }
        self.ivars().borrow_mut().suppress_until = Some(Instant::now() + SUPPRESS);
    }

    fn alert(&self, message: &str) {
        self.show(message, None);
    }

    /// Shows a message panel. With `retry`, it offers Retry and Cancel for that attempt.
    fn show(&self, message: &str, retry: Option<Target>) {
        self.close_message();
        let buttons = if retry.is_some() {
            vec![
                Button {
                    title: "Retry",
                    action: sel!(messageRetry:),
                    key: Key::Return,
                },
                Button {
                    title: "Cancel",
                    action: sel!(messageDismiss:),
                    key: Key::Escape,
                },
            ]
        } else {
            vec![Button {
                title: "OK",
                action: sel!(messageDismiss:),
                key: Key::Return,
            }]
        };
        let form = panels::form(self.mtm(), self, "fido2kpxc", message, &[], &buttons);
        self.ivars().borrow_mut().message = Some(Message { form, retry });
    }

    /// Closes the message panel and returns the attempt it could have retried.
    fn close_message(&self) -> Option<Target> {
        let message = self.ivars().borrow_mut().message.take()?;
        message.form.close();
        message.retry
    }

    /// One "Copy Password" item for a single password, or a submenu with one item per database.
    fn fill_copy_menu(&self, item: &NSMenuItem) {
        let databases: Vec<String> = load()
            .map(|(_, vault)| vault.databases().into_iter().map(str::to_owned).collect())
            .unwrap_or_default();
        let entry = |target: &NSMenuItem, database: &str| unsafe {
            target.setTarget(Some(self));
            target.setAction(Some(sel!(copyPassword:)));
            target.setRepresentedObject(Some(&NSString::from_str(database)));
        };
        if let [only] = databases.as_slice() {
            item.setSubmenu(None);
            entry(item, only);
            return;
        }
        let submenu = NSMenu::new(self.mtm());
        for database in &databases {
            let title = if database == ANY {
                "Any other database"
            } else {
                database
            };
            let sub = NSMenuItem::new(self.mtm());
            sub.setTitle(&NSString::from_str(title));
            entry(&sub, database);
            submenu.addItem(&sub);
        }
        unsafe { item.setAction(None) };
        item.setSubmenu(Some(&submenu));
    }

    fn refresh_menu(&self) {
        let config = self.check_health(true);
        let state = self.ivars().borrow();
        let Some(menu) = state.menu.as_ref() else {
            return;
        };
        let status = match state.health.as_ref() {
            Some((_, Err(error))) => error.clone(),
            _ => "Ready".to_owned(),
        };
        menu.status
            .setTitle(&NSString::from_str(&format!("fido2kpxc - {status}")));
        let copy = config.as_ref().is_some_and(|c| c.copy_password);
        menu.copy.setHidden(!copy);
        if copy {
            self.fill_copy_menu(&menu.copy);
        }
        let configured = Config::path().and_then(|path| Config::load(&path));
        let vault_exists = configured.as_ref().is_ok_and(|c| c.vault.exists());
        menu.set_up.setEnabled(configured.is_ok() && !vault_exists);
        for item in &menu.manage {
            item.setEnabled(config.is_some());
        }
        menu.grant.setHidden(kpxc::accessibility_trusted());
        let enabled =
            unsafe { SMAppService::mainAppService().status() } == SMAppServiceStatus::Enabled;
        menu.login.setState(if enabled {
            NSControlStateValueOn
        } else {
            NSControlStateValueOff
        });
    }
}

pub fn run() -> Result<()> {
    let mtm = MainThreadMarker::new().ok_or_else(|| anyhow::anyhow!("Run on the main thread"))?;
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let controller = Controller::new(mtm);

    let menu = NSMenu::new(mtm);
    let add = |title: &str, action| {
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &NSString::from_str(title),
                action,
                ns_string!(""),
            )
        };
        unsafe { item.setTarget(Some(&controller)) };
        menu.addItem(&item);
        item
    };
    // Manual enabling keeps the status line inert without an action.
    menu.setAutoenablesItems(false);
    let status = add("fido2kpxc - Starting…", None);
    status.setEnabled(false);
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let copy = add("Copy Password", Some(sel!(copyPassword:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let set_up = add("Set Up…", Some(sel!(setUp:)));
    let manage = vec![
        add("Add Security Key…", Some(sel!(addKey:))),
        add("Remove Security Key…", Some(sel!(removeKey:))),
        add("Set Database Password…", Some(sel!(setPassword:))),
    ];
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Settings…", Some(sel!(openSettings:)));
    add("Open Config…", Some(sel!(openConfig:)));
    add("Show Vault in Finder", Some(sel!(showVault:)));
    add("Copy Diagnostics", Some(sel!(copyDiagnostics:)));
    add("Help…", Some(sel!(showHelp:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let grant = add("Grant Accessibility…", Some(sel!(grantAccessibility:)));
    let login = add("Start at Login", Some(sel!(toggleLogin:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("About fido2kpxc", Some(sel!(showAbout:)));
    add("Quit", Some(sel!(quit:)));

    let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
    menu.setDelegate(Some(ProtocolObject::from_ref(&*controller)));
    item.setMenu(Some(&menu));
    controller.ivars().borrow_mut().menu = Some(Menu {
        status,
        copy,
        grant,
        login,
        set_up,
        manage,
        item,
        key_icon: key_icon(),
        warning_icon: warning_icon(),
    });
    controller.refresh_menu();

    // Default-mode timers pause while a modal dialog runs, so a tick never re-enters a dialog.
    let _timer = unsafe {
        NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
            TICK_SECONDS,
            &controller,
            sel!(tick:),
            None,
            true,
        )
    };
    app.run();
    Ok(())
}

/// The security key from the app icon, embedded so it also shows when the app runs unbundled.
fn key_icon() -> Option<Retained<NSImage>> {
    template_icon(include_bytes!("../assets/menubar.pdf"), "fido2kpxc")
}

/// The same key with an exclamation mark, for a config or vault that needs attention.
fn warning_icon() -> Option<Retained<NSImage>> {
    template_icon(
        include_bytes!("../assets/menubar-warning.pdf"),
        "fido2kpxc: needs attention",
    )
}

fn template_icon(pdf: &[u8], description: &str) -> Option<Retained<NSImage>> {
    let pdf = NSData::with_bytes(pdf);
    let image = NSImage::initWithData(NSImage::alloc(), &pdf)?;
    image.setSize(NSSize::new(16.0, 16.0));
    // Template images take the menu bar's color in light mode, dark mode, and when highlighted.
    image.setTemplate(true);
    image.setAccessibilityDescription(Some(&NSString::from_str(description)));
    Some(image)
}

fn load() -> Result<(Config, Vault)> {
    let config = Config::load(&Config::path()?)?;
    ensure!(
        config.vault.exists(),
        "No vault at {}. Run `fido2kpxc enroll`.",
        config.vault.display()
    );
    let vault = Vault::load(&config.vault)?;
    Ok((config, vault))
}

/// Steps whose form asks for a PIN, so their key is chosen first.
fn needs_key(step: &Step) -> bool {
    matches!(
        step,
        Step::Create
            | Step::AddCurrent
            | Step::AddNew { .. }
            | Step::RemoveTouch { .. }
            | Step::SetPassword
    )
}

/// Labels for the autofill choice, in the order of [`Autofill::ALL`].
const AUTOFILL_LABELS: [&str; 3] = ["Fill and unlock", "Fill only", "Off"];

/// Values the settings form starts with: a rejected draft, else the current config, else defaults.
/// Other steps get empty values they never read.
fn settings_values(step: &Step, config: Option<&Config>) -> (String, String, usize, usize) {
    if let Step::Settings { draft: Some(draft) } = step {
        let autofill = AUTOFILL_LABELS
            .iter()
            .position(|l| *l == draft[1])
            .unwrap_or(0);
        return (
            draft[0].clone(),
            draft[3].clone(),
            autofill,
            usize::from(draft[2] == "On"),
        );
    }
    let Some(config) = config else {
        return (String::new(), "20".to_owned(), 0, 0);
    };
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let folder = match home
        .as_deref()
        .and_then(|home| config.folder.strip_prefix(home).ok())
    {
        Some(rest) => format!("~/{}", rest.display()),
        None => config.folder.display().to_string(),
    };
    let autofill = Autofill::ALL
        .iter()
        .position(|a| *a == config.autofill)
        .unwrap_or(0);
    (
        folder,
        config.clear_seconds.to_string(),
        autofill,
        usize::from(config.copy_password),
    )
}

/// A panel without buttons that stays up while the worker thread waits for a touch.
fn touch_form(mtm: MainThreadMarker, target: &AnyObject, text: &str) -> Form {
    panels::form(mtm, target, "fido2kpxc", text, &[], &[])
}

/// Why the password fields cannot be used, if they cannot.
fn password_problem(password: &str, repeat: &str) -> Option<&'static str> {
    if password.is_empty() {
        Some("Enter the database password.")
    } else if password != repeat {
        Some("The passwords differ.")
    } else {
        None
    }
}

/// A blank database name stores the password for any database without its own entry.
fn database_or_any(name: &str) -> String {
    match name.trim() {
        "" => ANY.to_owned(),
        name => name.to_owned(),
    }
}

fn copy_concealed(text: &str) -> isize {
    let pasteboard = NSPasteboard::generalPasteboard();
    // Keeps the password off Universal Clipboard, so it never reaches other devices.
    pasteboard.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    pasteboard.setString_forType(&NSString::from_str(text), unsafe { NSPasteboardTypeString });
    // Clipboard managers skip entries that carry this marker type.
    pasteboard.setString_forType(
        ns_string!(""),
        &NSString::from_str("org.nspasteboard.ConcealedType"),
    );
    pasteboard.changeCount()
}

/// Opens `path` with `/usr/bin/open`, which picks the user's default app or Finder.
fn open(flags: &[&str], path: &std::path::Path) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/open")
        .args(flags)
        .arg(path)
        .status()?;
    ensure!(status.success(), "Cannot open {}", path.display());
    Ok(())
}

fn help_text() -> String {
    let exe = std::env::current_exe()
        .map_or_else(|_| "fido2kpxc".to_owned(), |p| p.display().to_string());
    format!(
        "Setup
1. Choose Settings… and set the vault folder.
2. Choose Set Up… and follow the panels, or run in Terminal: fido2kpxc enroll --label primary
3. Choose Grant Accessibility… and allow fido2kpxc.

Then locking KeePassXC opens the PIN panel. The first line of this menu shows any config or vault error.

Menu items
Add Security Key… enrolls a backup key, which may be another brand.
Remove Security Key… removes a key, for example a lost one. Each remaining key needs a touch.
Set Database Password… stores the password for one database file, or for any database when the name is blank.

If autofill does not start, choose Copy Diagnostics and include the report in a bug report.
The same actions exist in Terminal. Run fido2kpxc help for the list.
If fido2kpxc is not on your PATH, use {exe}"
    )
}

fn request_accessibility() {
    use objc2_application_services::{AXIsProcessTrustedWithOptions, kAXTrustedCheckOptionPrompt};
    use objc2_core_foundation::{CFBoolean, CFDictionary};
    let key = unsafe { kAXTrustedCheckOptionPrompt };
    let options = CFDictionary::from_slices(&[key], &[CFBoolean::new(true)]);
    unsafe { AXIsProcessTrustedWithOptions(Some(options.as_opaque())) };
}

#[cfg(test)]
mod tests;
