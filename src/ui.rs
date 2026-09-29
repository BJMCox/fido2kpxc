use std::cell::RefCell;
use std::path::{Path, PathBuf};
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
    NSControlStateValueOn, NSImage, NSMenu, NSMenuDelegate, NSMenuItem, NSModalResponseOK,
    NSOpenPanel, NSPasteboard, NSPasteboardContentsOptions, NSPasteboardItem,
    NSPasteboardTypeString, NSStatusBar, NSStatusItem, NSVariableStatusItemLength, NSWorkspace,
    NSWorkspaceDidActivateApplicationNotification,
};
use objc2_foundation::{
    NSArray, NSData, NSDictionary, NSNotification, NSNumber, NSObject, NSObjectProtocol,
    NSProcessInfo, NSRunLoop, NSRunLoopCommonModes, NSSize, NSString, NSTimer, NSUserDefaults,
    ns_string,
};
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use zeroize::Zeroizing;

use crate::config::{self, Autofill, Config, Stamp};
use crate::fido::{self, FidoError};
use crate::kpxc::{self, Kpxc, Verdict};
use crate::ops;
use crate::panels::{self, Button, Field, Form, Key};
use crate::vault::{ANY, Unlock, Vault};

// Fast ticks run only while work is in flight or KeePassXC is frontmost. Idle ticks keep the
// warning icon current.
const TICK: Duration = Duration::from_millis(250);
const IDLE_TICK: Duration = Duration::from_secs(30);
const REPOSITORY: &str = "https://github.com/BJMCox/fido2kpxc";
// Stops the refocus after a closed dialog from reopening it at once.
const SUPPRESS: Duration = Duration::from_secs(3);
// Longer than any key's own touch timeout, so only a key that stopped answering reaches it.
const WAIT: Duration = Duration::from_secs(120);
const NO_ANSWER: &str = "The security key did not answer. Remove it and insert it again.";

#[derive(Clone)]
enum Target {
    /// Fills the KeePassXC prompt as it was when the attempt started. Retries and a second
    /// key choice keep it, since KeePassXC's focus moves while fido2kpxc's panels show.
    Fill(kpxc::Prompt),
    /// Copies the password stored for this database name.
    Copy(String),
}

impl Target {
    /// The database name whose stored password the attempt opens.
    fn database(&self) -> String {
        match self {
            Target::Fill(prompt) => prompt.database(),
            Target::Copy(database) => database.clone(),
        }
    }
}

/// The open PIN panel, waiting for Unlock or Cancel.
struct Asking {
    target: Target,
    form: Form,
}

/// An open message panel. `retry` holds the attempt or step that Retry would restart, and
/// `update` the database whose stored password the offered button replaces.
struct Message {
    form: Form,
    retry: Option<AfterKey>,
    update: Option<String>,
}

struct Pending {
    target: Target,
    result: Receiver<Result<Zeroizing<Vec<u8>>, FidoError>>,
    touch: Form,
    since: Instant,
}

/// A key-management step waiting for input in a form.
struct Setup {
    step: Step,
    form: Form,
}

/// The typed values of a failed attempt, so its form reopens with them. A PIN is never kept.
type Draft = Vec<Zeroizing<String>>;

enum Step {
    Create {
        draft: Draft,
    },
    AddCurrent,
    AddNew {
        current: Unlock,
        draft: Draft,
    },
    RemoveChoose,
    /// Collects an output from each key in `left`, which the new data key must be wrapped for.
    RemoveTouch {
        labels: Vec<String>,
        left: Vec<(String, Vec<u8>)>,
        collected: Vec<Unlock>,
    },
    /// The first draft value prefills the file name, for example of a password KeePassXC rejected.
    SetPassword {
        draft: Draft,
    },
    CheckKey,
    RemovePassword,
    /// Asks the user to swap keys, then opens `then`, which chooses the key again. So no PIN
    /// reaches the previous key.
    Swap {
        text: String,
        then: Box<Step>,
    },
    /// `draft` holds the values of a rejected attempt, so the form reopens with them.
    /// `then_set_up` continues into Set Up after a save.
    Settings {
        draft: Option<Vec<String>>,
        then_set_up: bool,
    },
}

/// A key-management operation on the worker thread, and what follows it.
struct Job {
    next: Next,
    touch: Option<Form>,
    result: Receiver<Result<Outcome>>,
    /// The step that a failure reopens.
    retry: Option<Step>,
    since: Instant,
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
    /// Created the vault. The report offers the setup steps that are still missing.
    Created(String),
    /// Stored the password for `database`. If KeePassXC waits for that database, unlocking
    /// starts again with the new password.
    Stored {
        report: String,
        database: String,
    },
    /// Shows the report that the operation returns.
    Show,
    AskNewKey,
    Collect {
        labels: Vec<String>,
        left: Vec<(String, Vec<u8>)>,
        collected: Vec<Unlock>,
    },
}

enum Outcome {
    Done,
    Report(String),
    Unlock(Unlock),
    Devices(Vec<fido::Device>),
    Key(fido::Key),
}

struct Menu {
    status: Retained<NSMenuItem>,
    unlock: Retained<NSMenuItem>,
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
    /// The timer that clears a copied password, and the clipboard's change count after the copy.
    clear: Option<(Retained<NSTimer>, isize)>,
    menu: Option<Menu>,
    /// The last config and vault check, with the stamps it was made at. An error keeps the app
    /// idle until the files are fixed.
    health: Option<([Stamp; 3], Result<Config, String>)>,
    /// Sync-conflict copies of the vault, found at the last health check. Unlocking still works.
    conflicts: Vec<String>,
    /// The vault folder from the last readable config. It stays watched while the vault fails to load.
    folder: Option<PathBuf>,
    /// The next tick and when it fires.
    timer: Option<(Retained<NSTimer>, Instant)>,
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
            // Ticks do not poll while autofill is off, so "Unlock KeePassXC" learns of a prompt here.
            let off = self.check_health(false).is_some_and(|c| c.autofill == Autofill::Off);
            if off && !self.busy() {
                self.ivars().borrow_mut().kpxc.poll();
            }
            self.refresh_menu();
        }
    }

    impl Controller {
        #[unsafe(method(tick:))]
        fn tick(&self, _timer: &NSTimer) {
            self.ivars().borrow_mut().timer = None;
            self.on_tick();
            self.reschedule();
        }

        #[unsafe(method(appActivated:))]
        fn app_activated(&self, _notification: &NSNotification) {
            // A timer, not a direct tick, so the tick still waits out a modal dialog.
            self.wake_in(Duration::ZERO);
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
            self.set_start_at_login(!starts_at_login());
            self.refresh_menu();
        }

        #[unsafe(method(createdDone:))]
        fn created_done(&self, _sender: &AnyObject) {
            self.finish_created(false);
        }

        #[unsafe(method(createdGrant:))]
        fn created_grant(&self, _sender: &AnyObject) {
            self.finish_created(true);
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
            let database = asking.target.database();
            self.ivars().borrow().worker.run(move || {
                let secret = fido::derive(ops::APP, &key, &pin, &vault.salt(), &vault.cred_ids())
                    .and_then(|unlock| {
                        vault
                            .open(&unlock, Some(&database))
                            .map_err(FidoError::Other)
                    });
                let _ = sender.send(secret);
            });
            let touch = touch_form(self.mtm(), self, "Touch your security key now.", true);
            self.ivars().borrow_mut().pending = Some(Pending {
                target: asking.target,
                result,
                touch,
                since: Instant::now(),
            });
            self.reschedule();
        }

        /// Stops waiting for a touch whose result can be dropped: an unlock, a copy, a key choice,
        /// or a touch that only derives. The key may keep blinking until its own timeout.
        #[unsafe(method(touchCancel:))]
        fn touch_cancel(&self, _sender: &AnyObject) {
            let pending = self.ivars().borrow_mut().pending.take();
            if let Some(pending) = pending {
                pending.touch.close();
                return self.done(pending.target);
            }
            let job = {
                let mut state = self.ivars().borrow_mut();
                match &state.job {
                    Some(job) if cancellable(&job.next) => state.job.take(),
                    _ => None,
                }
            };
            if let Some(job) = job {
                if let Some(touch) = &job.touch {
                    touch.close();
                }
                if let Next::Devices(AfterKey::Unlock(target)) | Next::Chosen(AfterKey::Unlock(target)) =
                    job.next
                {
                    self.done(target);
                }
            }
        }

        #[unsafe(method(messageDismiss:))]
        fn message_dismiss(&self, _sender: &AnyObject) {
            if let Some(AfterKey::Unlock(target)) = self.close_message() {
                self.done(target);
            }
        }

        #[unsafe(method(messageRetry:))]
        fn message_retry(&self, _sender: &AnyObject) {
            match self.close_message() {
                Some(AfterKey::Unlock(target)) => self.start(target, None),
                // The failure may have come from the wrong key, so the key is chosen again.
                Some(AfterKey::Setup(step)) => self.open_setup_fresh(step, None),
                None => {}
            }
        }

        #[unsafe(method(unlockNow:))]
        fn unlock_now(&self, _sender: &AnyObject) {
            let prompt = self.ivars().borrow().kpxc.prompt();
            if let Some(prompt) = prompt {
                self.start(Target::Fill(prompt), None);
            }
        }

        #[unsafe(method(updatePassword:))]
        fn update_password(&self, _sender: &AnyObject) {
            let Some(message) = self.ivars().borrow_mut().message.take() else {
                return;
            };
            message.form.close();
            let database = message.update.unwrap_or_default();
            self.open_setup_fresh(
                Step::SetPassword {
                    draft: vec![Zeroizing::new(database)],
                },
                None,
            );
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
            let step = set_up_step(&Config::path().and_then(|path| Config::load(&path)));
            let note = matches!(step, Step::Settings { .. })
                .then_some("Choose a folder for the vault first. Set Up continues after Save.");
            self.open_setup_fresh(step, note);
        }

        #[unsafe(method(addKey:))]
        fn add_key(&self, _sender: &AnyObject) {
            self.open_setup_fresh(Step::AddCurrent, None);
        }

        #[unsafe(method(removeKey:))]
        fn remove_key(&self, _sender: &AnyObject) {
            self.open_setup_fresh(Step::RemoveChoose, None);
        }

        #[unsafe(method(checkKey:))]
        fn check_key(&self, _sender: &AnyObject) {
            self.open_setup_fresh(Step::CheckKey, None);
        }

        #[unsafe(method(setPassword:))]
        fn set_password(&self, _sender: &AnyObject) {
            self.open_setup_fresh(Step::SetPassword { draft: Vec::new() }, None);
        }

        #[unsafe(method(removePassword:))]
        fn remove_password(&self, _sender: &AnyObject) {
            self.open_setup_fresh(Step::RemovePassword, None);
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

        #[unsafe(method(chooseFolder:))]
        fn choose_folder(&self, sender: &AnyObject) {
            let message = "Choose the vault folder, or the vault.toml in it.";
            self.choose_into(sender, message, true, |path| {
                picked_folder(path)
                    .map(|folder| tilde(folder, home().as_deref()))
                    .ok_or("That file is not a vault.toml.")
            });
        }

        #[unsafe(method(chooseDatabase:))]
        fn choose_database(&self, sender: &AnyObject) {
            let message = "Choose the KeePassXC database. fido2kpxc stores only its file name.";
            self.choose_into(sender, message, false, |path| {
                picked_database(path)
                    .map(str::to_owned)
                    .ok_or("That file name is not valid text.")
            });
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
            self.open_setup(Step::Settings { draft: None, then_set_up: false }, None);
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
                Button { title: "Source", action: sel!(openRepository:), key: Key::Escape },
            ];
            let form = panels::form(self.mtm(), self, "About fido2kpxc", &text, &[], &buttons);
            self.ivars().borrow_mut().message = Some(Message {
                form,
                retry: None,
                update: None,
            });
        }

        #[unsafe(method(openRepository:))]
        fn open_repository(&self, _sender: &AnyObject) {
            self.close_message();
            let _ = open(&[], std::path::Path::new(REPOSITORY));
        }

        #[unsafe(method(clearClipboard:))]
        fn clear_clipboard_now(&self, _timer: &NSTimer) {
            self.clear_clipboard();
        }

        #[unsafe(method(quit:))]
        fn quit(&self, _sender: &AnyObject) {
            self.clear_clipboard();
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
            match state
                .pending
                .as_ref()
                .map(|p| (p.result.try_recv(), p.since))
            {
                Some((Ok(result), _)) => state.pending.take().map(|p| (p, result)),
                Some((Err(TryRecvError::Disconnected), _)) => state.pending.take().map(|p| {
                    (
                        p,
                        Err(FidoError::Other(anyhow::anyhow!(
                            "The unlock worker stopped"
                        ))),
                    )
                }),
                Some((Err(TryRecvError::Empty), since)) if since.elapsed() >= WAIT => state
                    .pending
                    .take()
                    .map(|p| (p, Err(FidoError::Other(anyhow::anyhow!(NO_ANSWER))))),
                Some((Err(TryRecvError::Empty), _)) | None => None,
            }
        };
        if let Some((pending, result)) = finished {
            self.finish(pending, result);
        }

        let job_done = {
            let mut state = self.ivars().borrow_mut();
            match state.job.as_ref().map(|j| (j.result.try_recv(), j.since)) {
                Some((Ok(result), _)) => state.job.take().map(|j| (j, result)),
                Some((Err(TryRecvError::Disconnected), _)) => state
                    .job
                    .take()
                    .map(|j| (j, Err(anyhow::anyhow!("The worker stopped")))),
                Some((Err(TryRecvError::Empty), since)) if since.elapsed() >= WAIT => state
                    .job
                    .take()
                    .map(|j| {
                        // A write keeps running on the worker, so it can still save later.
                        let text = if cancellable(&j.next) {
                            NO_ANSWER.to_owned()
                        } else {
                            format!(
                                "{NO_ANSWER} The change may still be saved if the key answers later, so check the menu before you try again."
                            )
                        };
                        (j, Err(anyhow::anyhow!(text)))
                    }),
                Some((Err(TryRecvError::Empty), _)) | None => None,
            }
        };
        if let Some((job, result)) = job_done {
            if let Some(touch) = &job.touch {
                touch.close();
            }
            self.after_job(job.next, job.retry, result);
        }

        let result = self.ivars().borrow_mut().kpxc.unlock_result();
        if let Some((database, Verdict::Rejected(said))) = result {
            self.show_rejected(&database, said.as_deref());
        }

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
            let idle = state.pending.is_none() && state.asking.is_none();
            (started && !suppressed && idle)
                .then(|| state.kpxc.prompt())
                .flatten()
        };
        if let Some(prompt) = prompt {
            self.start(Target::Fill(prompt), None);
        }
    }

    /// Clears a copied password now, unless something newer replaced it on the clipboard.
    fn clear_clipboard(&self) {
        let clear = self.ivars().borrow_mut().clear.take();
        if let Some((timer, change_count)) = clear {
            timer.invalidate();
            let pasteboard = NSPasteboard::generalPasteboard();
            if pasteboard.changeCount() == change_count {
                pasteboard.clearContents();
            }
        }
    }

    /// Clears the clipboard after `seconds`. The timer runs in the common run-loop modes, which
    /// include menu tracking and modal panels, where the default-mode tick pauses.
    fn schedule_clear(&self, seconds: u64, change_count: isize) {
        let timer = unsafe {
            NSTimer::timerWithTimeInterval_target_selector_userInfo_repeats(
                seconds as f64,
                self,
                sel!(clearClipboard:),
                None,
                false,
            )
        };
        unsafe { NSRunLoop::mainRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };
        let old = self
            .ivars()
            .borrow_mut()
            .clear
            .replace((timer, change_count));
        if let Some((old, _)) = old {
            old.invalidate();
        }
    }

    /// Rechecks the config and the vault when either file or the vault folder changed, or when
    /// `force` is set. Returns the config when both load.
    fn check_health(&self, force: bool) -> Option<Config> {
        let (stamps, saved) = {
            let state = self.ivars().borrow();
            (
                stamps(state.folder.as_deref()),
                state.health.as_ref().map(|(s, _)| *s),
            )
        };
        // A new folder shows up as changed stamps at the next check, which then stamps it.
        if force || saved != Some(stamps) {
            let (folder, health) = load_health(Config::path());
            let conflicts = health.as_ref().map(Config::conflicts).unwrap_or_default();
            let mut state = self.ivars().borrow_mut();
            state.health = Some((stamps, health));
            state.folder = folder;
            state.conflicts = conflicts;
            drop(state);
            self.update_icon();
        }
        let state = self.ivars().borrow();
        state
            .health
            .as_ref()
            .and_then(|(_, health)| health.as_ref().ok().cloned())
    }

    /// Schedules the next tick from what is in flight.
    fn reschedule(&self) {
        let delay = {
            let state = self.ivars().borrow();
            let autofill = state
                .health
                .as_ref()
                .and_then(|(_, h)| h.as_ref().ok())
                .is_some_and(|c| c.autofill != Autofill::Off);
            let busy =
                state.pending.is_some() || state.job.is_some() || state.kpxc.active(autofill);
            if busy { TICK } else { IDLE_TICK }
        };
        self.wake_in(delay);
    }

    /// Makes the next tick fire within `delay`, keeping a timer that fires sooner.
    fn wake_in(&self, delay: Duration) {
        let due = Instant::now() + delay;
        let mut state = self.ivars().borrow_mut();
        if let Some((timer, at)) = state.timer.take() {
            if at <= due {
                state.timer = Some((timer, at));
                return;
            }
            timer.invalidate();
        }
        // Default-mode timers pause while a modal dialog runs, so a tick never re-enters a dialog.
        let timer = unsafe {
            NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                delay.as_secs_f64(),
                self,
                sel!(tick:),
                None,
                false,
            )
        };
        // Lets macOS batch idle wakeups with other work.
        if delay == IDLE_TICK {
            timer.setTolerance(delay.as_secs_f64() / 10.0);
        }
        state.timer = Some((timer, due));
    }

    fn update_icon(&self) {
        let state = self.ivars().borrow();
        let (Some(menu), Some((_, health))) = (state.menu.as_ref(), state.health.as_ref()) else {
            return;
        };
        let (icon, fallback, description) = match health {
            Ok(_) if state.conflicts.is_empty() => (
                &menu.key_icon,
                ns_string!("key.fill"),
                ns_string!("fido2kpxc"),
            ),
            _ => (
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
                match ops::load_vault(&config) {
                    Err(error) => lines.push(format!("Vault: {error:#}")),
                    Ok(vault) => {
                        let keys: Vec<&str> = vault
                            .entries()
                            .into_iter()
                            .map(|(label, _)| label)
                            .collect();
                        lines.push(format!("Vault: {} (loads)", config.vault.display()));
                        lines.push(format!("Keys: {}", keys.join(", ")));
                        lines.push(format!("Stored passwords: {}", vault.names().join(", ")));
                    }
                }
                let conflicts = config.conflicts();
                lines.push(format!(
                    "Sync conflicts: {}",
                    if conflicts.is_empty() {
                        "none".to_owned()
                    } else {
                        conflicts.join(", ")
                    }
                ));
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
        lines.push(format!("Start at Login: {}", starts_at_login()));
        lines.extend(kpxc::diagnose());
        lines.join("\n") + "\n"
    }

    /// Starts a flow at `step` with a new key choice. While another flow runs, it does nothing,
    /// so that flow keeps its chosen key.
    fn open_setup_fresh(&self, step: Step, note: Option<&str>) {
        if self.busy() {
            return;
        }
        self.begin_flow();
        self.open_setup(step, note);
    }

    /// Validates and writes the settings form, or reopens it with the problem and the typed values.
    fn save_settings(&self, draft: Vec<String>, then_set_up: bool) {
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
            Some(problem) => self.open_setup(
                Step::Settings {
                    draft: Some(draft),
                    then_set_up,
                },
                Some(&problem),
            ),
            None => {
                self.check_health(true);
                // A synced folder may already hold a vault, which needs no Set Up.
                if then_set_up && can_set_up(&Config::path().and_then(|path| Config::load(&path))) {
                    self.open_setup(Step::Create { draft: Vec::new() }, None);
                } else {
                    self.alert("Saved the settings.");
                }
            }
        }
    }

    /// Runs an open panel for the "Choose…" button `sender`, and puts what `pick` makes of the
    /// chosen path into that button's field. While `pick` rejects the path, the panel asks again.
    fn choose_into(
        &self,
        sender: &AnyObject,
        message: &str,
        folders: bool,
        pick: impl Fn(&Path) -> Result<String, &'static str>,
    ) {
        let Some(button) = sender.downcast_ref::<NSButton>() else {
            return;
        };
        let open = NSOpenPanel::openPanel(self.mtm());
        open.setCanChooseDirectories(folders);
        open.setCanChooseFiles(true);
        open.setCanCreateDirectories(folders);
        open.setAllowsMultipleSelection(false);
        let mut text = message.to_owned();
        let value = loop {
            open.setMessage(Some(&NSString::from_str(&text)));
            if open.runModal() != NSModalResponseOK {
                return;
            }
            let Some(path) = open.URL().and_then(|url| url.path()) else {
                return;
            };
            match pick(Path::new(&path.to_string())) {
                Ok(value) => break value,
                Err(problem) => text = format!("{problem} {message}"),
            }
        };
        if let Some(setup) = self.ivars().borrow().setup.as_ref() {
            setup.form.set_text(button.tag() as usize, &value);
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
        let vault = config.as_ref().map(ops::load_vault);
        if !matches!(step, Step::Create { .. } | Step::Settings { .. })
            && let Some(Err(error)) = &vault
        {
            return self.alert(&format!("{error:#}\n\nChoose Set Up… first."));
        }
        let vault = vault.and_then(Result::ok);
        let (folder_value, clear_value, autofill_index, copy_index) =
            settings_values(&step, config.as_ref());
        let pin = Field::secret("PIN");
        let draft: &[Zeroizing<String>] = match &step {
            Step::Create { draft } | Step::AddNew { draft, .. } | Step::SetPassword { draft } => {
                draft
            }
            _ => &[],
        };
        let typed = |i: usize| draft.get(i).map_or("", |v| v.as_str());
        let password = |i| Field::revealable("Password", typed(i), sel!(toggleReveal:));
        let repeat = |i| Field::revealable("Repeat", typed(i), sel!(toggleReveal:));
        let enrolled: Vec<String> = vault
            .as_ref()
            .map(|v| v.entries().into_iter().map(|(l, _)| l.to_owned()).collect())
            .unwrap_or_default();
        let (message, fields, submit) = match &step {
            Step::Create { .. } => {
                let Some(config) = &config else {
                    return;
                };
                if let Err(error) = ops::check_new(config) {
                    return self.alert(&format!("{error:#}"));
                }
                let text = format!(
                    "Set up fido2kpxc with this security key. This creates the vault at {}. Leave the database file blank to use the password for any database. After Set Up, touch the key twice.",
                    config.vault.display()
                );
                let label = Field::plain("Key label", if draft.is_empty() { "primary" } else { typed(0) });
                let database = Field::path("Database file", typed(1), sel!(chooseDatabase:));
                (text, vec![label, database, password(2), repeat(3), pin], "Set Up")
            }
            Step::AddCurrent => (
                "Insert a security key that is already enrolled, and enter its PIN. Then touch it.".to_owned(),
                vec![pin],
                "Continue",
            ),
            Step::AddNew { .. } => (
                "Enter a label for the new key and its PIN, then touch it twice.".to_owned(),
                vec![Field::plain("Key label", typed(0)), pin],
                "Add Key",
            ),
            Step::RemoveChoose => (
                "Check the keys to remove. Then each kept key needs its PIN and a touch.".to_owned(),
                enrolled
                    .iter()
                    .enumerate()
                    .map(|(i, label)| Field::check(if i == 0 { "Remove" } else { "" }, label))
                    .collect(),
                "Continue",
            ),
            Step::RemoveTouch { left, .. } => (
                format!("Enter the PIN of {}, then touch it.", ops::needed(left)),
                vec![pin],
                "Continue",
            ),
            Step::SetPassword { .. } => {
                let database = Field::path("Database file", typed(0), sel!(chooseDatabase:));
                let stored = vault
                    .as_ref()
                    .map(|v| v.names().into_iter().map(ops::describe).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default();
                let text = format!(
                    "Enter the database file name, such as pdb.kdbx, and its password, then touch your security key. Leave the name blank for any other database. Passwords stored now: {stored}."
                );
                (text, vec![database, password(1), repeat(2), pin], "Save")
            }
            Step::RemovePassword => {
                let stored: Vec<&str> = vault.as_ref().map(Vault::names).unwrap_or_default();
                let fields = stored
                    .iter()
                    .enumerate()
                    .map(|(i, name)| Field::check(if i == 0 { "Remove" } else { "" }, ops::describe(name)))
                    .collect();
                ("Check the passwords to remove. At least one password stays.".to_owned(), fields, "Remove")
            }
            Step::Swap { text, .. } => (text.clone(), Vec::new(), "Continue"),
            Step::CheckKey => (
                "Enter this security key's PIN, then touch it. fido2kpxc shows which enrolled key it is and whether it opens every stored password. It does not fill in a password.".to_owned(),
                vec![pin],
                "Check",
            ),
            Step::Settings { .. } => {
                let path = Config::path().map_or_else(|_| "the config file".to_owned(), |p| p.display().to_string());
                let text = format!(
                    "The vault is vault.toml in the vault folder. A path that starts with ~/ works on every Mac. fido2kpxc saves the settings to {path}."
                );
                let fields = vec![
                    Field::path("Vault folder", &folder_value, sel!(chooseFolder:)),
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
        match step {
            Step::Settings { then_set_up, .. } => {
                let draft = values.iter().map(|v| v.to_string()).collect();
                return self.save_settings(draft, then_set_up);
            }
            Step::Swap { then, .. } => return self.open_setup_fresh(*then, None),
            _ => {}
        }
        let Ok(config) = Config::path().and_then(|path| Config::load(&path)) else {
            return;
        };
        let owned = |i: usize| Zeroizing::new(values[i].trim().to_owned());
        // PINs pass as typed. Trimming would change a valid PIN and spend a hardware retry.
        let raw = |i: usize| values[i].clone();
        // Steps that ask for a PIN run only after their key was chosen, so the key is set here.
        let key = self.ivars().borrow().key.clone();
        match step {
            Step::Create { .. } => {
                let (label, database, pin) = (owned(0), database_or_any(&values[1]), raw(4));
                let draft = values[..4].to_vec();
                let secret = Zeroizing::new(values[2].to_string());
                let problem = password_problem(&values[2], &values[3])
                    .or_else(|| label.is_empty().then_some("Enter a key label."))
                    .or_else(|| pin.is_empty().then_some("Enter the PIN."));
                if let Some(problem) = problem {
                    return self.open_setup(Step::Create { draft }, Some(problem));
                }
                let report = format!("Created the vault at {}.", config.vault.display());
                self.spawn_step(
                    Step::Create { draft },
                    Next::Created(report),
                    Some("Touch your security key twice. To cancel, remove the key."),
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
                let pin = raw(0);
                if pin.is_empty() {
                    return self.open_setup(Step::AddCurrent, Some("Enter the PIN."));
                }
                self.spawn_step(
                    Step::AddCurrent,
                    Next::AskNewKey,
                    Some("Touch the enrolled security key."),
                    move || {
                        ops::derive(&config, &key.context("No security key was chosen")?, &pin)
                            .map(Outcome::Unlock)
                    },
                );
            }
            Step::AddNew { current, .. } => {
                let (label, pin) = (owned(0), raw(1));
                let draft = values[..1].to_vec();
                if label.is_empty() || pin.is_empty() {
                    return self.open_setup(
                        Step::AddNew { current, draft },
                        Some("Enter a key label and the PIN."),
                    );
                }
                let report = format!("Added key {:?}.", label.as_str());
                let retry = Step::AddNew {
                    current: current.clone(),
                    draft,
                };
                self.spawn_step(
                    retry,
                    Next::Report(report),
                    Some("Touch the new security key twice. To cancel, remove the key."),
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
                let labels: Vec<String> = values
                    .iter()
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_string())
                    .collect();
                if labels.is_empty() {
                    return self.open_setup(Step::RemoveChoose, Some("Check a key to remove."));
                }
                match ops::keys_to_touch(&config, &labels) {
                    Ok(left) => self.open_setup(
                        Step::Swap {
                            text: swap_insert(&left),
                            then: Box::new(Step::RemoveTouch {
                                labels,
                                left,
                                collected: Vec::new(),
                            }),
                        },
                        None,
                    ),
                    Err(error) => self.alert(&format!("{error:#}")),
                }
            }
            Step::RemoveTouch {
                labels,
                left,
                collected,
            } => {
                let pin = raw(0);
                if pin.is_empty() {
                    return self.open_setup(
                        Step::RemoveTouch {
                            labels,
                            left,
                            collected,
                        },
                        Some("Enter the PIN."),
                    );
                }
                let needed = left.clone();
                self.spawn(
                    Next::Collect {
                        labels,
                        left,
                        collected,
                    },
                    Some("Touch the key."),
                    move || {
                        ops::derive_needed(
                            &config,
                            &key.context("No security key was chosen")?,
                            &needed,
                            &pin,
                        )
                        .map(Outcome::Unlock)
                    },
                );
            }
            Step::Settings { .. } | Step::Swap { .. } => {}
            Step::RemovePassword => {
                let names: Vec<String> = match ops::load_vault(&config) {
                    Ok(vault) => vault
                        .names()
                        .into_iter()
                        .filter(|name| values.iter().any(|v| v.as_str() == ops::describe(name)))
                        .map(str::to_owned)
                        .collect(),
                    Err(error) => return self.alert(&format!("{error:#}")),
                };
                if names.is_empty() {
                    return self
                        .open_setup(Step::RemovePassword, Some("Check a password to remove."));
                }
                match ops::remove_secrets(&config, &names) {
                    Ok(()) => {
                        self.check_health(true);
                        self.alert(&ops::removal_report(&names));
                    }
                    Err(error) => self.alert(&format!("{error:#}")),
                }
            }
            Step::CheckKey => {
                let pin = raw(0);
                if pin.is_empty() {
                    return self.open_setup(Step::CheckKey, Some("Enter the PIN."));
                }
                self.spawn_step(
                    Step::CheckKey,
                    Next::Show,
                    Some("Touch your security key."),
                    move || {
                        ops::check_key(&config, &key.context("No security key was chosen")?, &pin)
                            .map(|(report, _)| Outcome::Report(report))
                    },
                );
            }
            Step::SetPassword { .. } => {
                let (database, pin) = (database_or_any(&values[0]), raw(3));
                let secret = Zeroizing::new(values[1].to_string());
                let problem = password_problem(&values[1], &values[2])
                    .or_else(|| pin.is_empty().then_some("Enter the PIN."));
                let draft = values[..3].to_vec();
                if let Some(problem) = problem {
                    return self.open_setup(Step::SetPassword { draft }, Some(problem));
                }
                let report = format!("Stored the password for {}.", ops::describe(&database));
                self.spawn_step(
                    Step::SetPassword { draft },
                    Next::Stored {
                        report,
                        database: database.clone(),
                    },
                    Some("Touch your security key. To cancel, remove the key."),
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
        let cancel = cancellable(&next);
        let touch = touch.map(|text| touch_form(self.mtm(), self, text, cancel));
        self.ivars().borrow_mut().job = Some(Job {
            next,
            touch,
            result,
            retry: None,
            since: Instant::now(),
        });
        self.reschedule();
    }

    /// Like `spawn`, but a failure reopens `retry` instead of ending the flow.
    fn spawn_step(
        &self,
        retry: Step,
        next: Next,
        touch: Option<&str>,
        work: impl FnOnce() -> Result<Outcome> + Send + 'static,
    ) {
        self.spawn(next, touch, work);
        if let Some(job) = self.ivars().borrow_mut().job.as_mut() {
            job.retry = Some(retry);
        }
    }

    /// Reopens a step after its operation failed. After a wrong PIN it asks again at once. Any
    /// other failure may need another key, so a message offers Retry, which chooses the key again.
    fn step_failed(&self, step: Step, error: &anyhow::Error) {
        let text = format!("{error:#}");
        if fido::retry_pin(error) {
            self.open_setup(step, Some(&text));
        } else {
            // A key that is not the one asked for may still be plugged in, so Remove Security
            // Key… asks for the swap again, and no PIN reaches that key.
            let step = match step {
                Step::RemoveTouch { ref left, .. } => Step::Swap {
                    text: swap_insert(left),
                    then: Box::new(step),
                },
                step => step,
            };
            self.show(&text, Some(AfterKey::Setup(step)));
        }
    }

    fn after_job(&self, next: Next, retry: Option<Step>, result: Result<Outcome>) {
        match (next, result) {
            // No key, or no touch to choose one. Retry keeps the attempt or the step.
            (Next::Devices(after) | Next::Chosen(after), Err(error)) => {
                self.show(&format!("{error:#}"), Some(after));
            }
            (
                Next::Collect {
                    labels,
                    left,
                    collected,
                },
                Err(error),
            ) => self.step_failed(
                Step::RemoveTouch {
                    labels,
                    left,
                    collected,
                },
                &error,
            ),
            (_, Err(error)) => match retry {
                Some(step) => self.step_failed(step, &error),
                None => self.alert(&format!("{error:#}")),
            },
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
                    Err(error) => self.show(&error.to_string(), Some(after)),
                }
            }
            (Next::Chosen(after), Ok(Outcome::Key(key))) => {
                self.ivars().borrow_mut().key = Some(key);
                self.continue_with_key(after);
            }
            (Next::Show, Ok(Outcome::Report(report))) => self.alert(&report),
            (Next::Stored { report, database }, Ok(_)) => {
                self.check_health(true);
                let mut state = self.ivars().borrow_mut();
                let waiting = state.kpxc.database();
                if waiting.as_deref() == Some(database.as_str()) {
                    state.kpxc.rearm();
                }
                drop(state);
                self.alert(&report);
            }
            (Next::Report(report), Ok(_)) => {
                self.check_health(true);
                self.alert(&report);
            }
            (Next::Created(report), Ok(_)) => {
                self.check_health(true);
                self.show_created(&report);
            }
            (Next::AskNewKey, Ok(Outcome::Unlock(current))) => self.open_setup(
                Step::Swap {
                    text: "Remove the enrolled key and insert the new one. Then choose Continue."
                        .to_owned(),
                    then: Box::new(Step::AddNew {
                        current,
                        draft: Vec::new(),
                    }),
                },
                None,
            ),
            (
                Next::Collect {
                    labels,
                    mut left,
                    mut collected,
                },
                Ok(Outcome::Unlock(unlock)),
            ) => {
                if ops::touched(&mut left, &unlock.cred_id).is_some() {
                    collected.push(unlock);
                }
                if !left.is_empty() {
                    return self.open_setup(
                        Step::Swap {
                            text: swap_insert(&left),
                            then: Box::new(Step::RemoveTouch {
                                labels,
                                left,
                                collected,
                            }),
                        },
                        None,
                    );
                }
                let Ok(config) = Config::path().and_then(|path| Config::load(&path)) else {
                    return;
                };
                let report = format!(
                    "{} If a removed key was lost, change the database password in KeePassXC, then choose Set Database Password….",
                    ops::removed(&labels)
                );
                self.spawn(
                    Next::Report(report),
                    Some("Saving the vault…"),
                    move || ops::remove_keys(&config, &labels, &collected).map(|()| Outcome::Done),
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
        let database = target.database();
        if vault.has_secret_for(Some(&database)) {
            return true;
        }
        self.offer_password(
            &format!("No password is stored for {database}. Store it now?"),
            &database,
            "Store…",
        );
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
        let message = message.map_or_else(
            || {
                format!(
                    "Enter your security key's FIDO2 PIN to unlock {}.",
                    target.database()
                )
            },
            str::to_owned,
        );
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
        self.ivars().borrow_mut().asking = Some(Asking { target, form });
    }

    fn finish(&self, pending: Pending, result: Result<Zeroizing<Vec<u8>>, FidoError>) {
        pending.touch.close();
        let secret = match result {
            Ok(secret) => secret,
            Err(error @ FidoError::WrongPin { .. }) => {
                return self.start(pending.target, Some(&error.to_string()));
            }
            // Each of these ends when the user swaps, reinserts, or touches a key, so Retry helps.
            Err(
                error @ (FidoError::NoDevice
                | FidoError::MultipleDevices
                | FidoError::Timeout
                | FidoError::NotEnrolled
                | FidoError::PinAuthBlocked),
            ) => {
                return self.show(&error.to_string(), Some(AfterKey::Unlock(pending.target)));
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
                self.schedule_clear(seconds, change_count);
            }
            Target::Fill(prompt) => {
                let press = self
                    .check_health(false)
                    .is_some_and(|c| c.autofill == Autofill::FillAndUnlock);
                let filled = self.ivars().borrow_mut().kpxc.fill(prompt, text, press);
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
        if matches!(target, Target::Fill(_)) {
            Kpxc::activate();
        }
        self.ivars().borrow_mut().suppress_until = Some(Instant::now() + SUPPRESS);
    }

    fn alert(&self, message: &str) {
        self.show(message, None);
    }

    /// Shows a message panel. With `retry`, it offers Retry and Cancel for that attempt or step.
    fn show(&self, message: &str, retry: Option<AfterKey>) {
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
        self.ivars().borrow_mut().message = Some(Message {
            form,
            retry,
            update: None,
        });
    }

    /// Reports the new vault. It offers Start at Login and Accessibility while they are missing,
    /// so one click finishes the setup.
    fn show_created(&self, report: &str) {
        let trusted = kpxc::accessibility_trusted();
        let login = starts_at_login();
        if trusted && login {
            return self.alert(report);
        }
        self.close_message();
        let mut text = report.to_owned();
        if !trusted {
            text += "\n\nfido2kpxc needs Accessibility access to fill in KeePassXC.";
        }
        let fields = if login {
            Vec::new()
        } else {
            vec![Field::check("", "Start at Login")]
        };
        let done = |title, key| Button {
            title,
            action: sel!(createdDone:),
            key,
        };
        let buttons = if trusted {
            vec![done("Done", Key::Return)]
        } else {
            vec![
                Button {
                    title: "Grant Accessibility…",
                    action: sel!(createdGrant:),
                    key: Key::Return,
                },
                done("Later", Key::Escape),
            ]
        };
        let form = panels::form(self.mtm(), self, "fido2kpxc", &text, &fields, &buttons);
        self.ivars().borrow_mut().message = Some(Message {
            form,
            retry: None,
            update: None,
        });
    }

    /// Applies the Start at Login box of the report on a new vault, then asks for Accessibility
    /// with `grant`.
    fn finish_created(&self, grant: bool) {
        let login = self
            .ivars()
            .borrow()
            .message
            .as_ref()
            .is_some_and(|message| {
                message
                    .form
                    .take_values()
                    .first()
                    .is_some_and(|value| !value.is_empty())
            });
        self.close_message();
        if login {
            self.set_start_at_login(true);
        }
        if grant {
            request_accessibility();
        }
    }

    fn set_start_at_login(&self, on: bool) {
        let service = unsafe { SMAppService::mainAppService() };
        let result = unsafe {
            if on {
                service.registerAndReturnError()
            } else {
                service.unregisterAndReturnError()
            }
        };
        if let Err(error) = result {
            self.alert(&format!(
                "Start at Login failed: {}",
                error.localizedDescription()
            ));
        }
    }

    /// Tells the user KeePassXC refused the stored password, most likely after a password change,
    /// and offers to store the new one.
    fn show_rejected(&self, database: &str, said: Option<&str>) {
        if self.busy() {
            return;
        }
        let said = said.map_or_else(String::new, |said| format!(" KeePassXC says: \"{said}\""));
        let text = format!(
            "KeePassXC did not unlock {database} with the stored password.{said}\n\nIf you changed the database password, store the new one."
        );
        self.offer_password(&text, database, "Update…");
    }

    /// Shows `text` with a button titled `button` that opens Set Database Password… for `database`.
    fn offer_password(&self, text: &str, database: &str, button: &str) {
        self.close_message();
        let buttons = [
            Button {
                title: button,
                action: sel!(updatePassword:),
                key: Key::Return,
            },
            Button {
                title: "Cancel",
                action: sel!(messageDismiss:),
                key: Key::Escape,
            },
        ];
        let form = panels::form(self.mtm(), self, "fido2kpxc", text, &[], &buttons);
        self.ivars().borrow_mut().message = Some(Message {
            form,
            retry: None,
            update: Some(database.to_owned()),
        });
    }

    /// Closes the message panel and returns the attempt or step it could have retried.
    fn close_message(&self) -> Option<AfterKey> {
        let message = self.ivars().borrow_mut().message.take()?;
        message.form.close();
        message.retry
    }

    /// One "Copy Password" item for a single password, or a submenu with one item per database.
    fn fill_copy_menu(&self, item: &NSMenuItem) {
        let databases: Vec<String> = load()
            .map(|(_, vault)| vault.names().into_iter().map(str::to_owned).collect())
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
        let busy = self.busy();
        let state = self.ivars().borrow();
        let Some(menu) = state.menu.as_ref() else {
            return;
        };
        let status = match (state.health.as_ref(), state.conflicts.as_slice()) {
            (Some((_, Err(error))), _) => error.clone(),
            (_, [first, ..]) => format!("Sync conflict: {first}. See Help…"),
            _ => "Ready".to_owned(),
        };
        menu.status.setTitle(&NSString::from_str(&format!(
            "fido2kpxc {} - {status}",
            env!("CARGO_PKG_VERSION")
        )));
        menu.unlock.setEnabled(state.kpxc.at_prompt() && !busy);
        let copy = config.as_ref().is_some_and(|c| c.copy_password);
        menu.copy.setHidden(!copy);
        menu.copy.setEnabled(!busy);
        if copy {
            self.fill_copy_menu(&menu.copy);
        }
        menu.set_up
            .setEnabled(!busy && can_set_up(&Config::path().and_then(|path| Config::load(&path))));
        // A second flow would replace the running flow's chosen key.
        for item in &menu.manage {
            item.setEnabled(config.is_some() && !busy);
        }
        menu.grant.setHidden(kpxc::accessibility_trusted());
        menu.login.setState(if starts_at_login() {
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
    // macOS 26 adds icons to menu items with standard actions, and they break the alignment.
    // The registration domain turns them off for this app only, and a user setting still wins.
    let no_icons = NSDictionary::from_slices(
        &[ns_string!("NSMenuEnableActionImages")],
        &[&*NSNumber::new_bool(false) as &AnyObject],
    );
    // The only value is an NSNumber, which is a property-list object as the call requires.
    unsafe { NSUserDefaults::standardUserDefaults().registerDefaults(&no_icons) };

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
    let unlock = add("Unlock KeePassXC", Some(sel!(unlockNow:)));
    let copy = add("Copy Password", Some(sel!(copyPassword:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let set_up = add("Set Up…", Some(sel!(setUp:)));
    let manage = vec![
        add("Set Database Password…", Some(sel!(setPassword:))),
        add("Remove Database Password…", Some(sel!(removePassword:))),
        add("Add Security Key…", Some(sel!(addKey:))),
        add("Check a Security Key…", Some(sel!(checkKey:))),
        add("Remove Security Key…", Some(sel!(removeKey:))),
    ];
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Settings…", Some(sel!(openSettings:)));
    let grant = add("Grant Accessibility…", Some(sel!(grantAccessibility:)));
    let login = add("Start at Login", Some(sel!(toggleLogin:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Show Vault in Finder", Some(sel!(showVault:)));
    add("Open Config…", Some(sel!(openConfig:)));
    add("Copy Diagnostics", Some(sel!(copyDiagnostics:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Help…", Some(sel!(showHelp:)));
    add("About fido2kpxc", Some(sel!(showAbout:)));
    add("Quit", Some(sel!(quit:)));

    let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
    menu.setDelegate(Some(ProtocolObject::from_ref(&*controller)));
    item.setMenu(Some(&menu));
    controller.ivars().borrow_mut().menu = Some(Menu {
        status,
        unlock,
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

    unsafe {
        NSWorkspace::sharedWorkspace()
            .notificationCenter()
            .addObserver_selector_name_object(
                &controller,
                sel!(appActivated:),
                Some(NSWorkspaceDidActivateApplicationNotification),
                None,
            );
    }
    controller.wake_in(Duration::ZERO);
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
    // The menu bar leaves 18 pt of height for an icon. The width follows the drawing.
    let size = image.size();
    image.setSize(NSSize::new(size.width * 18.0 / size.height, 18.0));
    // Template images take the menu bar's color in light mode, dark mode, and when highlighted.
    image.setTemplate(true);
    image.setAccessibilityDescription(Some(&NSString::from_str(description)));
    Some(image)
}

/// Stamps of the config, the vault, and the vault folder's listing.
fn stamps(folder: Option<&Path>) -> [Stamp; 3] {
    let path = Config::path().ok();
    let vault = folder.map(|f| f.join("vault.toml"));
    [
        path.as_deref().and_then(config::stamp),
        vault.as_deref().and_then(config::stamp),
        folder.and_then(config::stamp),
    ]
}

fn load() -> Result<(Config, Vault)> {
    let config = Config::load(&Config::path()?)?;
    let vault = load_existing_vault(&config)?;
    Ok((config, vault))
}

fn load_existing_vault(config: &Config) -> Result<Vault> {
    ensure!(
        config.vault.exists(),
        "No vault at {}. Run `fido2kpxc enroll`.",
        config.vault.display()
    );
    ops::load_vault(config)
}

/// The vault folder, when the config at `path` reads, and the config, when the vault loads too.
fn load_health(path: Result<PathBuf>) -> (Option<PathBuf>, Result<Config, String>) {
    let config = path.and_then(|path| Config::load(&path));
    let folder = config.as_ref().ok().map(|c| c.folder.clone());
    let health = config
        .and_then(|config| load_existing_vault(&config).map(|_| config))
        .map_err(|e| format!("{e:#}"));
    (folder, health)
}

/// Steps whose form asks for a PIN, so their key is chosen first.
fn needs_key(step: &Step) -> bool {
    matches!(
        step,
        Step::Create { .. }
            | Step::AddCurrent
            | Step::AddNew { .. }
            | Step::RemoveTouch { .. }
            | Step::SetPassword { .. }
            | Step::CheckKey
    )
}

/// Set Up stays offered until a vault exists, so a fresh install can start with it.
fn can_set_up(config: &Result<Config>) -> bool {
    !config.as_ref().is_ok_and(|c| c.vault.exists())
}

/// Set Up needs a vault folder, so without a working config it opens Settings first.
fn set_up_step(config: &Result<Config>) -> Step {
    match config {
        Ok(_) => Step::Create { draft: Vec::new() },
        Err(_) => Step::Settings {
            draft: None,
            then_set_up: true,
        },
    }
}

/// Labels for the autofill choice, in the order of [`Autofill::ALL`].
const AUTOFILL_LABELS: [&str; 3] = ["Fill and unlock", "Fill only", "Off"];

/// Values the settings form starts with: a rejected draft, else the current config, else defaults.
/// Other steps get empty values they never read.
fn settings_values(step: &Step, config: Option<&Config>) -> (String, String, usize, usize) {
    if let Step::Settings {
        draft: Some(draft), ..
    } = step
    {
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
    let folder = tilde(&config.folder, home().as_deref());
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

fn starts_at_login() -> bool {
    let status = unsafe { SMAppService::mainAppService().status() };
    status == SMAppServiceStatus::Enabled
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Shows a path under `home` as `~/…`, which works on every Mac.
fn tilde(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// The vault folder that a pick names: a folder itself, or the folder of a vault.toml.
fn picked_folder(path: &Path) -> Option<&Path> {
    if path.is_dir() {
        Some(path)
    } else if path.file_name() == Some("vault.toml".as_ref()) {
        path.parent()
    } else {
        None
    }
}

/// The database name that a pick names. The vault keys passwords by file name.
fn picked_database(path: &Path) -> Option<&str> {
    path.file_name()?.to_str()
}

/// A panel that stays up while the worker thread waits for a touch, with Cancel when the wait's
/// result can be dropped.
fn touch_form(mtm: MainThreadMarker, target: &AnyObject, text: &str, cancel: bool) -> Form {
    let buttons: &[Button] = if cancel {
        &[Button {
            title: "Cancel",
            action: sel!(touchCancel:),
            key: Key::Escape,
        }]
    } else {
        &[]
    };
    panels::form(mtm, target, "fido2kpxc", text, &[], buttons)
}

/// Waits whose result can be dropped, because they only choose a key or derive. The others
/// write the vault and cannot stop once the key has the request, so their text says that
/// removing the key ends the wait.
fn cancellable(next: &Next) -> bool {
    matches!(
        next,
        Next::Devices(_) | Next::Chosen(_) | Next::AskNewKey | Next::Collect { .. } | Next::Show
    )
}

/// Asks for the next key in Remove Security Key… before it is chosen.
fn swap_insert(left: &[(String, Vec<u8>)]) -> String {
    format!("Insert {}. Then choose Continue.", ops::needed(left))
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
    ops::database_name(name)
}

fn copy_concealed(text: &str) -> isize {
    let pasteboard = NSPasteboard::generalPasteboard();
    // Keeps the password off Universal Clipboard, so it never reaches other devices.
    pasteboard.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
    // Clipboard managers skip entries that carry this marker type. One item carries the marker
    // and the text, so no reader sees the text without it.
    let item = NSPasteboardItem::new();
    item.setString_forType(
        ns_string!(""),
        &NSString::from_str("org.nspasteboard.ConcealedType"),
    );
    item.setString_forType(&NSString::from_str(text), unsafe { NSPasteboardTypeString });
    pasteboard.writeObjects(&NSArray::from_retained_slice(&[
        ProtocolObject::from_retained(item),
    ]));
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
        "Set up
Choose Set Up… and follow the panels. Allow Accessibility when the last panel asks.

Unlock
Lock KeePassXC, and the PIN panel opens. Enter the PIN and touch the key. If the panel does not open, choose Unlock KeePassXC. While KeePassXC offers quick unlock by Touch ID, the PIN panel waits until KeePassXC asks for the password.

Backup keys
Add a backup key of any brand with Add Security Key…. Test it at regular intervals with Check a Security Key….

Problems
The first line of this menu shows config and vault errors. A sync conflict means your sync tool left a second copy of the vault, such as vault 2.toml. Keep both files. Each lists its key labels and database names in plain text. Add any key or password missing from vault.toml with this menu, then delete the other copy. If autofill fails, attach Copy Diagnostics to a bug report.

Terminal
Run {exe} help for the commands."
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
