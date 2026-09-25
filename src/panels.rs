//! Non-activating panels. macOS no longer lets a background accessory app activate itself,
//! so a normal window or alert would open without keyboard focus while KeePassXC stays active.
//! A non-activating panel receives keys anyway.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Sel};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSButton, NSEvent, NSEventModifierFlags,
    NSFloatingWindowLevel, NSImage, NSPanel, NSPopUpButton, NSResponder, NSSecureTextField,
    NSTextField, NSView, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{NSObject, NSPoint, NSRect, NSSize, NSString, ns_string};

const WIDTH: f64 = 420.0;
const MARGIN: f64 = 20.0;
const EYE: f64 = 24.0;

define_class!(
    /// A panel that handles Cmd+V, C, X, A, and Z itself. A menu-bar app has no Edit menu,
    /// and an inactive app's menu gets no key equivalents, so paste would do nothing.
    #[unsafe(super(NSPanel, NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "Fido2kpxcPanel"]
    struct KeyPanel;

    impl KeyPanel {
        #[unsafe(method(performKeyEquivalent:))]
        fn perform_key_equivalent(&self, event: &NSEvent) -> bool {
            // A nil target sends the action along the responder chain to the focused field.
            let handled = edit_action(event).is_some_and(|action| {
                let app = NSApplication::sharedApplication(self.mtm());
                unsafe { app.sendAction_to_from(action, None, None) }
            });
            handled || unsafe { msg_send![super(self), performKeyEquivalent: event] }
        }
    }
);

fn edit_action(event: &NSEvent) -> Option<Sel> {
    if !event
        .modifierFlags()
        .contains(NSEventModifierFlags::Command)
    {
        return None;
    }
    match event.charactersIgnoringModifiers()?.to_string().as_str() {
        "v" => Some(sel!(paste:)),
        "c" => Some(sel!(copy:)),
        "x" => Some(sel!(cut:)),
        "a" => Some(sel!(selectAll:)),
        "z" => Some(sel!(undo:)),
        _ => None,
    }
}

pub struct Field<'a> {
    pub label: &'a str,
    pub secure: bool,
    pub value: &'a str,
    /// For secure fields: the action of an eye button that shows or hides the text.
    /// The button's tag is the field's index.
    pub reveal: Option<Sel>,
}

impl<'a> Field<'a> {
    pub fn plain(label: &'a str, value: &'a str) -> Self {
        Self {
            label,
            secure: false,
            value,
            reveal: None,
        }
    }

    pub fn secret(label: &'a str) -> Self {
        Self {
            label,
            secure: true,
            value: "",
            reveal: None,
        }
    }

    /// A secret field with an eye button, for long passwords that are easy to mistype.
    pub fn revealable(label: &'a str, action: Sel) -> Self {
        Self {
            label,
            secure: true,
            value: "",
            reveal: Some(action),
        }
    }
}

pub struct Button<'a> {
    pub title: &'a str,
    pub action: Sel,
    pub key: Key,
}

pub enum Key {
    Return,
    Escape,
}

pub struct Form {
    pub panel: Retained<NSPanel>,
    pub fields: Vec<Retained<NSTextField>>,
    /// For revealable fields: a plain field at the same spot, shown while the text is visible.
    plain: Vec<Option<Retained<NSTextField>>>,
    eyes: Vec<Option<Retained<NSButton>>>,
    pub choice: Option<Retained<NSPopUpButton>>,
}

impl Form {
    /// Reads every field, then clears them, so typed secrets do not linger in the controls.
    pub fn take_values(&self) -> Vec<zeroize::Zeroizing<String>> {
        self.fields
            .iter()
            .zip(&self.plain)
            .map(|(field, plain)| {
                let visible = plain.as_ref().filter(|p| !p.isHidden()).unwrap_or(field);
                let value = zeroize::Zeroizing::new(visible.stringValue().to_string());
                field.setStringValue(ns_string!(""));
                if let Some(plain) = plain {
                    plain.setStringValue(ns_string!(""));
                }
                value
            })
            .collect()
    }

    /// Shows or hides the text of revealable field `index`, moving its text across.
    pub fn toggle_reveal(&self, index: usize) {
        let (Some(secure), Some(Some(plain)), Some(Some(eye))) = (
            self.fields.get(index),
            self.plain.get(index),
            self.eyes.get(index),
        ) else {
            return;
        };
        let showing = !plain.isHidden();
        let (from, to) = if showing {
            (plain, secure)
        } else {
            (secure, plain)
        };
        to.setStringValue(&from.stringValue());
        from.setStringValue(ns_string!(""));
        from.setHidden(true);
        to.setHidden(false);
        self.panel.makeFirstResponder(Some(to));
        eye.setImage(eye_image(!showing).as_deref());
    }

    pub fn chosen(&self) -> Option<String> {
        let choice = self.choice.as_ref()?;
        Some(choice.titleOfSelectedItem()?.to_string())
    }

    pub fn close(&self) {
        self.panel.orderOut(None);
    }
}

/// Builds and shows a panel: `message` on top, one row per field, an optional choice menu,
/// and `buttons` right-aligned at the bottom. Buttons send their actions to `target`.
pub fn form(
    mtm: MainThreadMarker,
    target: &AnyObject,
    title: &str,
    message: &str,
    fields: &[Field],
    choices: &[String],
    buttons: &[Button],
) -> Form {
    let rect = |x, y, w, h| NSRect::new(NSPoint::new(x, y), NSSize::new(w, h));
    let text = NSTextField::wrappingLabelWithString(&NSString::from_str(message), mtm);
    text.setPreferredMaxLayoutWidth(WIDTH - 2.0 * MARGIN);
    let text_height = text.fittingSize().height;
    let rows = fields.len() + usize::from(!choices.is_empty());
    let buttons_height = if buttons.is_empty() { 0.0 } else { 44.0 };
    let height = MARGIN + text_height + 12.0 + rows as f64 * 32.0 + buttons_height + 12.0;

    let mask = NSWindowStyleMask::Titled | NSWindowStyleMask::NonactivatingPanel;
    let panel: Retained<KeyPanel> = unsafe {
        msg_send![
            KeyPanel::alloc(mtm),
            initWithContentRect: rect(0.0, 0.0, WIDTH, height),
            styleMask: mask,
            backing: NSBackingStoreType::Buffered,
            defer: false,
        ]
    };
    let panel: Retained<NSPanel> = Retained::into_super(panel);
    unsafe { panel.setReleasedWhenClosed(false) };
    panel.setTitle(&NSString::from_str(title));
    panel.setLevel(NSFloatingWindowLevel);
    // Panels hide while their app is inactive, and fido2kpxc never becomes the active app.
    panel.setHidesOnDeactivate(false);
    panel.setBecomesKeyOnlyIfNeeded(false);
    panel.setAutorecalculatesKeyViewLoop(true);
    let content = panel.contentView().expect("panels have a content view");

    let mut top = height - MARGIN - text_height;
    text.setFrame(rect(MARGIN, top, WIDTH - 2.0 * MARGIN, text_height));
    content.addSubview(&text);
    top -= 12.0;

    let (mut controls, mut plains, mut eyes) = (Vec::new(), Vec::new(), Vec::new());
    for (index, field) in fields.iter().enumerate() {
        top -= 24.0;
        let label = NSTextField::labelWithString(&NSString::from_str(field.label), mtm);
        label.setFrame(rect(MARGIN, top + 2.0, 110.0, 20.0));
        content.addSubview(&label);
        let eye_space = if field.reveal.is_some() {
            EYE + 4.0
        } else {
            0.0
        };
        let frame = rect(
            MARGIN + 116.0,
            top,
            WIDTH - 2.0 * MARGIN - 116.0 - eye_space,
            24.0,
        );
        let control: Retained<NSTextField> = if field.secure {
            Retained::into_super(NSSecureTextField::initWithFrame(
                NSSecureTextField::alloc(mtm),
                frame,
            ))
        } else {
            NSTextField::initWithFrame(NSTextField::alloc(mtm), frame)
        };
        control.setStringValue(&NSString::from_str(field.value));
        content.addSubview(&control);
        let (plain, eye) = match field.reveal {
            Some(action) => {
                let plain = NSTextField::initWithFrame(NSTextField::alloc(mtm), frame);
                plain.setHidden(true);
                content.addSubview(&plain);
                let eye = unsafe {
                    NSButton::buttonWithTitle_target_action(
                        ns_string!(""),
                        Some(target),
                        Some(action),
                        mtm,
                    )
                };
                eye.setBordered(false);
                eye.setImage(eye_image(false).as_deref());
                eye.setTag(index as isize);
                eye.setFrame(rect(WIDTH - MARGIN - EYE, top, EYE, 24.0));
                content.addSubview(&eye);
                (Some(plain), Some(eye))
            }
            None => (None, None),
        };
        controls.push(control);
        plains.push(plain);
        eyes.push(eye);
        top -= 8.0;
    }

    let choice = (!choices.is_empty()).then(|| {
        top -= 26.0;
        let popup = NSPopUpButton::initWithFrame_pullsDown(
            NSPopUpButton::alloc(mtm),
            rect(MARGIN + 112.0, top, WIDTH - 2.0 * MARGIN - 112.0, 26.0),
            false,
        );
        for item in choices {
            popup.addItemWithTitle(&NSString::from_str(item));
        }
        content.addSubview(&popup);
        popup
    });

    let mut right = WIDTH - MARGIN + 6.0;
    for button in buttons {
        right -= 96.0;
        let control = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str(button.title),
                Some(target),
                Some(button.action),
                mtm,
            )
        };
        control.setFrame(rect(right, 12.0, 90.0, 32.0));
        control.setKeyEquivalent(match button.key {
            Key::Return => ns_string!("\r"),
            Key::Escape => ns_string!("\u{1b}"),
        });
        content.addSubview(&*control as &NSView);
    }

    panel.center();
    panel.makeKeyAndOrderFront(None);
    if let Some(first) = controls.first() {
        panel.makeFirstResponder(Some(first));
    }
    Form {
        panel,
        fields: controls,
        plain: plains,
        eyes,
        choice,
    }
}

fn eye_image(showing: bool) -> Option<Retained<NSImage>> {
    let (name, description) = if showing {
        (ns_string!("eye.slash"), ns_string!("Hide password"))
    } else {
        (ns_string!("eye"), ns_string!("Show password"))
    };
    NSImage::imageWithSystemSymbolName_accessibilityDescription(name, Some(description))
}
