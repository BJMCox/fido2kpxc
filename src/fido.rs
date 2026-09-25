use std::fmt;

use anyhow::anyhow;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as Mext;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, HidParam, LibCfg};
use std::sync::{Arc, mpsc};
use zeroize::Zeroizing;

use crate::vault::Unlock;

const RP_ID: &str = "fido2kpxc";

#[derive(Debug)]
pub enum FidoError {
    NoDevice,
    MultipleDevices,
    WrongPin { retries: Option<i32> },
    PinBlocked,
    PinAuthBlocked,
    Timeout,
    NotEnrolled,
    AlreadyEnrolled,
    Other(anyhow::Error),
}

impl fmt::Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice => write!(f, "Insert your security key."),
            Self::MultipleDevices => write!(f, "Remove all security keys but one."),
            Self::WrongPin { retries: Some(n) } => write!(f, "Wrong PIN. {n} tries left."),
            Self::WrongPin { retries: None } => write!(f, "Wrong PIN."),
            Self::PinBlocked => write!(
                f,
                "The FIDO2 PIN is blocked. Only a FIDO2 reset with the vendor's tool recovers the key, and it erases all FIDO2 credentials. Use a backup key."
            ),
            Self::PinAuthBlocked => {
                write!(
                    f,
                    "Too many wrong PINs in a row. Remove and reinsert the security key."
                )
            }
            Self::Timeout => write!(f, "No touch detected. Try again."),
            Self::NotEnrolled => write!(f, "This security key is not enrolled in the vault."),
            Self::AlreadyEnrolled => write!(f, "This security key is already enrolled."),
            Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for FidoError {}

/// A plugged-in FIDO device, as the operating system names it.
pub type Device = HidParam;

/// Which plugged-in security key to talk to: the only one, or the one the user touched.
#[derive(Clone)]
pub struct Key(HidParam);

/// The plugged-in FIDO security keys.
pub fn devices() -> Vec<HidParam> {
    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .map(|info| info.param)
        .collect()
}

/// The key to use among `devices`. With one key it is that key. With several, every key blinks
/// until the user touches one (CTAP 2.1 authenticatorSelection), and the others are cancelled.
pub fn select(devices: Vec<HidParam>) -> Result<Key, FidoError> {
    match devices.as_slice() {
        [] => return Err(FidoError::NoDevice),
        [only] => return Ok(Key(only.clone())),
        _ => {}
    }
    let cfg = LibCfg::init();
    let opened: Vec<(HidParam, Arc<FidoKeyHid>)> = devices
        .into_iter()
        .filter_map(|param| {
            let device =
                FidoKeyHidFactory::create_by_params(std::slice::from_ref(&param), &cfg).ok()?;
            Some((param, Arc::new(device)))
        })
        .collect();
    let (sender, touched) = mpsc::channel();
    for (index, (_, device)) in opened.iter().enumerate() {
        let (device, sender) = (Arc::clone(device), sender.clone());
        std::thread::spawn(move || {
            let _ = sender.send((index, device.selection()));
        });
    }
    drop(sender);
    let mut last_error = None;
    for (index, result) in touched {
        match result {
            Ok(()) => {
                // Stops the other keys blinking. A key that already answered ignores the cancel.
                for (other, (_, device)) in opened.iter().enumerate() {
                    if other != index {
                        let _ = device.cancel_selection();
                    }
                }
                return Ok(Key(opened[index].0.clone()));
            }
            Err(error) => last_error = Some(classify(error)),
        }
    }
    // A key without authenticatorSelection (CTAP 2.0) cannot take part, so fall back to one key.
    Err(match last_error {
        Some(FidoError::Timeout) => FidoError::Timeout,
        _ => FidoError::MultipleDevices,
    })
}

/// Makes a non-resident hmac-secret credential and returns its output for `salt`. Needs two touches.
pub fn enroll(
    key: &Key,
    pin: &str,
    salt: &[u8; 32],
    exclude: &[&[u8]],
) -> Result<Unlock, FidoError> {
    let device = open(key)?;
    let extensions = [Mext::HmacSecret(Some(true))];
    let challenge = challenge()?;
    let mut builder = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
        .pin(pin)
        .extensions(&extensions);
    for id in exclude {
        builder = builder.exclude_authenticator(id);
    }
    let attestation = device
        .make_credential_with_args(&builder.build())
        .map_err(|e| with_retries(&device, e))?;
    if !attestation
        .extensions
        .iter()
        .any(|e| matches!(e, Mext::HmacSecret(Some(true))))
    {
        return Err(FidoError::Other(anyhow!(
            "This key does not support hmac-secret"
        )));
    }
    assert_hmac(&device, pin, salt, &[&attestation.credential_descriptor.id])
}

/// Returns the hmac-secret output of whichever enrolled credential the inserted key holds.
pub fn derive(
    key: &Key,
    pin: &str,
    salt: &[u8; 32],
    cred_ids: &[&[u8]],
) -> Result<Unlock, FidoError> {
    assert_hmac(&open(key)?, pin, salt, cred_ids)
}

fn assert_hmac(
    device: &FidoKeyHid,
    pin: &str,
    salt: &[u8; 32],
    cred_ids: &[&[u8]],
) -> Result<Unlock, FidoError> {
    let extensions = [Gext::HmacSecret(Some(*salt))];
    let challenge = challenge()?;
    let mut builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .pin(pin)
        .extensions(&extensions);
    for id in cred_ids {
        builder = builder.add_credential_id(id);
    }
    let assertion = device
        .get_assertion_with_args(&builder.build())
        .map_err(|e| with_retries(device, e))?
        .into_iter()
        .next()
        .ok_or_else(|| FidoError::Other(anyhow!("The key returned no assertion")))?;
    let output = assertion
        .extensions
        .iter()
        .find_map(|e| match e {
            Gext::HmacSecret(Some(output)) => Some(Zeroizing::new(*output)),
            _ => None,
        })
        .ok_or_else(|| FidoError::Other(anyhow!("The key returned no hmac-secret output")))?;
    // CTAP lets the key omit the credential ID when the allow list has one entry.
    let cred_id = match (assertion.credential_id.is_empty(), cred_ids) {
        (true, [only]) => only.to_vec(),
        _ => assertion.credential_id,
    };
    Ok(Unlock { cred_id, output })
}

fn open(key: &Key) -> Result<FidoKeyHid, FidoError> {
    FidoKeyHidFactory::create_by_params(std::slice::from_ref(&key.0), &LibCfg::init())
        .map_err(classify)
}

fn challenge() -> Result<[u8; 32], FidoError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| FidoError::Other(anyhow!("The random source failed: {e}")))?;
    Ok(bytes)
}

fn with_retries(device: &FidoKeyHid, error: anyhow::Error) -> FidoError {
    match classify(error) {
        FidoError::WrongPin { .. } => FidoError::WrongPin {
            retries: device.get_pin_retries().ok(),
        },
        other => other,
    }
}

/// Maps ctap-hid-fido2's error text, which carries the CTAP status name, to the cases the UI handles.
fn classify(error: anyhow::Error) -> FidoError {
    let text = format!("{error:#}");
    let cases = [
        ("FIDO device not found", FidoError::NoDevice),
        ("Multiple FIDO devices", FidoError::MultipleDevices),
        (
            "CTAP2_ERR_PIN_INVALID",
            FidoError::WrongPin { retries: None },
        ),
        ("CTAP2_ERR_PIN_BLOCKED", FidoError::PinBlocked),
        ("CTAP2_ERR_PIN_AUTH_BLOCKED", FidoError::PinAuthBlocked),
        ("CTAP2_ERR_USER_ACTION_TIMEOUT", FidoError::Timeout),
        // Some authenticators report a touch timeout with this older status name.
        ("CTAP2_ERR_ACTION_TIMEOUT", FidoError::Timeout),
        ("CTAP2_ERR_NO_CREDENTIALS", FidoError::NotEnrolled),
        ("CTAP2_ERR_CREDENTIAL_EXCLUDED", FidoError::AlreadyEnrolled),
    ];
    cases
        .into_iter()
        .find(|(needle, _)| text.contains(needle))
        .map_or(FidoError::Other(error), |(_, case)| case)
}

#[cfg(test)]
mod tests;
