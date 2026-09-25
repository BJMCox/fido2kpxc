use std::fmt;

use anyhow::anyhow;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as Mext;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};
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
                "The FIDO2 PIN is blocked. Only a FIDO2 reset with the vendor's tool recovers the key, such as `ykman fido reset` for a YubiKey, and it erases all FIDO2 credentials. Use a backup key."
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

/// Makes a non-resident hmac-secret credential and returns its output for `salt`. Needs two touches.
pub fn enroll(pin: &str, salt: &[u8; 32], exclude: &[&[u8]]) -> Result<Unlock, FidoError> {
    let device = device()?;
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
pub fn derive(pin: &str, salt: &[u8; 32], cred_ids: &[&[u8]]) -> Result<Unlock, FidoError> {
    assert_hmac(&device()?, pin, salt, cred_ids)
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

fn device() -> Result<FidoKeyHid, FidoError> {
    FidoKeyHidFactory::create(&LibCfg::init()).map_err(classify)
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
mod tests {
    use super::*;

    #[test]
    fn ctap_status_text_maps_to_ui_cases() {
        let map = |text: &str| classify(anyhow!("{text}"));
        assert!(matches!(map("FIDO device not found."), FidoError::NoDevice));
        assert!(matches!(
            map("0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."),
            FidoError::WrongPin { .. }
        ));
        assert!(matches!(
            map("0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked."),
            FidoError::PinBlocked
        ));
        assert!(matches!(
            map("0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked."),
            FidoError::PinAuthBlocked
        ));
        assert!(matches!(
            map("0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided."),
            FidoError::NotEnrolled
        ));
        assert!(matches!(
            map("0x3A CTAP2_ERR_ACTION_TIMEOUT Maximum time for user action expired."),
            FidoError::Timeout
        ));
        assert!(matches!(
            map("read err = something else"),
            FidoError::Other(_)
        ));
    }
}
