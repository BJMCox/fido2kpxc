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
