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

#[test]
fn only_a_wrong_pin_counts_as_one() {
    let bad_pin = anyhow::Error::from(FidoError::WrongPin { retries: Some(2) });
    let other_key = anyhow::Error::from(FidoError::NotEnrolled);
    assert!(wrong_pin(&bad_pin));
    assert!(!wrong_pin(&other_key));
    assert!(!wrong_pin(&anyhow::anyhow!("The vault is gone")));
}

#[test]
fn pins_are_normalized_to_nfc_and_keep_spaces() {
    assert_eq!(*nfc(" e\u{301} "), " \u{e9} ");
}

#[test]
fn keys_that_support_protocol_one_keep_it() {
    assert_eq!(pin_protocol(&[2, 1]), 1);
    assert_eq!(pin_protocol(&[2]), 2);
}

#[test]
fn credential_lists_split_only_above_the_limits() {
    let (a, b, c) = (&[1u8; 16][..], &[2u8; 16][..], &[3u8; 80][..]);
    assert!(chunks(&[a, b], 2, 0).is_none());
    assert_eq!(chunks(&[a, b], 1, 0).unwrap(), vec![vec![a], vec![b]]);
    assert_eq!(chunks(&[a, c, b], 2, 64).unwrap(), vec![vec![a, b]]);
}
