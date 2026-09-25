use super::*;

#[test]
fn password_fields_must_be_filled_and_match() {
    assert!(password_problem("", "").is_some());
    assert!(password_problem("a", "b").is_some());
    assert_eq!(password_problem("a", "a"), None);
}

#[test]
fn blank_database_name_means_any_database() {
    assert_eq!(database_or_any("  "), ANY);
    assert_eq!(database_or_any(" work.kdbx "), "work.kdbx");
}
