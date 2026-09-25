use super::*;

#[test]
fn completion_script_offers_every_command_in_the_usage() {
    let commands = USAGE
        .split(['[', '|', ']'])
        .skip(1)
        .filter_map(|part| part.split_whitespace().next())
        // Nested `[--option VALUE]` groups are options, not commands.
        .filter(|word| !word.starts_with('-'));
    for command in commands {
        assert!(
            COMPLETIONS.contains(&format!("'{command}:")),
            "{command} is missing"
        );
    }
}

#[test]
fn completion_script_offers_every_option() {
    let options = USAGE
        .split_whitespace()
        .map(|word| word.trim_matches(['[', ']', '|']))
        .filter(|word| word.starts_with("--"))
        .chain(["--help", "-h"]);
    for option in options {
        assert!(
            COMPLETIONS.contains(&format!(" {option}")),
            "{option} is missing"
        );
    }
}
