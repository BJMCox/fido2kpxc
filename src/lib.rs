//! The vault and security-key code, for other tools that read fido2kpxc's stored passwords.
//! `config` and `ops` are declared here and again by the binary, so its size does not change.
//! `fido` and `vault` come from fido2kit.

pub mod config;
pub mod ops;

pub use fido2kit::{fido, vault};
