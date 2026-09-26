//! The vault and security-key code, for other tools that read fido2kpxc's stored passwords. The
//! binary declares these modules itself, so its size does not change.

pub mod config;
pub mod fido;
pub mod ops;
pub mod vault;
