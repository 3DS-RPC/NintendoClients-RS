//! # NintendoClients-rs
//!
//! A Rust port of the 3DS and Wii U friend code from
//! [NintendoClients](https://github.com/kinnay/NintendoClients).
//!
//! The Python reference implementation is kept on the `reference` branch of
//! this repository. Module documentation points at the Python file that each
//! module is ported from.

pub mod account;
pub mod nex;

pub use nex::settings::Settings;
