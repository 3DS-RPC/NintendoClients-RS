//! The NEX protocol stack used by the 3DS and Wii U friend server.
//!
//! Ported from the `nintendo/nex` package of the Python reference.

pub mod authentication;
pub mod backend;
pub mod common;
pub mod errors;
pub mod friends;
pub mod kerberos;
pub mod notification;
pub mod prudp;
pub mod rmc;
pub mod settings;
pub mod streams;
