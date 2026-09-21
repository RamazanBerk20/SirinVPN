//! Small native boundaries shared by clients and privileged platform adapters.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod files;
#[cfg(windows)]
pub mod windows;
