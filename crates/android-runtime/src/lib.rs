//! Service-owned runtime. This library does not link Tauri, create an Activity,
//! or open an RPC listener on the network.
#![deny(unsafe_op_in_unsafe_fn)]

/// The host-testable command rules; on Android `commands` includes the same file.
#[cfg(all(test, not(target_os = "android")))]
#[path = "commands/rules.rs"]
#[allow(dead_code)] // Some rules are used only by the Android commands.
mod command_rules;
#[cfg(target_os = "android")]
mod commands;
#[cfg(target_os = "android")]
mod jni_bridge;
#[cfg(target_os = "android")]
mod quality;
#[cfg(any(target_os = "android", test))]
mod routes;
#[cfg(target_os = "android")]
mod tunnel;
#[cfg(any(target_os = "android", test))]
mod uapi;
