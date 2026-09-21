//! Service-owned runtime. This library does not link Tauri, create an Activity,
//! or open an RPC listener on the network.
#![deny(unsafe_op_in_unsafe_fn)]

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
