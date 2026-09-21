#![forbid(unsafe_code)]
#[cfg(not(target_os = "android"))]
include!("desktop.rs");
#[cfg(target_os = "android")]
mod mobile;
#[cfg(target_os = "android")]
pub use mobile::run;
