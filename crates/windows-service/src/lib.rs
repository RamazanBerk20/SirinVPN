//! Privileged Windows networking with a bounded, authenticated local IPC boundary.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod endpoint_plan;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))] // Native consumers are absent in host policy tests.
mod firewall_plan;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod network_plan;
mod protocol;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod quality_plan;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod state;
pub use protocol::{
    ApplicationRouteRequest, MAX_FRAME_BYTES, Operation, Request, Response, ServiceError,
};

#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod application_plan;
#[cfg(windows)]
pub(crate) use install::application_driver;

pub const SERVICE_NAME: &str = "SirinVPN";
pub const PIPE_NAME: &str = r"\\.\pipe\SirinVPN.Service.v1";

#[cfg(windows)]
mod firewall;
#[cfg(windows)]
pub mod ipc;
#[cfg(windows)]
mod wireguard;

#[cfg(windows)]
mod network;

#[cfg(windows)]
mod carrier;
#[cfg(windows)]
mod controller;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
mod probes;
#[cfg(windows)]
mod resolver;
#[cfg(windows)]
mod runtime;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod update;

#[cfg(test)]
mod tests;
