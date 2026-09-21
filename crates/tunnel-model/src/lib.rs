//! Versioned networking requests shared by clients and OS helpers.
#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{
    ConnectionState, EndpointIdentity, ServerId, TransportKind, ipv6_tunnel_address, validate_host,
};
use sirinvpn_transport::{TransportEngine, TransportSelection};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};
use thiserror::Error;
use zeroize::Zeroize;

const MAX_INCLUDED_ROUTES: usize = 32;
mod diagnostics;
mod model;
mod validation;
pub use model::*;
pub use validation::*;

mod preferences;
pub use preferences::{ConnectionPreferenceStore, ConnectionPreferences};
