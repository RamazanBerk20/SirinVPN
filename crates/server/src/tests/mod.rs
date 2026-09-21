use super::*;

use rustls::{ClientConfig, ClientConnection, ServerConnection, pki_types::ServerName};

use sirinvpn_core::{LocalIdentity, read_encrypted_server_backup, write_encrypted_server_backup};

use std::io::Cursor;

mod dns_policy_migration_is_reversible_and_preserves_server_identity;
mod management_permissions_keep_owner_admin_and_member_boundaries_separate;
mod runtime_authorization_load_does_not_require_the_root_wireguard_private_key;

mod endpoints;
mod https_transport;
mod member_lifecycle;
mod slow_handshake;
mod status_stream;
