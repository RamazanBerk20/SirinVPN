//! Command types.

use super::*;

#[derive(Deserialize)]
pub(super) struct UninstallInput {
    pub(super) server_id: String,
    pub(super) username: String,
    pub(super) ssh_port: u16,
    pub(super) authentication: String,
    pub(super) password: Option<String>,
    pub(super) private_key_path: Option<String>,
    pub(super) private_key_passphrase: Option<String>,
    pub(super) sudo_password: Option<String>,
    pub(super) host_key_sha256: String,
}

#[derive(Deserialize)]
pub(super) struct RepairInput {
    pub(super) server_id: String,
    pub(super) username: String,
    pub(super) ssh_port: u16,
    pub(super) authentication: String,
    pub(super) password: Option<String>,
    pub(super) private_key_path: Option<String>,
    pub(super) private_key_passphrase: Option<String>,
    pub(super) sudo_password: Option<String>,
    pub(super) host_key_sha256: String,
    pub(super) confirmed: bool,
    #[serde(default)]
    pub(super) dns_upstream: Option<DnsUpstream>,
    #[serde(default)]
    pub(super) private_dns_records: Option<Vec<PrivateDnsRecord>>,
    #[serde(default)]
    pub(super) transport: Option<sirinvpn_installer::TransportSetup>,
}

impl Drop for ProvisionInput {
    fn drop(&mut self) {
        if let Some(value) = &mut self.password {
            value.zeroize();
        }
        if let Some(value) = &mut self.private_key_passphrase {
            value.zeroize();
        }
        if let Some(value) = &mut self.sudo_password {
            value.zeroize();
        }
    }
}

impl Drop for UninstallInput {
    fn drop(&mut self) {
        if let Some(value) = &mut self.password {
            value.zeroize();
        }
        if let Some(value) = &mut self.private_key_passphrase {
            value.zeroize();
        }
        if let Some(value) = &mut self.sudo_password {
            value.zeroize();
        }
    }
}

impl Drop for RepairInput {
    fn drop(&mut self) {
        if let Some(value) = &mut self.password {
            value.zeroize();
        }
        if let Some(value) = &mut self.private_key_passphrase {
            value.zeroize();
        }
        if let Some(value) = &mut self.sudo_password {
            value.zeroize();
        }
    }
}

#[derive(Serialize)]
pub(super) struct ProvisionResult {
    pub(super) network_preflight: sirinvpn_installer::NetworkPreflight,
    pub(super) profile: ServerProfile,
    pub(super) events: Vec<sirinvpn_installer::InstallEvent>,
    pub(super) dns_upstream: DnsUpstream,
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Serialize)]
pub(super) struct RepairResult {
    pub(super) network_preflight: sirinvpn_installer::NetworkPreflight,
    pub(super) events: Vec<sirinvpn_installer::InstallEvent>,
    pub(super) artifact_sha256: String,
    pub(super) server_identity_fingerprint: String,
    pub(super) dns_upstream: DnsUpstream,
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Deserialize)]
pub(super) struct JoinInput {
    #[serde(default)]
    pub(super) member_name: Option<String>,
    #[serde(default)]
    pub(super) device_name: Option<String>,
    pub(super) code: String,
}

impl Drop for JoinInput {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

#[derive(Deserialize)]
pub(super) struct KeyRotationInput {
    pub(super) server_id: String,
    pub(super) confirmed: bool,
}

#[derive(Deserialize)]
pub(super) struct EndpointUpdateInput {
    pub(super) server_id: String,
    pub(super) code: String,
}

#[derive(Serialize)]
pub(super) struct EndpointUpdateCodeResult {
    pub(super) server_id: ServerId,
    pub(super) generation: u64,
    pub(super) previous_endpoint: ServerEndpoint,
    pub(super) endpoint: ServerEndpoint,
    pub(super) code: String,
}

#[derive(Deserialize)]
pub(super) struct BackupExportInput {
    pub(super) server_id: String,
    pub(super) path: String,
    pub(super) password: String,
    pub(super) confirmed: bool,
}

impl Drop for BackupExportInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Deserialize)]
pub(super) struct BackupImportInput {
    pub(super) path: String,
    pub(super) password: String,
}

#[derive(Deserialize)]
pub(super) struct VpsBackupInput {
    pub(super) server_id: String,
    pub(super) path: String,
    pub(super) backup_password: String,
    pub(super) username: String,
    pub(super) ssh_port: u16,
    pub(super) authentication: String,
    pub(super) password: Option<String>,
    pub(super) private_key_path: Option<String>,
    pub(super) private_key_passphrase: Option<String>,
    pub(super) sudo_password: Option<String>,
    pub(super) host_key_sha256: String,
    pub(super) confirmed: bool,
}

impl Drop for VpsBackupInput {
    fn drop(&mut self) {
        self.backup_password.zeroize();
        if let Some(value) = &mut self.password {
            value.zeroize();
        }
        if let Some(value) = &mut self.private_key_passphrase {
            value.zeroize();
        }
        if let Some(value) = &mut self.sudo_password {
            value.zeroize();
        }
    }
}

#[derive(Deserialize)]
pub(super) struct VpsRestoreInput {
    pub(super) server_id: String,
    pub(super) path: String,
    pub(super) backup_password: String,
    pub(super) host: String,
    pub(super) username: String,
    pub(super) ssh_port: u16,
    pub(super) authentication: String,
    pub(super) password: Option<String>,
    pub(super) private_key_path: Option<String>,
    pub(super) private_key_passphrase: Option<String>,
    pub(super) sudo_password: Option<String>,
    pub(super) host_key_sha256: String,
    pub(super) replace_existing: bool,
    pub(super) confirmed: bool,
}

impl Drop for VpsRestoreInput {
    fn drop(&mut self) {
        self.backup_password.zeroize();
        if let Some(value) = &mut self.password {
            value.zeroize();
        }
        if let Some(value) = &mut self.private_key_passphrase {
            value.zeroize();
        }
        if let Some(value) = &mut self.sudo_password {
            value.zeroize();
        }
    }
}

impl Drop for BackupImportInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Deserialize)]
pub(super) struct HostKeyInput {
    pub(super) host: String,
    pub(super) port: u16,
}

#[derive(Deserialize)]
pub(super) struct ProvisionInput {
    pub(super) name: String,
    pub(super) host: String,
    pub(super) username: String,
    pub(super) ssh_port: u16,
    pub(super) authentication: String,
    pub(super) password: Option<String>,
    pub(super) private_key_path: Option<String>,
    pub(super) private_key_passphrase: Option<String>,
    pub(super) sudo_password: Option<String>,
    pub(super) host_key_sha256: String,
    pub(super) replace_existing_installation: bool,
    #[serde(default)]
    pub(super) dns_upstream: DnsUpstream,
    #[serde(default)]
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
    #[serde(default)]
    pub(super) transport: sirinvpn_installer::TransportSetup,
}
