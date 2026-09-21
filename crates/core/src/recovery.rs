//! Self-contained offline recovery keys and password-encrypted recovery packages.
use crate::{
    LocalIdentity, PublicIdentity, SecretIdentity, encrypted_backup,
    identity::extract_ed25519_public_key,
};
use anyhow::{Context, Result, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Verifier};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::*;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
};
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "sirr1.";
const PACKAGE_FORMAT: &str = "sirinvpn-recovery-key";
pub const MAX_RECOVERY_PACKAGE_BYTES: usize = 64 * 1024;

pub struct RecoveryKeyDraft {
    request: RecoveryKeyCreateRequest,
    identity: LocalIdentity,
    expected: ServerProfile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedRecoveryKey {
    schema_version: u16,
    response: RecoveryKeyResponse,
    secret: SecretIdentity,
}

pub struct DecodedRecoveryKey {
    encoded: EncodedRecoveryKey,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryKeyPreview {
    pub server_id: ServerId,
    pub server_name: String,
    pub host: String,
    pub recovery_id: RecoveryId,
    pub server_identity_fingerprint: String,
}

impl RecoveryKeyDraft {
    pub fn new(profile: &ServerProfile, replace_recovery_id: Option<RecoveryId>) -> Result<Self> {
        let identity = LocalIdentity::generate("SirinVPN offline recovery")?;
        Ok(Self {
            request: RecoveryKeyCreateRequest {
                recovery_id: RecoveryId::new(),
                server_id: profile.id,
                endpoint: profile.endpoint.clone(),
                endpoint_generation: profile.endpoint_generation,
                recovery_wireguard_public_key: identity.public.wireguard_public_key.clone(),
                recovery_management_certificate_pem: identity
                    .public
                    .management_certificate_pem
                    .clone(),
                replace_recovery_id,
                confirmed: true,
            },
            identity,
            expected: profile.clone(),
        })
    }
    pub fn request(&self) -> &RecoveryKeyCreateRequest {
        &self.request
    }
    pub fn finish(self, response: RecoveryKeyResponse) -> Result<Zeroizing<String>> {
        let claims = &response.claims;
        validate_recovery_response(&response)?;
        if claims.recovery_id != self.request.recovery_id
            || claims.server_id != self.expected.id
            || self
                .expected
                .member_id
                .is_some_and(|id| id != claims.issuer_member_id)
            || claims.endpoint != self.expected.endpoint
            || claims.endpoint_generation != self.expected.endpoint_generation
            || claims.server_tunnel_address != self.expected.server_tunnel_address
            || claims.server_wireguard_public_key != self.expected.server_wireguard_public_key
            || claims.pinned_server_certificate_pem != self.expected.pinned_server_certificate_pem
            || claims.obfuscated_udp != self.expected.obfuscated_udp
            || claims.tcp_fallback != self.expected.tcp_fallback
            || claims.tls_like != self.expected.tls_like
            || claims.alternate_endpoint_hosts != self.expected.alternate_endpoint_hosts
            || claims.endpoint_discovery_port != self.expected.endpoint_discovery_port
            || claims.recovery_wireguard_public_key != self.identity.public.wireguard_public_key
            || claims.recovery_management_certificate_pem
                != self.identity.public.management_certificate_pem
            || (self.expected.role == ServerRole::Owner
                && self
                    .expected
                    .member_id
                    .is_some_and(|id| id != claims.owner_member_id))
        {
            bail!(
                "the recovery authorization does not match this server and local recovery identity"
            );
        }
        let encoded = EncodedRecoveryKey {
            schema_version: 1,
            response,
            secret: self.identity.secret,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&encoded)?);
        let mut compressor = ZlibEncoder::new(Vec::new(), Compression::best());
        compressor.write_all(&plaintext)?;
        let compressed = Zeroizing::new(compressor.finish()?);
        Ok(Zeroizing::new(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&compressed)
        )))
    }
}

impl DecodedRecoveryKey {
    pub async fn current_bootstrap_profile(&self) -> Result<ServerProfile> {
        let mut profile = self.bootstrap_profile();
        if let Some(response) = crate::discover_endpoint_checkpoint(
            &profile.endpoint_identity(),
            &self.encoded.secret.wireguard_private_key,
            None,
        )
        .await?
        {
            let current =
                crate::verify_endpoint_checkpoint(&profile.endpoint_identity(), &response)?;
            profile.set_endpoint_descriptor(&current.descriptor);
            profile.endpoint_generation = current.generation;
            profile.ipv6_tunnel_enabled = false;
        }
        Ok(profile)
    }
    pub fn decode(code: &str) -> Result<Self> {
        let code = code.trim();
        if code.len() > 32768 {
            bail!("the recovery key is too large");
        }
        let payload = code
            .strip_prefix(PREFIX)
            .context("this is not a supported SirinVPN recovery key")?;
        let compressed = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(payload)
                .context("the recovery key is invalid")?,
        );
        let mut plaintext = Zeroizing::new(Vec::new());
        ZlibDecoder::new(compressed.as_slice())
            .take(32769)
            .read_to_end(&mut plaintext)?;
        if plaintext.len() > 32768 {
            bail!("the recovery key payload is too large");
        }
        let encoded: EncodedRecoveryKey =
            serde_json::from_slice(&plaintext).context("the recovery key is invalid")?;
        if encoded.schema_version != 1 {
            bail!("this recovery key version is unsupported");
        }
        validate_recovery_response(&encoded.response)?;
        let public = encoded
            .secret
            .public_identity(&encoded.response.claims.recovery_management_certificate_pem)?;
        if public.wireguard_public_key != encoded.response.claims.recovery_wireguard_public_key {
            bail!("the recovery key does not match its authorization");
        }
        Ok(Self { encoded })
    }
    pub fn preview(&self) -> Result<RecoveryKeyPreview> {
        let claims = &self.encoded.response.claims;
        Ok(RecoveryKeyPreview {
            server_id: claims.server_id,
            server_name: claims.server_name.clone(),
            host: claims.endpoint.host.clone(),
            recovery_id: claims.recovery_id,
            server_identity_fingerprint: crate::management_certificate_fingerprint(
                &claims.pinned_server_certificate_pem,
            )?,
        })
    }
    pub fn recovery_id(&self) -> RecoveryId {
        self.encoded.response.claims.recovery_id
    }
    pub fn secret(&self) -> &SecretIdentity {
        &self.encoded.secret
    }
    pub fn bootstrap_profile(&self) -> ServerProfile {
        let c = &self.encoded.response.claims;
        ServerProfile {
            schema_version: 1,
            id: c.server_id,
            name: c.server_name.clone(),
            favorite: false,
            endpoint: c.endpoint.clone(),
            endpoint_generation: c.endpoint_generation,
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: c.endpoint_discovery_port,
            alternate_endpoint_hosts: c.alternate_endpoint_hosts.clone(),
            client_tunnel_address: c.recovery_tunnel_address,
            server_tunnel_address: c.server_tunnel_address,
            server_wireguard_public_key: c.server_wireguard_public_key.clone(),
            pinned_server_certificate_pem: c.pinned_server_certificate_pem.clone(),
            client_management_certificate_pem: c.recovery_management_certificate_pem.clone(),
            identity_reference: format!("recovery-{}", c.recovery_id),
            role: ServerRole::Owner,
            administrator: false,
            member_id: Some(c.owner_member_id),
            device_id: None,
            ipv6_tunnel_enabled: false,
            obfuscated_udp: c.obfuscated_udp.clone(),
            tcp_fallback: c.tcp_fallback.clone(),
            tls_like: c.tls_like.clone(),
        }
    }
    pub fn request(&self, public: &PublicIdentity, device_name: String) -> RecoveryRedeemRequest {
        RecoveryRedeemRequest {
            recovery_id: self.recovery_id(),
            device_name,
            device_wireguard_public_key: public.wireguard_public_key.clone(),
            device_management_certificate_pem: public.management_certificate_pem.clone(),
            confirmed: true,
        }
    }
    pub fn permanent_profile(
        &self,
        result: &EnrollmentResult,
        public: &PublicIdentity,
        reference: String,
    ) -> Result<ServerProfile> {
        let c = &self.encoded.response.claims;
        if result.server_id != c.server_id
            || result.member_id != c.owner_member_id
            || result.role != ServerRole::Owner
            || result.administrator
            || result.server_wireguard_public_key != c.server_wireguard_public_key
            || result.pinned_server_certificate_pem != c.pinned_server_certificate_pem
            || result.server_tunnel_address != c.server_tunnel_address
            || result.endpoint_generation < c.endpoint_generation
            || !matches!(result.client_tunnel_address, IpAddr::V4(address) if address.octets()[..3] == [10,77,0] && (2..=223).contains(&address.octets()[3]))
        {
            bail!("the recovered Owner identity does not match this server");
        }
        validate_host(&result.endpoint.host)?;
        if result.endpoint.wireguard_port == 0
            || result.device_id.0.is_nil()
            || !crate::invitation::valid_transport_endpoints(
                result.endpoint.wireguard_port,
                result.obfuscated_udp.as_ref(),
                result.tcp_fallback.as_ref(),
                result.tls_like.as_ref(),
            )
        {
            bail!("the recovered endpoint is invalid");
        }
        let mut profile = self.bootstrap_profile();
        profile.endpoint = result.endpoint.clone();
        profile.endpoint_generation = result.endpoint_generation;
        profile.endpoint_discovery_port = result.endpoint_discovery_port;
        profile.alternate_endpoint_hosts = result.alternate_endpoint_hosts.clone();
        profile.client_tunnel_address = result.client_tunnel_address;
        profile.client_management_certificate_pem = public.management_certificate_pem.clone();
        profile.identity_reference = reference;
        profile.device_id = Some(result.device_id);
        profile.ipv6_tunnel_enabled = result.ipv6_tunnel_enabled;
        profile.obfuscated_udp = result.obfuscated_udp.clone();
        profile.tcp_fallback = result.tcp_fallback.clone();
        profile.tls_like = result.tls_like.clone();
        Ok(profile)
    }
}

pub fn validate_recovery_response(response: &RecoveryKeyResponse) -> Result<()> {
    let c = &response.claims;
    if c.schema_version != c.required_schema_version()
        || !valid_alternate_endpoint_hosts(&c.endpoint.host, &c.alternate_endpoint_hosts)
        || c.endpoint_discovery_port
            .is_some_and(|port| port == 0 || c.tls_like.is_none())
        || c.recovery_id.0.is_nil()
        || c.owner_member_id.0.is_nil()
        || c.server_id.0.is_nil()
        || c.issuer_member_id.0.is_nil()
        || c.management_port != DEFAULT_MANAGEMENT_PORT
        || c.endpoint.wireguard_port == 0
        || c.server_tunnel_address != IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1))
        || c.recovery_tunnel_address != IpAddr::V4(Ipv4Addr::new(10, 77, 0, 254))
        || !crate::invitation::valid_transport_endpoints(
            c.endpoint.wireguard_port,
            c.obfuscated_udp.as_ref(),
            c.tcp_fallback.as_ref(),
            c.tls_like.as_ref(),
        )
    {
        bail!("the recovery authorization is invalid");
    }
    validate_server_name(&c.server_name)?;
    validate_host(&c.endpoint.host)?;
    for key in [
        &c.server_wireguard_public_key,
        &c.recovery_wireguard_public_key,
    ] {
        if STANDARD.decode(key).map_or(true, |bytes| {
            bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0)
        }) {
            bail!("a recovery public key is invalid");
        }
    }
    extract_ed25519_public_key(&c.recovery_management_certificate_pem)?;
    let key = extract_ed25519_public_key(&c.pinned_server_certificate_pem)?;
    let signature = Signature::from_slice(&STANDARD.decode(&response.signature)?)?;
    key.verify(&serde_json::to_vec(c)?, &signature)
        .context("the recovery authorization signature is invalid")?;
    Ok(())
}

pub fn encrypt_recovery_package(code: &str, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    DecodedRecoveryKey::decode(code)?;
    encrypted_backup::validate_export_password(password)?;
    Ok(Zeroizing::new(encrypted_backup::encrypt(
        PACKAGE_FORMAT,
        code.trim().as_bytes(),
        password,
    )?))
}

pub fn decrypt_recovery_package(bytes: &[u8], password: &str) -> Result<Zeroizing<String>> {
    if bytes.len() > MAX_RECOVERY_PACKAGE_BYTES {
        bail!("the recovery package is too large");
    }
    encrypted_backup::validate_import_password(password)?;
    let plaintext = encrypted_backup::decrypt(PACKAGE_FORMAT, bytes, password)?;
    let code = Zeroizing::new(String::from_utf8(plaintext.to_vec())?);
    DecodedRecoveryKey::decode(&code)?;
    Ok(code)
}

pub fn write_recovery_package(
    destination: &std::path::Path,
    code: &str,
    password: &str,
) -> Result<()> {
    let bytes = encrypt_recovery_package(code, password)?;
    encrypted_backup::write_file(destination, &bytes, ".recovery-")?;
    Ok(())
}

pub fn read_recovery_package(
    source: &std::path::Path,
    password: &str,
) -> Result<Zeroizing<String>> {
    let bytes = encrypted_backup::read_file(source, MAX_RECOVERY_PACKAGE_BYTES)?;
    decrypt_recovery_package(&bytes, password)
}

impl std::fmt::Debug for DecodedRecoveryKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedRecoveryKey")
            .field("recovery_id", &self.recovery_id())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for EncodedRecoveryKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(test)]
mod tests;
