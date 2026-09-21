//! Validation.

use super::*;

pub(crate) fn load_authorization(path: &Path) -> Result<AuthorizationDocument> {
    let bytes = fs::read(path).context("authorization state is unavailable")?;
    let document: AuthorizationDocument =
        serde_json::from_slice(&bytes).context("authorization state is invalid")?;
    document.validate()?;
    Ok(document)
}

pub(crate) fn write_authorization(path: &Path, document: &AuthorizationDocument) -> Result<()> {
    document.validate()?;
    let bytes = serde_json::to_vec_pretty(document)?;
    let temporary = path.with_extension("new");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("could not stage {}", path.display()))?;
    io::Write::write_all(&mut file, &bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn certificate_fingerprint(certificate_pem: &str) -> Result<String> {
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
            .collect::<std::result::Result<_, _>>()?;
    if certificates.len() != 1 {
        bail!("exactly one client certificate is required");
    }
    let mut roots = RootCertStore::empty();
    roots.add(certificates[0].clone())?;
    Ok(hex::encode(Sha256::digest(certificates[0].as_ref())))
}

pub(crate) fn validate_wireguard_public_key(public_key: &str) -> Result<()> {
    let decoded = STANDARD
        .decode(public_key)
        .context("WireGuard public key is not valid base64")?;
    if decoded.len() != 32 {
        bail!("WireGuard public key must contain 32 bytes");
    }
    Ok(())
}

pub(crate) fn validate_display_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 64 || trimmed.chars().any(char::is_control) {
        bail!("name must contain 1 to 64 visible characters");
    }
    Ok(trimmed.to_owned())
}

pub(crate) fn sign_claims(private_key_path: &Path, claims: &InvitationClaims) -> Result<String> {
    sign_serialized(private_key_path, claims)
}

pub(crate) fn sign_endpoint_transition(
    private_key_path: &Path,
    claims: &EndpointTransitionClaims,
) -> Result<String> {
    sign_serialized(private_key_path, claims)
}

pub(crate) fn verify_endpoint_transition_signature(
    private_key_path: &Path,
    response: &EndpointTransitionResponse,
) -> Result<()> {
    let private_key_pem = fs::read_to_string(private_key_path)
        .context("server management signing key is unavailable")?;
    verify_endpoint_transition_signature_with_key(&private_key_pem, response)
}

pub(crate) fn verify_endpoint_transition_signature_with_key(
    private_key_pem: &str,
    response: &EndpointTransitionResponse,
) -> Result<()> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .context("server management signing key is invalid")?;
    let signature = STANDARD
        .decode(&response.signature)
        .context("endpoint transition signature is invalid")?;
    let signature =
        Signature::from_slice(&signature).context("endpoint transition signature is invalid")?;
    let canonical = serde_json::to_vec(&response.claims)?;
    signing_key
        .verifying_key()
        .verify(&canonical, &signature)
        .context("endpoint transition signature is invalid")
}

pub(super) fn sign_serialized(private_key_path: &Path, value: &impl Serialize) -> Result<String> {
    let private_key_pem = fs::read_to_string(private_key_path)
        .context("server management signing key is unavailable")?;
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .context("server management signing key is invalid")?;
    let canonical = serde_json::to_vec(value)?;
    Ok(STANDARD.encode(signing_key.sign(&canonical).to_bytes()))
}

pub(super) fn validate_endpoint_transition(
    server_id: ServerId,
    claims: &EndpointTransitionClaims,
) -> Result<()> {
    if !matches!(claims.schema_version, 1 | 2)
        || claims.server_id != server_id
        || claims.generation == 0
        || (claims.schema_version == 1
            && (claims.previous_endpoint == claims.endpoint
                || claims.previous_transports.is_some()
                || !claims.alternate_endpoint_hosts.is_empty()
                || claims.endpoint_discovery_port.is_some()))
        || (claims.schema_version == 2 && claims.previous_transports.is_none())
        || claims.previous_endpoint.wireguard_port == 0
        || claims.endpoint.wireguard_port == 0
        || claims.server_tunnel_address != SERVER_TUNNEL_ADDRESS.parse::<IpAddr>()?
        || claims.management_port != DEFAULT_MANAGEMENT_PORT
    {
        bail!("endpoint transition is inconsistent with this server");
    }
    validate_display_name(&claims.server_name)?;
    validate_host(&claims.previous_endpoint.host)?;
    validate_host(&claims.endpoint.host)?;
    validate_endpoint_descriptor(&claims.endpoint_descriptor())?;
    if let Some(previous) = &claims.previous_transports {
        validate_endpoint_descriptor(previous)?;
        anyhow::ensure!(
            previous.endpoint == claims.previous_endpoint,
            "previous transport endpoint does not match"
        );
    }
    validate_wireguard_public_key(&claims.server_wireguard_public_key)?;
    certificate_fingerprint(&claims.pinned_server_certificate_pem)?;
    let authorization_fingerprint = hex::decode(&claims.authorization_fingerprint)
        .context("endpoint authorization fingerprint is invalid")?;
    if authorization_fingerprint.len() != 32
        || hex::encode(authorization_fingerprint) != claims.authorization_fingerprint
    {
        bail!("endpoint authorization fingerprint is invalid");
    }
    if claims.obfuscated_udp.as_ref().is_some_and(|endpoint| {
        endpoint.port == 0
            || endpoint.port == claims.endpoint.wireguard_port
            || validate_wireguard_public_key(&endpoint.server_public_key).is_err()
    }) || claims.tcp_fallback.as_ref().is_some_and(|endpoint| {
        endpoint.port == 0
            || endpoint.port == claims.endpoint.wireguard_port
            || validate_wireguard_public_key(&endpoint.server_public_key).is_err()
    }) || claims
        .obfuscated_udp
        .as_ref()
        .zip(claims.tcp_fallback.as_ref())
        .is_some_and(|(udp, tcp)| udp.server_public_key != tcp.server_public_key)
    {
        bail!("endpoint transition contains invalid transport capabilities");
    }
    Ok(())
}

pub(crate) fn validate_endpoint_descriptor(
    descriptor: &sirinvpn_protocol::EndpointDescriptor,
) -> Result<()> {
    use sirinvpn_transport::TransportEngine;
    anyhow::ensure!(
        sirinvpn_protocol::valid_alternate_endpoint_hosts(
            &descriptor.endpoint.host,
            &descriptor.alternate_endpoint_hosts
        ),
        "alternate endpoint hosts are invalid"
    );
    // Reuse the protocol's full transport validation without any network access.
    TransportEngine
        .validate_descriptor(descriptor)
        .context("invalid public transport descriptor")
}

pub(super) fn validate_device_address(address: IpAddr) -> Result<()> {
    match address {
        IpAddr::V4(address)
            if address.octets()[..3] == [10, 77, 0]
                && (FIRST_MEMBER_ADDRESS..=LAST_MEMBER_ADDRESS).contains(&address.octets()[3]) =>
        {
            Ok(())
        }
        IpAddr::V4(address) if address == Ipv4Addr::new(10, 77, 0, 2) => Ok(()),
        _ => bail!("device tunnel address is outside the authorized pool"),
    }
}

pub(super) fn validate_bootstrap_address(address: IpAddr) -> Result<()> {
    match address {
        IpAddr::V4(address)
            if address.octets()[..3] == [10, 77, 0]
                && (FIRST_BOOTSTRAP_ADDRESS..=LAST_BOOTSTRAP_ADDRESS)
                    .contains(&address.octets()[3]) =>
        {
            Ok(())
        }
        _ => bail!("bootstrap tunnel address is outside the invitation pool"),
    }
}

pub(super) fn validate_claims(server_id: ServerId, claims: &InvitationClaims) -> Result<()> {
    let target_is_valid = match (claims.target_member_id, claims.target_role) {
        (None, None) => true,
        (Some(target_member_id), Some(target_role)) => {
            target_member_id != claims.member_id
                && !(target_role == ServerRole::Owner && claims.administrator)
        }
        _ => false,
    };
    if claims.schema_version != claims.required_schema_version()
        || !sirinvpn_protocol::valid_alternate_endpoint_hosts(
            &claims.endpoint.host,
            &claims.alternate_endpoint_hosts,
        )
        || claims
            .endpoint_discovery_port
            .is_some_and(|port| port == 0 || claims.tls_like.is_none())
        || claims.server_id != server_id
        || claims.role != ServerRole::Member
        || !target_is_valid
        || claims.management_port == 0
        || claims.endpoint.wireguard_port == 0
    {
        bail!("invitation claims are inconsistent with this server");
    }
    if !(1..=100).contains(&claims.max_uses)
        || (claims.target_role == Some(ServerRole::Owner)
            && (claims.max_uses > 1 || !claims.member_policy.is_default()))
    {
        bail!("invitation use limit or owner policy is invalid");
    }
    claims
        .member_policy
        .validate()
        .map_err(anyhow::Error::msg)?;
    validate_display_name(&claims.member_name)?;
    validate_display_name(&claims.device_name)?;
    validate_device_address(claims.client_tunnel_address)?;
    if claims.client_tunnel_address == IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)) {
        bail!("an invitation cannot reserve the owner tunnel address");
    }
    validate_bootstrap_address(claims.bootstrap_tunnel_address)?;
    validate_wireguard_public_key(&claims.bootstrap_wireguard_public_key)?;
    certificate_fingerprint(&claims.bootstrap_management_certificate_pem)?;
    certificate_fingerprint(&claims.pinned_server_certificate_pem)?;
    let token_hash = hex::decode(&claims.token_hash).context("invitation token hash is invalid")?;
    if token_hash.len() != 32 || claims.token_hash.len() != 64 {
        bail!("invitation token hash is invalid");
    }
    Ok(())
}
