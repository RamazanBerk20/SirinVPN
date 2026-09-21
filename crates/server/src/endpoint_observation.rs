//! Observe only the VPS's own current interface addresses. No client addresses,
//! external IP service, network history, or remote probe is involved.
use super::*;

/// Conservative automatic selection; unusual allocations remain configurable.
pub(crate) fn automatic_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            a != 0
                && a != 10
                && a != 127
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            segments[0] & 0xe000 == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn assigned_addresses(bytes: &[u8]) -> Result<Vec<IpAddr>> {
    anyhow::ensure!(
        bytes.len() <= 128 * 1024,
        "interface address response is too large"
    );
    let interfaces: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut result = Vec::new();
    for interface in interfaces
        .as_array()
        .context("interface response is invalid")?
    {
        for address in interface
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if address.get("scope").and_then(serde_json::Value::as_str) != Some("global")
                || ["temporary", "tentative", "deprecated", "dadfailed"]
                    .iter()
                    .any(|flag| {
                        address.get(flag).and_then(serde_json::Value::as_bool) == Some(true)
                    })
                || address
                    .get("preferred_life_time")
                    .and_then(serde_json::Value::as_u64)
                    == Some(0)
            {
                continue;
            }
            if let Some(ip) = address
                .get("local")
                .and_then(serde_json::Value::as_str)
                .and_then(|text| text.parse::<IpAddr>().ok())
                && automatic_address(ip)
                && !result.contains(&ip)
            {
                result.push(ip);
            }
        }
    }
    Ok(result)
}

pub(super) async fn observe(state: &AppState) -> Result<()> {
    let Some(configuration) = &state.operational_configuration else {
        return Ok(());
    };
    let output = tokio::time::timeout(
        Duration::from_secs(2),
        Command::new("ip")
            .args([
                "-j",
                "address",
                "show",
                "dev",
                &configuration.external_interface,
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    anyhow::ensure!(
        output.status.success(),
        "interface addresses are unavailable"
    );
    let addresses = assigned_addresses(&output.stdout)?;
    let Some(authorization) = &state.authorization else {
        return Ok(());
    };
    let mut current = authorization.write().await;
    if let Some(next) = observed_update(&state.paths, &state.configuration, &current, &addresses)? {
        commit_authorization(state, &mut current, next)
            .await
            .map_err(|error| anyhow!(error.message))?;
    }
    Ok(())
}

fn observed_update(
    paths: &ServerPaths,
    configuration: &ServerConfiguration,
    current: &AuthorizationDocument,
    addresses: &[IpAddr],
) -> Result<Option<AuthorizationDocument>> {
    if current.endpoint_transition_source {
        return Ok(None);
    }
    let Some(head) = &current.endpoint_transition else {
        return Ok(None);
    };
    let Ok(endpoint) = head.claims.endpoint.host.parse::<IpAddr>() else {
        return Ok(None);
    };
    if !automatic_address(endpoint) {
        return Ok(None);
    }
    let mut next = current.clone();
    if addresses.contains(&endpoint) {
        if current.endpoint_observed_address == Some(endpoint) {
            return Ok(None);
        }
        next.endpoint_observed_address = Some(endpoint);
        next.schema_version = next.required_schema_version();
        next.validate()?;
        return Ok(Some(next));
    }
    // Never infer a NAT gateway's public mapping from the VPS's private address,
    // nor replace a manually configured endpoint that was never assigned here.
    if current.endpoint_observed_address != Some(endpoint) {
        return Ok(None);
    }
    let candidates = addresses
        .iter()
        .copied()
        .filter(|candidate| {
            automatic_address(*candidate)
                && candidate.is_ipv4() == endpoint.is_ipv4()
                && !head
                    .claims
                    .alternate_endpoint_hosts
                    .iter()
                    .any(|host| host.parse::<IpAddr>().ok() == Some(*candidate))
        })
        .collect::<Vec<_>>();
    let [replacement] = candidates.as_slice() else {
        return Ok(None);
    };
    next.prune_expired(unix_time());
    if !next.enrollment_receipts.is_empty()
        || !next.key_rotations.is_empty()
        || next.recovery_receipt.is_some()
    {
        return Ok(None);
    }
    let previous = head.claims.endpoint_descriptor();
    let mut descriptor = previous.clone();
    descriptor.endpoint.host = replacement.to_string();
    let generation = next
        .endpoint_generation()
        .checked_add(1)
        .context("endpoint generation exhausted")?;
    let claims = endpoint_transition::checkpoint_claims(
        paths,
        configuration,
        &next,
        previous,
        descriptor,
        generation,
    )?;
    let signature = sign_endpoint_transition(&paths.tls_private_key, &claims)?;
    next.accept_endpoint_transition(EndpointTransitionResponse { claims, signature })?;
    next.endpoint_observed_address = Some(*replacement);
    next.validate()?;
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_ambiguous_and_temporary_addresses_cannot_be_published() {
        let addresses = assigned_addresses(br#"[{"addr_info":[{"local":"10.2.3.4","scope":"global"},{"local":"100.64.2.3","scope":"global"},{"local":"203.0.113.3","scope":"global"},{"local":"2606:4700::1111","scope":"global","temporary":true},{"local":"8.8.4.4","scope":"global"},{"local":"2606:4700::1001","scope":"global"}]}]"#).unwrap();
        assert_eq!(
            addresses,
            vec![
                "8.8.4.4".parse::<IpAddr>().unwrap(),
                "2606:4700::1001".parse().unwrap()
            ]
        );
    }

    #[test]
    fn only_a_previously_assigned_endpoint_can_follow_an_unambiguous_interface_change() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ServerPaths::under(directory.path());
        let owner = sirinvpn_core::LocalIdentity::generate("Observation owner").unwrap();
        initialize_with_transport_capabilities(
            &paths,
            "Observation",
            &owner.public.management_certificate_pem,
            ServerId::new(),
            &owner.public.wireguard_public_key,
            51820,
            ServerCapabilities {
                public_host: Some("8.8.8.8".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let configuration = load_configuration(&paths).unwrap();
        let original = load_authorization(&paths.authorization).unwrap();
        let old = "8.8.8.8".parse().unwrap();
        let new = "9.9.9.9".parse().unwrap();
        assert!(
            observed_update(&paths, &configuration, &original, &[new])
                .unwrap()
                .is_none()
        );
        let observed = observed_update(&paths, &configuration, &original, &[old])
            .unwrap()
            .unwrap();
        assert_eq!(
            observed.endpoint_generation(),
            original.endpoint_generation()
        );
        assert!(
            observed_update(
                &paths,
                &configuration,
                &observed,
                &[new, "1.1.1.1".parse().unwrap()]
            )
            .unwrap()
            .is_none()
        );
        let updated = observed_update(&paths, &configuration, &observed, &[new])
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.endpoint_generation(),
            original.endpoint_generation() + 1
        );
        assert_eq!(updated.endpoint_observed_address, Some(new));
        let head = updated.endpoint_transition.unwrap();
        assert_eq!(head.claims.previous_endpoint.host, old.to_string());
        assert_eq!(head.claims.endpoint.host, new.to_string());
        sirinvpn_core::DecodedEndpointTransition::from_response(head).unwrap();
        assert_eq!(
            original.endpoint_authorization_fingerprint().unwrap(),
            observed.endpoint_authorization_fingerprint().unwrap()
        );
    }
}
