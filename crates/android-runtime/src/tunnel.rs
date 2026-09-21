use crate::jni_bridge::Runtime;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use sirinvpn_core::SecretIdentity;
use sirinvpn_protocol::{ServerProfile, TransportKind};
use sirinvpn_transport::*;
use sirinvpn_tunnel_model::ConnectionPreferences;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

// Only these static, reviewed messages may leave JNI; raw transport errors can contain endpoints.
#[derive(Debug)]
pub struct ConnectionFailure(pub &'static str);
impl std::fmt::Display for ConnectionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ConnectionFailure {}

pub fn stop_relay(runtime: &Runtime) {
    if let Ok(relay) = runtime.relay.lock()
        && let Some(task) = relay.as_ref()
    {
        task.abort();
    }
}

pub struct Carrier {
    pub endpoint: SocketAddr,
    pub task: Option<tokio::task::JoinHandle<Result<(), RelayError>>>,
}
impl Drop for Carrier {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Carrier {
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

pub async fn connect(
    runtime: &Runtime,
    profile: &ServerProfile,
    secret: &SecretIdentity,
    prefs: &ConnectionPreferences,
    generation: i64,
) -> Result<()> {
    if let Some(value) = prefs.manual_mtu {
        sirinvpn_protocol::MtuPolicy::Manual { value }
            .validate(profile.ipv6_tunnel_enabled)
            .map_err(anyhow::Error::msg)?;
    }
    ensure!(
        prefs.routing.mode != sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications
            || prefs
                .android_applications
                .as_ref()
                .is_some_and(|apps| !apps.packages.is_empty()),
        "Choose Android applications before connecting"
    );
    let selections = if prefs.transport == sirinvpn_protocol::TransportPreference::Automatic {
        TransportEngine.automatic_plan(profile, prefs.network_profile, None)?
    } else {
        TransportEngine.plan(profile, prefs.transport)?
    };
    // Negotiate one safe TUN MTU for all automatic candidates, allowing a later
    // endpoint handoff without replacing the TUN or breaking existing TCP flows.
    let mtu = prefs
        .manual_mtu
        .unwrap_or_else(|| selections.iter().map(|item| item.mtu).min().unwrap_or(1280));
    let mut failure = anyhow::Error::new(ConnectionFailure(
        "No configured transport reached the server.",
    ));
    for selection in selections {
        runtime.platform.current(generation)?;
        let previous = runtime
            .relay
            .lock()
            .map_err(|_| anyhow::anyhow!("Transport unavailable"))?
            .take();
        if let Some(task) = previous {
            task.abort();
            let _ = task.await;
        }
        match activate(runtime, profile, secret, prefs, selection, mtu, generation).await {
            Ok(()) => return Ok(()),
            Err(error) => failure = error,
        }
        stop_relay(runtime);
        runtime.platform.current(generation)?;
        runtime.platform.deactivate(generation)?;
    }
    Err(failure)
}

pub async fn carrier(
    runtime: &Runtime,
    selection: &TransportSelection,
    private_key: &str,
    local: Option<SocketAddr>,
    timeout: u64,
) -> Result<Carrier> {
    let address: IpAddr = runtime
        .platform
        .resolve(&selection.network_endpoint.host)
        .context(ConnectionFailure(
            "The server endpoint could not be resolved on the underlying network.",
        ))?
        .parse()?;
    let remote = SocketAddr::new(address, selection.network_endpoint.wireguard_port);
    if selection.kind == TransportKind::DirectUdp {
        return Ok(Carrier {
            endpoint: remote,
            task: None,
        });
    }
    let platform = runtime.platform.clone();
    let protect = move |socket: &_| {
        platform
            .protect(std::os::fd::AsRawFd::as_raw_fd(socket))
            .map_err(|_| RelayError::NetworkBindingFailed)
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let ready = move || {
        let _ = tx.send(());
    };
    let server_key = selection
        .server_transport_public_key
        .as_deref()
        .context("Missing transport identity")?;
    let task = match selection.kind {
        TransportKind::ObfuscatedUdp => {
            let mut config = client_relay_config_unmarked(remote, private_key, server_key)?;
            if let Some(local) = local {
                config.local_listen = local;
            }
            runtime
                .executor
                .spawn(run_client_relay_with_socket_protector(
                    config, protect, ready,
                ))
        }
        TransportKind::TcpFallback => {
            let mut config = tcp_client_relay_config_unmarked(remote, private_key, server_key)?;
            if let Some(local) = local {
                config.local_listen = local;
            }
            runtime
                .executor
                .spawn(run_tcp_client_relay_with_socket_protector(
                    config, protect, ready,
                ))
        }
        TransportKind::TlsLike => {
            let mut config = tls_like_client_relay_config_unmarked(
                remote,
                private_key,
                server_key,
                selection
                    .server_certificate_sha256
                    .as_deref()
                    .context("Missing TLS pin")?,
            )?;
            if let Some(local) = local {
                config.local_listen = local;
            }
            config.https = selection.https.clone();
            runtime
                .executor
                .spawn(run_tls_like_client_relay_with_socket_protector(
                    config, protect, ready,
                ))
        }
        _ => bail!("Unsupported transport"),
    };
    match tokio::time::timeout(Duration::from_secs(timeout), rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let message = match task.await {
                Ok(Err(RelayError::NetworkBindingFailed)) => {
                    "Android could not protect or bind the transport socket."
                }
                Ok(Err(RelayError::HandshakeFailed | RelayError::Noise(_))) => {
                    "The server did not authenticate the transport relay."
                }
                Ok(Err(RelayError::Io(ref e))) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    "The local transport relay port is already in use."
                }
                Ok(Err(RelayError::Io(ref e)))
                    if e.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    "Android denied access to the transport socket."
                }
                Ok(Err(RelayError::Io(_))) => "The transport socket could not reach the server.",
                _ => "The transport relay could not start.",
            };
            return Err(ConnectionFailure(message).into());
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            return Err(ConnectionFailure("The transport relay did not start in time.").into());
        }
    }
    Ok(Carrier {
        task: Some(task),
        endpoint: local.unwrap_or(SocketAddr::new(
            selection.wireguard_endpoint.host.parse()?,
            selection.wireguard_endpoint.wireguard_port,
        )),
    })
}

async fn activate(
    runtime: &Runtime,
    profile: &ServerProfile,
    secret: &SecretIdentity,
    prefs: &ConnectionPreferences,
    selection: TransportSelection,
    mtu: u16,
    generation: i64,
) -> Result<()> {
    let mut carrier = carrier(runtime, &selection, &secret.wireguard_private_key, None, 12).await?;
    let endpoint = carrier.endpoint;
    *runtime
        .relay
        .lock()
        .map_err(|_| anyhow::anyhow!("Transport unavailable"))? = carrier.task.take();
    let private =
        zeroize::Zeroizing::new(hex::encode(STANDARD.decode(&secret.wireguard_private_key)?));
    let public = hex::encode(STANDARD.decode(&profile.server_wireguard_public_key)?);
    let wireguard = zeroize::Zeroizing::new(format!(
        "private_key={}\nreplace_peers=true\npublic_key={}\nendpoint={}\nallowed_ip=0.0.0.0/0\n{}persistent_keepalive_interval=25\n",
        *private,
        public,
        endpoint,
        if profile.ipv6_tunnel_enabled {
            "allowed_ip=::/0\n"
        } else {
            ""
        }
    ));
    let mut addresses = vec![format!("{}/32", profile.client_tunnel_address)];
    if profile.ipv6_tunnel_enabled {
        addresses.push(format!(
            "{}/128",
            crate::routes::ipv6(profile.id, profile.client_tunnel_address)?
        ));
    }
    let routes: Vec<String> = crate::routes::routes(profile, prefs)?
        .iter()
        .map(ToString::to_string)
        .collect();
    runtime.platform.activate(&json!({
        "server_id": profile.id, "addresses": addresses, "routes": routes, "dns": profile.server_tunnel_address,
        "wireguard": *wireguard, "mtu": mtu, "applications": prefs.android_applications,"endpoint":endpoint.to_string(),"peer":public,
        "transport": selection.kind, "routing_mode": prefs.routing.mode, "allow_lan": prefs.routing.allow_lan,
        "ipv6_blocked": !profile.ipv6_tunnel_enabled && prefs.routing.mode != sirinvpn_tunnel_model::TunnelRoutingMode::SelectedRoutes, "ipv6_tunneled": profile.ipv6_tunnel_enabled,
        "automatic_reconnect": prefs.policy.automatic_reconnect,
        "mtu_automatic":prefs.manual_mtu.is_none(),
        "automatic_transport": prefs.transport == sirinvpn_protocol::TransportPreference::Automatic
    }), generation).context(ConnectionFailure("Android could not establish the VPN interface and protected sockets."))?;
    // A management API outage must not tear down a working data tunnel.
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            runtime.platform.current(generation)?;
            if runtime.platform.has_handshake()? {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context(ConnectionFailure(
        "The server did not complete a WireGuard handshake on this transport.",
    ))??;
    runtime.platform.current(generation)
}
