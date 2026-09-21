use crate::network::{self, Underlay};
use sirinvpn_protocol::TransportKind;
use sirinvpn_transport::{
    ClientRelayConfig, RelayError, TcpClientRelayConfig, TlsLikeClientRelayConfig,
    run_client_relay_with_socket_protector, run_tcp_client_relay_with_socket_protector,
    run_tls_like_client_relay_with_socket_protector,
};
use sirinvpn_tunnel_model::TunnelConnectRequest;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};

pub(crate) struct Carrier {
    task: JoinHandle<Result<(), RelayError>>,
}
impl Carrier {
    pub(crate) fn finished(&self) -> bool {
        self.task.is_finished()
    }
    pub(crate) async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) async fn start(
    request: &TunnelConnectRequest,
    remote: SocketAddr,
    underlay: Underlay,
) -> io::Result<(SocketAddr, Option<Carrier>)> {
    if request.transport == TransportKind::DirectUdp {
        return Ok((remote, None));
    }
    // The transport binds this port exclusively before signalling readiness.
    // A competing bind fails the attempt; it never hands our datagrams to a peer.
    let random = uuid::Uuid::new_v4();
    let port = 49152 + u16::from_le_bytes([random.as_bytes()[0], random.as_bytes()[1]]) % 16384;
    let local = SocketAddr::from(([127, 0, 0, 1], port));
    let private = zeroize::Zeroizing::new(request.private_key.clone());
    let public = request
        .server_transport_public_key
        .clone()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let certificate = request.server_certificate_sha256.clone();
    let https = request.https.clone();
    let transport = request.transport;
    let (ready, ready_receiver) = oneshot::channel();
    let carrier = Carrier {
        task: tokio::spawn(async move {
            let protect = move |socket: &socket2::Socket| {
                network::protect_socket(socket, underlay, remote.is_ipv6())
                    .map_err(RelayError::from)
            };
            let ready = move || {
                let _ = ready.send(());
            };
            match transport {
                TransportKind::ObfuscatedUdp => {
                    run_client_relay_with_socket_protector(
                        ClientRelayConfig {
                            local_listen: local,
                            server_address: remote,
                            socket_mark: None,
                            client_private_key: private.to_string(),
                            server_public_key: public,
                        },
                        protect,
                        ready,
                    )
                    .await
                }
                TransportKind::TcpFallback => {
                    run_tcp_client_relay_with_socket_protector(
                        TcpClientRelayConfig {
                            local_listen: local,
                            server_address: remote,
                            socket_mark: None,
                            client_private_key: private.to_string(),
                            server_public_key: public,
                        },
                        protect,
                        ready,
                    )
                    .await
                }
                TransportKind::TlsLike => {
                    run_tls_like_client_relay_with_socket_protector(
                        TlsLikeClientRelayConfig {
                            local_listen: local,
                            server_address: remote,
                            socket_mark: None,
                            client_private_key: private.to_string(),
                            server_public_key: public,
                            server_certificate_sha256: certificate
                                .ok_or(RelayError::InvalidConfiguration)?,
                            https,
                        },
                        protect,
                        ready,
                    )
                    .await
                }
                TransportKind::DirectUdp => Err(RelayError::InvalidConfiguration),
            }
        }),
    };
    match tokio::time::timeout(Duration::from_secs(9), ready_receiver).await {
        Ok(Ok(())) if !carrier.finished() => Ok((local, Some(carrier))),
        _ => {
            carrier.stop().await;
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "carrier did not become ready",
            ))
        }
    }
}
