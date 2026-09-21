use super::*;
use std::time::Duration;
use tokio::{
    net::{TcpListener, UdpSocket},
    time::timeout,
};

#[tokio::test]
async fn refused_carrier_socket_protection_sends_no_udp_tcp_or_tls_traffic() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = |socket: &socket2::Socket| {
        assert!(
            socket.peer_addr().is_err(),
            "carrier connected before protection"
        );
        Err(RelayError::NetworkBindingFailed)
    };
    let not_ready = || panic!("unprotected carrier must never be ready");
    assert!(
        run_client_relay_with_socket_protector(
            ClientRelayConfig {
                local_listen: "127.0.0.1:0".parse().unwrap(),
                server_address: udp.local_addr().unwrap(),
                socket_mark: None,
                client_private_key: STANDARD.encode([7u8; 32]),
                server_public_key: STANDARD.encode([9u8; 32]),
            },
            refused,
            not_ready
        )
        .await
        .is_err()
    );
    assert!(
        run_tcp_client_relay_with_socket_protector(
            TcpClientRelayConfig {
                local_listen: "127.0.0.1:0".parse().unwrap(),
                server_address: tcp.local_addr().unwrap(),
                socket_mark: None,
                client_private_key: STANDARD.encode([7u8; 32]),
                server_public_key: STANDARD.encode([9u8; 32]),
            },
            refused,
            not_ready
        )
        .await
        .is_err()
    );
    assert!(
        run_tls_like_client_relay_with_socket_protector(
            TlsLikeClientRelayConfig {
                local_listen: "127.0.0.1:0".parse().unwrap(),
                server_address: tcp.local_addr().unwrap(),
                socket_mark: None,
                client_private_key: STANDARD.encode([7u8; 32]),
                server_public_key: STANDARD.encode([9u8; 32]),
                server_certificate_sha256: STANDARD.encode([8u8; 32]),
                https: None,
            },
            refused,
            not_ready
        )
        .await
        .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), udp.recv(&mut [0u8; 64]))
            .await
            .is_err()
    );
    let discovery = || EndpointDiscoveryConfig {
        server_address: tcp.local_addr().unwrap(),
        server_name: "vpn.example.com".into(),
        client_private_key: zeroize::Zeroizing::new([7u8; 32]),
        server_public_key: [9u8; 32],
        socket_mark: None,
    };
    assert!(
        fetch_endpoint_checkpoint_with_socket_protector(discovery(), refused)
            .await
            .is_err()
    );
    assert!(
        offer_endpoint_checkpoint_with_socket_protector(discovery(), b"checkpoint", refused)
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(50), tcp.accept())
            .await
            .is_err()
    );
}
