//! Bounded, user-requested DNS probes. Only current results exist in memory.
use crate::{ServerConfiguration, doh_proxy};
use futures_util::future::join_all;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use sirinvpn_protocol::{
    DiagnosticCheck, DiagnosticLevel, DnsOverTlsEndpoint, DnsUpstream, SplitDnsUpstream,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::timeout,
};
use tokio_rustls::TlsConnector;

static DIAGNOSING: Mutex<()> = Mutex::const_new(());
const LIMIT: Duration = Duration::from_secs(3);
type ProbeResult = Result<(), &'static str>;

enum Resolver {
    Tcp(SocketAddr),
    Tls(DnsOverTlsEndpoint),
    Https(sirinvpn_protocol::DnsOverHttpsEndpoint),
}

pub(crate) async fn diagnose(configuration: &ServerConfiguration) -> Vec<DiagnosticCheck> {
    let Ok(_guard) = DIAGNOSING.try_lock() else {
        return vec![DiagnosticCheck {
            code: "dns_probe_busy".into(),
            label: "DNS response checks".into(),
            level: DiagnosticLevel::Warning,
            message: "Another DNS check is running. Try again in a few seconds.".into(),
        }];
    };
    diagnose_with_local_port(configuration, 53).await
}

async fn diagnose_with_local_port(
    configuration: &ServerConfiguration,
    port: u16,
) -> Vec<DiagnosticCheck> {
    // Server-originated traffic to the tunnel address arrives over loopback,
    // where the tunnel-only DNS firewall correctly rejects it. Unbound also
    // listens on localhost for the server's own checks and split-zone queries.
    let local_resolver = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut probes = vec![(
        "dns_resolver_response".into(),
        "Private resolver response".into(),
        ".".into(),
        Resolver::Tcp(local_resolver),
    )];
    match configuration.dns_upstream.default_upstream() {
        DnsUpstream::DnsOverTls { endpoints } => {
            for (index, endpoint) in endpoints.iter().enumerate() {
                probes.push((
                    format!("dns_tls_{index}"),
                    format!("TLS resolver {}", endpoint.address),
                    ".".into(),
                    Resolver::Tls(endpoint.clone()),
                ));
            }
        }
        DnsUpstream::DnsOverHttps { endpoints } => {
            for (index, endpoint) in endpoints.iter().enumerate() {
                probes.push((
                    format!("dns_https_{index}"),
                    format!("HTTPS resolver {}", endpoint.address),
                    ".".into(),
                    Resolver::Https(endpoint.clone()),
                ));
            }
        }
        _ => {}
    }
    for (index, zone) in configuration.dns_upstream.split_zones().iter().enumerate() {
        probes.push((
            format!("dns_zone_{index}"),
            format!("Split zone {}", zone.suffix),
            zone.suffix.clone(),
            Resolver::Tcp(local_resolver),
        ));
        match &zone.upstream {
            SplitDnsUpstream::Private { addresses } => {
                for (endpoint_index, address) in addresses.iter().enumerate() {
                    probes.push((
                        format!("dns_zone_{index}_{endpoint_index}"),
                        format!("{} via {address}", zone.suffix),
                        zone.suffix.clone(),
                        Resolver::Tcp(SocketAddr::new(*address, 53)),
                    ));
                }
            }
            SplitDnsUpstream::DnsOverTls { endpoints } => {
                for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
                    probes.push((
                        format!("dns_zone_{index}_{endpoint_index}"),
                        format!("{} via TLS {}", zone.suffix, endpoint.address),
                        zone.suffix.clone(),
                        Resolver::Tls(endpoint.clone()),
                    ));
                }
            }
        }
    }
    join_all(probes.into_iter().map(|(code, label, name, resolver)| async move {
        let started = Instant::now();
        let query = ns_query(&name);
        let result = timeout(LIMIT, async {
            let response = match resolver {
                Resolver::Tcp(address) => {
                    let mut stream = TcpStream::connect(address).await.map_err(|_| "TCP connection failed. Check the resolver address, route and port 53 firewall.")?;
                    exchange(&mut stream, &query).await?
                }
                Resolver::Tls(endpoint) => tls_exchange(&endpoint, &query).await?,
                Resolver::Https(endpoint) => doh_proxy::diagnostic_exchange(&endpoint, &query).await
                    .map_err(|_| "Authenticated HTTPS DNS failed. Check the resolver address, TLS name, HTTPS path and outbound port 443.")?,
            };
            validate_reply(&query, &response)
        }).await.unwrap_or(Err("No DNS reply within three seconds. Check upstream reachability and firewall rules; DNS protection remains enabled."));
        DiagnosticCheck { code, label, level: if result.is_ok() { DiagnosticLevel::Pass } else { DiagnosticLevel::Fail },
            message: result.map_or_else(str::to_owned, |_| format!("Valid DNS response in {} ms. No query history is retained.", started.elapsed().as_millis())) }
    })).await
}

async fn tls_exchange(
    endpoint: &DnsOverTlsEndpoint,
    query: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut roots = RootCertStore::empty();
    let certificates = CertificateDer::pem_file_iter("/etc/ssl/certs/ca-certificates.crt")
        .map_err(|_| "The VPS certificate trust bundle is unavailable. Repair the CA certificates package.")?
        .collect::<Result<Vec<_>,_>>().map_err(|_| "The VPS certificate trust bundle is invalid.")?;
    roots.add_parsable_certificates(certificates);
    let tls = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let name = ServerName::try_from(endpoint.authentication_name.clone())
        .map_err(|_| "The TLS resolver authentication name is invalid.")?;
    let stream = TcpStream::connect(SocketAddr::new(endpoint.address, 853))
        .await
        .map_err(
            |_| "The TLS resolver could not be reached. Check its IP, route and outbound port 853.",
        )?;
    let mut stream = tls.connect(name, stream).await
        .map_err(|_| "TLS authentication failed. Check the resolver's certificate, configured TLS name and VPS clock.")?;
    exchange(&mut stream, query).await
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    query: &[u8],
) -> Result<Vec<u8>, &'static str> {
    stream
        .write_u16(query.len() as u16)
        .await
        .map_err(|_| "The DNS request could not be sent.")?;
    stream
        .write_all(query)
        .await
        .map_err(|_| "The DNS request could not be sent.")?;
    let length = stream
        .read_u16()
        .await
        .map_err(|_| "The DNS resolver closed the connection without a reply.")?
        as usize;
    if !(12..=4096).contains(&length) {
        return Err("The DNS response had an invalid size.");
    }
    let mut response = vec![0; length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| "The DNS reply was incomplete.")?;
    Ok(response)
}

fn ns_query(name: &str) -> Vec<u8> {
    let id: u16 = rand::random();
    let mut query = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    if name != "." {
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
    }
    query.extend_from_slice(&[0, 0, 2, 0, 1]);
    query
}

fn question(message: &[u8]) -> Option<(Vec<u8>, [u8; 4])> {
    let mut offset = 12;
    let mut return_offset = None;
    let mut name = Vec::new();
    for _ in 0..128 {
        let byte = *message.get(offset)?;
        if byte & 0xc0 == 0xc0 {
            return_offset.get_or_insert(offset + 2);
            offset = ((usize::from(byte) & 0x3f) << 8) | usize::from(*message.get(offset + 1)?);
            continue;
        }
        if byte > 63 {
            return None;
        }
        offset += 1;
        if byte == 0 {
            let end = return_offset.unwrap_or(offset);
            return Some((name, message.get(end..end + 4)?.try_into().ok()?));
        }
        name.push(byte);
        name.extend(
            message
                .get(offset..offset + usize::from(byte))?
                .iter()
                .map(u8::to_ascii_lowercase),
        );
        if name.len() > 254 {
            return None;
        }
        offset += usize::from(byte);
    }
    None
}

fn validate_reply(query: &[u8], response: &[u8]) -> ProbeResult {
    if response.len() < 12
        || response[..2] != query[..2]
        || response[2] & 0xfa != 0x80
        || response[4..6] != [0, 1]
        || question(response).is_none()
        || question(response) != question(query)
    {
        return Err("The DNS reply did not match the request or was truncated.");
    }
    match response[3] & 15 {
        0 | 3 => Ok(()),
        2 => Err(
            "The resolver returned SERVFAIL. Check its upstream reachability, DNSSEC validation and clock.",
        ),
        5 => Err(
            "The resolver refused this query. Check its client access policy and zone forwarding rules.",
        ),
        _ => {
            Err("The resolver returned a DNS error. Check its configured zone and upstream policy.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn server_resolver_check_uses_loopback_without_a_tunnel_interface() {
        let directory = tempfile::tempdir().unwrap();
        let paths = crate::ServerPaths::under(directory.path());
        let owner = sirinvpn_core::LocalIdentity::generate("DNS probe fixture").unwrap();
        crate::initialize(
            &paths,
            "DNS probe fixture",
            &owner.public.management_certificate_pem,
            sirinvpn_protocol::ServerId::new(),
            &owner.public.wireguard_public_key,
            51820,
        )
        .unwrap();
        let configuration = crate::load_configuration(&paths).unwrap();
        assert!(!configuration.server_tunnel_address.is_loopback());
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let size = stream.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(size)];
            stream.read_exact(&mut query).await.unwrap();
            query[2] |= 0x80;
            stream.write_u16(size).await.unwrap();
            stream.write_all(&query).await.unwrap();
        });
        let checks = diagnose_with_local_port(&configuration, port).await;
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].code, "dns_resolver_response");
        assert_eq!(
            checks[0].level,
            DiagnosticLevel::Pass,
            "{}",
            checks[0].message
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn actual_tcp_dns_probe_detects_refused_mismatched_and_truncated_replies() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let size = stream.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(size)];
            stream.read_exact(&mut query).await.unwrap();
            query[2] |= 0x80;
            stream.write_u16(size).await.unwrap();
            stream.write_all(&query).await.unwrap();
        });
        let query = ns_query("corp.example");
        let response = exchange(&mut TcpStream::connect(address).await.unwrap(), &query)
            .await
            .unwrap();
        assert!(validate_reply(&query, &response).is_ok());
        let mut refused = response.clone();
        refused[3] = 5;
        assert!(
            validate_reply(&query, &refused)
                .unwrap_err()
                .contains("refused")
        );
        let mut mismatched = response.clone();
        mismatched[14] ^= 1;
        assert!(validate_reply(&query, &mismatched).is_err());
        assert!(validate_reply(&query, &response[..10]).is_err());
        let mut pointer_loop = response.clone();
        pointer_loop[12..14].copy_from_slice(&[0xc0, 12]);
        assert!(validate_reply(&query, &pointer_loop).is_err());
        server.await.unwrap();
    }
}
