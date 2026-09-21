use crate::{ServerPaths, load_configuration};
use anyhow::{Context, Result, bail};
use reqwest::{
    Client,
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
};
pub use sirinvpn_protocol::DOH_PROXY_PORT;
use sirinvpn_protocol::{DnsOverHttpsEndpoint, DnsUpstream, validate_dns_upstream};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};

const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;
const MAX_UDP_RESPONSE_SIZE: usize = 65_507;
const MAX_UDP_REQUESTS: usize = 256;
const MAX_TCP_CONNECTIONS: usize = 128;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const HTTPS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTPS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const HTTPS_SCHEME: &str = "https";

#[derive(Clone)]
struct EndpointClient {
    url: String,
    client: Client,
}

#[derive(Clone)]
struct DohResolver {
    endpoints: Arc<[EndpointClient]>,
}

impl DohResolver {
    fn new(upstream: &DnsUpstream) -> Result<Self> {
        validate_dns_upstream(upstream).context("DNS-over-HTTPS policy is invalid")?;
        let DnsUpstream::DnsOverHttps { endpoints } = upstream.default_upstream() else {
            bail!("DNS-over-HTTPS proxy requires a DNS-over-HTTPS policy");
        };
        let endpoints = endpoints
            .iter()
            .map(endpoint_client)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            endpoints: endpoints.into(),
        })
    }

    async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
        validate_dns_query(query)?;
        for endpoint in self.endpoints.iter() {
            if let Ok(response) = endpoint.exchange(query).await {
                return Ok(response);
            }
        }
        bail!("every configured DNS-over-HTTPS endpoint failed")
    }
}

impl EndpointClient {
    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        let mut response = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/dns-message")
            .header(ACCEPT, "application/dns-message")
            .body(query.to_vec())
            .send()
            .await
            .context("DNS-over-HTTPS request failed")?;
        if response.status() != reqwest::StatusCode::OK {
            bail!("DNS-over-HTTPS endpoint returned a non-success status");
        }
        let valid_content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/dns-message"));
        if !valid_content_type {
            bail!("DNS-over-HTTPS endpoint returned an invalid content type");
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_DNS_MESSAGE_SIZE as u64)
        {
            bail!("DNS-over-HTTPS response is oversized");
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("DNS-over-HTTPS response body failed")?
        {
            if body.len() + chunk.len() > MAX_DNS_MESSAGE_SIZE {
                bail!("DNS-over-HTTPS response is oversized");
            }
            body.extend_from_slice(&chunk);
        }
        validate_dns_response(query, &body)?;
        Ok(body)
    }
}

fn endpoint_client(endpoint: &DnsOverHttpsEndpoint) -> Result<EndpointClient> {
    let address = SocketAddr::new(endpoint.address, 443);
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(HTTPS_CONNECT_TIMEOUT)
        .timeout(HTTPS_REQUEST_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(60))
        .http2_adaptive_window(true)
        .resolve(&endpoint.authentication_name, address)
        .build()
        .context("DNS-over-HTTPS client setup failed")?;
    Ok(EndpointClient {
        url: format!(
            "{HTTPS_SCHEME}://{}{}",
            endpoint.authentication_name, endpoint.path
        ),
        client,
    })
}

pub(crate) async fn diagnostic_exchange(
    endpoint: &DnsOverHttpsEndpoint,
    query: &[u8],
) -> Result<Vec<u8>> {
    sirinvpn_protocol::validate_dns_over_https_endpoint(endpoint)?;
    endpoint_client(endpoint)?.exchange(query).await
}

fn validate_dns_query(query: &[u8]) -> Result<()> {
    if query.len() < 12
        || query.len() > MAX_DNS_MESSAGE_SIZE
        || query[2] & 0x80 != 0
        || query[2] & 0x78 != 0
        || u16::from_be_bytes([query[4], query[5]]) != 1
    {
        bail!("invalid DNS query");
    }
    Ok(())
}

fn validate_dns_response(query: &[u8], response: &[u8]) -> Result<()> {
    if response.len() < 12
        || response.len() > MAX_DNS_MESSAGE_SIZE
        || response[..2] != query[..2]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != query[2] & 0x78
    {
        bail!("invalid DNS-over-HTTPS response");
    }
    Ok(())
}

fn truncated_udp_response(query: &[u8]) -> [u8; 12] {
    let mut response = [0_u8; 12];
    response[..2].copy_from_slice(&query[..2]);
    response[2] = (query[2] & 0x79) | 0x82;
    response
}

pub async fn serve_doh_proxy(paths: &ServerPaths) -> Result<()> {
    let configuration = load_configuration(paths)?;
    let resolver = Arc::new(DohResolver::new(&configuration.dns_upstream)?);
    let address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), DOH_PROXY_PORT);
    let udp = Arc::new(
        UdpSocket::bind(address)
            .await
            .context("DNS-over-HTTPS UDP loopback listener failed")?,
    );
    let tcp = TcpListener::bind(address)
        .await
        .context("DNS-over-HTTPS TCP loopback listener failed")?;
    tokio::try_join!(serve_udp(udp, resolver.clone()), serve_tcp(tcp, resolver))?;
    Ok(())
}

async fn serve_udp(socket: Arc<UdpSocket>, resolver: Arc<DohResolver>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_UDP_REQUESTS));
    let mut buffer = vec![0_u8; MAX_DNS_MESSAGE_SIZE];
    loop {
        let (length, peer) = socket
            .recv_from(&mut buffer)
            .await
            .context("DNS-over-HTTPS UDP receive failed")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let query = buffer[..length].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(response) = resolver.resolve(&query).await else {
                return;
            };
            if response.len() <= MAX_UDP_RESPONSE_SIZE {
                let _ = socket.send_to(&response, peer).await;
            } else {
                let _ = socket.send_to(&truncated_udp_response(&query), peer).await;
            }
        });
    }
}

async fn serve_tcp(listener: TcpListener, resolver: Arc<DohResolver>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("DNS-over-HTTPS TCP accept failed")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_tcp(stream, resolver).await;
        });
    }
}

async fn handle_tcp(mut stream: TcpStream, resolver: Arc<DohResolver>) -> Result<()> {
    loop {
        let length = timeout(TCP_IDLE_TIMEOUT, stream.read_u16())
            .await
            .context("DNS-over-HTTPS TCP connection became idle")?
            .context("DNS-over-HTTPS TCP length read failed")? as usize;
        if !(12..=MAX_DNS_MESSAGE_SIZE).contains(&length) {
            bail!("invalid DNS-over-HTTPS TCP query length");
        }
        let mut query = vec![0_u8; length];
        timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut query))
            .await
            .context("DNS-over-HTTPS TCP query became idle")?
            .context("DNS-over-HTTPS TCP query read failed")?;
        let response = resolver.resolve(&query).await?;
        stream
            .write_u16(response.len() as u16)
            .await
            .context("DNS-over-HTTPS TCP length write failed")?;
        stream
            .write_all(&response)
            .await
            .context("DNS-over-HTTPS TCP response write failed")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn resolver_uses_only_validated_pinned_https_endpoints() {
        let resolver = DohResolver::new(&DnsUpstream::DnsOverHttps {
            endpoints: vec!["1.1.1.1#cloudflare-dns.com/dns-query".parse().unwrap()],
        })
        .unwrap();
        assert_eq!(resolver.endpoints.len(), 1);
        assert_eq!(
            resolver.endpoints[0].url,
            format!("{HTTPS_SCHEME}://cloudflare-dns.com/dns-query")
        );
        assert!(DohResolver::new(&DnsUpstream::Recursive).is_err());
    }

    #[test]
    fn dns_messages_are_bounded_and_transaction_bound() {
        let query = query();
        assert!(validate_dns_query(&query).is_ok());
        let mut response = query.clone();
        response[2] |= 0x80;
        assert!(validate_dns_response(&query, &response).is_ok());
        response[0] ^= 1;
        assert!(validate_dns_response(&query, &response).is_err());

        let mut invalid_query = query.clone();
        invalid_query[2] |= 0x80;
        assert!(validate_dns_query(&invalid_query).is_err());
        assert!(validate_dns_query(&query[..11]).is_err());
    }

    #[test]
    fn oversized_udp_answers_request_a_tcp_retry_without_payload_data() {
        let query = query();
        let response = truncated_udp_response(&query);
        assert_eq!(&response[..2], &query[..2]);
        assert_ne!(response[2] & 0x80, 0);
        assert_ne!(response[2] & 0x02, 0);
        assert!(response[4..].iter().all(|byte| *byte == 0));
    }
}
