//! Short endpoint-only DNS exchanges. DNS search suffixes and application queries
//! are never sent here; addresses are checked against the enrolled VPN identity.
use crate::{network, network_plan, state::ResolvedEndpoint};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use sirinvpn_tunnel_model::TunnelConnectRequest;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[derive(Clone, Copy)]
pub(crate) struct Resolver {
    pub address: SocketAddr,
    pub underlay: network::Underlay,
}

pub(crate) async fn resolve(
    request: &TunnelConnectRequest,
    servers: &[Resolver],
) -> Vec<ResolvedEndpoint> {
    let mut hosts = vec![request.endpoint_host.clone()];
    if let Some(identity) = &request.endpoint_identity {
        for host in sirinvpn_tunnel_model::hosts(identity) {
            if !hosts.iter().any(|known| known == host) {
                hosts.push(host.to_owned());
            }
        }
    }
    let mut queries = tokio::task::JoinSet::new();
    let mut found = vec![Vec::new(); hosts.len()];
    for (index, host) in hosts.iter().enumerate().take(4) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            found[index].push(ip);
            continue;
        }
        for server in servers.iter().copied().take(4) {
            for kind in [RecordType::A, RecordType::AAAA] {
                let host = host.clone();
                queries.spawn(async move {
                    let addresses = tokio::time::timeout(
                        Duration::from_millis(1500),
                        query(&host, server, kind),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default();
                    (index, addresses)
                });
            }
        }
    }
    while let Some(Ok((index, addresses))) = queries.join_next().await {
        found[index].extend(addresses);
    }
    let mut result = Vec::new();
    for (host, mut addresses) in hosts.into_iter().zip(found) {
        addresses.retain(|ip| network_plan::usable_endpoint(*ip));
        addresses.sort();
        addresses.dedup();
        for address in [
            addresses.iter().find(|ip| ip.is_ipv4()),
            addresses.iter().find(|ip| ip.is_ipv6()),
        ]
        .into_iter()
        .flatten()
        {
            result.push(ResolvedEndpoint {
                host: host.clone(),
                address: *address,
            });
        }
    }
    result
}

async fn query(host: &str, resolver: Resolver, kind: RecordType) -> anyhow::Result<Vec<IpAddr>> {
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request
        .queries
        .push(Query::query(Name::from_ascii(format!("{host}."))?, kind));
    let encoded = request.to_vec()?;
    let socket = socket(resolver, false)?;
    let local = SocketAddr::new(
        if resolver.address.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    );
    socket.bind(&local.into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    socket.connect(resolver.address).await?;
    socket.send(&encoded).await?;
    let mut bytes = [0u8; 4096];
    let length = socket.recv(&mut bytes).await?;
    let mut response = Message::from_vec(&bytes[..length])?;
    validate(&request, &response)?;
    if response.metadata.truncation {
        let socket = socket_tcp(resolver).await?;
        let mut stream = socket;
        stream.write_u16(encoded.len() as u16).await?;
        stream.write_all(&encoded).await?;
        let length = stream.read_u16().await? as usize;
        anyhow::ensure!(
            (12..=bytes.len()).contains(&length),
            "invalid DNS response size"
        );
        stream.read_exact(&mut bytes[..length]).await?;
        response = Message::from_vec(&bytes[..length])?;
        validate(&request, &response)?;
        anyhow::ensure!(!response.metadata.truncation, "incomplete DNS response");
    }
    let mut names = vec![request.queries[0].name.clone()];
    for _ in 0..8 {
        let previous = names.len();
        for record in &response.answers {
            if record.dns_class == DNSClass::IN
                && names.contains(&record.name)
                && let RData::CNAME(target) = &record.data
                && !names.contains(&target.0)
            {
                names.push(target.0.clone());
            }
        }
        if previous == names.len() {
            break;
        }
    }
    Ok(response
        .answers
        .iter()
        .filter(|record| record.dns_class == DNSClass::IN && names.contains(&record.name))
        .filter_map(|record| match (&record.data, kind) {
            (RData::A(value), RecordType::A) => Some(value.0.into()),
            (RData::AAAA(value), RecordType::AAAA) => Some(value.0.into()),
            _ => None,
        })
        .collect())
}

fn validate(request: &Message, response: &Message) -> anyhow::Result<()> {
    anyhow::ensure!(
        response.metadata.id == request.metadata.id
            && response.metadata.message_type == MessageType::Response
            && response.metadata.op_code == OpCode::Query
            && response.metadata.response_code == ResponseCode::NoError
            && response.queries == request.queries
            && response.answers.len() <= 64,
        "DNS response does not match its endpoint query"
    );
    Ok(())
}

fn socket(resolver: Resolver, tcp: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        if resolver.address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        if tcp { Type::STREAM } else { Type::DGRAM },
        Some(if tcp { Protocol::TCP } else { Protocol::UDP }),
    )?;
    sirinvpn_platform::windows::sockets::exclusive(&socket)?;
    network::protect_socket(&socket, resolver.underlay, resolver.address.is_ipv6())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

async fn socket_tcp(resolver: Resolver) -> io::Result<TcpStream> {
    use windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK;
    let socket = socket(resolver, true)?;
    match socket.connect(&resolver.address.into()) {
        Ok(()) => (),
        Err(error) if error.raw_os_error() == Some(WSAEWOULDBLOCK) => (),
        Err(error) => return Err(error),
    }
    let stream = TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}
