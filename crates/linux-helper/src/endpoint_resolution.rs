//! Resolve only configured VPN endpoint names through the OS's current underlay
//! resolvers. Marked, destination-scoped DNS sockets remain usable behind the
//! kill switch. Application DNS always stays subject to the normal tunnel policy.
use super::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddrV6, TcpStream, UdpSocket};
use std::time::Instant;

pub(super) fn resolve_hosts(hosts: &[&str], servers: &[SocketAddr]) -> Vec<Vec<IpAddr>> {
    thread::scope(|scope| {
        let queries = hosts
            .iter()
            .take(4)
            .map(|host| scope.spawn(move || resolve(host, servers)))
            .collect::<Vec<_>>();
        queries
            .into_iter()
            .map(|task| task.join().unwrap_or_default())
            .collect()
    })
}

pub(super) fn configured_resolvers(output: &[u8]) -> Vec<SocketAddr> {
    let Ok(text) = std::str::from_utf8(output) else {
        return Vec::new();
    };
    let mut resolvers = Vec::new();
    for line in text.lines() {
        if line.contains(&format!("({INTERFACE_NAME})")) {
            continue;
        }
        let Some((prefix, addresses)) = line.split_once(": ") else {
            continue;
        };
        let index = prefix
            .strip_prefix("Link ")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|id| id.parse::<u32>().ok());
        if !prefix.starts_with("Global") && index.is_none() {
            continue;
        }
        for value in addresses.split_whitespace() {
            let value = value.split('#').next().unwrap_or(value);
            let value = value.split('%').next().unwrap_or(value);
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_loopback()
                || ip == IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1))
            {
                continue;
            }
            let address = match ip {
                IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                    let Some(index) = index else {
                        continue;
                    };
                    SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, index))
                }
                _ => SocketAddr::new(ip, 53),
            };
            if !resolvers.contains(&address) {
                resolvers.push(address);
            }
            if resolvers.len() == 4 {
                return resolvers;
            }
        }
    }
    resolvers
}

pub(super) fn resolve(host: &str, servers: &[SocketAddr]) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return usable(ip).then_some(ip).into_iter().collect();
    }
    if validate_host(host).is_err() || servers.is_empty() {
        return Vec::new();
    }
    // All DNS exchanges share the same short window. No global resolver choice,
    // search suffix, application query, or response is recorded in this helper.
    let mut results = thread::scope(|scope| {
        let mut queries = Vec::new();
        for server in servers.iter().take(4) {
            for kind in [RecordType::A, RecordType::AAAA] {
                queries.push(scope.spawn(move || query(host, *server, kind).unwrap_or_default()));
            }
        }
        queries
            .into_iter()
            .filter_map(|task| task.join().ok())
            .flatten()
            .collect::<Vec<_>>()
    });
    results.retain(|address| usable(*address));
    results.sort();
    results.dedup();
    // Retain one address of each family before additional records.
    let preferred = [
        results.iter().find(|ip| ip.is_ipv4()).copied(),
        results.iter().find(|ip| ip.is_ipv6()).copied(),
    ];
    preferred.into_iter().flatten().collect()
}

fn usable(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

fn query(host: &str, server: SocketAddr, kind: RecordType) -> Result<Vec<IpAddr>> {
    let deadline = Instant::now() + Duration::from_millis(1_500);
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request
        .queries
        .push(Query::query(Name::from_ascii(format!("{host}."))?, kind));
    let encoded = request.to_vec()?;
    let socket = marked_socket(server, Type::DGRAM, Protocol::UDP)?;
    socket.bind(
        &SocketAddr::new(
            if server.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        )
        .into(),
    )?;
    let socket: UdpSocket = socket.into();
    socket.connect(server)?;
    socket.send(&encoded)?;
    let mut bytes = [0_u8; 4096];
    let length = socket.recv(&mut bytes)?;
    let mut response = Message::from_vec(&bytes[..length])?;
    validate_response(&request, &response)?;
    if response.metadata.truncation {
        let socket = marked_socket(server, Type::STREAM, Protocol::TCP)?;
        socket.connect_timeout(&server.into(), remaining(deadline)?)?;
        let mut stream: TcpStream = socket.into();
        stream.write_all(&(encoded.len() as u16).to_be_bytes())?;
        stream.write_all(&encoded)?;
        let mut length = [0_u8; 2];
        read_before(&mut stream, &mut length, deadline)?;
        let length = u16::from_be_bytes(length) as usize;
        anyhow::ensure!(
            (12..=4096).contains(&length),
            "endpoint DNS response is too large"
        );
        read_before(&mut stream, &mut bytes[..length], deadline)?;
        response = Message::from_vec(&bytes[..length])?;
        validate_response(&request, &response)?;
        anyhow::ensure!(
            !response.metadata.truncation,
            "endpoint DNS response is incomplete"
        );
    }
    let mut names = vec![request.queries[0].name.clone()];
    for _ in 0..8 {
        let before = names.len();
        for record in &response.answers {
            if record.dns_class == DNSClass::IN
                && names.contains(&record.name)
                && let RData::CNAME(target) = &record.data
                && !names.contains(&target.0)
            {
                names.push(target.0.clone());
            }
        }
        if before == names.len() {
            break;
        }
    }
    Ok(response
        .answers
        .iter()
        .filter(|record| record.dns_class == DNSClass::IN && names.contains(&record.name))
        .filter_map(|record| match (&record.data, kind) {
            (RData::A(address), RecordType::A) => Some(IpAddr::V4(address.0)),
            (RData::AAAA(address), RecordType::AAAA) => Some(IpAddr::V6(address.0)),
            _ => None,
        })
        .collect())
}

fn validate_response(request: &Message, response: &Message) -> Result<()> {
    anyhow::ensure!(
        response.metadata.id == request.metadata.id
            && response.metadata.message_type == MessageType::Response
            && response.metadata.op_code == OpCode::Query
            && response.metadata.response_code == ResponseCode::NoError
            && response.queries == request.queries
            && response.answers.len() <= 64,
        "endpoint DNS response does not match its query"
    );
    Ok(())
}

fn marked_socket(address: SocketAddr, kind: Type, protocol: Protocol) -> Result<Socket> {
    let socket = Socket::new(
        if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        kind,
        Some(protocol),
    )?;
    socket.set_mark(51_820)?;
    socket.set_read_timeout(Some(Duration::from_millis(750)))?;
    socket.set_write_timeout(Some(Duration::from_millis(750)))?;
    Ok(socket)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "endpoint DNS deadline elapsed"))
}

fn read_before(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match io::Read::read(stream, bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(length) => bytes = &mut bytes[length..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
