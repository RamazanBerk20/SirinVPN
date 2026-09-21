use super::check;
use sirinvpn_protocol::{DiagnosticCheck, DiagnosticLevel};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDnsOutcome {
    Available,
    Servfail,
    Refused,
    Timeout,
    ConnectFailed,
    InvalidReply,
    Unavailable,
}

pub fn private_dns_check(outcome: PrivateDnsOutcome) -> DiagnosticCheck {
    result(match outcome {
        PrivateDnsOutcome::Available => "available",
        PrivateDnsOutcome::Servfail => "servfail",
        PrivateDnsOutcome::Refused => "refused",
        PrivateDnsOutcome::Timeout => "timeout",
        PrivateDnsOutcome::ConnectFailed => "connect_failed",
        PrivateDnsOutcome::InvalidReply => "invalid_reply",
        PrivateDnsOutcome::Unavailable => "unavailable",
    })
}

/// Only a root NS query to the private VPS address, bound to this device's tunnel address.
/// Android uses Network.bindSocket in its native controller instead.
pub async fn probe_private_dns(source: IpAddr, destination: IpAddr) -> DiagnosticCheck {
    let valid = matches!((source, destination), (IpAddr::V4(source), IpAddr::V4(destination))
        if source.octets()[..3] == [10, 77, 0] && source.octets()[3] > 1
            && destination.octets() == [10, 77, 0, 1]);
    if !valid {
        return result("unavailable");
    }
    let outcome = tokio::time::timeout(Duration::from_secs(3), async {
        let socket = TcpSocket::new_v4().map_err(|_| "unavailable")?;
        socket
            .bind(SocketAddr::new(source, 0))
            .map_err(|_| "unavailable")?;
        let mut stream = socket
            .connect(SocketAddr::new(destination, 53))
            .await
            .map_err(|_| "connect_failed")?;
        exchange(&mut stream).await
    })
    .await
    .unwrap_or(Err("timeout"));
    result(outcome.err().unwrap_or("available"))
}

pub(super) fn result(outcome: &str) -> DiagnosticCheck {
    let (level, message) = match outcome {
        "available" => (
            DiagnosticLevel::Pass,
            "The private VPS resolver returned a matching DNS response through the current VPN.",
        ),
        "servfail" => (
            DiagnosticLevel::Fail,
            "The private resolver returned SERVFAIL. Check VPS upstream DNS, DNSSEC validation and the VPS clock.",
        ),
        "refused" => (
            DiagnosticLevel::Fail,
            "The private resolver refused the query. Check resolver access policy and server DNS configuration.",
        ),
        "timeout" => (
            DiagnosticLevel::Fail,
            "The private resolver did not reply within three seconds. Check the tunnel's DNS route, port 53 rules and VPS resolver service.",
        ),
        "connect_failed" => (
            DiagnosticLevel::Fail,
            "The private resolver's TCP port 53 could not be reached through the VPN. Check the included DNS route and VPS resolver service.",
        ),
        "invalid_reply" => (
            DiagnosticLevel::Fail,
            "The private resolver returned an invalid or mismatched DNS reply. Check VPS DNS configuration and rerun diagnostics.",
        ),
        _ => (
            DiagnosticLevel::Warning,
            "The current VPN network or source address was unavailable for a private DNS probe. Connect or wait for recovery, then retry.",
        ),
    };
    check(
        "local_dns",
        "Private DNS through this device",
        level,
        message,
    )
}

async fn exchange(stream: &mut TcpStream) -> Result<(), &'static str> {
    let id = rand::random::<u16>().to_be_bytes();
    let query = [id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
    stream
        .write_u16(query.len() as u16)
        .await
        .map_err(|_| "connect_failed")?;
    stream
        .write_all(&query)
        .await
        .map_err(|_| "connect_failed")?;
    let length = usize::from(stream.read_u16().await.map_err(|_| "invalid_reply")?);
    if !(17..=4096).contains(&length) {
        return Err("invalid_reply");
    }
    let mut reply = vec![0; length];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|_| "invalid_reply")?;
    validate_reply(&query, &reply)
}

fn validate_reply(query: &[u8], reply: &[u8]) -> Result<(), &'static str> {
    if reply.len() < 17
        || reply[..2] != query[..2]
        || reply[2] & 0xfa != 0x80
        || reply[4..6] != [0, 1]
        || !root_question(reply)
    {
        return Err("invalid_reply");
    }
    match reply[3] & 15 {
        0 | 3 => Ok(()),
        2 => Err("servfail"),
        5 => Err("refused"),
        _ => Err("invalid_reply"),
    }
}

fn root_question(reply: &[u8]) -> bool {
    let mut offset = 12;
    let mut question_end = None;
    for _ in 0..32 {
        let Some(&byte) = reply.get(offset) else {
            return false;
        };
        if byte == 0 {
            let end = question_end.unwrap_or(offset + 1);
            return reply.get(end..end + 4) == Some(&[0, 2, 0, 1]);
        }
        if byte & 0xc0 != 0xc0 {
            return false;
        }
        let Some(&low) = reply.get(offset + 1) else {
            return false;
        };
        question_end.get_or_insert(offset + 2);
        offset = (usize::from(byte & 0x3f) << 8) | usize::from(low);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_dns_exchange_requires_matching_root_answer_and_classifies_server_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut bytes = vec![0; usize::from(length)];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes[12..], &[0, 0, 2, 0, 1]);
            bytes[2] |= 0x80;
            bytes[3] = 2;
            stream.write_u16(length).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        assert_eq!(
            exchange(&mut TcpStream::connect(address).await.unwrap()).await,
            Err("servfail")
        );
        fixture.await.unwrap();
        let query = [1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
        let mut reply = query;
        reply[2] = 0x81;
        assert_eq!(validate_reply(&query, &reply), Ok(()));
        reply[3] = 5;
        assert_eq!(validate_reply(&query, &reply), Err("refused"));
        reply[0] = 3;
        assert_eq!(validate_reply(&query, &reply), Err("invalid_reply"));
        assert_eq!(
            probe_private_dns("127.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap())
                .await
                .level,
            DiagnosticLevel::Warning
        );
    }
}
