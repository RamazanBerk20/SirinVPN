//! Packet marks are a Linux routing mechanism. Other platforms must use their
//! native socket/route isolation and must never silently ignore a requested mark.
pub(crate) fn bind_loopback(
    address: std::net::SocketAddr,
) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    if !address.ip().is_loopback() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let socket = Socket::new(
        if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    #[cfg(windows)]
    sirinvpn_platform::windows::sockets::exclusive(&socket)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

pub(crate) fn set_mark(socket: &socket2::Socket, mark: Option<u32>) -> std::io::Result<()> {
    let Some(mark) = mark else {
        return Ok(());
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        socket.set_mark(mark)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (socket, mark);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "packet marks are unavailable on this platform",
        ))
    }
}
