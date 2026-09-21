use std::{
    io,
    os::windows::io::{AsRawSocket, AsSocket},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET, SOL_SOCKET, WSAGetLastError, setsockopt,
};

/// Call before bind/connect. Windows' SO_REUSEADDR otherwise permits another
/// process to share a UDP port even when the original socket did not request it.
pub fn exclusive(socket: &impl AsSocket) -> io::Result<()> {
    let enabled = 1i32;
    let code = unsafe {
        setsockopt(
            socket.as_socket().as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            ptr::addr_of!(enabled).cast(),
            size_of::<i32>() as i32,
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exclusive_udp_socket_rejects_port_reuse() {
        use socket2::{Domain, Protocol, Socket, Type};
        let first = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        super::exclusive(&first).unwrap();
        first
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();
        let second = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        second.set_reuse_address(true).unwrap();
        assert!(second.bind(&first.local_addr().unwrap()).is_err());
    }
}
