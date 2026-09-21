use super::*;
use crate::resolver::Resolver;
use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW, NetworkManagement::Ndis::IfOperStatusUp,
};

pub(crate) fn resolvers(request: &TunnelConnectRequest) -> io::Result<Vec<Resolver>> {
    let addresses = if request.endpoint_dns_servers.is_empty() {
        current_resolvers()?
    } else {
        request.endpoint_dns_servers.clone()
    };
    Ok(addresses
        .into_iter()
        .filter_map(|address| {
            let mut interface = underlay(address.ip(), None).ok()?;
            if let SocketAddr::V6(address) = address
                && address.ip().is_unicast_link_local()
            {
                if address.scope_id() == 0 {
                    return None;
                }
                interface.index = address.scope_id();
                let mut luid = NET_LUID_LH::default();
                check(unsafe { ConvertInterfaceIndexToLuid(interface.index, &mut luid) }).ok()?;
                interface.luid = unsafe { luid.Value };
            }
            Some(Resolver {
                address,
                underlay: interface,
            })
        })
        .take(4)
        .collect())
}

fn current_resolvers() -> io::Result<Vec<SocketAddr>> {
    let mut length = 16_384u32;
    for _ in 0..3 {
        if length as usize > 1024 * 1024 {
            return Err(invalid());
        }
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                ptr::null(),
                head,
                &mut length,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        check(code)?;
        let mut current = head;
        let mut result = Vec::new();
        for _ in 0..512 {
            if current.is_null() {
                break;
            }
            // All list nodes and socket addresses are owned by this API buffer.
            let adapter = unsafe { &*current };
            current = adapter.Next;
            if adapter.OperStatus != IfOperStatusUp
                || adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK
                || require_adapter(adapter.Luid).is_ok()
            {
                continue;
            }
            let mut dns = adapter.FirstDnsServerAddress;
            for _ in 0..32 {
                if dns.is_null() {
                    break;
                }
                let row = unsafe { &*dns };
                dns = row.Next;
                let raw = row.Address.lpSockaddr;
                if raw.is_null() || row.Address.iSockaddrLength < size_of::<SOCKADDR>() as i32 {
                    continue;
                }
                let address = unsafe {
                    match (*raw).sa_family {
                        AF_INET
                            if row.Address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 =>
                        {
                            let value = ptr::read_unaligned(raw.cast::<SOCKADDR_IN>());
                            SocketAddr::new(
                                Ipv4Addr::from(value.sin_addr.S_un.S_addr.to_ne_bytes()).into(),
                                53,
                            )
                        }
                        AF_INET6
                            if row.Address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 =>
                        {
                            let value = ptr::read_unaligned(raw.cast::<SOCKADDR_IN6>());
                            let ip = Ipv6Addr::from(value.sin6_addr.u.Byte);
                            SocketAddr::V6(std::net::SocketAddrV6::new(
                                ip,
                                53,
                                0,
                                if ip.is_unicast_link_local() {
                                    adapter.Ipv6IfIndex
                                } else {
                                    value.Anonymous.sin6_scope_id
                                },
                            ))
                        }
                        _ => continue,
                    }
                };
                if address.ip().is_unspecified()
                    || address.ip().is_loopback()
                    || address.ip().is_multicast()
                    || address.ip() == IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1))
                {
                    continue;
                }
                if !result.contains(&address) {
                    result.push(address);
                }
                if result.len() == 4 {
                    return Ok(result);
                }
            }
        }
        return Ok(result);
    }
    Err(invalid())
}
