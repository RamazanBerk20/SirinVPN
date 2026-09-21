//! Native IP Helper configuration, limited to the owned WireGuard adapter and
//! precisely journaled host/LAN routes. Other adapters' DNS and routes are preserved.
use crate::{
    firewall::guid_equal,
    firewall_plan::host,
    network_plan::{self, OWNED_ROUTE_METRIC, RouteRecord},
    wireguard::{ADAPTER_GUID, socket_address},
};
use ipnet::IpNet;
use sirinvpn_platform::windows::security;
use sirinvpn_tunnel_model::TunnelConnectRequest;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS},
        NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
        Networking::WinSock::*,
    },
    core::GUID,
};

mod dns;
pub(crate) use dns::resolvers;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Underlay {
    pub luid: u64,
    pub index: u32,
    pub next_hop: IpAddr,
    pub scope: u32,
    pub source: IpAddr,
    pub network_identity: Option<u128>,
}

pub(crate) fn configure_adapter(
    luid: NET_LUID_LH,
    request: &TunnelConnectRequest,
) -> io::Result<()> {
    require_adapter(luid)?;
    for family in [AF_INET, AF_INET6] {
        if family == AF_INET6 && request.client_ipv6_address.is_none() {
            continue;
        }
        set_mtu(luid, family, request.mtu)?;
    }
    add_address(luid, request.client_address.into())?;
    if let Some(address) = request.client_ipv6_address {
        add_address(luid, address.into())?;
    }
    let mut guid = GUID::default();
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    let mut name = security::wide(&request.dns_address.to_string())?;
    let dns = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(
            DNS_SETTING_NAMESERVER
                | DNS_SETTING_REGISTRATION_ENABLED
                | DNS_SETTING_REGISTER_ADAPTER_NAME
                | DNS_SETTINGS_ENABLE_LLMNR
                | DNS_SETTINGS_QUERY_ADAPTER_NAME,
        ),
        NameServer: name.as_mut_ptr(),
        ..Default::default()
    };
    check(unsafe { SetInterfaceDnsSettings(guid, &dns) })
}

pub(crate) fn set_mtu(luid: NET_LUID_LH, family: ADDRESS_FAMILY, mtu: u16) -> io::Result<()> {
    require_adapter(luid)?;
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe {
        InitializeIpInterfaceEntry(&mut row);
    }
    row.Family = family;
    row.InterfaceLuid = luid;
    check(unsafe { GetIpInterfaceEntry(&mut row) })?;
    row.NlMtu = u32::from(mtu);
    row.UseAutomaticMetric = false;
    row.Metric = 0;
    row.ForwardingEnabled = false;
    row.WeakHostSend = false;
    row.WeakHostReceive = false;
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.DadTransmits = 0;
    row.SitePrefixLength = 0;
    check(unsafe { SetIpInterfaceEntry(&mut row) })
}

fn add_address(luid: NET_LUID_LH, address: IpAddr) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
    }
    row.InterfaceLuid = luid;
    row.Address = socket_address(SocketAddr::new(address, 0));
    row.OnLinkPrefixLength = if address.is_ipv4() { 32 } else { 128 };
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row.DadState = IpDadStatePreferred;
    let code = unsafe { CreateUnicastIpAddressEntry(&row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        // This adapter was created/opened by the service and its GUID was checked.
        check(unsafe { GetUnicastIpAddressEntry(&mut row) })?;
        if row.OnLinkPrefixLength != if address.is_ipv4() { 32 } else { 128 } {
            return Err(invalid());
        }
        Ok(())
    } else {
        check(code)
    }
}

pub(crate) fn require_adapter(luid: NET_LUID_LH) -> io::Result<()> {
    let mut guid = GUID::default();
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    if !guid_equal(&guid, &ADAPTER_GUID) {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn underlay(address: IpAddr, exclude_luid: Option<u64>) -> io::Result<Underlay> {
    let family = if address.is_ipv4() { AF_INET } else { AF_INET6 };
    let mut table = ptr::null_mut();
    check(unsafe { GetIpForwardTable2(family, &mut table) })?;
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    let _table = Table(table);
    if table.is_null() || unsafe { (*table).NumEntries } > 65536 {
        return Err(invalid());
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table).NumEntries as usize,
        )
    };
    let mut choices = Vec::new();
    for row in rows {
        let luid = unsafe { row.InterfaceLuid.Value };
        if Some(luid) == exclude_luid || row.Metric == OWNED_ROUTE_METRIC || row.Loopback {
            continue;
        }
        let Some(prefix) = address_of(row.DestinationPrefix.Prefix)
            .and_then(|address| IpNet::new(address, row.DestinationPrefix.PrefixLength).ok())
        else {
            continue;
        };
        if !prefix.contains(&address) {
            continue;
        }
        // Never use a surviving SirinVPN adapter as an underlay after a crash.
        let mut guid = GUID::default();
        if unsafe { ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid) } != 0
            || guid_equal(&guid, &ADAPTER_GUID)
        {
            continue;
        }
        let mut interface = MIB_IPINTERFACE_ROW {
            InterfaceLuid: row.InterfaceLuid,
            Family: family,
            ..Default::default()
        };
        if unsafe { GetIpInterfaceEntry(&mut interface) } != 0 || !interface.Connected {
            continue;
        }
        let Some(next_hop) = address_of(row.NextHop) else {
            continue;
        };
        let scope = if family == AF_INET6 {
            unsafe { row.NextHop.Ipv6.Anonymous.sin6_scope_id }
        } else {
            0
        };
        choices.push((
            prefix.prefix_len(),
            u64::from(row.Metric) + u64::from(interface.Metric),
            Underlay {
                luid,
                index: row.InterfaceIndex,
                next_hop,
                scope,
                source: if address.is_ipv4() {
                    Ipv4Addr::UNSPECIFIED.into()
                } else {
                    Ipv6Addr::UNSPECIFIED.into()
                },
                network_identity: None,
            },
        ));
    }
    choices.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut selected = choices
        .into_iter()
        .next()
        .map(|choice| choice.2)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "no usable Windows underlay route",
            )
        })?;
    let luid = NET_LUID_LH {
        Value: selected.luid,
    };
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let mut destination = SocketAddr::new(address, 0);
    if let SocketAddr::V6(destination) = &mut destination
        && destination.ip().is_unicast_link_local()
    {
        destination.set_scope_id(selected.index);
    }
    check(unsafe {
        GetBestRoute2(
            &luid,
            selected.index,
            ptr::null(),
            &socket_address(destination),
            0,
            &mut best,
            &mut source,
        )
    })?;
    selected.source = address_of(source).ok_or_else(invalid)?;
    selected.network_identity =
        sirinvpn_platform::windows::network_context::identity_for_interface(selected.luid);
    Ok(selected)
}

pub(crate) fn route(underlay: Underlay, destination: IpNet) -> RouteRecord {
    RouteRecord {
        tunnel: false,
        interface_luid: underlay.luid,
        interface_index: underlay.index,
        destination: destination.trunc().to_string(),
        next_hop: underlay.next_hop,
        scope_id: underlay.scope,
        metric: OWNED_ROUTE_METRIC,
    }
}

pub(crate) fn endpoint_route(underlay: Underlay, address: IpAddr) -> RouteRecord {
    route(underlay, host(address))
}

pub(crate) fn tunnel_routes(
    luid: NET_LUID_LH,
    request: &TunnelConnectRequest,
) -> io::Result<Vec<RouteRecord>> {
    require_adapter(luid)?;
    let mut index = 0;
    check(unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) })?;
    let routes = network_plan::tunnel_routes(request)
        .into_iter()
        .map(|network| {
            let next_hop = if network.addr().is_ipv4() {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            };
            let mut route = route(
                Underlay {
                    luid: unsafe { luid.Value },
                    index,
                    next_hop,
                    scope: 0,
                    source: next_hop,
                    network_identity: None,
                },
                network,
            );
            route.tunnel = true;
            route.metric = if request.routing.mode
                == sirinvpn_tunnel_model::TunnelRoutingMode::SelectedApplications
                && network.to_string() == "0.0.0.0/0"
            {
                network_plan::APPLICATION_ROUTE_METRIC
            } else {
                0
            };
            route
        })
        .collect::<Vec<_>>();
    if routes.len() > 1024 {
        return Err(invalid());
    }
    Ok(routes)
}

pub(crate) fn route_exists(record: &RouteRecord) -> io::Result<bool> {
    let mut row = row(record)?;
    let code = unsafe { GetIpForwardEntry2(&mut row) };
    if code == ERROR_NOT_FOUND {
        return Ok(false);
    }
    check(code)?;
    Ok(true)
}

pub(crate) fn create_route(record: &RouteRecord) -> io::Result<()> {
    if record.tunnel {
        require_adapter(NET_LUID_LH {
            Value: record.interface_luid,
        })?;
    }
    check(unsafe { CreateIpForwardEntry2(&row(record)?) })
}

/// A missing route or one replaced by another administrator is no longer ours.
/// Never delete a foreign replacement or enumerate/delete general default routes.
pub(crate) fn remove_owned_route(record: &RouteRecord) -> io::Result<()> {
    if record.tunnel
        && require_adapter(NET_LUID_LH {
            Value: record.interface_luid,
        })
        .is_err()
    {
        return Ok(());
    }
    let mut row = row(record)?;
    let code = unsafe { GetIpForwardEntry2(&mut row) };
    if code == ERROR_NOT_FOUND {
        return Ok(());
    }
    check(code)?;
    if row.Metric != record.metric || row.Protocol != MIB_IPPROTO_NETMGMT {
        return Ok(());
    }
    let code = unsafe { DeleteIpForwardEntry2(&row) };
    if code == ERROR_NOT_FOUND {
        Ok(())
    } else {
        check(code)
    }
}

fn row(record: &RouteRecord) -> io::Result<MIB_IPFORWARD_ROW2> {
    if !record.validate() {
        return Err(invalid());
    }
    let network: IpNet = record.destination.parse().map_err(|_| invalid())?;
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }
    row.InterfaceLuid.Value = record.interface_luid;
    row.InterfaceIndex = record.interface_index;
    row.DestinationPrefix.Prefix = socket_address(SocketAddr::new(network.addr(), 0));
    row.DestinationPrefix.PrefixLength = network.prefix_len();
    let mut next = SocketAddr::new(record.next_hop, 0);
    if let SocketAddr::V6(next) = &mut next {
        next.set_scope_id(record.scope_id);
    }
    row.NextHop = socket_address(next);
    row.Metric = record.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Publish = false;
    Ok(row)
}

pub(crate) fn protect_socket(
    socket: &socket2::Socket,
    interface: Underlay,
    ipv6: bool,
) -> io::Result<()> {
    sirinvpn_platform::windows::sockets::exclusive(socket)?;
    use std::os::windows::io::AsRawSocket;
    let index = if ipv6 {
        interface.index
    } else {
        interface.index.to_be()
    };
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            if ipv6 { IPPROTO_IPV6 } else { IPPROTO_IP },
            if ipv6 { IPV6_UNICAST_IF } else { IP_UNICAST_IF },
            ptr::addr_of!(index).cast(),
            size_of::<u32>() as i32,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

pub(crate) fn address_of(value: SOCKADDR_INET) -> Option<IpAddr> {
    unsafe {
        match value.si_family {
            AF_INET => Some(Ipv4Addr::from(value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()),
            AF_INET6 => Some(Ipv6Addr::from(value.Ipv6.sin6_addr.u.Byte).into()),
            _ => None,
        }
    }
}
fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid owned Windows route or interface",
    )
}
