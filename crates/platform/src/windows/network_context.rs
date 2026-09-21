//! Read only the current physical route and its Windows network identity. No
//! BSSID, network history, location permission, or connectivity probe. Saved
//! network names are resolved separately only for the local settings display.
use std::ptr;
use windows::{
    Win32::{Foundation::RPC_E_CHANGED_MODE, Networking::NetworkListManager::*, System::Com::*},
    core::GUID,
};
use windows_sys::Win32::{
    NetworkManagement::{
        IpHelper::*,
        Ndis::{IfOperStatusUp, NET_LUID_LH},
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};
use zeroize::Zeroizing;

pub struct CurrentNetwork {
    pub identifier: Zeroizing<String>,
    pub wifi: bool,
    pub trustable: bool,
}

pub fn discover() -> Option<CurrentNetwork> {
    let mut raw = ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut raw) } != 0 {
        return None;
    }
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    let _table = Table(raw);
    if raw.is_null() || unsafe { (*raw).NumEntries } > 65536 {
        return None;
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*raw).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*raw).NumEntries as usize,
        )
    };
    let mut best: Option<(u64, u64, bool, String)> = None;
    for route in rows {
        if route.DestinationPrefix.PrefixLength != 0 || route.Loopback {
            continue;
        }
        let mut interface = MIB_IF_ROW2 {
            InterfaceLuid: route.InterfaceLuid,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut interface) } != 0
            || interface.OperStatus != IfOperStatusUp
            || !matches!(
                interface.Type,
                IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 | IF_TYPE_WWANPP | IF_TYPE_WWANPP2
            )
        {
            continue;
        }
        let family = unsafe { route.DestinationPrefix.Prefix.si_family };
        if !matches!(family, AF_INET | AF_INET6) {
            continue;
        }
        let mut ip = MIB_IPINTERFACE_ROW {
            InterfaceLuid: route.InterfaceLuid,
            Family: family,
            ..Default::default()
        };
        if unsafe { GetIpInterfaceEntry(&mut ip) } != 0 || !ip.Connected {
            continue;
        }
        let metric = u64::from(route.Metric) + u64::from(ip.Metric);
        if best.as_ref().is_some_and(|value| value.0 <= metric) {
            continue;
        }
        let next_hop = unsafe {
            if family == AF_INET {
                format!("{:08x}", route.NextHop.Ipv4.sin_addr.S_un.S_addr)
            } else {
                format!("{:02x?}", route.NextHop.Ipv6.sin6_addr.u.Byte)
            }
        };
        best = Some((
            metric,
            unsafe { route.InterfaceLuid.Value },
            interface.Type == IF_TYPE_IEEE80211,
            next_hop,
        ));
    }
    let (_, luid, wifi, gateway) = best?;
    let network_id = identity_for_interface(luid);
    let identifier = network_id.map_or_else(
        || format!("windows-route:v1:{luid:016x}:{gateway}"),
        |id| format!("windows-network:v1:{id:032x}"),
    );
    Some(CurrentNetwork {
        identifier: Zeroizing::new(identifier),
        wifi,
        trustable: wifi && network_id.is_some(),
    })
}

/// The opaque ID remains in memory. Callers must salt and hash it before saving
/// a user-selected trust record, and must never write a list of observed networks.
pub fn identity_for_interface(luid: u64) -> Option<u128> {
    let mut adapter = windows_sys::core::GUID::default();
    if unsafe { ConvertInterfaceLuidToGuid(&NET_LUID_LH { Value: luid }, &mut adapter) } != 0 {
        return None;
    }
    let adapter = GUID::from_values(adapter.data1, adapter.data2, adapter.data3, adapter.data4);
    let (_apartment, manager) = network_manager()?;
    let connections = unsafe { manager.GetNetworkConnections() }.ok()?;
    let mut selected = None;
    for _ in 0..256 {
        let mut connection = [None];
        let mut fetched = 0;
        unsafe { connections.Next(&mut connection, Some(&mut fetched)) }.ok()?;
        if fetched == 0 {
            return selected;
        }
        let connection = connection[0].take()?;
        if unsafe { connection.IsConnected() }.ok()?.0 == 0
            || unsafe { connection.GetAdapterId() }.ok()? != adapter
        {
            continue;
        }
        let network = unsafe { connection.GetNetwork() }.ok()?;
        let id = unsafe { network.GetNetworkId() }.ok()?.to_u128();
        if id == 0 || selected.is_some_and(|previous| previous != id) {
            return None;
        }
        selected = Some(id);
    }
    None
}

/// Read names only for the caller's current/trusted IDs; never persist or log them.
pub fn display_names(
    wanted: impl Fn(&str) -> Option<String>,
) -> std::collections::BTreeMap<String, String> {
    let mut names = std::collections::BTreeMap::new();
    let Some((_apartment, manager)) = network_manager() else {
        return names;
    };
    let Ok(networks) = (unsafe { manager.GetNetworks(NLM_ENUM_NETWORK_ALL) }) else {
        return names;
    };
    for _ in 0..4096 {
        let mut entry = [None];
        let mut fetched = 0;
        if unsafe { networks.Next(&mut entry, Some(&mut fetched)) }.is_err() || fetched == 0 {
            break;
        }
        let Some(network) = entry[0].take() else {
            continue;
        };
        let Ok(id) = (unsafe { network.GetNetworkId() }) else {
            continue;
        };
        let Some(key) = wanted(&format!("windows-network:v1:{:032x}", id.to_u128())) else {
            continue;
        };
        if let Ok(name) = unsafe { network.GetName() } {
            names.insert(key, name.to_string());
        }
    }
    names
}

struct Apartment(bool);
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn network_manager() -> Option<(Apartment, INetworkListManager)> {
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if initialized.is_err() && initialized != RPC_E_CHANGED_MODE {
        return None;
    }
    let apartment = Apartment(initialized.is_ok());
    let manager: INetworkListManager =
        unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }.ok()?;
    Some((apartment, manager))
}
