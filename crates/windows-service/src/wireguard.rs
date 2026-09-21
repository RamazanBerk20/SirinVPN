//! Minimal bindings to WireGuardNT's dual-licensed C ABI (GPL-2.0 OR MIT).
//! ABI source: https://git.zx2c4.com/wireguard-nt/tree/api/wireguard.h
//! Copyright (C) 2018-2026 WireGuard LLC. See THIRD-PARTY-NOTICES for the MIT notice.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use sirinvpn_platform::windows::{ProtectedProgramFile, open_protected_program, security};
use std::{ffi::c_void, io, net::SocketAddr, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::{
    Win32::{
        Foundation::{FreeLibrary, HMODULE},
        NetworkManagement::Ndis::NET_LUID_LH,
        Networking::WinSock::*,
        System::LibraryLoader::*,
    },
    core::{BOOL, GUID},
};
use zeroize::Zeroizing;

pub(crate) const ADAPTER_GUID: GUID = GUID::from_u128(0x2b9759b8_c48e_4bca_ac5a_b0e9a197da13);
pub(crate) const ADAPTER_NAME: &str = "SirinVPN";
type AdapterHandle = *mut c_void;
type CreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(AdapterHandle);
type GetLuid = unsafe extern "system" fn(AdapterHandle, *mut NET_LUID_LH);
type SetState = unsafe extern "system" fn(AdapterHandle, i32) -> BOOL;
type SetLogging = unsafe extern "system" fn(AdapterHandle, i32) -> BOOL;
type SetConfiguration = unsafe extern "system" fn(AdapterHandle, *const Interface, u32) -> BOOL;
type GetConfiguration = unsafe extern "system" fn(AdapterHandle, *mut Interface, *mut u32) -> BOOL;

#[repr(C, align(8))]
struct Interface {
    flags: u32,
    listen_port: u16,
    private_key: [u8; 32],
    public_key: [u8; 32],
    peers_count: u32,
}
#[repr(C, align(8))]
struct Peer {
    flags: u32,
    reserved: u32,
    public_key: [u8; 32],
    preshared_key: [u8; 32],
    keepalive: u16,
    endpoint: SOCKADDR_INET,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake: u64,
    allowed_count: u32,
}
#[repr(C, align(8))]
struct AllowedIp {
    address: [u8; 16],
    family: u16,
    cidr: u8,
    flags: u32,
}

const _: () = {
    assert!(size_of::<Interface>() == 80);
    assert!(size_of::<Peer>() == 136);
    assert!(size_of::<AllowedIp>() == 24);
};

struct Library(HMODULE);
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

pub(crate) struct Adapter {
    handle: AdapterHandle,
    close: CloseAdapter,
    set_state: SetState,
    set_configuration: SetConfiguration,
    get_configuration: GetConfiguration,
    luid: NET_LUID_LH,
    _library: Library,
    _verified_file: ProtectedProgramFile,
}

// The adapter is owned by the single service controller. Its handle may move
// between executor threads; concurrent configuration is prevented by that owner.
unsafe impl Send for Adapter {}

impl Adapter {
    pub(crate) fn create() -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let directory = executable.parent().ok_or_else(invalid)?;
        let path = directory.join("wireguard.dll");
        let verified_file = open_protected_program(&path)?;
        verify_vendor_library(&path)?;
        let name = wide_path(&path)?;
        // Dependencies resolve from the protected DLL directory and System32 only.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let library = Library(module);
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                let value = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }
                    .ok_or_else(invalid)?;
                // Each signature is taken from the corresponding WireGuardNT C typedef.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(value) }
            }};
        }
        let create = symbol!("WireGuardCreateAdapter", CreateAdapter);
        let close = symbol!("WireGuardCloseAdapter", CloseAdapter);
        let get_luid = symbol!("WireGuardGetAdapterLUID", GetLuid);
        let set_state = symbol!("WireGuardSetAdapterState", SetState);
        let set_logging = symbol!("WireGuardSetAdapterLogging", SetLogging);
        let set_configuration = symbol!("WireGuardSetConfiguration", SetConfiguration);
        let get_configuration = symbol!("WireGuardGetConfiguration", GetConfiguration);
        let name = security::wide(ADAPTER_NAME)?;
        let handle = unsafe { create(name.as_ptr(), name.as_ptr(), &ADAPTER_GUID) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut result = Self {
            handle,
            close,
            set_state,
            set_configuration,
            get_configuration,
            luid: NET_LUID_LH::default(),
            _library: library,
            _verified_file: verified_file,
        };
        if unsafe { set_logging(handle, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            get_luid(handle, &mut result.luid);
        }
        Ok(result)
    }

    pub(crate) fn luid(&self) -> NET_LUID_LH {
        self.luid
    }

    pub(crate) fn configure(
        &self,
        private: &str,
        public: &str,
        endpoint: SocketAddr,
        routes: &[IpNet],
    ) -> io::Result<()> {
        if routes.is_empty() || routes.len() > 40 {
            return Err(invalid());
        }
        let private = Zeroizing::new(STANDARD.decode(private).map_err(|_| invalid())?);
        let public = STANDARD.decode(public).map_err(|_| invalid())?;
        if private.len() != 32 || public.len() != 32 {
            return Err(invalid());
        }
        let bytes =
            size_of::<Interface>() + size_of::<Peer>() + routes.len() * size_of::<AllowedIp>();
        // C requires eight-byte alignment for the variable-length configuration.
        // The allocation starts zeroed, including reserved fields and padding.
        let mut memory = Zeroizing::new(vec![0u64; bytes.div_ceil(8)]);
        let interface = unsafe { &mut *memory.as_mut_ptr().cast::<Interface>() };
        interface.flags = 2 | 8; // private key, replace peers
        interface.private_key.copy_from_slice(&private);
        interface.peers_count = 1;
        let base = memory.as_mut_ptr().cast::<u8>();
        let peer = unsafe { &mut *base.add(size_of::<Interface>()).cast::<Peer>() };
        peer.flags = 1 | 4 | 8 | 32; // public key, keepalive, endpoint, replace allowed IPs
        peer.public_key.copy_from_slice(&public);
        peer.keepalive = 25;
        peer.endpoint = socket_address(endpoint);
        peer.allowed_count = routes.len() as u32;
        for (index, route) in routes.iter().enumerate() {
            let allowed = unsafe {
                &mut *base
                    .add(
                        size_of::<Interface>() + size_of::<Peer>() + index * size_of::<AllowedIp>(),
                    )
                    .cast::<AllowedIp>()
            };
            allowed.cidr = route.prefix_len();
            match route {
                IpNet::V4(network) => {
                    allowed.family = AF_INET;
                    allowed.address[..4].copy_from_slice(&network.network().octets());
                }
                IpNet::V6(network) => {
                    allowed.family = AF_INET6;
                    allowed.address.copy_from_slice(&network.network().octets());
                }
            }
        }
        if unsafe { (self.set_configuration)(self.handle, base.cast(), bytes as u32) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn set_up(&self, up: bool) -> io::Result<()> {
        if unsafe { (self.set_state)(self.handle, i32::from(up)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn statistics(&self) -> io::Result<Statistics> {
        // One peer and at most forty routes; a larger driver reply is unexpected.
        let capacity = size_of::<Interface>() + size_of::<Peer>() + 40 * size_of::<AllowedIp>();
        let mut memory = Zeroizing::new(vec![0u64; capacity.div_ceil(8)]);
        let mut bytes = capacity as u32;
        if unsafe { (self.get_configuration)(self.handle, memory.as_mut_ptr().cast(), &mut bytes) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        if (bytes as usize) < size_of::<Interface>() + size_of::<Peer>()
            || bytes as usize > capacity
        {
            return Err(invalid());
        }
        let interface = unsafe { &*memory.as_ptr().cast::<Interface>() };
        if interface.peers_count != 1 {
            return Err(invalid());
        }
        let peer = unsafe {
            &*memory
                .as_ptr()
                .cast::<u8>()
                .add(size_of::<Interface>())
                .cast::<Peer>()
        };
        Ok(Statistics {
            rx_bytes: peer.rx_bytes,
            tx_bytes: peer.tx_bytes,
            last_handshake_unix: (peer.last_handshake != 0)
                .then_some(peer.last_handshake / 10_000_000)
                .and_then(|seconds| seconds.checked_sub(11_644_473_600)),
        })
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        unsafe {
            (self.set_state)(self.handle, 0);
            (self.close)(self.handle);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Statistics {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_unix: Option<u64>,
}

pub(crate) fn socket_address(address: SocketAddr) -> SOCKADDR_INET {
    match address {
        SocketAddr::V4(address) => {
            let mut value = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: address.port().to_be(),
                ..Default::default()
            };
            value.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.ip().octets());
            SOCKADDR_INET { Ipv4: value }
        }
        SocketAddr::V6(address) => {
            let mut value = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: address.port().to_be(),
                ..Default::default()
            };
            value.sin6_addr.u.Byte = address.ip().octets();
            value.Anonymous.sin6_scope_id = address.scope_id();
            SOCKADDR_INET { Ipv6: value }
        }
    }
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut result: Vec<u16> = path.as_os_str().encode_wide().collect();
    if result.contains(&0) || result.len() >= 32767 {
        return Err(invalid());
    }
    result.push(0);
    Ok(result)
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native WireGuard adapter configuration",
    )
}

pub(crate) fn verify_vendor_library(path: &Path) -> io::Result<()> {
    use std::io::Read;
    let lock: serde_json::Value =
        serde_json::from_str(include_str!("../../../packaging/windows/wireguard-nt.json"))
            .map_err(|_| invalid())?;
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return Err(invalid()),
    };
    let expected = lock["dll_sha256"][architecture]
        .as_str()
        .ok_or_else(invalid)?;
    let file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let size = std::io::copy(&mut file.take(8 * 1024 * 1024 + 1), &mut digest)?;
    if size == 0 || size > 8 * 1024 * 1024 || hex::encode(digest.finalize()) != expected {
        return Err(invalid());
    }
    Ok(())
}
