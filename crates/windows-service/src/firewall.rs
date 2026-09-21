//! Only SirinVPN's provider and sublayer are changed. Persistent/boot filters
//! never depend on the service process remaining alive; updates use BFE transactions.
// These C structures combine pointer unions and reserved fields. Initialize
// their complete native representation before filling each discriminator/value.
#![allow(clippy::field_reassign_with_default)]
use crate::{
    SERVICE_NAME,
    firewall_plan::{Condition, FirewallPlan, Layer, Rule},
};
use sirinvpn_platform::windows::security::{self, SecurityDescriptor};
use std::{ffi::c_void, io, os::windows::ffi::OsStrExt, ptr};
use windows_sys::{
    Win32::{
        Foundation::{FWP_E_ALREADY_EXISTS, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::GetSecurityDescriptorLength,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::GUID,
};

static PROVIDER: GUID = GUID::from_u128(0x8139b417_bdeb_475f_8131_9f47e90b5f20);
const SUBLAYER: GUID = GUID::from_u128(0xbc504a81_d821_418a_944a_f9db39b06321);
const FILTER_NAMESPACE: u128 = 0xa093ab89_975e_425d_a552_cfc000000000;
const MAX_FILTERS: usize = 1024;
const MARKER: &[u8] = b"SirinVPN WFP policy v1";
pub(crate) const BIND_KEY: GUID = GUID::from_u128(0x6e6de0cd_25db_48fb_a00c_3ba216771452);

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FwpmFreeMemory0(&mut self.0);
            }
        }
    }
}
struct Engine {
    handle: HANDLE,
    persistent: bool,
}
unsafe impl Send for Engine {}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.handle);
        }
    }
}

pub(crate) struct Firewall {
    persistent: Engine,
    dynamic: Engine,
    expected: Option<FirewallPlan>,
}

impl Firewall {
    pub(crate) fn open() -> io::Result<Self> {
        let persistent = Engine::open(true)?;
        persistent.register_provider()?;
        let dynamic = Engine::open(false)?;
        dynamic.register_callout()?;
        Ok(Self {
            persistent,
            dynamic,
            expected: None,
        })
    }

    pub(crate) fn apply(&mut self, plan: FirewallPlan) -> io::Result<()> {
        if plan.rules.len() > MAX_FILTERS {
            return Err(invalid());
        }
        if plan.persistent {
            // Durable policy contains no process/socket or reusable LUID permits.
            // Those are dynamic and vanish even if the service is terminated.
            self.persistent.replace(&plan.persistent_rules())?;
            self.dynamic.replace(&plan.dynamic_rules())?;
        } else {
            // Changing a persistent guard requires an explicit Disconnect.
            if !self.persistent.keys()?.is_empty() {
                return Err(invalid());
            }
            self.dynamic.replace(&plan.rules)?;
        }
        self.expected = Some(plan);
        if !self.verified()? {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn clear(&mut self) -> io::Result<()> {
        self.dynamic.replace(&[])?;
        self.persistent.replace(&[])?;
        self.expected = None;
        if !self.absent()? {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn uninstall(mut self) -> io::Result<()> {
        self.clear()?;
        check(unsafe { FwpmCalloutDeleteByKey0(self.dynamic.handle, &BIND_KEY) })?;
        // open() already verified these objects' service binding and private
        // ownership marker. Never enumerate or delete other providers.
        self.persistent.transaction(|| {
            check(unsafe { FwpmSubLayerDeleteByKey0(self.persistent.handle, &SUBLAYER) })?;
            check(unsafe { FwpmProviderDeleteByKey0(self.persistent.handle, &PROVIDER) })
        })
    }

    pub(crate) fn absent(&self) -> io::Result<bool> {
        Ok(self.persistent.keys()?.is_empty() && self.dynamic.keys()?.is_empty())
    }
    pub(crate) fn application_driver_registered(&self) -> bool {
        self.dynamic.callout_registered().unwrap_or(false)
    }
    pub(crate) fn verified(&self) -> io::Result<bool> {
        let Some(plan) = &self.expected else {
            return self.absent();
        };
        Ok(self.persistent.matches(&plan.persistent_rules())?
            && self.dynamic.matches(&plan.dynamic_rules())?)
    }
}

impl Engine {
    fn register_callout(&self) -> io::Result<()> {
        let mut title = security::wide("SirinVPN selected application routing")?;
        let mut callout = FWPM_CALLOUT0::default();
        callout.calloutKey = BIND_KEY;
        callout.displayData.name = title.as_mut_ptr();
        callout.providerKey = ptr::addr_of!(PROVIDER).cast_mut();
        callout.providerData = FWP_BYTE_BLOB {
            size: MARKER.len() as u32,
            data: MARKER.as_ptr().cast_mut(),
        };
        callout.applicableLayer = FWPM_LAYER_ALE_BIND_REDIRECT_V4;
        let sd = SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
        check(unsafe {
            FwpmCalloutAdd0(
                self.handle,
                &callout,
                sd.attributes().lpSecurityDescriptor,
                ptr::null_mut(),
            )
        })
    }

    fn callout_registered(&self) -> io::Result<bool> {
        let mut found = ptr::null_mut();
        check(unsafe { FwpmCalloutGetByKey0(self.handle, &BIND_KEY, &mut found) })?;
        let _memory = Allocation(found.cast());
        if found.is_null() {
            return Ok(false);
        }
        let found = unsafe { &*found };
        Ok(found.flags & FWPM_CALLOUT_FLAG_REGISTERED != 0
            && !found.providerKey.is_null()
            && guid_equal(unsafe { &*found.providerKey }, &PROVIDER)
            && guid_equal(&found.applicableLayer, &FWPM_LAYER_ALE_BIND_REDIRECT_V4))
    }

    fn open(persistent: bool) -> io::Result<Self> {
        let mut session = FWPM_SESSION0::default();
        session.flags = if persistent {
            0
        } else {
            FWPM_SESSION_FLAG_DYNAMIC
        };
        session.txnWaitTimeoutInMSec = 5000;
        let mut handle = ptr::null_mut();
        check(unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            )
        })?;
        Ok(Self { handle, persistent })
    }

    fn transaction(&self, operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.handle, 0) })?;
        let result =
            operation().and_then(|()| check(unsafe { FwpmTransactionCommit0(self.handle) }));
        if result.is_err() {
            unsafe {
                FwpmTransactionAbort0(self.handle);
            }
        }
        result
    }

    fn register_provider(&self) -> io::Result<()> {
        self.transaction(|| {
            let mut title = security::wide("SirinVPN traffic protection")?;
            let mut service = security::wide(SERVICE_NAME)?;
            let sd = SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
            let mut provider = FWPM_PROVIDER0::default();
            provider.providerKey = PROVIDER;
            provider.displayData.name = title.as_mut_ptr();
            provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
            provider.serviceName = service.as_mut_ptr();
            provider.providerData = FWP_BYTE_BLOB {
                size: MARKER.len() as u32,
                data: MARKER.as_ptr().cast_mut(),
            };
            let code = unsafe {
                FwpmProviderAdd0(self.handle, &provider, sd.attributes().lpSecurityDescriptor)
            };
            if code == FWP_E_ALREADY_EXISTS as u32 {
                let mut found = ptr::null_mut();
                check(unsafe { FwpmProviderGetByKey0(self.handle, &PROVIDER, &mut found) })?;
                let _memory = Allocation(found.cast());
                if found.is_null() {
                    return Err(invalid());
                }
                let found = unsafe { &*found };
                if found.flags & FWPM_PROVIDER_FLAG_PERSISTENT == 0
                    || !blob_equals(&found.providerData, &provider.providerData)
                    || !wide_equals(found.serviceName, &service)
                {
                    return Err(invalid());
                }
            } else {
                check(code)?;
            }
            let mut sublayer = FWPM_SUBLAYER0::default();
            sublayer.subLayerKey = SUBLAYER;
            sublayer.providerKey = ptr::addr_of!(PROVIDER).cast_mut();
            sublayer.displayData.name = title.as_mut_ptr();
            sublayer.weight = u16::MAX;
            sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
            sublayer.providerData = provider.providerData;
            let code = unsafe {
                FwpmSubLayerAdd0(self.handle, &sublayer, sd.attributes().lpSecurityDescriptor)
            };
            if code == FWP_E_ALREADY_EXISTS as u32 {
                let mut found = ptr::null_mut();
                check(unsafe { FwpmSubLayerGetByKey0(self.handle, &SUBLAYER, &mut found) })?;
                let _memory = Allocation(found.cast());
                if found.is_null() {
                    return Err(invalid());
                }
                let found = unsafe { &*found };
                if found.providerKey.is_null()
                    || !guid_equal(unsafe { &*found.providerKey }, &PROVIDER)
                    || found.weight != u16::MAX
                    || found.flags != sublayer.flags
                    || !blob_equals(&found.providerData, &sublayer.providerData)
                {
                    return Err(invalid());
                }
            } else {
                check(code)?;
            }
            Ok(())
        })
    }

    fn replace(&self, rules: &[Rule]) -> io::Result<()> {
        self.transaction(|| {
            for key in self.keys()? {
                check(unsafe { FwpmFilterDeleteByKey0(self.handle, &key) })?;
            }
            let resources = Resources::new()?;
            for (index, rule) in rules.iter().enumerate() {
                if rule.boot && !self.persistent {
                    return Err(invalid());
                }
                let mut native = NativeRule::new(rule, &resources)?;
                let mut title = security::wide("SirinVPN current traffic policy")?;
                let mut weight = rule.weight;
                let mut filter = FWPM_FILTER0::default();
                filter.filterKey = filter_key(index, self.persistent);
                filter.displayData.name = title.as_mut_ptr();
                filter.providerKey = ptr::addr_of!(PROVIDER).cast_mut();
                filter.subLayerKey = SUBLAYER;
                filter.layerKey = layer_key(rule.layer);
                filter.flags = self.flags(rule);
                filter.weight.r#type = FWP_UINT64;
                filter.weight.Anonymous.uint64 = &mut weight;
                filter.action.r#type = if rule.bind_address.is_some() {
                    FWP_ACTION_CALLOUT_TERMINATING
                } else if rule.permit {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                };
                if let Some(source) = rule.bind_address {
                    filter.action.Anonymous.calloutKey = BIND_KEY;
                    filter.Anonymous.rawContext = bind_context(source);
                }
                filter.numFilterConditions = native.conditions.len() as u32;
                filter.filterCondition = native.conditions.as_mut_ptr();
                // Soft permits respect other installed firewall restrictions.
                // Blocks retain WFP's default hard-block behavior.
                check(unsafe {
                    FwpmFilterAdd0(
                        self.handle,
                        &filter,
                        resources.object_sd.attributes().lpSecurityDescriptor,
                        ptr::null_mut(),
                    )
                })?;
            }
            Ok(())
        })
    }

    fn flags(&self, rule: &Rule) -> u32 {
        if rule.boot {
            FWPM_FILTER_FLAG_BOOTTIME
        } else if self.persistent {
            FWPM_FILTER_FLAG_PERSISTENT
        } else {
            0
        }
    }

    fn keys(&self) -> io::Result<Vec<GUID>> {
        let mut result = Vec::new();
        for layer in Layer::ALL {
            let mut query = FWPM_FILTER_ENUM_TEMPLATE0::default();
            query.providerKey = ptr::addr_of!(PROVIDER).cast_mut();
            query.layerKey = layer_key(layer);
            query.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
            query.flags =
                FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
            query.actionMask = u32::MAX;
            let mut handle = ptr::null_mut();
            check(unsafe { FwpmFilterCreateEnumHandle0(self.handle, &query, &mut handle) })?;
            struct Enumeration {
                engine: HANDLE,
                handle: HANDLE,
            }
            impl Drop for Enumeration {
                fn drop(&mut self) {
                    unsafe {
                        FwpmFilterDestroyEnumHandle0(self.engine, self.handle);
                    }
                }
            }
            let _enumeration = Enumeration {
                engine: self.handle,
                handle,
            };
            let mut entries = ptr::null_mut();
            let mut count = 0;
            check(unsafe {
                FwpmFilterEnum0(
                    self.handle,
                    handle,
                    (MAX_FILTERS + 1) as u32,
                    &mut entries,
                    &mut count,
                )
            })?;
            let _memory = Allocation(entries.cast());
            if count as usize > MAX_FILTERS || count > 0 && entries.is_null() {
                return Err(invalid());
            }
            for index in 0..count as usize {
                let filter = unsafe { *entries.add(index) };
                if filter.is_null() {
                    return Err(invalid());
                }
                let filter = unsafe { &*filter };
                if !guid_equal(&filter.subLayerKey, &SUBLAYER) {
                    return Err(invalid());
                }
                if filter.filterKey.data1 != filter_key(0, self.persistent).data1
                    || filter.filterKey.data2 != filter_key(0, self.persistent).data2
                    || filter.filterKey.data3 != filter_key(0, self.persistent).data3
                {
                    return Err(invalid());
                }
                if filter.filterKey.data4[..6] == filter_key(0, self.persistent).data4[..6] {
                    result.push(filter.filterKey);
                } else if filter.filterKey.data4[..6] != filter_key(0, !self.persistent).data4[..6]
                {
                    return Err(invalid());
                }
            }
        }
        if result.len() > MAX_FILTERS {
            return Err(invalid());
        }
        Ok(result)
    }

    fn matches(&self, rules: &[Rule]) -> io::Result<bool> {
        if self.keys()?.len() != rules.len() {
            return Ok(false);
        }
        let resources = Resources::new()?;
        for (index, rule) in rules.iter().enumerate() {
            let mut found = ptr::null_mut();
            check(unsafe {
                FwpmFilterGetByKey0(self.handle, &filter_key(index, self.persistent), &mut found)
            })?;
            let _memory = Allocation(found.cast());
            if found.is_null() {
                return Ok(false);
            }
            let found = unsafe { &*found };
            let expected = NativeRule::new(rule, &resources)?;
            if !guid_equal(&found.layerKey, &layer_key(rule.layer))
                || !guid_equal(&found.subLayerKey, &SUBLAYER)
                || found.flags != self.flags(rule)
                || found.action.r#type
                    != if rule.bind_address.is_some() {
                        FWP_ACTION_CALLOUT_TERMINATING
                    } else if rule.permit {
                        FWP_ACTION_PERMIT
                    } else {
                        FWP_ACTION_BLOCK
                    }
                || found.weight.r#type != FWP_UINT64
                || unsafe { found.weight.Anonymous.uint64.is_null() }
                || unsafe { *found.weight.Anonymous.uint64 } != rule.weight
                || found.numFilterConditions as usize != expected.conditions.len()
                || found.numFilterConditions > 0 && found.filterCondition.is_null()
            {
                return Ok(false);
            }
            if let Some(source) = rule.bind_address
                && (!guid_equal(unsafe { &found.action.Anonymous.calloutKey }, &BIND_KEY)
                    || unsafe { found.Anonymous.rawContext } != bind_context(source))
            {
                return Ok(false);
            }
            for (index, condition) in expected.conditions.iter().enumerate() {
                if !condition_equal(unsafe { &*found.filterCondition.add(index) }, condition) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

struct Resources {
    app: Allocation,
    system_sd: SecurityDescriptor,
    object_sd: SecurityDescriptor,
}
impl Resources {
    fn new() -> io::Result<Self> {
        let mut path: Vec<u16> = std::env::current_exe()?.as_os_str().encode_wide().collect();
        if path.contains(&0) {
            return Err(invalid());
        }
        path.push(0);
        let mut app = ptr::null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app) })?;
        Ok(Self {
            app: Allocation(app.cast()),
            system_sd: SecurityDescriptor::from_sddl("O:SYG:SYD:(A;;1;;;SY)")?,
            object_sd: SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?,
        })
    }
}

// Boxed values do not move when another condition is appended. Each allocation
// remains alive across FwpmFilterAdd/Get comparison, including pointer unions.
#[allow(clippy::vec_box)] // Stable addresses are passed through WFP pointer unions.
struct NativeRule {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    numbers: Vec<Box<u64>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    blobs: Vec<Box<FWP_BYTE_BLOB>>,
    user_descriptors: Vec<SecurityDescriptor>,
}
impl NativeRule {
    fn new(rule: &Rule, resources: &Resources) -> io::Result<Self> {
        let mut result = Self {
            conditions: Vec::new(),
            numbers: Vec::new(),
            v4: Vec::new(),
            v6: Vec::new(),
            blobs: Vec::new(),
            user_descriptors: Vec::new(),
        };
        for value in &rule.conditions {
            let mut condition = FWPM_FILTER_CONDITION0::default();
            condition.matchType = FWP_MATCH_EQUAL;
            let native = &mut condition.conditionValue;
            match value {
                Condition::Application(bytes) => {
                    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    native.r#type = FWP_BYTE_BLOB_TYPE;
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size: bytes.len() as u32,
                        data: bytes.as_ptr().cast_mut(),
                    });
                    native.Anonymous.byteBlob = &mut *blob;
                    result.blobs.push(blob);
                }
                Condition::User(sid) => {
                    // SID originates in named-pipe impersonation or the validated
                    // SYSTEM journal, never from the caller's JSON payload.
                    if sid.len() > 184
                        || !sid.starts_with("S-1-")
                        || !sid
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-'))
                    {
                        return Err(invalid());
                    }
                    let descriptor =
                        SecurityDescriptor::from_sddl(&format!("O:SYG:SYD:(A;;1;;;{sid})"))?;
                    let pointer = descriptor.attributes().lpSecurityDescriptor;
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size: unsafe { GetSecurityDescriptorLength(pointer) },
                        data: pointer.cast(),
                    });
                    condition.fieldKey = FWPM_CONDITION_ALE_USER_ID;
                    native.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
                    native.Anonymous.sd = &mut *blob;
                    result.blobs.push(blob);
                    result.user_descriptors.push(descriptor);
                }
                Condition::ServiceApplication => {
                    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    native.r#type = FWP_BYTE_BLOB_TYPE;
                    native.Anonymous.byteBlob = resources.app.0.cast();
                }
                Condition::SystemUser => {
                    condition.fieldKey = FWPM_CONDITION_ALE_USER_ID;
                    native.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
                    let pointer = resources.system_sd.attributes().lpSecurityDescriptor;
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size: unsafe { GetSecurityDescriptorLength(pointer) },
                        data: pointer.cast(),
                    });
                    native.Anonymous.sd = &mut *blob;
                    result.blobs.push(blob);
                }
                Condition::Interface(luid) => {
                    condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                    native.r#type = FWP_UINT64;
                    let mut value = Box::new(*luid);
                    native.Anonymous.uint64 = &mut *value;
                    result.numbers.push(value);
                }
                Condition::Remote(address) => {
                    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    match address {
                        ipnet::IpNet::V4(address) => {
                            let mut mask = Box::new(FWP_V4_ADDR_AND_MASK {
                                addr: u32::from(address.network()),
                                mask: u32::from(address.netmask()),
                            });
                            native.r#type = FWP_V4_ADDR_MASK;
                            native.Anonymous.v4AddrMask = &mut *mask;
                            result.v4.push(mask);
                        }
                        ipnet::IpNet::V6(address) => {
                            let mut mask = Box::new(FWP_V6_ADDR_AND_MASK {
                                addr: address.network().octets(),
                                prefixLength: address.prefix_len(),
                            });
                            native.r#type = FWP_V6_ADDR_MASK;
                            native.Anonymous.v6AddrMask = &mut *mask;
                            result.v6.push(mask);
                        }
                    }
                }
                Condition::RemotePort(value)
                | Condition::LocalPort(value)
                | Condition::IcmpType(value)
                | Condition::IcmpCode(value) => {
                    native.r#type = FWP_UINT16;
                    native.Anonymous.uint16 = *value;
                }
                Condition::Protocol(value) => {
                    condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    native.r#type = FWP_UINT8;
                    native.Anonymous.uint8 = *value;
                }
                Condition::Loopback => {
                    condition.fieldKey = FWPM_CONDITION_FLAGS;
                    condition.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    native.r#type = FWP_UINT32;
                    native.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                }
            }
            // These scalar fields share the same native value representation.
            condition.fieldKey = match value {
                Condition::RemotePort(_) => FWPM_CONDITION_IP_REMOTE_PORT,
                Condition::LocalPort(_) => FWPM_CONDITION_IP_LOCAL_PORT,
                // These are the ICMP aliases defined by fwpmu.h.
                Condition::IcmpType(_) => FWPM_CONDITION_IP_LOCAL_PORT,
                Condition::IcmpCode(_) => FWPM_CONDITION_IP_REMOTE_PORT,
                _ => condition.fieldKey,
            };
            result.conditions.push(condition);
        }
        Ok(result)
    }
}

fn condition_equal(a: &FWPM_FILTER_CONDITION0, b: &FWPM_FILTER_CONDITION0) -> bool {
    if !guid_equal(&a.fieldKey, &b.fieldKey)
        || a.matchType != b.matchType
        || a.conditionValue.r#type != b.conditionValue.r#type
    {
        return false;
    }
    let x = a.conditionValue.Anonymous;
    let y = b.conditionValue.Anonymous;
    unsafe {
        match a.conditionValue.r#type {
            FWP_UINT8 => x.uint8 == y.uint8,
            FWP_UINT16 => x.uint16 == y.uint16,
            FWP_UINT32 => x.uint32 == y.uint32,
            FWP_UINT64 => !x.uint64.is_null() && !y.uint64.is_null() && *x.uint64 == *y.uint64,
            FWP_BYTE_BLOB_TYPE | FWP_SECURITY_DESCRIPTOR_TYPE => {
                !x.byteBlob.is_null()
                    && !y.byteBlob.is_null()
                    && blob_equals(&*x.byteBlob, &*y.byteBlob)
            }
            FWP_V4_ADDR_MASK => {
                !x.v4AddrMask.is_null()
                    && !y.v4AddrMask.is_null()
                    && (*x.v4AddrMask).addr == (*y.v4AddrMask).addr
                    && (*x.v4AddrMask).mask == (*y.v4AddrMask).mask
            }
            FWP_V6_ADDR_MASK => {
                !x.v6AddrMask.is_null()
                    && !y.v6AddrMask.is_null()
                    && (*x.v6AddrMask).addr == (*y.v6AddrMask).addr
                    && (*x.v6AddrMask).prefixLength == (*y.v6AddrMask).prefixLength
            }
            _ => false,
        }
    }
}

fn blob_equals(a: &FWP_BYTE_BLOB, b: &FWP_BYTE_BLOB) -> bool {
    a.size == b.size
        && a.size <= 65536
        && (a.size == 0
            || !a.data.is_null()
                && !b.data.is_null()
                && unsafe {
                    std::slice::from_raw_parts(a.data, a.size as usize)
                        == std::slice::from_raw_parts(b.data, b.size as usize)
                })
}
fn wide_equals(value: *const u16, expected: &[u16]) -> bool {
    !value.is_null()
        && expected
            .iter()
            .enumerate()
            .all(|(index, expected)| unsafe { *value.add(index) == *expected })
}
fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ReceiveV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::ReceiveV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        Layer::BindV4 => FWPM_LAYER_ALE_BIND_REDIRECT_V4,
    }
}
fn bind_context(source: std::net::Ipv4Addr) -> u64 {
    (u64::from(crate::application_plan::BIND_CONTEXT_TAG) << 32)
        | u64::from(u32::from_le_bytes(source.octets()))
}
fn filter_key(index: usize, persistent: bool) -> GUID {
    GUID::from_u128(FILTER_NAMESPACE + (if persistent { 0 } else { 0x10000 }) + index as u128 + 1)
}
pub(crate) fn guid_equal(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
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
        "the owned Windows firewall policy could not be verified",
    )
}
