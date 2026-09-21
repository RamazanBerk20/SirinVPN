//! Owned Windows security descriptors and current-user checks.
use std::{
    ffi::c_void,
    io,
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::{
    Foundation::{HANDLE, LocalFree},
    Security::{
        self, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, Authorization::*, DACL_SECURITY_INFORMATION,
        GetAce, GetSecurityDescriptorDacl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

pub const SYSTEM_SID: &str = "S-1-5-18";
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

pub struct LocalAllocation(pub(crate) *mut c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub struct SecurityDescriptor(LocalAllocation);
impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(sddl)?;
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(LocalAllocation(descriptor)))
    }

    pub fn private_for_current_user() -> io::Result<Self> {
        let user = current_user_sid()?;
        Self::from_sddl(&format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"))
    }

    /// The returned structure borrows this descriptor until the native create call returns.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }

    pub(crate) fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(unsafe_security());
        }
        Ok(dacl)
    }
}

pub fn current_user_sid() -> io::Result<String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    token_user_sid(&token)
}

pub fn token_user_sid(token: &impl AsHandle) -> io::Result<String> {
    let token = token.as_handle().as_raw_handle();
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut bytes);
    }
    if !(size_of::<TOKEN_USER>() as u32..=16384).contains(&bytes) {
        return Err(unsafe_security());
    }
    // Align for TOKEN_USER. All SID data referenced by it remains in this buffer.
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

pub fn owner_sid(handle: &impl AsHandle) -> io::Result<String> {
    let (descriptor, owner, _) = query(handle.as_handle().as_raw_handle())?;
    let result = sid_string(owner);
    drop(descriptor);
    result
}

/// Program code is readable by ordinary users but writable only by Windows
/// administrators and SYSTEM. A caller's own SID is deliberately not trusted.
pub fn require_system_managed(handle: &impl AsHandle) -> io::Result<()> {
    require_system_managed_access(handle, false)
}

/// Creating unrelated children of an ancestor (for example ProgramData) cannot
/// replace an existing protected child. Delete-child and ACL changes remain denied.
pub fn require_system_managed_ancestor(handle: &impl AsHandle) -> io::Result<()> {
    require_system_managed_access(handle, true)
}

fn require_system_managed_access(handle: &impl AsHandle, ancestor: bool) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };
    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    let trusted = |sid: &str| matches!(sid, SYSTEM_SID | ADMINISTRATORS_SID | TRUSTED_INSTALLER);
    let (_descriptor, owner, dacl) = query(handle.as_handle().as_raw_handle())?;
    if !trusted(&sid_string(owner)?) || dacl.is_null() {
        return Err(unsafe_security());
    }
    let mut write_mask = 0x4000_0000
        | 0x1000_0000
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_DELETE_CHILD;
    if ancestor {
        write_mask &= !(FILE_WRITE_DATA | FILE_APPEND_DATA);
    }
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & Security::INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        match u32::from(header.AceType) {
            ACCESS_DENIED_ACE_TYPE => {}
            ACCESS_ALLOWED_ACE_TYPE
                if header.AceSize as usize >= size_of::<ACCESS_ALLOWED_ACE>() =>
            {
                let value = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                if value.Mask & write_mask != 0
                    && !trusted(&sid_string(
                        ptr::addr_of!(value.SidStart).cast_mut().cast(),
                    )?)
                {
                    return Err(unsafe_security());
                }
            }
            _ => return Err(unsafe_security()),
        }
    }
    Ok(())
}

/// State can be read only by its owner, SYSTEM and machine administrators.
/// Reject unknown ACE types instead of guessing their access semantics.
pub fn require_private(handle: &impl AsHandle) -> io::Result<()> {
    let user = current_user_sid()?;
    let (_descriptor, owner, dacl) = query(handle.as_handle().as_raw_handle())?;
    let trusted = |sid: &str| sid == user || sid == SYSTEM_SID || sid == ADMINISTRATORS_SID;
    if !trusted(&sid_string(owner)?) || dacl.is_null() {
        return Err(unsafe_security());
    }
    let count = unsafe { (*dacl).AceCount };
    for index in 0..count {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        match u32::from(header.AceType) {
            ACCESS_DENIED_ACE_TYPE => {}
            ACCESS_ALLOWED_ACE_TYPE
                if header.AceSize as usize >= size_of::<ACCESS_ALLOWED_ACE>() =>
            {
                let value = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                if !trusted(&sid_string(
                    ptr::addr_of!(value.SidStart).cast_mut().cast(),
                )?) {
                    return Err(unsafe_security());
                }
            }
            _ => return Err(unsafe_security()),
        }
    }
    Ok(())
}

pub(crate) fn restrict(handle: &impl AsHandle) -> io::Result<()> {
    let user = current_user_sid()?;
    let owner = owner_sid(handle)?;
    if owner != user && owner != SYSTEM_SID && owner != ADMINISTRATORS_SID {
        return Err(unsafe_security());
    }
    let descriptor = SecurityDescriptor::private_for_current_user()?;
    let result = unsafe {
        SetSecurityInfo(
            handle.as_handle().as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | Security::PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            descriptor.dacl()?,
            ptr::null(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    require_private(handle)
}

fn query(handle: HANDLE) -> io::Result<(LocalAllocation, PSID, *mut ACL)> {
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let descriptor = LocalAllocation(descriptor);
    if owner.is_null() {
        return Err(unsafe_security());
    }
    Ok((descriptor, owner, dacl))
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut value = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(value.cast());
    let mut length = 0;
    // A SID string is system-generated and well below this bound.
    while length < 256 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(unsafe_security());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| unsafe_security())
}

pub fn wide(value: &str) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let value = std::ffi::OsStr::new(value)
        .encode_wide()
        .collect::<Vec<_>>();
    wide_units(value)
}

pub(crate) fn wide_units(mut value: Vec<u16>) -> io::Result<Vec<u16>> {
    if value.len() >= 32767 || value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows name",
        ));
    }
    value.push(0);
    Ok(value)
}

fn unsafe_security() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Windows state has unsafe ownership or access rules",
    )
}
