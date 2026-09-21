//! SCM kernel-driver lifecycle. No signature-enforcement settings are changed.
use super::*;
use std::path::Path;
const NAME: &str = "SirinVPNAppRouting";
const FILE: &str = "sirinvpn-app-routing.sys";

fn open_driver(manager: &Handle, access: u32) -> io::Result<Handle> {
    let name = security::wide(NAME)?;
    let raw = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if raw.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(raw))
    }
}
fn owned(service: &Handle, directory: &Path) -> io::Result<()> {
    let file = directory.join(FILE);
    let _protected = open_protected_program(&file)?;
    let mut length = 0;
    unsafe {
        QueryServiceConfigW(service.0, ptr::null_mut(), 0, &mut length);
    }
    if !(size_of::<QUERY_SERVICE_CONFIGW>() as u32..=16384).contains(&length) {
        return Err(invalid());
    }
    let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(service.0, config, length, &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let config = unsafe { &*config };
    let path = bounded_string(config.lpBinaryPathName, &buffer)?;
    let expected = format!("\\??\\{}", file.to_str().ok_or_else(invalid)?);
    if config.dwServiceType != SERVICE_KERNEL_DRIVER
        || config.dwStartType != SERVICE_DEMAND_START
        || !path.eq_ignore_ascii_case(&expected)
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn install(directory: &Path) -> io::Result<()> {
    let file = directory.join(FILE);
    let _protected = open_protected_program(&file)?;
    let binary = security::wide(&format!("\\??\\{}", file.to_str().ok_or_else(invalid)?))?;
    let name = security::wide(NAME)?;
    let title = security::wide("SirinVPN application routing")?;
    let manager = manager()?;
    let raw = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            title.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    let service = if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_EXISTS as i32) {
            return Err(error);
        }
        let service = open_driver(&manager, SERVICE_ALL_ACCESS)?;
        owned(&service, directory)?;
        service
    } else {
        Handle(raw)
    };
    let descriptor = SecurityDescriptor::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x20004;;;IU)")?;
    if unsafe {
        SetServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION,
            descriptor.attributes().lpSecurityDescriptor,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // The ordinary VPN remains installable if Windows rejects an unsigned or
    // incompatible driver. Runtime capability publication checks SCM and WFP.
    let _ = start(&service, false);
    Ok(())
}
pub(crate) fn start_installed() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let directory = executable.parent().ok_or_else(invalid)?;
    let manager = manager()?;
    let service = open_driver(&manager, SERVICE_START | SERVICE_QUERY_CONFIG)?;
    owned(&service, directory)?;
    start(&service, false)
}
pub(crate) fn running() -> bool {
    fn query() -> io::Result<bool> {
        let executable = std::env::current_exe()?;
        let raw = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let manager = Handle(raw);
        let service = open_driver(&manager, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
        owned(&service, executable.parent().ok_or_else(invalid)?)?;
        let mut status = SERVICE_STATUS::default();
        if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status.dwCurrentState == SERVICE_RUNNING)
    }
    query().unwrap_or(false)
}
pub(crate) fn stop_in(directory: &Path) -> io::Result<()> {
    change(directory, false)
}
pub(crate) fn uninstall_in(directory: &Path) -> io::Result<()> {
    change(directory, true)
}
fn change(directory: &Path, delete: bool) -> io::Result<()> {
    let manager = manager()?;
    let service = match open_driver(&manager, SERVICE_ALL_ACCESS) {
        Ok(service) => service,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    owned(&service, directory)?;
    stop(&service)?;
    if delete && unsafe { DeleteService(service.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
