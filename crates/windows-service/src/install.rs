//! Elevated installer operations. The pipe protocol deliberately exposes none of
//! these actions; Windows' SCM access checks enforce administrator authorization.
use crate::SERVICE_NAME;
use sirinvpn_platform::windows::{
    open_protected_program,
    security::{self, SecurityDescriptor},
};
use std::{
    io, ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Security::DACL_SECURITY_INFORMATION, System::Services::*};
pub(crate) mod application_driver;
mod paths;

/// Invoked from a freshly extracted helper in Program Files before any installed
/// executable is run. An unsafe pre-existing directory or binary is rejected.
pub fn prepare_install(directory: &std::path::Path) -> io::Result<()> {
    require_administrator()?;
    paths::require_install_directory(directory)?;
    let _program = open_protected_program(&std::env::current_exe()?)?;
    sirinvpn_platform::windows::create_program_directory(directory)?;
    for name in [
        "sirinvpn-windows-service.exe",
        "wireguard.dll",
        "sirinvpn-app-routing.sys",
    ] {
        let path = directory.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let _protected = open_protected_program(&path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    stop_in(directory)?;
    application_driver::stop_in(directory)
}

pub fn uninstall_from(directory: &std::path::Path) -> io::Result<()> {
    require_administrator()?;
    paths::require_install_directory(directory)?;
    let _program = open_protected_program(&std::env::current_exe()?)?;
    crate::update::uninstall_with_cleanup(|| uninstall_in(directory))
}

struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

pub fn install() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let _protected = open_protected_program(&executable)?;
    let dll = executable
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?
        .join("wireguard.dll");
    let _library = open_protected_program(&dll)?;
    crate::wireguard::verify_vendor_library(&dll)?;
    application_driver::install(executable.parent().ok_or_else(invalid)?)?;
    let path = executable.to_str().ok_or(io::ErrorKind::InvalidInput)?;
    if path.contains('"') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let command = format!("\"{path}\" --service");
    let binary = security::wide(&command)?;
    let manager = manager()?;
    let name = security::wide(SERVICE_NAME)?;
    let display = security::wide("SirinVPN networking service")?;
    let dependencies = multi_string(&["BFE", "Tcpip", "Nsi"])?;
    let raw = unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            dependencies.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    };
    let service = if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_EXISTS as i32) {
            return Err(error);
        }
        let service = open(&manager, SERVICE_ALL_ACCESS)?;
        require_owned(&service, &command)?;
        if unsafe {
            ChangeServiceConfigW(
                service.0,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                binary.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                dependencies.as_ptr(),
                ptr::null(),
                ptr::null(),
                display.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        service
    } else {
        Handle(raw)
    };
    harden(&service)?;
    start(&service, false)?;
    wait_for(&service, SERVICE_RUNNING, false)
}

/// Used before an installer replaces the protected program files. It does not
/// discard saved intent or remove the persistent firewall.
pub fn stop_for_update() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let directory = executable.parent().ok_or_else(invalid)?;
    stop_in(directory)?;
    application_driver::stop_in(directory)
}
fn stop_in(directory: &std::path::Path) -> io::Result<()> {
    let manager = manager()?;
    let service = match open(
        &manager,
        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
    ) {
        Ok(service) => service,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let executable = directory.join("sirinvpn-windows-service.exe");
    let _protected = open_protected_program(&executable)?;
    let path = executable.to_str().ok_or_else(invalid)?;
    require_owned(&service, &format!("\"{path}\" --service"))?;
    stop(&service)
}

pub fn uninstall() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    crate::update::uninstall_with_cleanup(|| uninstall_in(executable.parent().ok_or_else(invalid)?))
}
fn uninstall_in(directory: &std::path::Path) -> io::Result<()> {
    let manager = manager()?;
    let service = match open(&manager, SERVICE_ALL_ACCESS) {
        Ok(service) => service,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let executable = directory.join("sirinvpn-windows-service.exe");
    let _protected = open_protected_program(&executable)?;
    let path = executable.to_str().ok_or_else(invalid)?;
    require_owned(&service, &format!("\"{path}\" --service"))?;
    stop(&service)?;
    // Cleanup must execute as LocalSystem to read the SYSTEM-only DPAPI journal.
    // SERVICE_START belongs only to administrators and SYSTEM in our service DACL.
    start(&service, true)?;
    wait_for(&service, SERVICE_STOPPED, true)?;
    application_driver::uninstall_in(directory)?;
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn manager() -> io::Result<Handle> {
    let handle = unsafe {
        OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    };
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(handle))
    }
}

pub(crate) fn require_administrator() -> io::Result<()> {
    manager().map(|_| ())
}

pub(crate) fn require_installed_program() -> io::Result<()> {
    let manager = manager()?;
    require_current_program(&open(&manager, SERVICE_QUERY_CONFIG)?)
}

pub(crate) fn verify_installed_service(
    directory: &std::path::Path,
    version: &str,
) -> io::Result<()> {
    use std::process::{Command, Stdio};
    let executable = directory.join("sirinvpn-windows-service.exe");
    let _protected = open_protected_program(&executable)?;
    let path = executable.to_str().ok_or_else(invalid)?;
    if path.contains('"') {
        return Err(invalid());
    }
    let manager = manager()?;
    let service = open(&manager, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    if !require_owned(&service, &format!("\"{path}\" --service"))? {
        return Err(invalid());
    }
    wait_for(&service, SERVICE_RUNNING, false)?;
    let output = Command::new(&executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success()
        || output.stdout.len() > 128
        || std::str::from_utf8(&output.stdout).map(str::trim) != Ok(version)
    {
        return Err(invalid());
    }
    Ok(())
}
fn open(manager: &Handle, access: u32) -> io::Result<Handle> {
    let name = security::wide(SERVICE_NAME)?;
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(handle))
    }
}

fn harden(service: &Handle) -> io::Result<()> {
    let descriptor = SecurityDescriptor::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x20085;;;IU)")?;
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
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    configure(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid)?;
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 15000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 60000,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86400,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    configure(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure)?;
    configure(
        service,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        &SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: 1,
        },
    )?;
    configure(
        service,
        SERVICE_CONFIG_PRESHUTDOWN_INFO,
        &SERVICE_PRESHUTDOWN_INFO {
            dwPreshutdownTimeout: 30_000,
        },
    )?;
    let mut text = security::wide(
        "Maintains SirinVPN connections and the selected network protection policy.",
    )?;
    configure(
        service,
        SERVICE_CONFIG_DESCRIPTION,
        &SERVICE_DESCRIPTIONW {
            lpDescription: text.as_mut_ptr(),
        },
    )
}

fn configure<T>(service: &Handle, kind: u32, value: &T) -> io::Result<()> {
    if unsafe { ChangeServiceConfig2W(service.0, kind, ptr::from_ref(value).cast()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn require_current_program(service: &Handle) -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let _protected = open_protected_program(&executable)?;
    let path = executable.to_str().ok_or(io::ErrorKind::InvalidInput)?;
    require_owned(service, &format!("\"{path}\" --service")).map(|_| ())
}
fn require_owned(service: &Handle, command: &str) -> io::Result<bool> {
    let (path, auto_start) = local_system_config(service.0)?;
    if !path.eq_ignore_ascii_case(command) {
        return Err(invalid());
    }
    Ok(auto_start)
}

/// SCM configuration is readable by interactive clients; process/token handles
/// for the LocalSystem service are not. Only administrators may change it.
pub(crate) fn local_system_config(service: SC_HANDLE) -> io::Result<(String, bool)> {
    let mut length = 0;
    unsafe {
        QueryServiceConfigW(service, ptr::null_mut(), 0, &mut length);
    }
    if !(size_of::<QUERY_SERVICE_CONFIGW>() as u32..=16384).contains(&length) {
        return Err(invalid());
    }
    let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(service, config, length, &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let config = unsafe { &*config };
    let path = bounded_string(config.lpBinaryPathName, &buffer)?;
    let account = bounded_string(config.lpServiceStartName, &buffer)?;
    if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || !account.eq_ignore_ascii_case("LocalSystem")
    {
        return Err(invalid());
    }
    Ok((path, config.dwStartType == SERVICE_AUTO_START))
}

pub(crate) fn registered_auto_start() -> io::Result<bool> {
    let raw = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = Handle(raw);
    let service = open(&manager, SERVICE_QUERY_CONFIG)?;
    let executable = std::env::current_exe()?;
    let path = executable.to_str().ok_or(io::ErrorKind::InvalidInput)?;
    require_owned(&service, &format!("\"{path}\" --service"))
}

fn bounded_string(value: *const u16, buffer: &[u64]) -> io::Result<String> {
    let begin = buffer.as_ptr() as usize;
    let end = begin + size_of_val(buffer);
    let address = value as usize;
    if address < begin || address >= end || !address.is_multiple_of(2) {
        return Err(invalid());
    }
    let available = (end - address) / 2;
    let characters = unsafe { std::slice::from_raw_parts(value, available) };
    let length = characters
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(invalid)?;
    String::from_utf16(&characters[..length]).map_err(|_| invalid())
}

fn start(service: &Handle, cleanup: bool) -> io::Result<()> {
    let argument = security::wide("--uninstall")?;
    let arguments = [argument.as_ptr()];
    if unsafe {
        StartServiceW(
            service.0,
            u32::from(cleanup),
            if cleanup {
                arguments.as_ptr()
            } else {
                ptr::null()
            },
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if cleanup || error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(error);
        }
    }
    Ok(())
}
fn stop(service: &Handle) -> io::Result<()> {
    let mut status = SERVICE_STATUS::default();
    if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
            return Err(error);
        }
    }
    wait_for(service, SERVICE_STOPPED, false)
}
fn wait_for(service: &Handle, expected: u32, require_success: bool) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut bytes = 0;
        if unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                ptr::addr_of_mut!(status).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if status.dwCurrentState == expected {
            if require_success
                && (status.dwWin32ExitCode != 0 || status.dwServiceSpecificExitCode != 0)
            {
                return Err(invalid());
            }
            return Ok(());
        }
        if status.dwCurrentState == SERVICE_STOPPED || Instant::now() >= deadline {
            return Err(invalid());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn multi_string(values: &[&str]) -> io::Result<Vec<u16>> {
    let mut result = Vec::new();
    for value in values {
        result.extend(security::wide(value)?);
    }
    result.push(0);
    Ok(result)
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Windows service ownership or state is invalid",
    )
}
