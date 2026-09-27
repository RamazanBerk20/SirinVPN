use sirinvpn_platform::windows::security;
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::*,
    System::{Pipes::*, Services::*, Threading::*},
};
fn checked(name: &str, ok: bool) -> io::Result<()> {
    if ok {
        println!("{name}: ok");
        Ok(())
    } else {
        let e = io::Error::last_os_error();
        println!("{name}: {e}");
        Err(e)
    }
}
fn main() -> io::Result<()> {
    let marker = std::fs::read_to_string(r"C:\ProgramData\SirinVpnAcceptance\fixture.json")?;
    assert!(marker.contains("disposable_vm"));
    let name = security::wide(r"\\.\pipe\SirinVPN.Service.v1")?;
    let access = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    checked("Open pipe", raw != INVALID_HANDLE_VALUE)?;
    let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
    println!("Pipe owner: {}", security::owner_sid(&pipe)?);
    let mut pid = 0;
    checked(
        "Server PID",
        unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } != 0,
    )?;
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    checked("SCM connect", !manager.is_null())?;
    let service_name = security::wide("SirinVPN")?;
    let svc = unsafe { OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
    checked("SCM query handle", !svc.is_null())?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    checked(
        "SCM status",
        unsafe {
            QueryServiceStatusEx(
                svc,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } != 0,
    )?;
    println!("SCM/PID match: {}", pid == status.dwProcessId);
    unsafe {
        CloseServiceHandle(svc);
        CloseServiceHandle(manager);
    }
    // The production pipe grants data rights, never CREATE_PIPE_INSTANCE.
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            16,
            8192,
            8192,
            0,
            ptr::null(),
        )
    };
    if raw != INVALID_HANDLE_VALUE {
        let _unexpected = unsafe { OwnedHandle::from_raw_handle(raw) };
        panic!("Unprivileged client created another pipe instance")
    }
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(5));
    println!("Additional pipe instance: access denied");
    // Keep the original regression diagnostic; this query is not an IPC requirement.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        println!("Process query unavailable: {}", io::Error::last_os_error())
    } else {
        let _process = unsafe { OwnedHandle::from_raw_handle(raw) };
        println!("Process query available")
    }
    Ok(())
}
