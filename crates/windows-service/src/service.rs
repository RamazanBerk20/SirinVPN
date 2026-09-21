//! SCM is the only privileged service entry. There is no interactive networking
//! mode and the desktop never elevates itself to run a VPN session.
use crate::{
    SERVICE_NAME,
    controller::{Cancellation, Controller},
    ipc, runtime,
};
use sirinvpn_platform::windows::{open_protected_program, security};
use std::{
    ffi::c_void,
    io, ptr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicIsize, Ordering},
    },
};
use tokio::sync::watch;
use windows_sys::Win32::{Foundation::*, System::Services::*};

struct Control {
    handle: AtomicIsize,
    status: Mutex<SERVICE_STATUS>,
    stop: watch::Sender<bool>,
    cancel: Arc<Cancellation>,
}
static CONTROL: OnceLock<Control> = OnceLock::new();

pub fn run() -> io::Result<()> {
    let mut name = security::wide(SERVICE_NAME)?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe extern "system" fn service_main(count: u32, arguments: *mut *mut u16) {
    // Panics and library diagnostics must never dump keys or request state.
    std::panic::set_hook(Box::new(|_| {}));
    let (stop, stop_receiver) = watch::channel(false);
    if CONTROL
        .set(Control {
            handle: AtomicIsize::new(0),
            status: Mutex::new(SERVICE_STATUS::default()),
            stop,
            cancel: Arc::new(Cancellation::default()),
        })
        .is_err()
    {
        return;
    }
    let Some(control) = CONTROL.get() else {
        return;
    };
    let Ok(name) = security::wide(SERVICE_NAME) else {
        return;
    };
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), ptr::null_mut()) };
    if handle.is_null() {
        return;
    }
    control.handle.store(handle as isize, Ordering::SeqCst);
    let result = std::panic::catch_unwind(|| -> io::Result<()> {
        report(SERVICE_START_PENDING, 0)?;
        let _executable = open_protected_program(&std::env::current_exe()?)?;
        let cleanup = unsafe { cleanup_argument(count, arguments) }?;
        if cleanup {
            return Controller::uninstall();
        }
        let mut controller = Controller::open()?;
        // The same cancellation object is signalled by both SCM and pipe commands.
        controller.set_cancellation(Arc::clone(&control.cancel));
        let executor = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(2)
            .enable_all()
            .build()?;
        executor.block_on(async {
            let listener = ipc::Listener::new()?;
            report(SERVICE_RUNNING, 0)?;
            runtime::serve(controller, listener, stop_receiver).await
        })
    });
    let code = if matches!(result, Ok(Ok(()))) {
        0
    } else {
        ERROR_SERVICE_SPECIFIC_ERROR
    };
    let _ = report(SERVICE_STOPPED, code);
}

unsafe fn cleanup_argument(count: u32, arguments: *mut *mut u16) -> io::Result<bool> {
    if count == 1 {
        return Ok(false);
    }
    if count != 2 || arguments.is_null() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let argument = unsafe { *arguments.add(1) };
    if argument.is_null() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let expected = security::wide("--uninstall")?;
    for (offset, value) in expected.iter().enumerate() {
        if unsafe { *argument.add(offset) } != *value {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(true)
}

unsafe extern "system" fn handler(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    let Some(control) = CONTROL.get() else {
        return ERROR_CALL_NOT_IMPLEMENTED;
    };
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
            let _ = report(SERVICE_STOP_PENDING, 0);
            control.cancel.cancel();
            control.stop.send_replace(true);
            0
        }
        SERVICE_CONTROL_INTERROGATE => {
            if let Ok(status) = control.status.lock() {
                unsafe {
                    SetServiceStatus(
                        control.handle.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE,
                        &*status,
                    )
                };
            }
            0
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn report(state: u32, error: u32) -> io::Result<()> {
    let control = CONTROL.get().ok_or(io::ErrorKind::NotConnected)?;
    let mut status = control.status.lock().map_err(|_| io::ErrorKind::Other)?;
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN
    } else {
        0
    };
    status.dwWin32ExitCode = error;
    status.dwServiceSpecificExitCode = u32::from(error != 0);
    if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
        status.dwCheckPoint += 1;
        status.dwWaitHint = 30_000;
    } else {
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
    }
    if unsafe {
        SetServiceStatus(
            control.handle.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE,
            &*status,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
