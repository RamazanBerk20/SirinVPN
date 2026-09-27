//! Local-only pipe transport. No private bytes are sent before SCM, pipe owner,
//! and pipe PID authentication agree on the running LocalSystem service.
use crate::{
    MAX_FRAME_BYTES, Operation, PIPE_NAME, Request, Response, SERVICE_NAME, ServiceError,
    protocol::IPC_VERSION,
};
use sirinvpn_platform::windows::security::{self, SYSTEM_SID, SecurityDescriptor};
use sirinvpn_protocol::ConnectionState;
use sirinvpn_tunnel_model::LocalTunnelStatus;
use std::{
    io,
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
    time::{Instant, timeout},
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_BUSY, INVALID_HANDLE_VALUE},
    Security::{RevertToSelf, TOKEN_QUERY},
    Storage::FileSystem::*,
    System::{Pipes::*, Services::*, Threading::*},
};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const CLIENT_ACCESS: u32 =
    FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;

pub async fn call(operation: Operation) -> Result<LocalTunnelStatus, ServiceError> {
    let mut pipe = connect_authenticated().await?;
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Request::new(operation)).map_err(|_| ServiceError::InvalidRequest)?,
    );
    let response = timeout(REQUEST_TIMEOUT, async {
        write_frame(&mut pipe, &bytes).await?;
        read_frame(&mut pipe).await
    })
    .await
    .map_err(|_| ServiceError::Unavailable)??;
    let response: Response =
        serde_json::from_slice(&response).map_err(|_| ServiceError::IncompatibleService)?;
    if response.version != IPC_VERSION {
        return Err(ServiceError::IncompatibleService);
    }
    response.result
}

/// Existing desktop management transactions use a synchronous helper callback.
/// A separate thread avoids nesting a runtime on the caller's async executor.
pub fn call_blocking(
    command: &str,
    input: Option<&[u8]>,
) -> Result<LocalTunnelStatus, ServiceError> {
    let operation = Operation::from_helper(command, input)?;
    let connecting = matches!(operation, Operation::Connect(_));
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ServiceError::Unavailable)?
            .block_on(async move {
                let initial = call(operation).await?;
                if !connecting {
                    return Ok(initial);
                }
                // Connect acknowledges the saved intent before the controller's
                // next tick creates the adapter and routes. Synchronous helper
                // callers immediately use the private management API, so wait
                // for actual network setup without blocking the service actor.
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut current = initial.clone();
                while !connection_ready(&initial, &current)? {
                    if Instant::now() >= deadline {
                        return Err(ServiceError::NetworkOperation);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    current = call(Operation::Status).await?;
                }
                Ok(current)
            })
    })
    .join()
    .map_err(|_| ServiceError::Unavailable)?
}

fn connection_ready(
    initial: &LocalTunnelStatus,
    current: &LocalTunnelStatus,
) -> Result<bool, ServiceError> {
    if initial.server_id.is_none()
        || current.server_id != initial.server_id
        || current.transport != initial.transport
    {
        return Err(ServiceError::SessionChanged);
    }
    match current.state {
        ConnectionState::Connected => Ok(true),
        ConnectionState::Connecting => Ok(current.counter_epoch.is_some()),
        _ => Err(ServiceError::NetworkOperation),
    }
}

async fn connect_authenticated() -> Result<NamedPipeClient, ServiceError> {
    let name = security::wide(PIPE_NAME).map_err(|_| ServiceError::Unavailable)?;
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                CLIENT_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            // from_raw_handle takes ownership even if registration with Tokio fails.
            let pipe = unsafe { NamedPipeClient::from_raw_handle(raw) }
                .map_err(|_| ServiceError::Unavailable)?;
            authenticate_server(&pipe).map_err(|_| ServiceError::Unauthenticated)?;
            return Ok(pipe);
        }
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_PIPE_BUSY as i32)
            || Instant::now() >= deadline
        {
            return Err(ServiceError::Unavailable);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn authenticate_server(pipe: &NamedPipeClient) -> io::Result<()> {
    if security::owner_sid(pipe)? != SYSTEM_SID {
        return Err(denied());
    }
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 || pid != running_service_pid()? {
        return Err(denied());
    }
    Ok(())
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn running_service_pid() -> io::Result<u32> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = ServiceHandle(manager);
    let name = security::wide(SERVICE_NAME)?;
    let service = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ServiceHandle(service);
    // The existing service DACL grants only read/query access to interactive
    // users. Bind its administrator-controlled LocalSystem configuration and
    // live PID to the SYSTEM-owned pipe before sending any private bytes.
    crate::install::local_system_config(service.0)?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            ptr::addr_of_mut!(status).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if status.dwCurrentState != SERVICE_RUNNING {
        return Err(denied());
    }
    Ok(status.dwProcessId)
}

pub struct Listener {
    pipe: NamedPipeServer,
}

impl Listener {
    pub fn new() -> io::Result<Self> {
        if security::current_user_sid()? != SYSTEM_SID {
            return Err(denied());
        }
        Ok(Self {
            pipe: create_server(true)?,
        })
    }

    /// The previous instance remains open until its replacement has been created.
    /// Together with FIRST_PIPE_INSTANCE and the DACL this prevents pipe-name theft.
    pub async fn accept(&mut self) -> io::Result<Connection> {
        self.pipe.connect().await?;
        let next = create_server(false)?;
        let pipe = std::mem::replace(&mut self.pipe, next);
        Ok(Connection { pipe })
    }
}

fn create_server(first: bool) -> io::Result<NamedPipeServer> {
    // Grant interactive users individual data rights, excluding APPEND_DATA:
    // for pipes that bit means CREATE_PIPE_INSTANCE, including in GENERIC_WRITE.
    let descriptor = SecurityDescriptor::from_sddl(&format!(
        "O:SYG:SYD:P(A;;FA;;;SY)(A;;0x{CLIENT_ACCESS:x};;;IU)"
    ))?;
    let mut attributes = descriptor.attributes();
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(16)
            .in_buffer_size(8192)
            .out_buffer_size(8192)
            .create_with_security_attributes_raw(PIPE_NAME, ptr::addr_of_mut!(attributes).cast())
    }
}

pub struct AuthenticatedRequest {
    pub owner_sid: String,
    pub operation: Operation,
}
pub struct Connection {
    pipe: NamedPipeServer,
}

impl Connection {
    pub async fn read(&mut self) -> Result<AuthenticatedRequest, ServiceError> {
        let bytes = timeout(CONNECT_TIMEOUT, read_frame(&mut self.pipe))
            .await
            .map_err(|_| ServiceError::InvalidRequest)??;
        // Impersonation is strictly synchronous and is reverted before any await.
        let owner_sid =
            authenticate_client(&self.pipe).map_err(|_| ServiceError::Unauthenticated)?;
        let request = Request::parse(&bytes)?;
        Ok(AuthenticatedRequest {
            owner_sid,
            operation: request.operation,
        })
    }

    pub async fn reply(
        &mut self,
        result: Result<LocalTunnelStatus, ServiceError>,
    ) -> Result<(), ServiceError> {
        let bytes = serde_json::to_vec(&Response {
            version: IPC_VERSION,
            result,
        })
        .map_err(|_| ServiceError::NetworkOperation)?;
        timeout(CONNECT_TIMEOUT, write_frame(&mut self.pipe, &bytes))
            .await
            .map_err(|_| ServiceError::Unavailable)?
    }
}

struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // Continuing on a pooled worker while impersonated would be unsafe.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

fn authenticate_client(pipe: &impl AsHandle) -> io::Result<String> {
    let raw = pipe.as_handle().as_raw_handle();
    let mut session = 0;
    if unsafe { GetNamedPipeClientSessionId(raw, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if session == 0 {
        return Err(denied());
    }
    if unsafe { ImpersonateNamedPipeClient(raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = Revert;
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let sid = security::token_user_sid(&token)?;
    if sid == SYSTEM_SID || !sid.starts_with("S-1-") {
        return Err(denied());
    }
    Ok(sid)
}

async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Zeroizing<Vec<u8>>, ServiceError> {
    let length = stream
        .read_u32_le()
        .await
        .map_err(|_| ServiceError::Unavailable)? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ServiceError::InvalidRequest);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    Ok(bytes)
}

async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
) -> Result<(), ServiceError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ServiceError::InvalidRequest);
    }
    stream
        .write_u32_le(bytes.len() as u32)
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| ServiceError::Unavailable)?;
    stream.flush().await.map_err(|_| ServiceError::Unavailable)
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Windows pipe identity could not be verified",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_connect_waits_for_the_adapter_and_rejects_interrupted_sessions() {
        let initial: LocalTunnelStatus = serde_json::from_value(serde_json::json!({
            "state":"connecting", "interface_name":"SirinVPN",
            "server_id":"123e4567-e89b-42d3-a456-426614174000",
            "transport":"direct_udp", "rx_bytes":0, "tx_bytes":0,
            "ipv6_blocked":true, "ipv6_tunneled":false,
            "kill_switch_enabled":false, "auto_reconnect_enabled":false,
            "transport_fallback_enabled":false, "routing_mode":"full_tunnel",
            "allow_lan":false
        }))
        .unwrap();
        assert!(!connection_ready(&initial, &initial).unwrap());
        let mut ready = initial.clone();
        ready.counter_epoch = Some(uuid::Uuid::new_v4().to_string());
        // The adapter and routes may be ready before the peer's first handshake.
        assert!(connection_ready(&initial, &ready).unwrap());
        ready.state = ConnectionState::Connected;
        assert!(connection_ready(&initial, &ready).unwrap());
        ready.state = ConnectionState::Degraded;
        assert!(matches!(
            connection_ready(&initial, &ready),
            Err(ServiceError::NetworkOperation)
        ));
        ready = initial.clone();
        ready.server_id = None;
        ready.state = ConnectionState::Disconnected;
        assert!(matches!(
            connection_ready(&initial, &ready),
            Err(ServiceError::SessionChanged)
        ));
        ready = initial.clone();
        ready.transport = Some(sirinvpn_protocol::TransportKind::TcpFallback);
        assert!(matches!(
            connection_ready(&initial, &ready),
            Err(ServiceError::SessionChanged)
        ));
    }
}
