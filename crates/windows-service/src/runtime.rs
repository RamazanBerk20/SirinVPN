use crate::{
    Operation, ServiceError,
    controller::{Cancellation, Controller, SharedStatus},
    ipc,
};
use sirinvpn_tunnel_model::LocalTunnelStatus;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

/// Pipe connections served at once, shared by every interactive user.
const PIPE_SLOTS: usize = 8;
/// Requests from one authenticated user hold at most half of the pipe slots,
/// leaving the rest for others such as the session owner. Connections that
/// have not identified their caller yet are bounded by ipc's read deadline.
const CLIENT_SLOTS: usize = PIPE_SLOTS / 2;

struct Command {
    owner: String,
    operation: Operation,
    response: oneshot::Sender<Result<LocalTunnelStatus, ServiceError>>,
}

pub(crate) async fn serve(
    mut controller: Controller,
    listener: ipc::Listener,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let (status, cancel) = controller.shared();
    let (sender, mut requests) = mpsc::channel(8);
    let mut clients = ServerTask(tokio::spawn(accept(listener, status, cancel, sender)));
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = loop {
        if *stop.borrow() {
            break Ok(());
        }
        tokio::select! {
            biased;
            _ = stop.changed() => break Ok(()),
            Some(command) = requests.recv() => {
                let response = controller.handle(&command.owner, command.operation).await;
                let _ = command.response.send(response);
            }
            result = &mut clients.0 => break result.map_err(io::Error::other).and_then(|result| result),
            _ = interval.tick() => controller.tick().await,
        }
    };
    clients.0.abort();
    let cleanup = controller.shutdown().await;
    cleanup.and(result)
}

struct ServerTask(JoinHandle<io::Result<()>>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn accept(
    mut listener: ipc::Listener,
    status: SharedStatus,
    cancel: Arc<Cancellation>,
    sender: mpsc::Sender<Command>,
) -> io::Result<()> {
    let limit = Arc::new(Semaphore::new(PIPE_SLOTS));
    let clients = ClientSlots::default();
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        let permit = Arc::clone(&limit)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let mut connection = listener.accept().await?;
        let status = Arc::clone(&status);
        let cancel = Arc::clone(&cancel);
        let sender = sender.clone();
        let clients = clients.clone();
        tasks.spawn(async move {
            let _permit = permit;
            // The caller's slot is held until its reply is written.
            let (result, _slot) = match connection.read().await {
                Ok(request) => match clients.admit(&request.owner_sid) {
                    Some(slot) => (dispatch(request, status, cancel, sender).await, Some(slot)),
                    None => (Err(ServiceError::Busy), None),
                },
                Err(error) => (Err(error), None),
            };
            let _ = connection.reply(result).await;
        });
    }
}

/// In-flight requests per authenticated caller SID.
#[derive(Clone, Default)]
struct ClientSlots(Arc<Mutex<HashMap<String, usize>>>);

struct ClientSlot {
    slots: ClientSlots,
    owner: String,
}

impl ClientSlots {
    fn admit(&self, owner: &str) -> Option<ClientSlot> {
        let mut active = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = active.entry(owner.to_owned()).or_default();
        if *count >= CLIENT_SLOTS {
            return None;
        }
        *count += 1;
        Some(ClientSlot {
            slots: self.clone(),
            owner: owner.to_owned(),
        })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut active = self.slots.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = active.get_mut(&self.owner) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.owner);
            }
        }
    }
}

async fn dispatch(
    request: ipc::AuthenticatedRequest,
    status: SharedStatus,
    cancel: Arc<Cancellation>,
    sender: mpsc::Sender<Command>,
) -> Result<LocalTunnelStatus, ServiceError> {
    let current = status
        .read()
        .map_err(|_| ServiceError::NetworkOperation)?
        .for_user(&request.owner_sid)?;
    if matches!(request.operation, Operation::Status) {
        return Ok(current);
    }
    let slot = sender.try_reserve().map_err(|_| ServiceError::Busy)?;
    let expected = match &request.operation {
        Operation::PauseSession(id)
        | Operation::PauseForKeyRotation(id)
        | Operation::Resume(id)
        | Operation::ReconnectSession(id)
        | Operation::DisconnectSession(id) => Some(*id),
        Operation::SwitchSession(change) => Some(change.expected_server_id),
        _ => None,
    };
    if expected.is_some() && expected != current.server_id {
        return Err(ServiceError::SessionChanged);
    }
    if current.server_id.is_some()
        && (expected.is_some() || matches!(request.operation, Operation::Disconnect))
    {
        cancel.cancel();
    }
    let (response, received) = oneshot::channel();
    slot.send(Command {
        owner: request.owner_sid,
        operation: request.operation,
        response,
    });
    tokio::time::timeout(Duration::from_secs(110), received)
        .await
        .map_err(|_| ServiceError::Busy)?
        .map_err(|_| ServiceError::Unavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_caller_cannot_hold_every_pipe_slot() {
        let clients = ClientSlots::default();
        let held = (0..CLIENT_SLOTS)
            .map(|_| clients.admit("S-1-5-21-1").unwrap())
            .collect::<Vec<_>>();
        assert!(clients.admit("S-1-5-21-1").is_none());
        // Another user, such as the session owner, still has its own slots.
        let owner = clients.admit("S-1-5-21-2").unwrap();
        drop(held);
        assert!(clients.admit("S-1-5-21-1").is_some());
        drop(owner);
        assert!(clients.0.lock().unwrap().is_empty());
    }
}
