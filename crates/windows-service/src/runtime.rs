use crate::{
    Operation, ServiceError,
    controller::{Cancellation, Controller},
    ipc,
    published::{SharedStatus, wait_for_change},
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
/// Status waiters release their request slot and hold one of these instead, so
/// long polls never starve commands. With the request slots and the listening
/// instance this stays below the pipe's 16 instances.
const WAIT_SLOTS: usize = 6;
const CLIENT_WAIT_SLOTS: usize = 2;

struct Command {
    owner: String,
    administrator: bool,
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
                let response = controller
                    .handle(&command.owner, command.administrator, command.operation)
                    .await;
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
    let clients = ClientSlots::new(CLIENT_SLOTS);
    let waiting = Arc::new(Semaphore::new(WAIT_SLOTS));
    let waiters = ClientSlots::new(CLIENT_WAIT_SLOTS);
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        let permit = Arc::clone(&limit)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let mut connection = listener.accept().await?;
        let status = status.clone();
        let cancel = Arc::clone(&cancel);
        let sender = sender.clone();
        let clients = clients.clone();
        let waiting = Arc::clone(&waiting);
        let waiters = waiters.clone();
        tasks.spawn(async move {
            let request = match connection.read().await {
                Ok(request) => request,
                Err(error) => {
                    let _ = connection.reply(Err(error), None).await;
                    return;
                }
            };
            // Slots are held until the reply is written.
            if let Operation::WaitForChange(wait) = request.operation {
                let slots = (
                    waiting.try_acquire_owned().ok(),
                    waiters.admit(&request.owner_sid),
                );
                let (result, sequence) = match slots {
                    (Some(_), Some(_)) => {
                        // An admitted waiter's pipe instance is counted by WAIT_SLOTS.
                        drop(permit);
                        match wait_for_change(&request.owner_sid, request.is_admin, wait, status)
                            .await
                        {
                            Ok((sequence, current)) => (Ok(current), Some(sequence)),
                            Err(error) => (Err(error), None),
                        }
                    }
                    _ => (Err(ServiceError::Busy), None),
                };
                let _ = connection.reply(result, sequence).await;
                drop(slots);
                return;
            }
            let _permit = permit;
            let slot = clients.admit(&request.owner_sid);
            let result = match slot {
                Some(_) => dispatch(request, status, cancel, sender).await,
                None => Err(ServiceError::Busy),
            };
            let _ = connection.reply(result, None).await;
            drop(slot);
        });
    }
}

/// In-flight requests per authenticated caller SID, up to `limit` each.
#[derive(Clone)]
struct ClientSlots {
    active: Arc<Mutex<HashMap<String, usize>>>,
    limit: usize,
}

struct ClientSlot {
    slots: ClientSlots,
    owner: String,
}

impl ClientSlots {
    fn new(limit: usize) -> Self {
        Self {
            active: Arc::default(),
            limit,
        }
    }

    fn admit(&self, owner: &str) -> Option<ClientSlot> {
        let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        let count = active.entry(owner.to_owned()).or_default();
        if *count >= self.limit {
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
        let mut active = self
            .slots
            .active
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
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
    let current =
        status
            .borrow()
            .for_user(&request.owner_sid, request.is_admin, &request.operation)?;
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
        administrator: request.is_admin,
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
        let clients = ClientSlots::new(CLIENT_SLOTS);
        let held = (0..CLIENT_SLOTS)
            .map(|_| clients.admit("S-1-5-21-1").unwrap())
            .collect::<Vec<_>>();
        assert!(clients.admit("S-1-5-21-1").is_none());
        // Another user, such as the session owner, still has its own slots.
        let owner = clients.admit("S-1-5-21-2").unwrap();
        drop(held);
        assert!(clients.admit("S-1-5-21-1").is_some());
        drop(owner);
        assert!(clients.active.lock().unwrap().is_empty());
    }
}
