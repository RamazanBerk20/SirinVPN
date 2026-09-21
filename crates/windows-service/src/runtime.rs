use crate::{
    Operation, ServiceError,
    controller::{Cancellation, Controller, SharedStatus},
    ipc,
};
use sirinvpn_tunnel_model::LocalTunnelStatus;
use std::{io, sync::Arc, time::Duration};
use tokio::{
    sync::{Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

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
    let limit = Arc::new(Semaphore::new(8));
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
        tasks.spawn(async move {
            let _permit = permit;
            let result = match connection.read().await {
                Ok(request) => dispatch(request, status, cancel, sender).await,
                Err(error) => Err(error),
            };
            let _ = connection.reply(result).await;
        });
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
