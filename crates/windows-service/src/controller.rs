//! A single owner serializes intent, firewall changes, adapter state, and recovery.
//! Named-pipe readers can publish status and cancel this owner's pending attempt;
//! they never configure networking themselves.
use crate::{
    Operation, ServiceError,
    carrier::Carrier,
    firewall::Firewall,
    firewall_plan::FirewallPlan,
    link::{Event, Link},
    network::{self, Underlay},
    published::{PublishedStatus, SharedStatus},
    state::{SavedConnection, SessionPhase, SessionStore},
    wireguard::{Adapter, Statistics},
};
use sirinvpn_protocol::{ConnectionState, ServerId};
use sirinvpn_tunnel_model::{LocalTunnelStatus, TunnelConnectRequest};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, watch};

mod applications;
mod connection;
mod endpoints;
mod lifecycle;
mod measurements;
mod status;

/// Every admitted stop-like operation increments the epoch before entering the
/// command queue. notify_one retains a permit if cancellation precedes the await.
#[derive(Default)]
pub(crate) struct Cancellation {
    pub epoch: AtomicU64,
    pub notify: Notify,
}
impl Cancellation {
    pub(crate) fn cancel(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }
    pub(crate) async fn changed(&self, epoch: u64) {
        loop {
            let wake = self.notify.notified();
            if self.epoch.load(Ordering::SeqCst) != epoch {
                return;
            }
            wake.await;
        }
    }
}

pub(crate) struct Active {
    adapter: Adapter,
    carrier: Option<Carrier>,
    request: TunnelConnectRequest,
    endpoint: SocketAddr,
    underlay: Underlay,
    started: Instant,
    connected_at: Option<Instant>,
    handshake_marker: Option<u64>,
    handshake_seen: Instant,
    stats: Option<Statistics>,
    epoch: uuid::Uuid,
    mtu: sirinvpn_protocol::MtuStatus,
}

pub(crate) struct Controller {
    store: SessionStore,
    firewall: Firewall,
    saved: Option<SavedConnection>,
    /// Runtime state beside `saved.phase`: Stopped while there is no session or
    /// it is Held/Disconnecting; Connecting/Connected while it is Connecting/Active.
    link: Link<Box<Active>>,
    boot: uuid::Uuid,
    published: watch::Sender<PublishedStatus>,
    cancel: Arc<Cancellation>,
    operation_epoch: u64,
    endpoints: endpoints::EndpointMonitor,
    quality: crate::quality_plan::QualityMonitor,
}

impl Controller {
    pub(crate) fn set_cancellation(&mut self, cancel: Arc<Cancellation>) {
        self.cancel = cancel;
    }

    /// Only SCM start arguments supplied by an administrator reach this path.
    /// Both end the current session as an explicit Disconnect would; `uninstall`
    /// also removes the WFP provider and the service's state directory.
    pub(crate) fn release(uninstall: bool) -> io::Result<()> {
        let store = SessionStore::open()?;
        let saved = match store.load() {
            Ok(saved) => saved,
            Err(_) => {
                // An explicit elevated uninstall must still release the owned
                // persistent guard after DPAPI/JSON corruption. Unknown route
                // ownership is never guessed from an unreadable record.
                store.validate_unreadable_removal()?;
                None
            }
        };
        if let Some(mut saved) = saved {
            saved.phase = SessionPhase::Disconnecting;
            store.save(&saved)?;
            while let Some(route) = saved.routes.last().cloned() {
                network::remove_owned_route(&route)?;
                saved.routes.pop();
                store.save(&saved)?;
            }
        }
        let mut firewall = Firewall::open()?;
        if uninstall {
            firewall.uninstall()?;
            store.remove_installation()
        } else {
            firewall.clear()?;
            store.remove()
        }
    }

    pub(crate) fn open() -> io::Result<Self> {
        let store = SessionStore::open()?;
        let boot = store.boot_nonce()?;
        let saved = store.load()?;
        let firewall = Firewall::open()?;
        let _ = crate::application_driver::start_installed();
        let mut controller = Self {
            store,
            firewall,
            saved,
            link: Link::Stopped {
                enforcement_failed: false,
            },
            boot,
            published: PublishedStatus::channel(status::idle()),
            cancel: Arc::new(Cancellation::default()),
            operation_epoch: 0,
            endpoints: endpoints::EndpointMonitor::default(),
            quality: crate::quality_plan::QualityMonitor::default(),
        };
        if let Some(saved) = controller.saved.as_ref() {
            let resume = saved.may_resume_after_restart(boot);
            if saved.phase == SessionPhase::Disconnecting {
                controller.finish_disconnect()?;
            } else {
                // Replace surviving runtime allowances with a closed policy before
                // examining old routes or starting the driver. Boot intent is separate.
                controller.close_guard()?;
                controller.cleanup_routes()?;
                let saved = controller.saved.as_mut().expect("saved session");
                saved.boot_nonce = boot;
                saved.phase = if resume {
                    SessionPhase::Connecting
                } else {
                    SessionPhase::Held
                };
                controller.persist()?;
                controller.reset_attempts();
                if !resume && !saved_policy_kill(&controller.saved) {
                    controller.firewall.clear()?;
                }
            }
        } else if !controller.firewall.absent()? {
            // An unreadable/missing ownership journal never authorizes removal of
            // persistent protection. The elevated installer provides repair/uninstall.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guard has no session owner",
            ));
        }
        controller.publish();
        Ok(controller)
    }

    pub(crate) fn shared(&self) -> (SharedStatus, Arc<Cancellation>) {
        (self.published.subscribe(), Arc::clone(&self.cancel))
    }

    pub(crate) async fn handle(
        &mut self,
        owner: &str,
        administrator: bool,
        operation: Operation,
    ) -> Result<LocalTunnelStatus, ServiceError> {
        self.operation_epoch = self.cancel.epoch.load(Ordering::SeqCst);
        crate::state::authorize(
            self.saved.as_ref().map(|saved| saved.owner_sid.as_str()),
            owner,
            administrator,
            &operation,
        )?;
        let result = match operation {
            Operation::Status | Operation::WaitForChange(_) => Ok(()),
            Operation::RouteApplication(request) => self.route_application(request).await,
            Operation::Connect(request) => self.connect(owner, request, false).await,
            Operation::Disconnect => self.disconnect().await,
            Operation::DisconnectSession(id) => {
                self.expect_server(id)?;
                self.disconnect().await
            }
            Operation::PauseSession(id) | Operation::PauseForKeyRotation(id) => {
                if self.saved.is_some() {
                    self.expect_server(id)?;
                    self.hold().await
                } else {
                    Ok(())
                }
            }
            Operation::Resume(id) => {
                self.expect_server(id)?;
                if self
                    .saved
                    .as_ref()
                    .is_none_or(|saved| saved.phase != SessionPhase::Held)
                {
                    return Err(ServiceError::SessionChanged);
                }
                self.restart().await
            }
            Operation::ReconnectSession(id) => {
                self.expect_server(id)?;
                self.restart().await
            }
            Operation::SwitchSession(change) => {
                self.expect_server(change.expected_server_id)?;
                if change.request.server_id == change.expected_server_id {
                    return Err(ServiceError::InvalidRequest);
                }
                self.connect(owner, change.request, true).await
            }
            Operation::ApplyEndpointCheckpoint(head) => {
                self.expect_server(head.claims.server_id)?;
                self.apply_endpoint(head).await
            }
            Operation::PublishEndpointCheckpoint(head) => {
                self.expect_server(head.claims.server_id)?;
                self.publish_endpoint(&head).await
            }
        };
        self.publish();
        result?;
        self.current_status()
    }

    fn expect_server(&self, expected: ServerId) -> Result<(), ServiceError> {
        if self.saved.as_ref().is_some_and(|saved| {
            saved.request.server_id == expected && saved.phase != SessionPhase::Disconnecting
        }) {
            Ok(())
        } else {
            Err(ServiceError::SessionChanged)
        }
    }

    fn persist(&self) -> io::Result<()> {
        if let Some(saved) = &self.saved {
            self.store.save(saved)
        } else {
            Ok(())
        }
    }

    fn close_guard(&mut self) -> io::Result<()> {
        if let Some(saved) = &self.saved {
            let plan = self.session_plan(&saved.request, &[], None);
            self.firewall.apply(plan)?;
        }
        Ok(())
    }

    fn plan(&self) -> Option<FirewallPlan> {
        self.saved.as_ref().map(|saved| {
            if let Some(active) = self.link.active() {
                self.session_plan(
                    &active.request,
                    &[active.endpoint],
                    Some(unsafe { active.adapter.luid().Value }),
                )
            } else {
                self.session_plan(&saved.request, &[], None)
            }
        })
    }

    fn session_plan(
        &self,
        request: &TunnelConnectRequest,
        endpoints: &[SocketAddr],
        luid: Option<u64>,
    ) -> FirewallPlan {
        let plan = FirewallPlan::for_tunnel(request, endpoints, luid);
        if let Some(saved) = &self.saved {
            plan.with_applications(
                &saved.applications,
                &saved.owner_sid,
                request.client_address,
                luid,
            )
        } else {
            plan
        }
    }

    fn control_plan(&self) -> Option<FirewallPlan> {
        if self.saved.as_ref().is_some_and(|saved| {
            saved.phase == SessionPhase::Held && !saved.request.connection_policy().kill_switch
        }) {
            None
        } else {
            self.plan()
        }
    }

    fn current_status(&self) -> Result<LocalTunnelStatus, ServiceError> {
        Ok(self.published.borrow().status.clone())
    }

    /// SCM stop preserves the acknowledged boot policy and persistent kill switch,
    /// so a crash or an update never opens the guard. An owner's or elevated
    /// administrator's Disconnect, `--release-guard` and uninstall release it.
    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        let keep = self.link.enforcement_failed();
        if self
            .saved
            .as_ref()
            .is_some_and(|saved| saved.phase == SessionPhase::Disconnecting)
        {
            self.transition(Event::Stop {
                enforcement_failed: keep,
            })
            .await;
            return self.finish_disconnect();
        }
        self.close_guard()?;
        self.transition(Event::Stop {
            enforcement_failed: keep,
        })
        .await;
        self.cleanup_routes()?;
        if !saved_policy_kill(&self.saved) {
            self.firewall.clear()?;
        }
        self.publish();
        Ok(())
    }
}

fn saved_policy_kill(saved: &Option<SavedConnection>) -> bool {
    saved
        .as_ref()
        .is_some_and(|saved| saved.request.connection_policy().kill_switch)
}
fn network_error(_: io::Error) -> ServiceError {
    ServiceError::NetworkOperation
}
