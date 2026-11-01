//! Opt-in VPS alerts. An unprivileged timer task checks a few local facts every five minutes,
//! sends fixed text when a problem starts or clears, and pings an optional heartbeat address.
//! Notices name only a problem kind: no addresses, names, counts or traffic data.
use super::*;
use sirinvpn_protocol::{
    AlertFailure, AlertFormat, AlertPolicy, AlertSettings, AlertStatus, AlertTestResult,
    public_ip_address,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

pub const STATE_DIRECTORY: &str = "/var/lib/sirinvpn-alerts";
const STATE_FILE: &str = "state.json";
/// Installed by the SSH installer; older installations need a repair first.
const TIMER_UNIT: &str = "/etc/systemd/system/sirinvpn-alerts.timer";
/// A problem must still be present at the next five-minute check before it is sent.
const CONFIRM_SECONDS: u64 = 4 * 60;
const RESTART_PENDING_SECONDS: u64 = 3 * 24 * 60 * 60;
const MIN_SECONDS_BETWEEN_ALERTS: u64 = 15 * 60;
const MAX_ALERTS_PER_DAY: usize = 12;
const DAY_SECONDS: u64 = 24 * 60 * 60;
/// Restarts between two checks that count as a restart loop.
const RESTART_LOOP: u64 = 3;
const DISK_FULL_PERCENT: u128 = 90;
const DISK_CLEARED_PERCENT: u128 = 85;
/// Below the eight-second management request deadline, so a test alert can report its result.
const DELIVERY_SECONDS: u64 = 6;
const TEST_INTERVAL: Duration = Duration::from_secs(10);
const SERVICES: [&str; 4] = [
    "sirinvpn-server.service",
    "sirinvpn-network.service",
    "sirinvpn-firewall.service",
    "unbound.service",
];

static LAST_TEST: Mutex<Option<Instant>> = Mutex::new(None);
#[cfg(test)]
pub(crate) static TEST_ROOT: Mutex<Option<Vec<u8>>> = Mutex::new(None);

#[derive(clap::Subcommand)]
pub enum AlertsCommand {
    /// Timer task: check this VPS, send due alerts and the heartbeat.
    Check,
}

pub async fn run(command: AlertsCommand, paths: &ServerPaths) -> Result<()> {
    match command {
        AlertsCommand::Check => check(paths, Path::new(STATE_DIRECTORY)).await,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Problem {
    ServiceDown,
    ServiceRestarting,
    NetworkSetup,
    DnsFailing,
    DiskNearlyFull,
    SecurityUpdatesOff,
    RestartPending,
}

impl Problem {
    /// The complete text a receiver can see, as listed in docs/vps-alerts.md.
    fn text(self) -> (&'static str, &'static str) {
        match self {
            Self::ServiceDown => (
                "SirinVPN service",
                "A SirinVPN service on the VPS has stopped.",
            ),
            Self::ServiceRestarting => (
                "SirinVPN service restarts",
                "A SirinVPN service on the VPS keeps restarting.",
            ),
            Self::NetworkSetup => (
                "VPN network setup",
                "The VPN interface, forwarding or a listening port on the VPS is missing. Use server repair.",
            ),
            Self::DnsFailing => ("Private DNS", "The VPS DNS resolver does not answer."),
            Self::DiskNearlyFull => ("Disk space", "The VPS disk is over 90% full."),
            Self::SecurityUpdatesOff => (
                "Security updates",
                "Automatic security updates on the VPS are off or could not be confirmed.",
            ),
            Self::RestartPending => (
                "Pending restart",
                "An installed update has waited over three days for a VPS restart.",
            ),
        }
    }

    fn delay(self) -> u64 {
        match self {
            Self::RestartPending => RESTART_PENDING_SECONDS,
            _ => CONFIRM_SECONDS,
        }
    }
}

/// Only the current problems and the last day's send times are kept.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AlertState {
    pub first_seen: BTreeMap<Problem, u64>,
    /// Problems the receiver was told about and not yet told have cleared.
    pub notified: BTreeSet<Problem>,
    pub sent: Vec<u64>,
    /// Automatic restart counters at the previous check, by unit.
    pub restarts: BTreeMap<String, u64>,
    pub status: AlertStatus,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Notice {
    pub problems: Vec<Problem>,
    pub resolved: Vec<Problem>,
}

/// Records the current problems and returns the net change the receiver has not heard yet,
/// unless the rate limit holds it back. A held change is sent by a later check, and a problem
/// that started and cleared in between is never sent.
pub(crate) fn due(state: &mut AlertState, current: &BTreeSet<Problem>, now: u64) -> Option<Notice> {
    state
        .first_seen
        .retain(|problem, _| current.contains(problem));
    for problem in current {
        state.first_seen.entry(*problem).or_insert(now);
    }
    state
        .sent
        .retain(|sent| now.saturating_sub(*sent) < DAY_SECONDS);
    let problems = current
        .iter()
        .filter(|problem| {
            !state.notified.contains(*problem)
                && now.saturating_sub(state.first_seen[*problem]) >= problem.delay()
        })
        .copied()
        .collect::<Vec<_>>();
    let resolved = state
        .notified
        .iter()
        .filter(|problem| !current.contains(*problem))
        .copied()
        .collect::<Vec<_>>();
    let limited = state.sent.len() >= MAX_ALERTS_PER_DAY
        || state
            .sent
            .last()
            .is_some_and(|sent| now.saturating_sub(*sent) < MIN_SECONDS_BETWEEN_ALERTS);
    ((!problems.is_empty() || !resolved.is_empty()) && !limited)
        .then_some(Notice { problems, resolved })
}

pub(crate) fn delivered(state: &mut AlertState, notice: &Notice, now: u64) {
    state.notified.extend(&notice.problems);
    for problem in &notice.resolved {
        state.notified.remove(problem);
    }
    state.sent.push(now);
    state.status.alert_sent_at_unix = Some(now);
    state.status.alert_failure = None;
}

pub(crate) struct Message {
    event: &'static str,
    title: &'static str,
    body: String,
    problems: Vec<Problem>,
    resolved: Vec<Problem>,
}

pub(crate) fn message(notice: &Notice) -> Message {
    let lines = notice
        .problems
        .iter()
        .map(|problem| problem.text().1.to_owned())
        .chain(
            notice
                .resolved
                .iter()
                .map(|problem| format!("Resolved: {}.", problem.text().0)),
        );
    Message {
        event: "alert",
        title: if notice.problems.is_empty() {
            "SirinVPN: VPS problem resolved"
        } else {
            "SirinVPN: your VPS needs attention"
        },
        body: lines.collect::<Vec<_>>().join("\n"),
        problems: notice.problems.clone(),
        resolved: notice.resolved.clone(),
    }
}

fn test_message() -> Message {
    Message {
        event: "test",
        title: "SirinVPN test alert",
        body: "This test alert came from your SirinVPN VPS. Alerts reach this address.".into(),
        problems: Vec::new(),
        resolved: Vec::new(),
    }
}

/// Unit states and automatic restart counters from one `systemctl show` call, in unit order.
pub(crate) fn service_problems(
    text: &str,
    units: &[&str],
    previous: &BTreeMap<String, u64>,
) -> (BTreeSet<Problem>, BTreeMap<String, u64>) {
    let mut problems = BTreeSet::new();
    let mut restarts = BTreeMap::new();
    for (unit, block) in units.iter().zip(text.split("\n\n")) {
        let field = |name: &str| {
            block
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
        };
        // `activating` is also the wait between automatic restarts; the counter covers loops.
        if matches!(field("ActiveState"), Some("failed" | "inactive")) {
            problems.insert(Problem::ServiceDown);
        }
        if let Some(count) = field("NRestarts").and_then(|count| count.parse::<u64>().ok()) {
            let before = previous.get(*unit).copied().unwrap_or(count);
            if count.saturating_sub(before) >= RESTART_LOOP {
                problems.insert(Problem::ServiceRestarting);
            }
            restarts.insert((*unit).to_owned(), count);
        }
    }
    (problems, restarts)
}

async fn current_problems(
    configuration: &ServerConfiguration,
    state: &mut AlertState,
) -> BTreeSet<Problem> {
    let mut units = SERVICES.to_vec();
    if configuration.dns_upstream.doh_endpoints().is_some() {
        units.push("sirinvpn-doh.service");
    }
    let arguments = ["show", "--property=ActiveState,NRestarts"]
        .into_iter()
        .chain(units.iter().copied())
        .collect::<Vec<_>>();
    let (services, resolver, disk, (automatic_updates, restart)) = tokio::join!(
        crate::diagnostics::output("systemctl", &arguments),
        crate::dns_diagnostics::local_resolver_answers(),
        service_metrics::root_disk_usage(),
        crate::diagnostics::update_state(),
    );
    let (mut problems, restarts) = service_problems(
        services.as_deref().unwrap_or_default(),
        &units,
        &state.restarts,
    );
    state.restarts = restarts;
    if !metrics::interface_exists(&configuration.interface_name)
        || crate::diagnostics::flag("/proc/sys/net/ipv4/ip_forward") == Some(false)
        || crate::diagnostics::ports(configuration) == Some(false)
    {
        problems.insert(Problem::NetworkSetup);
    }
    if !resolver {
        problems.insert(Problem::DnsFailing);
    }
    // A reported full disk clears only well below the threshold, so it cannot flap.
    let threshold = if state.notified.contains(&Problem::DiskNearlyFull) {
        DISK_CLEARED_PERCENT
    } else {
        DISK_FULL_PERCENT
    };
    if disk.is_some_and(|(used, total)| {
        total > 0 && u128::from(used) * 100 >= threshold * u128::from(total)
    }) {
        problems.insert(Problem::DiskNearlyFull);
    }
    if !automatic_updates {
        problems.insert(Problem::SecurityUpdatesOff);
    }
    if restart == Some(true) {
        problems.insert(Problem::RestartPending);
    }
    problems
}

/// Every address the request may use: an IP literal, or all resolved addresses of a name.
/// Unless allowed, one private answer refuses the whole name.
pub(crate) async fn checked_addresses(
    url: &reqwest::Url,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, AlertFailure> {
    let host = url.host_str().ok_or(AlertFailure::Address)?;
    let port = url.port_or_known_default().ok_or(AlertFailure::Address)?;
    let addresses = match host.trim_start_matches('[').trim_end_matches(']').parse() {
        Ok(address) => vec![SocketAddr::new(address, port)],
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| AlertFailure::Address)?
            .collect(),
    };
    if addresses.is_empty()
        || (!allow_private
            && addresses
                .iter()
                .any(|address| !public_ip_address(address.ip())))
    {
        return Err(AlertFailure::Address);
    }
    Ok(addresses)
}

/// One bounded HTTPS request: a notice with `message`, or a heartbeat `GET` without. The
/// connection goes only to the checked addresses, without redirects or proxies.
pub(crate) async fn send(
    url: &str,
    allow_private: bool,
    message: Option<(&Message, AlertFormat)>,
) -> Result<(), (AlertFailure, Option<u16>)> {
    let url = reqwest::Url::parse(url).map_err(|_| (AlertFailure::Address, None))?;
    let request = async {
        let addresses = checked_addresses(&url, allow_private)
            .await
            .map_err(|failure| (failure, None))?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(Duration::from_secs(DELIVERY_SECONDS))
            .user_agent("SirinVPN-alerts/1")
            .resolve_to_addrs(url.host_str().unwrap_or_default(), &addresses);
        #[cfg(test)]
        let client = match TEST_ROOT.lock().unwrap().as_deref() {
            Some(pem) => client.add_root_certificate(reqwest::Certificate::from_pem(pem).unwrap()),
            None => client,
        };
        let client = client
            .build()
            .map_err(|_| (AlertFailure::Connection, None))?;
        let request = match message {
            None => client.get(url.clone()),
            Some((message, AlertFormat::Ntfy)) => {
                let request = client
                    .post(url.clone())
                    .header("Title", message.title)
                    .body(message.body.clone());
                match (message.event, message.problems.is_empty()) {
                    ("test", _) => request,
                    (_, false) => request.header("Tags", "warning").header("Priority", "high"),
                    (_, true) => request.header("Tags", "white_check_mark"),
                }
            }
            Some((message, AlertFormat::Webhook)) => {
                client.post(url.clone()).json(&serde_json::json!({
                    "event": message.event,
                    "title": message.title,
                    "message": message.body,
                    // Chat webhooks read `text`.
                    "text": format!("{}\n{}", message.title, message.body),
                    "problems": message.problems,
                    "resolved": message.resolved,
                }))
            }
        };
        let status = request
            .send()
            .await
            .map_err(|_| (AlertFailure::Connection, None))?
            .status();
        if !status.is_success() {
            return Err((AlertFailure::Rejected, Some(status.as_u16())));
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(DELIVERY_SECONDS), request)
        .await
        .unwrap_or(Err((AlertFailure::Connection, None)))
}

/// The fingerprint ties stored outcomes and notified problems to one policy.
fn fingerprint(policy: &AlertPolicy) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(policy).unwrap_or_default(),
    ))
}

pub(crate) fn read_state(directory: &Path) -> AlertState {
    sirinvpn_platform::files::read_bounded(&directory.join(STATE_FILE), 16 * 1024)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_state(directory: &Path, state: &AlertState) -> Result<()> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".state-")
        .tempfile_in(directory)?;
    temporary.write_all(&serde_json::to_vec(state)?)?;
    sirinvpn_platform::files::persist(temporary, &directory.join(STATE_FILE), true)?;
    Ok(())
}

pub(crate) async fn check(paths: &ServerPaths, directory: &Path) -> Result<()> {
    let policy = if paths.authorization.exists() {
        load_authorization(&paths.authorization)?.alerts
    } else {
        AlertPolicy::default()
    };
    if policy.alert_url.is_none() && policy.heartbeat_url.is_none() {
        return match fs::remove_file(directory.join(STATE_FILE)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        };
    }
    let mut state = read_state(directory);
    let policy_sha256 = fingerprint(&policy);
    if state.status.policy_sha256.as_deref() != Some(policy_sha256.as_str()) {
        // A changed address has heard nothing yet; the rate limit still applies.
        state = AlertState {
            sent: state.sent,
            restarts: state.restarts,
            ..Default::default()
        };
        state.status.policy_sha256 = Some(policy_sha256);
    }
    let now = unix_time();
    state.status.checked_at_unix = Some(now);
    if let Some(url) = &policy.alert_url {
        let current = current_problems(&load_configuration(paths)?, &mut state).await;
        if let Some(notice) = due(&mut state, &current, now) {
            let message = message(&notice);
            match send(
                url,
                policy.allow_private_addresses,
                Some((&message, policy.format)),
            )
            .await
            {
                Ok(()) => delivered(&mut state, &notice, now),
                Err((failure, _)) => state.status.alert_failure = Some(failure),
            }
        }
    }
    if let Some(url) = &policy.heartbeat_url {
        match send(url, policy.allow_private_addresses, None).await {
            Ok(()) => {
                state.status.heartbeat_sent_at_unix = Some(now);
                state.status.heartbeat_failure = None;
            }
            Err((failure, _)) => state.status.heartbeat_failure = Some(failure),
        }
    }
    write_state(directory, &state)
}

pub(super) fn management_available(state: &AppState) -> bool {
    state.authorization.is_some() && Path::new(TIMER_UNIT).exists()
}

fn settings(policy: AlertPolicy) -> AlertSettings {
    let mut status = read_state(Path::new(STATE_DIRECTORY)).status;
    if status.policy_sha256.as_deref() != Some(fingerprint(&policy).as_str()) {
        status = AlertStatus::default();
    }
    AlertSettings { policy, status }
}

fn require_owner(
    authorization: &AuthorizationDocument,
    identity: &CallerIdentity,
) -> Result<(), ApiError> {
    if !authorize_current(authorization, identity, true)?.is_owner() {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

pub(super) async fn settings_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<AlertSettings>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let current = authorization.read().await;
    require_owner(&current, &identity)?;
    Ok(Json(ApiEnvelope::new(settings(current.alerts.clone()))))
}

pub(super) async fn update_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    Json(policy): Json<AlertPolicy>,
) -> Result<Json<ApiEnvelope<AlertSettings>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    require_owner(&current, &identity)?;
    policy.validate().map_err(ApiError::invalid)?;
    if current.alerts != policy {
        if !management_available(&state) {
            return Err(ApiError::conflict(
                "repair this SirinVPN server before setting VPS alerts",
            ));
        }
        ensure_active_endpoint_authority(&current)?;
        let mut next = current.clone();
        next.alerts = policy;
        commit_authorization(&state, &mut current, next).await?;
    }
    Ok(Json(ApiEnvelope::new(settings(current.alerts.clone()))))
}

/// Sends a test notice to the saved alert address and reports the outcome.
pub(super) async fn test_handler(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<AlertTestResult>>, ApiError> {
    let policy = {
        let authorization = require_authorization(&state)?;
        let current = authorization.read().await;
        require_owner(&current, &identity)?;
        current.alerts.clone()
    };
    let Some(url) = &policy.alert_url else {
        return Err(ApiError::invalid(
            "save an alert address before sending a test alert",
        ));
    };
    {
        let mut last = LAST_TEST.lock().map_err(|_| ApiError::internal())?;
        if last.is_some_and(|sent| sent.elapsed() < TEST_INTERVAL) {
            return Err(ApiError::conflict(
                "wait a few seconds before sending another test alert",
            ));
        }
        *last = Some(Instant::now());
    }
    let result = send(
        url,
        policy.allow_private_addresses,
        Some((&test_message(), policy.format)),
    )
    .await
    .err();
    Ok(Json(ApiEnvelope::new(AlertTestResult {
        failure: result.map(|(failure, _)| failure),
        http_status: result.and_then(|(_, status)| status),
    })))
}

#[cfg(test)]
mod tests;
