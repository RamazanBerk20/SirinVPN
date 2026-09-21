//! Current client conditions and sanitized, authenticated remote checks. Never persisted.
use crate::{ManagementClient, ManagementError, SecretIdentity};
use sirinvpn_protocol::{
    API_VERSION, ConnectionState, DiagnosticCheck, DiagnosticLevel, DiagnosticReport, ErrorCode,
    MtuPolicy, MtuProbeOutcome, MtuStatus, ServerProfile, TransportKind, TransportQualitySample,
};
use std::error::Error;

mod dns;
mod remote;
pub use dns::{PrivateDnsOutcome, private_dns_check, probe_private_dns};
pub(crate) use remote::sanitize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protection {
    Off,
    Armed,
    Blocking,
    Failed,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CurrentConnection {
    pub state: ConnectionState,
    pub selected_server: bool,
    pub another_server: bool,
    pub recovering: bool,
    pub waiting_for_user: bool,
    pub protection: Protection,
    pub transport: Option<TransportKind>,
    pub split_routes: bool,
    pub split_applications: bool,
    pub ipv6_tunneled: bool,
    pub ipv6_blocked: bool,
    pub mtu: Option<MtuStatus>,
    pub quality: Option<TransportQualitySample>,
}

impl CurrentConnection {
    pub fn can_probe(&self) -> bool {
        self.selected_server
            && !self.another_server
            && self.state == ConnectionState::Connected
            && !self.recovering
            && !self.waiting_for_user
    }
}

pub fn check(code: &str, label: &str, level: DiagnosticLevel, message: &str) -> DiagnosticCheck {
    DiagnosticCheck {
        code: code.into(),
        label: label.into(),
        level,
        message: message.into(),
    }
}

pub async fn diagnose(
    profile: &ServerProfile,
    identity: Option<&SecretIdentity>,
    current: Option<&CurrentConnection>,
) -> DiagnosticReport {
    let mut checks = local_checks(current);
    let Some(identity) = identity else {
        checks.push(check("local_identity", "Device identity storage", DiagnosticLevel::Fail,
            "The device identity could not be opened. Unlock the system secret store or this phone, then retry. Restore a device backup or enroll again if the identity is missing."));
        return report(checks);
    };
    let client = match ManagementClient::for_diagnostics(profile, identity) {
        Ok(client) => client,
        Err(error) => {
            checks.push(management_failure(&error));
            return report(checks);
        }
    };
    checks.push(check("local_identity", "Saved management identities", DiagnosticLevel::Pass,
        "The saved server pin and device certificate/key can be loaded. Their current server authorization is checked over the VPN."));
    if !current.is_some_and(CurrentConnection::can_probe) {
        checks.push(check("management", "VPS authentication and connectivity", DiagnosticLevel::Warning,
            "Connect this device to the selected server to check authenticated management, current server DNS and VPS networking. Local checks are available while disconnected."));
        return report(checks);
    }
    match client.diagnostics().await {
        Ok(remote) => {
            checks.push(check("management", "VPS authentication and connectivity", DiagnosticLevel::Pass,
                "The private management service accepted the pinned TLS connection and this device's current authorization."));
            checks.extend(remote.checks);
        }
        Err(error) => checks.push(management_failure(&error)),
    }
    report(checks)
}

fn report(checks: Vec<DiagnosticCheck>) -> DiagnosticReport {
    DiagnosticReport {
        api_version: API_VERSION.into(),
        checks,
    }
}

pub fn local_checks(current: Option<&CurrentConnection>) -> Vec<DiagnosticCheck> {
    use DiagnosticLevel::{Fail, Pass, Warning};
    let Some(state) = current else {
        return vec![check(
            "local_backend",
            "Local VPN service",
            Fail,
            "The local VPN service did not return a usable state. Open the app's connection screen and refresh; repair or reinstall the local component if it remains unavailable.",
        )];
    };
    let (level, message) = if state.another_server {
        (
            Warning,
            "Another server owns the local VPN. Select that server to inspect its current tunnel, or disconnect it before connecting this server.",
        )
    } else if state.state == ConnectionState::Connected && !state.selected_server {
        (
            Warning,
            "The active tunnel could not be matched to the selected server. Refresh connection state before running remote checks.",
        )
    } else if state.waiting_for_user {
        (
            Warning,
            "Reconnection is paused for your decision. Use Resume in the connection screen when ready.",
        )
    } else if state.recovering {
        (
            Warning,
            "The local service is recovering the connection. Wait for a fresh handshake; if recovery does not finish, review transport and endpoint settings.",
        )
    } else {
        match state.state {
            ConnectionState::Connected => (
                Pass,
                "The local VPN service reports an active tunnel for the selected server.",
            ),
            ConnectionState::Connecting => (
                Warning,
                "A connection attempt is running. Wait for it to finish or cancel it from the connection screen.",
            ),
            ConnectionState::Degraded => (
                Fail,
                "The selected tunnel has no current usable connection. Check the network and endpoint; automatic transport selection can try another configured carrier.",
            ),
            ConnectionState::Disconnected => (
                Warning,
                "This device is disconnected. Connect to run current tunnel and server checks.",
            ),
        }
    };
    let mut checks = vec![
        check(
            "local_backend",
            "Local VPN service",
            Pass,
            "The native VPN service responded to the current status request.",
        ),
        check("local_tunnel", "Selected VPN connection", level, message),
    ];
    let (level, message) = match state.protection {
        Protection::Armed => (
            Pass,
            "The native service reports the kill switch armed for the active connection.",
        ),
        Protection::Blocking => (
            Pass,
            "The kill switch is blocking unprotected traffic. Connectivity may remain blocked until the VPN recovers or protection is explicitly disabled.",
        ),
        Protection::Off => (
            Warning,
            "The kill switch is off. Enable it in connection settings if traffic must remain blocked outside the VPN.",
        ),
        Protection::Failed => (
            Fail,
            "Traffic protection could not be enforced. Recheck the native service or Android Always-on and Block connections without VPN settings before relying on protection.",
        ),
        Protection::Unknown => (
            Warning,
            "The current kill switch state is unavailable. Refresh native status or check Android VPN protection settings.",
        ),
    };
    checks.push(check(
        "local_protection",
        "Current traffic protection",
        level,
        message,
    ));
    if state.selected_server && state.state != ConnectionState::Disconnected {
        if let Some(transport) = state.transport {
            checks.push(check("local_transport", "Current transport", if state.can_probe() { Pass } else { Warning }, match transport {
                TransportKind::DirectUdp => "Direct UDP is selected for the current tunnel. If it cannot establish a handshake, check the public UDP port or choose Automatic transport.",
                TransportKind::ObfuscatedUdp => "Obfuscated UDP is selected for the current tunnel. If it cannot connect, check its public UDP port and current server keys.",
                TransportKind::TcpFallback => "TCP fallback is selected for the current tunnel. If it cannot connect, check its public TCP port and current server keys.",
                TransportKind::TlsLike => "Pinned TLS/HTTPS transport is selected for the current tunnel. If it cannot connect, check its public TCP port, endpoint pin and configured HTTPS name/path.",
            }));
        }
        checks.push(check("local_routes", "Configured VPN routing", if state.can_probe() { Pass } else { Warning },
            if state.split_applications { "Application routing is selected. Only the configured applications use this VPN; the private management and DNS routes remain included." }
            else if state.split_routes { "Selected-subnet routing is configured. Only those subnets and the private management and DNS routes use this VPN." }
            else { "Full-tunnel routing is configured. Explicit local-network or application exceptions still follow the saved policy." }));
        checks.push(check("local_ipv6", "Configured IPv6 handling", if state.ipv6_tunneled || state.ipv6_blocked { Pass } else { Warning },
            if state.ipv6_tunneled { "IPv6 is configured inside the VPN for included traffic." }
            else if state.ipv6_blocked { "IPv6 outside the supported VPN route is blocked by the current policy." }
            else { "This configuration does not claim to tunnel or block all IPv6. Review routing exceptions and system lockdown settings." }));
        if state.can_probe() {
            checks.push(mtu_check(state.mtu));
            if let Some(sample) = state
                .quality
                .filter(|sample| sample.valid() && Some(sample.transport) == state.transport)
            {
                checks.push(check("local_quality", "Current private-tunnel probes", if sample.stable() { Pass } else { Warning },
                    &format!("{} of {} probes returned; average latency {} ms, jitter {} ms. This is a current private-tunnel sample, not an Internet speed test.",
                        sample.probes_received, sample.probes_sent, sample.latency_micros / 1000, sample.jitter_micros / 1000)));
            } else {
                checks.push(check("local_quality", "Current private-tunnel probes", Warning,
                    "No fresh private-tunnel quality sample is available. ICMP filtering can prevent measurement even when the VPN works."));
            }
        }
    }
    checks
}

fn mtu_check(mtu: Option<MtuStatus>) -> DiagnosticCheck {
    use DiagnosticLevel::{Fail, Pass, Warning};
    let Some(mtu) = mtu else {
        return check(
            "local_mtu",
            "Current path MTU",
            Warning,
            "No current path MTU reading is available. Check Network settings after the tunnel connects.",
        );
    };
    let (level, action) = match mtu.outcome {
        MtuProbeOutcome::Pending => (
            Warning,
            "Path probing is pending. Keep the connection active until a current measurement is available.",
        ),
        MtuProbeOutcome::IcmpUnavailable => (
            Warning,
            "ICMP probing is unavailable. This does not establish an MTU failure; use a manual value only when the network's MTU is known.",
        ),
        MtuProbeOutcome::NoUsableMtu => (
            Fail,
            "Small probes returned but no supported nonfragmenting size worked. Try another transport; IPv6 requires at least 1280 bytes.",
        ),
        MtuProbeOutcome::ApplyFailed => (
            Warning,
            "The measured MTU could not be applied. Reconnect or review the manual MTU in Network settings.",
        ),
        MtuProbeOutcome::Measured if mtu.suggested.is_some_and(|value| value < mtu.configured) => (
            Warning,
            "The path supports a smaller MTU. Review the suggestion in Network settings; automatic application waits for protection and idle conditions.",
        ),
        MtuProbeOutcome::Measured if mtu.suggested == Some(mtu.configured) => (
            Pass,
            "The configured size was verified by the current path probes.",
        ),
        MtuProbeOutcome::Measured => (
            Warning,
            "The reported MTU measurement is incomplete. Refresh connection state to obtain a usable suggestion.",
        ),
    };
    let policy = if matches!(mtu.policy, MtuPolicy::Manual { .. }) {
        "Manual"
    } else {
        "Automatic"
    };
    check(
        "local_mtu",
        "Current path MTU",
        level,
        &format!("{policy} MTU: {} bytes. {action}", mtu.configured),
    )
}

pub fn management_failure(error: &ManagementError) -> DiagnosticCheck {
    let message = match error {
        ManagementError::InvalidServerIdentity => {
            "The saved server certificate pin is invalid. Restore a trusted device backup or use the authenticated endpoint recovery flow; do not accept an unverified replacement certificate."
        }
        ManagementError::InvalidClientIdentity => {
            "The saved device management certificate/key is invalid. Restore a device backup or enroll this device again."
        }
        ManagementError::DiagnosticTlsFailed => {
            "The private TLS handshake failed. Check the pinned server identity, this device's enrollment and both device and VPS clocks. Do not bypass certificate verification."
        }
        ManagementError::DiagnosticTimedOut => {
            "The private management request timed out. Check the local tunnel, included management route and VPS service. A timeout alone does not identify a certificate problem."
        }
        ManagementError::ProtocolMismatch | ManagementError::StatusStreamingUnsupported => {
            "The VPS management protocol is incompatible. Update the app and VPS to compatible versions."
        }
        ManagementError::RequestRejected {
            code: ErrorCode::AuthenticationFailed,
            ..
        } => {
            "The VPS rejected device authentication. Check the enrolled device certificate and recover or enroll again if it was replaced."
        }
        ManagementError::RequestRejected {
            code: ErrorCode::AuthorizationFailed | ErrorCode::PermissionDenied,
            ..
        } => {
            "The VPS rejected this device's current access. The owner can check device revocation, member suspension, expiration and access schedules."
        }
        ManagementError::RequestRejected {
            code: ErrorCode::RateLimited,
            ..
        } => "The VPS is limiting requests. Wait briefly, then rerun diagnostics.",
        ManagementError::RequestRejected { .. } => {
            "The authenticated VPS rejected diagnostics. Check current device access and compatible app/server versions."
        }
        ManagementError::ConnectionFailed => {
            "The private management connection did not complete. Check tunnel connectivity, its private route, the VPS service and pinned identities. The current response cannot distinguish those causes."
        }
    };
    check(
        "management",
        "VPS authentication and connectivity",
        DiagnosticLevel::Fail,
        message,
    )
}

pub(crate) fn request_failure(error: reqwest::Error) -> ManagementError {
    if error.is_timeout() {
        return ManagementError::DiagnosticTimedOut;
    }
    if contains_tls_failure(&error) {
        return ManagementError::DiagnosticTlsFailed;
    }
    ManagementError::ConnectionFailed
}

fn contains_tls_failure(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    for _ in 0..16 {
        let Some(error) = current else {
            break;
        };
        if error.is::<rustls::Error>() {
            return true;
        }
        // io::Error::source can skip the wrapped value's own type. Hyper-rustls
        // nests two io::Errors, so follow get_ref before the ordinary cause chain.
        current = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .map(|inner| inner as &(dyn Error + 'static))
            .or_else(|| error.source());
    }
    false
}

#[cfg(test)]
mod tests;
