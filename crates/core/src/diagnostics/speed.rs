//! Speed test through the tunnel to this device's own VPS. No third-party server is involved and
//! the result stays on this device. It measures one TCP connection to the VPS, not internet speed.
use crate::{ManagementClient, ManagementError, SecretIdentity};
use serde::Serialize;
use sirinvpn_protocol::{ErrorCode, SPEED_TEST_MAX_BYTES, SPEED_TEST_SECONDS, ServerProfile};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

const PHASE: Duration = Duration::from_secs(SPEED_TEST_SECONDS);
const IDLE_SAMPLES: usize = 5;
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
static ZEROS: [u8; 64 * 1024] = [0; 64 * 1024];

/// Latency is the median round trip of a small management request: idle, then while each
/// transfer runs. `None` when no request in that phase returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SpeedTestResult {
    pub download_bits_per_second: u64,
    pub upload_bits_per_second: u64,
    pub idle_latency_micros: Option<u64>,
    pub download_latency_micros: Option<u64>,
    pub upload_latency_micros: Option<u64>,
}

/// What to do next, for the person running the test; it never names an address or key.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SpeedTestFailure(String);

pub async fn speed_test(
    profile: &ServerProfile,
    identity: &SecretIdentity,
) -> Result<SpeedTestResult, SpeedTestFailure> {
    run(profile, identity)
        .await
        .map_err(|error| SpeedTestFailure(failure(&error)))
}

async fn run(
    profile: &ServerProfile,
    identity: &SecretIdentity,
) -> Result<SpeedTestResult, ManagementError> {
    // Separate clients keep separate connections, so a probe never waits behind transfer data
    // inside the same TLS stream; it still queues wherever the tunnel path is congested.
    let transfer = ManagementClient::for_speed_test(profile, identity)?;
    let probe = ManagementClient::new(profile, identity)?;
    // The first request opens the probe connection, so it is not a sample.
    probe.speed_test_latency().await?;
    let mut idle = Vec::new();
    // A probe that fails here means the path is stalled; the transfers would only fail later.
    while idle.len() < IDLE_SAMPLES
        && let Some(sample) = latency(&probe).await
    {
        idle.push(sample);
    }
    let (download_bits_per_second, download_latency_micros) =
        under_load(&probe, download(&transfer)).await?;
    let (upload_bits_per_second, upload_latency_micros) =
        under_load(&probe, upload(&transfer)).await?;
    Ok(SpeedTestResult {
        download_bits_per_second,
        upload_bits_per_second,
        idle_latency_micros: median(idle),
        download_latency_micros,
        upload_latency_micros,
    })
}

async fn latency(probe: &ManagementClient) -> Option<u64> {
    let started = Instant::now();
    probe.speed_test_latency().await.ok()?;
    Some(micros(started.elapsed()))
}

/// Times small requests until the transfer ends.
async fn under_load(
    probe: &ManagementClient,
    transfer: impl Future<Output = Result<u64, ManagementError>>,
) -> Result<(u64, Option<u64>), ManagementError> {
    tokio::pin!(transfer);
    let mut samples = Vec::new();
    loop {
        tokio::select! {
            result = &mut transfer => return Ok((result?, median(samples))),
            sample = async {
                tokio::time::sleep(PROBE_INTERVAL).await;
                latency(probe).await
            } => samples.extend(sample),
        }
    }
}

async fn download(transfer: &ManagementClient) -> Result<u64, ManagementError> {
    let mut response = transfer.speed_test_download().await?;
    // The clock starts once the response arrives, so connection setup is not part of the rate.
    let started = Instant::now();
    let end = tokio::time::Instant::now() + PHASE;
    let mut bytes = 0u64;
    loop {
        match tokio::time::timeout_at(end, response.chunk()).await {
            Ok(Ok(Some(chunk))) => bytes += chunk.len() as u64,
            Ok(Ok(None)) | Err(_) => break,
            Ok(Err(_)) => return Err(ManagementError::ConnectionFailed),
        }
    }
    Ok(rate(bytes, started.elapsed()))
}

async fn upload(transfer: &ManagementClient) -> Result<u64, ManagementError> {
    let started = Arc::new(OnceLock::new());
    let received = transfer
        .speed_test_upload(reqwest::Body::wrap(Generated {
            started: started.clone(),
            sent: 0,
        }))
        .await?
        .received_bytes;
    // The body is first polled once the connection is ready, so setup is not part of the rate.
    Ok(rate(
        received,
        started.get().map_or(Duration::ZERO, Instant::elapsed),
    ))
}

/// Zeros for `PHASE` after the first poll, up to the VPS's byte limit. The content is irrelevant
/// inside TLS and WireGuard.
struct Generated {
    started: Arc<OnceLock<Instant>>,
    sent: u64,
}

impl http_body::Body for Generated {
    type Data = &'static [u8];
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Infallible>>> {
        let started = *self.started.get_or_init(Instant::now);
        if started.elapsed() >= PHASE || self.sent >= SPEED_TEST_MAX_BYTES {
            return Poll::Ready(None);
        }
        self.sent += ZEROS.len() as u64;
        Poll::Ready(Some(Ok(http_body::Frame::data(&ZEROS[..]))))
    }
}

fn rate(bytes: u64, elapsed: Duration) -> u64 {
    u64::try_from(u128::from(bytes) * 8_000_000 / elapsed.as_micros().max(1)).unwrap_or(u64::MAX)
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn median(mut samples: Vec<u64>) -> Option<u64> {
    samples.sort_unstable();
    samples.get(samples.len() / 2).copied()
}

fn failure(error: &ManagementError) -> String {
    match error {
        ManagementError::SpeedTestUnsupported => {
            "Your VPS can't run the speed test yet. Update the VPS, then try again.".into()
        }
        ManagementError::RequestRejected {
            code: ErrorCode::AuthorizationFailed,
            ..
        } => "Only the Owner or an Admin can run the speed test.".into(),
        ManagementError::RequestRejected {
            code: ErrorCode::RateLimited | ErrorCode::ConflictDetected,
            message,
        } => format!("The speed test didn't start: {message}."),
        ManagementError::RequestRejected { message, .. } => {
            format!("The speed test didn't finish: {message}.")
        }
        _ => "The speed test didn't finish. Check that this device is connected to this VPN, then try again.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body as _;

    #[test]
    fn rates_are_bits_per_second_and_latency_is_the_median() {
        assert_eq!(rate(1_000_000, Duration::from_secs(8)), 1_000_000);
        assert_eq!(rate(125_000_000, Duration::from_secs(1)), 1_000_000_000);
        assert_eq!(rate(10, Duration::ZERO), 80_000_000);
        assert_eq!(median(vec![30, 10, 20, 9_000]), Some(30));
        assert_eq!(median(vec![7]), Some(7));
        assert_eq!(median(Vec::new()), None);
    }

    #[test]
    fn the_upload_body_ends_one_phase_after_its_first_poll_or_at_the_byte_limit() {
        let started = Arc::new(OnceLock::new());
        let mut body = Generated {
            started: started.clone(),
            sent: 0,
        };
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut context) else {
            panic!("no first chunk");
        };
        assert_eq!(frame.into_data().unwrap().len(), ZEROS.len());
        let first = *started.get().unwrap();
        // Pretend the phase began earlier: the next poll ends the body.
        let mut ended = Generated {
            started: Arc::new(OnceLock::from(first - PHASE)),
            sent: 0,
        };
        assert!(matches!(
            Pin::new(&mut ended).poll_frame(&mut context),
            Poll::Ready(None)
        ));
        body.sent = SPEED_TEST_MAX_BYTES;
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut context),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn failures_say_what_to_do() {
        let rejected = |code, message: &str| ManagementError::RequestRejected {
            code,
            message: message.into(),
        };
        assert!(failure(&ManagementError::SpeedTestUnsupported).contains("Update the VPS"));
        assert_eq!(
            failure(&rejected(ErrorCode::AuthorizationFailed, "denied")),
            "Only the Owner or an Admin can run the speed test."
        );
        assert_eq!(
            failure(&rejected(
                ErrorCode::RateLimited,
                "wait 41 seconds before the next speed test"
            )),
            "The speed test didn't start: wait 41 seconds before the next speed test."
        );
        assert!(failure(&ManagementError::ConnectionFailed).contains("connected to this VPN"));
    }
}
