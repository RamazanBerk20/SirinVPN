//! Authenticated, demand-driven VPS readings over one persistent connection.

use super::*;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream;
use tokio::sync::watch;

type Sample = Option<Arc<HostSample>>;

/// One sampler task serves every status request and stream. It runs while anyone listens
/// and stops one interval after the last reader leaves, so idle servers spawn nothing.
/// The slot keeps a receiver, not a sender: only the task holds the sender, so if the task
/// dies (panics) every waiting reader wakes with an error and the next subscriber restarts it.
#[derive(Clone, Default)]
pub(super) struct StatusFeed(Arc<Mutex<Option<watch::Receiver<Sample>>>>);

pub(super) const STATUS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

impl StatusFeed {
    pub(super) fn subscribe(&self, configuration: &ServerConfiguration) -> watch::Receiver<Sample> {
        let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(receiver) = slot.as_ref()
            && receiver.has_changed().is_ok()
        {
            return receiver.clone();
        }
        let (sender, receiver) = watch::channel(None);
        *slot = Some(receiver.clone());
        let feed = self.clone();
        let configuration = configuration.clone();
        tokio::spawn(async move {
            loop {
                let sample = sample_host(&configuration).await;
                sender.send_replace(Some(Arc::new(sample)));
                tokio::time::sleep(STATUS_SAMPLE_INTERVAL).await;
                // Checked under the slot lock, so a new subscriber either sees this task
                // running or starts the next one.
                let mut slot = feed.0.lock().unwrap_or_else(|e| e.into_inner());
                // The slot's own receiver is the one left when nobody listens.
                if sender.receiver_count() <= 1 {
                    *slot = None;
                    return;
                }
            }
        });
        receiver
    }

    /// The newest sample, at most one sampling interval old.
    pub(super) async fn latest(&self, configuration: &ServerConfiguration) -> Arc<HostSample> {
        let mut receiver = self.subscribe(configuration);
        let sample = receiver
            .wait_for(Option::is_some)
            .await
            .map(|sample| sample.clone())
            .ok()
            .flatten();
        match sample {
            Some(sample) => sample,
            // The sampler task ended unexpectedly; read once directly.
            None => Arc::new(sample_host(configuration).await),
        }
    }
}

pub(super) async fn status_stream_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Response, ApiError> {
    authorize_device(&state, &caller, false).await?;
    let slot = acquire_stream(&state, &caller)?;
    let samples = state.throttle.status.subscribe(&state.configuration);
    // A subscriber owns only its previous counters. REST requests and other
    // subscribers cannot shorten its sampling window or erase its rates.
    let sampler = Mutex::new(LiveMetricSampler::default());
    let events = stream::unfold(
        (state, caller, sampler, samples, slot),
        |(state, caller, sampler, mut samples, slot)| async move {
            samples.changed().await.ok()?;
            let sample = samples.borrow_and_update().clone()?;
            // A revoked device's existing TLS connection must stop receiving data.
            let status = caller_status(&state, &caller, &sampler, &sample)
                .await
                .ok()?;
            let event = Event::default()
                .event("status")
                .json_data(ApiEnvelope::new(status));
            Some((event, (state, caller, sampler, samples, slot)))
        },
    );
    // Dropping the response releases the stream slot and the sampler subscription.
    Ok(Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(5)))
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sampler task that died (for example by panicking) leaves a closed channel in the
    /// slot; readers must not wait on it forever, and the next one restarts the sampler.
    #[tokio::test]
    async fn a_dead_sampler_neither_hangs_readers_nor_stays_dead() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ServerPaths::under(directory.path());
        let owner = sirinvpn_core::LocalIdentity::generate("Sampler owner").unwrap();
        initialize(
            &paths,
            "Sampler",
            &owner.public.management_certificate_pem,
            ServerId::new(),
            &owner.public.wireguard_public_key,
            51_820,
        )
        .unwrap();
        let configuration = load_configuration(&paths).unwrap();
        let feed = StatusFeed::default();
        let (sender, dead) = watch::channel(None);
        *feed.0.lock().unwrap() = Some(dead);
        // A reader already waiting when the task dies wakes up.
        let mut waiting = feed.subscribe(&configuration);
        drop(sender);
        assert!(waiting.wait_for(Option::is_some).await.is_err());
        tokio::time::timeout(Duration::from_secs(10), feed.latest(&configuration))
            .await
            .expect("latest() must not wait on a dead sampler");
        let live = feed.0.lock().unwrap().clone().unwrap();
        assert!(live.has_changed().is_ok(), "the sampler was restarted");
    }
}
