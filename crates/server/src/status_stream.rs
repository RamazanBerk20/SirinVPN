//! Authenticated, demand-driven VPS readings over one persistent connection.

use super::*;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream;

pub(super) async fn status_stream_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Response, ApiError> {
    authorize_device(&state, &caller, false).await?;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // A subscriber owns only its previous counters. REST requests and other
    // subscribers cannot shorten its sampling window or erase its rates.
    let sampler = Mutex::new(LiveMetricSampler::default());
    let events = stream::unfold(
        (state, caller, sampler, interval),
        |(state, caller, sampler, mut interval)| async move {
            interval.tick().await;
            // A revoked device's existing TLS connection must stop receiving data.
            let status = caller_status(&state, &caller, &sampler).await.ok()?;
            let event = Event::default()
                .event("status")
                .json_data(ApiEnvelope::new(status));
            Some((event, (state, caller, sampler, interval)))
        },
    );
    // Dropping the response cancels collection; there is no detached polling task.
    Ok(Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(5)))
        .into_response())
}
