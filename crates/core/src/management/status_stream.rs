use super::*;

impl ManagementClient {
    /// Open a pinned, mutually authenticated stream without a total-body timeout.
    /// Each read still has a deadline; dropping the stream closes the response.
    pub async fn subscribe_status(
        profile: &ServerProfile,
        secret: &SecretIdentity,
    ) -> Result<ManagementStatusStream, ManagementError> {
        Self::with_timeout(profile, secret, None)?
            .open_status_stream()
            .await
    }

    async fn open_status_stream(&self) -> Result<ManagementStatusStream, ManagementError> {
        let response = self
            .client
            .get(format!("{}/v1/status/stream", self.base_url))
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await
            .map_err(|_| ManagementError::ConnectionFailed)?;
        if matches!(response.status().as_u16(), 404 | 405 | 501) {
            return Err(ManagementError::StatusStreamingUnsupported);
        }
        if !response.status().is_success() {
            self.decode::<ServerStatus>(response).await?;
            return Err(ManagementError::ConnectionFailed);
        }
        if response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_none_or(|value| !value.trim().eq_ignore_ascii_case("text/event-stream"))
        {
            return Err(ManagementError::ProtocolMismatch);
        }
        Ok(ManagementStatusStream {
            response,
            buffer: Vec::new(),
        })
    }
}

pub struct ManagementStatusStream {
    response: reqwest::Response,
    buffer: Vec<u8>,
}

impl ManagementStatusStream {
    pub async fn next_status(&mut self) -> Result<ServerStatus, ManagementError> {
        loop {
            if let Some((end, separator)) = event_boundary(&self.buffer) {
                let result = decode_event(&self.buffer[..end]);
                self.buffer.drain(..end + separator);
                if let Some(status) = result? {
                    return Ok(status);
                }
                continue;
            }
            let chunk = self
                .response
                .chunk()
                .await
                .map_err(|_| ManagementError::ConnectionFailed)?
                .ok_or(ManagementError::ConnectionFailed)?;
            if self.buffer.len().saturating_add(chunk.len()) > MAX_MANAGEMENT_RESPONSE_BYTES {
                return Err(ManagementError::ConnectionFailed);
            }
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

fn event_boundary(buffer: &[u8]) -> Option<(usize, usize)> {
    buffer.iter().enumerate().find_map(|(index, _)| {
        let tail = &buffer[index..];
        if tail.starts_with(b"\n\n") {
            Some((index, 2))
        } else if tail.starts_with(b"\r\n\r\n") {
            Some((index, 4))
        } else {
            None
        }
    })
}

fn decode_event(bytes: &[u8]) -> Result<Option<ServerStatus>, ManagementError> {
    let frame = std::str::from_utf8(bytes).map_err(|_| ManagementError::ConnectionFailed)?;
    let mut event = "message";
    let mut data = String::new();
    for line in frame.lines() {
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = value,
            "data" => {
                data.push_str(value);
                data.push('\n');
            }
            _ => {}
        }
    }
    if data.is_empty() || event != "status" {
        return Ok(None);
    }
    let envelope: ApiEnvelope<ServerStatus> =
        serde_json::from_str(&data).map_err(|_| ManagementError::ConnectionFailed)?;
    if envelope.api_version != API_VERSION || envelope.payload.api_version != API_VERSION {
        return Err(ManagementError::ProtocolMismatch);
    }
    Ok(Some(envelope.payload))
}

#[cfg(test)]
mod tests;
