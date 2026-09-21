//! Current peer authorization and signed migration control.
use super::*;

#[derive(Clone, Default)]
pub struct AuthorizedPeers {
    peers: Arc<RwLock<HashSet<[u8; 32]>>>,
    endpoint_checkpoint: Arc<RwLock<Option<Vec<u8>>>>,
    endpoint_publisher: Arc<RwLock<Option<tokio::sync::mpsc::Sender<EndpointPublicationRequest>>>>,
}

pub struct EndpointPublicationRequest {
    pub device_public_key: [u8; 32],
    pub checkpoint: Vec<u8>,
    pub result: tokio::sync::oneshot::Sender<bool>,
}

impl AuthorizedPeers {
    pub fn set_endpoint_publisher(
        &self,
        publisher: tokio::sync::mpsc::Sender<EndpointPublicationRequest>,
    ) {
        *self
            .endpoint_publisher
            .write()
            .unwrap_or_else(|error| error.into_inner()) = Some(publisher);
    }

    pub(crate) async fn offer_endpoint_checkpoint(
        &self,
        device_public_key: [u8; 32],
        checkpoint: Vec<u8>,
    ) -> bool {
        let publisher = self
            .endpoint_publisher
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let Some(publisher) = publisher else {
            return false;
        };
        let (result, received) = tokio::sync::oneshot::channel();
        if publisher
            .try_send(EndpointPublicationRequest {
                device_public_key,
                checkpoint,
                result,
            })
            .is_err()
        {
            return false;
        }
        tokio::time::timeout(Duration::from_secs(4), received)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
    }

    pub fn replace<I>(&self, peers: I)
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        *self
            .peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = peers.into_iter().collect();
    }

    pub fn contains(&self, peer: &[u8; 32]) -> bool {
        self.peers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(peer)
    }

    /// Only the current signed public endpoint checkpoint is retained.
    pub fn publish_endpoint_checkpoint(
        &self,
        checkpoint: Option<Vec<u8>>,
    ) -> Result<(), RelayError> {
        if checkpoint
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > 24 * 1024)
        {
            return Err(RelayError::InvalidConfiguration);
        }
        *self
            .endpoint_checkpoint
            .write()
            .unwrap_or_else(|error| error.into_inner()) = checkpoint;
        Ok(())
    }

    pub(crate) fn endpoint_checkpoint(&self) -> Option<Vec<u8>> {
        self.endpoint_checkpoint
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}
