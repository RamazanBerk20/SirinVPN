use super::*;

impl AuthorizationDocument {
    pub(super) fn validate_device_pairs(&self, device_ids: &HashSet<DeviceId>) -> Result<()> {
        if self.device_pairs.len() > MAX_DEVICE_PAIRS {
            bail!("authorization state contains too many device pairs");
        }
        for (index, pair) in self.device_pairs.iter().enumerate() {
            if pair.device_id == pair.peer_device_id
                || !device_ids.contains(&pair.device_id)
                || !device_ids.contains(&pair.peer_device_id)
                || self.device_pairs[..index]
                    .iter()
                    .any(|earlier| earlier.joins(pair.device_id, pair.peer_device_id))
            {
                bail!("authorization state contains an invalid device pair");
            }
        }
        Ok(())
    }

    /// Adds the pair, or replaces the one joining the same two devices.
    pub(crate) fn set_device_pair(&mut self, pair: DevicePair) -> Result<()> {
        self.device_pairs
            .retain(|existing| !existing.joins(pair.device_id, pair.peer_device_id));
        self.device_pairs.push(pair);
        self.schema_version = self.required_schema_version();
        self.validate()
    }

    pub(crate) fn remove_device_pair(
        &mut self,
        device_id: DeviceId,
        peer_device_id: DeviceId,
    ) -> Result<()> {
        self.device_pairs
            .retain(|pair| !pair.joins(device_id, peer_device_id));
        self.schema_version = self.required_schema_version();
        self.validate()
    }

    /// Both devices are active and a pair lets `source` start connections to `destination`.
    pub(crate) fn pair_permits(&self, source: &DeviceRecord, destination: &DeviceRecord) -> bool {
        !self.endpoint_transition_source
            && self
                .device_pairs
                .iter()
                .any(|pair| pair.permits(source.id, destination.id))
            && self.access_for_device(source).is_some()
            && self.access_for_device(destination).is_some()
    }
}
