use serde::{Deserialize, Serialize};

pub const MIN_IPV4_TUNNEL_MTU: u16 = 576;
pub const MIN_IPV6_TUNNEL_MTU: u16 = 1280;
pub const MAX_TUNNEL_MTU: u16 = 1420;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum MtuPolicy {
    #[default]
    Automatic,
    Manual {
        value: u16,
    },
}

impl MtuPolicy {
    pub fn validate(self, ipv6: bool) -> Result<(), &'static str> {
        let minimum = if ipv6 {
            MIN_IPV6_TUNNEL_MTU
        } else {
            MIN_IPV4_TUNNEL_MTU
        };
        if let Self::Manual { value } = self
            && !(minimum..=MAX_TUNNEL_MTU).contains(&value)
        {
            return Err(if ipv6 {
                "MTU must be 1280–1420 while tunneled IPv6 is enabled"
            } else {
                "MTU must be 576–1420"
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtuProbeOutcome {
    #[default]
    Pending,
    Measured,
    IcmpUnavailable,
    NoUsableMtu,
    ApplyFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MtuStatus {
    pub policy: MtuPolicy,
    pub configured: u16,
    pub suggested: Option<u16>,
    pub outcome: MtuProbeOutcome,
}
