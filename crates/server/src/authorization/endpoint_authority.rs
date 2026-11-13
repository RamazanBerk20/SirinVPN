//! Who answers for this VPS's endpoint. Persisted as the three historical document fields so
//! older readers and every stored fingerprint keep their exact JSON.
use super::*;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StoredEndpointAuthority", into = "StoredEndpointAuthority")]
pub(crate) enum EndpointAuthority {
    /// No signed endpoint yet (legacy or never published).
    #[default]
    Unpublished,
    /// This VPS serves the signed head; `observed` once the head's address was seen on an
    /// interface here, which lets the VPS follow an unambiguous address change itself.
    Active {
        head: EndpointTransitionResponse,
        observed: Option<IpAddr>,
    },
    /// The VPS has moved: it keeps the pinned control channel for offline clients, frozen
    /// to the head that names its successor, and serves no traffic.
    HandoffSource { head: EndpointTransitionResponse },
}

impl EndpointAuthority {
    pub(crate) fn head(&self) -> Option<&EndpointTransitionResponse> {
        match self {
            Self::Unpublished => None,
            Self::Active { head, .. } | Self::HandoffSource { head } => Some(head),
        }
    }

    pub(crate) fn is_handoff_source(&self) -> bool {
        matches!(self, Self::HandoffSource { .. })
    }

    pub(crate) fn observed(&self) -> Option<IpAddr> {
        match self {
            Self::Active { observed, .. } => *observed,
            _ => None,
        }
    }

    /// A new head clears the observation; a handoff source stays one.
    pub(super) fn with_head(&self, head: EndpointTransitionResponse) -> Self {
        match self {
            Self::HandoffSource { .. } => Self::HandoffSource { head },
            _ => Self::Active {
                head,
                observed: None,
            },
        }
    }

    /// Records that the active head's address is assigned here. No-op otherwise.
    pub(crate) fn observe(&mut self, address: IpAddr) {
        if let Self::Active { observed, .. } = self {
            *observed = Some(address);
        }
    }

    /// Freezes this VPS as the predecessor of `head`.
    pub(crate) fn hand_off(&mut self, head: EndpointTransitionResponse) {
        *self = Self::HandoffSource { head };
    }
}

#[derive(Serialize, Deserialize)]
struct StoredEndpointAuthority {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint_transition: Option<EndpointTransitionResponse>,
    #[serde(default, skip_serializing_if = "is_false")]
    endpoint_transition_source: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint_observed_address: Option<IpAddr>,
}

impl TryFrom<StoredEndpointAuthority> for EndpointAuthority {
    type Error = &'static str;
    fn try_from(stored: StoredEndpointAuthority) -> Result<Self, Self::Error> {
        match (
            stored.endpoint_transition,
            stored.endpoint_transition_source,
            stored.endpoint_observed_address,
        ) {
            (None, false, None) => Ok(Self::Unpublished),
            (Some(head), false, observed) => Ok(Self::Active { head, observed }),
            (Some(head), true, None) => Ok(Self::HandoffSource { head }),
            (None, true, _) => Err("an endpoint handoff source must retain its signed transition"),
            _ => Err("current endpoint address observation is inconsistent"),
        }
    }
}

impl From<EndpointAuthority> for StoredEndpointAuthority {
    fn from(authority: EndpointAuthority) -> Self {
        let (endpoint_transition, endpoint_transition_source, endpoint_observed_address) =
            match authority {
                EndpointAuthority::Unpublished => (None, false, None),
                EndpointAuthority::Active { head, observed } => (Some(head), false, observed),
                EndpointAuthority::HandoffSource { head } => (Some(head), true, None),
            };
        Self {
            endpoint_transition,
            endpoint_transition_source,
            endpoint_observed_address,
        }
    }
}
