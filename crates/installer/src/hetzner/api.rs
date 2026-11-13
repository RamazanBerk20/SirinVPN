use super::*;

#[derive(Deserialize)]
pub(super) struct ApiId {
    pub(super) id: u64,
}

#[derive(Deserialize)]
pub(super) struct ApiSshKey {
    pub(super) ssh_key: ApiId,
}

#[derive(Deserialize)]
pub(super) struct ApiServerResponse {
    pub(super) server: ApiServer,
}

#[derive(Deserialize)]
pub(super) struct ApiServer {
    pub(super) id: u64,
    pub(super) status: String,
    pub(super) public_net: ApiPublicNet,
}

#[derive(Deserialize)]
pub(super) struct ApiPublicNet {
    pub(super) ipv4: Option<ApiAddress>,
    pub(super) ipv6: Option<ApiAddress>,
}

#[derive(Deserialize)]
pub(super) struct ApiAddress {
    pub(super) ip: String,
}

#[derive(Deserialize)]
pub(super) struct ApiServerType {
    pub(super) name: String,
    pub(super) description: String,
    pub(super) cores: f64,
    pub(super) memory: f64,
    pub(super) disk: f64,
    pub(super) architecture: String,
    pub(super) deprecated: Option<bool>,
    pub(super) deprecation: Option<Value>,
    pub(super) prices: Vec<ApiPrice>,
    #[serde(default)]
    pub(super) locations: Vec<ApiTypeLocation>,
}

#[derive(Deserialize)]
pub(super) struct ApiTypeLocation {
    pub(super) name: String,
    pub(super) available: Option<bool>,
    pub(super) deprecation: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct ApiPrice {
    pub(super) location: String,
    pub(super) price_monthly: ApiAmount,
}

#[derive(Deserialize)]
pub(super) struct ApiAmount {
    pub(super) gross: String,
}

#[derive(Deserialize)]
pub(super) struct ApiPricing {
    pub(super) pricing: ApiPricingBody,
}

#[derive(Deserialize)]
pub(super) struct ApiPricingBody {
    pub(super) currency: String,
    #[serde(default)]
    pub(super) primary_ips: Vec<ApiPrimaryIpPrice>,
}

#[derive(Deserialize)]
pub(super) struct ApiPrimaryIpPrice {
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) prices: Vec<ApiPrice>,
}

/// Hetzner answered and refused, so nothing was created.
pub(super) fn refused(error: &HetznerError) -> bool {
    matches!(error, HetznerError::Api { status, .. } if *status < 500)
}

/// A decimal string in ten-thousandths, the precision cents are rounded from.
pub(super) fn money(value: &str) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let fraction = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(4)
        .fold(0, |total, digit| total * 10 + u64::from(digit - b'0'));
    whole
        .parse::<u64>()
        .ok()?
        .checked_mul(10_000)?
        .checked_add(fraction)
}

pub(super) fn cents(ten_thousandths: u64) -> String {
    let cents = (ten_thousandths + 50) / 100;
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// Hetzner assigns a /64; its first address is the server's.
pub(super) fn first_address(network: &str) -> Option<Ipv6Addr> {
    let mut segments = network
        .split('/')
        .next()?
        .parse::<Ipv6Addr>()
        .ok()?
        .segments();
    segments[7] = 1;
    Some(Ipv6Addr::from(segments))
}
