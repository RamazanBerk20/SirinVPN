use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub(crate) struct ReleaseUpdateStatus {
    pub installer_kind: &'static str,
    pub rollback_version: Option<String>,
    pub baseline_required: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackReleaseInput {
    pub confirmed: bool,
    pub expected_version: String,
}
